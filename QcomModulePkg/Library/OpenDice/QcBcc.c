/*
 * Copyright (c) 2023 Qualcomm Innovation Center, Inc. All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#include "opendice-util.h"

#include <LinuxLoaderLib.h>
#include <dice/android/bcc.h>
#include <dice/cbor_writer.h>
#include <dice/dice.h>
#include <dice/ops.h>
#include <dice/ops/trait/cose.h>
#include <dice/utils.h>

#define MAX_CERTIFICATE_SIZE 512
#define DICE_ARTIFACTS_WO_BCC_TOTAL_SIZE 71
#define CONFIG_DESCRIPTOR_TOTAL_SIZE 48
#define DICE_ARTIFACTS_WITH_BCC_TOTAL_SIZE 4096
#define BCC_COMPONENT_NAME_BUFFER_MAX_SIZE 32
#define NO_ERROR 0
#define ERR_INVALID_ARGS 1
#define ERR_NOT_ENOUGH_BUFFER 2

/* Set of information required to derive DICE artifacts for the child node. */
typedef struct BccChildParams
{
  /* Code Hash */
  UINT8               codeHash[DICE_HASH_SIZE];
  /* Authority Hash */
  UINT8               authorityHash[DICE_HASH_SIZE];
  /* Bcc Config Descriptor */
  BccConfigValues     bccCfgDesc;
} BccChildParams_t;

typedef struct BccRootState
{
  /* Unique Device Secret */
  UINT8               UDS[DICE_CDI_SIZE];
  /* Public key of the key pair derived from a seed derived from UDS */
  UINT8               UDSPubKey[DICE_PUBLIC_KEY_SIZE];
  /* Secret with factory reset life time */
  UINT8               FRS[DICE_HIDDEN_SIZE];
  /* Device Mode */
  DiceMode            Mode;
  /* Information of Child Node */
  BccChildParams_t ChildImage;
} BccRoot_t;

/* Set of BCC artifacts passed on from one stage to the next */
typedef struct BCCArtifacts
{
  UINT8               nextCDIAttest[DICE_CDI_SIZE];
  UINT8               nextCDISeal[DICE_CDI_SIZE];
  UINT8               nextBCC[MAX_CERTIFICATE_SIZE];
  size_t              nextBCCSize;
} BCCArtifacts_t;

typedef struct BccImgParams
{
  UINT8               codeHash[DICE_HASH_SIZE];      /*Code Hash*/
  UINT8               authorityHash[DICE_HASH_SIZE]; /*Key-0 PK Hash*/
  CHAR8               componentName[BCC_COMPONENT_NAME_BUFFER_MAX_SIZE];
  UINT64              componentVersion;
} BccImgParams_t;

typedef struct BccParams
{
  UINT8               UDS[DICE_CDI_SIZE];    /*Unique Device Secret*/
  UINT8               FRS[DICE_HIDDEN_SIZE]; /*Factory reset Secret*/
  DiceMode            Mode;
  BccImgParams_t      ChildImage;            /*Image Parameters*/
} BccParams_t;

STATIC CONST INT64 KcdiAttestLabel = 1;
STATIC CONST INT64 KcdiSealLabel   = 2;
STATIC BccRoot_t BccRoot;

STATIC UINT8 BccDiceToBccResult (DiceResult Result)
{
  switch (Result) {
  case kDiceResultOk:
    return NO_ERROR;
  case kDiceResultInvalidInput:
    return ERR_INVALID_ARGS;
  case kDiceResultBufferTooSmall:
    return ERR_NOT_ENOUGH_BUFFER;
  case kDiceResultPlatformError:
    return (INT8)Result;
  }
}

/**
  * BCC artifacts to be handed over from root to the child nodes takes the
  * following format.
  *
  *                 BccHandover = {
  *                    1 : bstr .size 32, // CDI_Attest
  *                    2 : bstr .size 32, // CDI_Seal
  *                    3 : Bcc,           // Cert_Chain
  *                  }
  *                  where Bcc = [
  *                          PubKeyEd25519 / PubKeyECDSA256, // Root pub key
  *                          BccEntry,                       // Root -> leaf
  *                        ]
  *
  * On Success this API will generate and return the BCC Artifacts in
  * the "FinalEncodedBccArtifacts" (allocated by the calling client for
  * "BccArtifactsBufferSize") and the actual encoded BCC Handover artifacts
  * size in "BccArtifactsValidSize".
  */
UINT8 GetBccArtifacts (UINT8  *FinalEncodedBccArtifacts,
                        size_t  BccArtifactsBufferSize,
                        size_t *BccArtifactsValidSize)
{
  BCCArtifacts_t  bccCDIsOnly;
  BccParams_t     BccParamsRecvdFromAVB;
  DiceInputValues BccInputValues = {{0}};
  UINT8 UDSPrivateKeySeed[DICE_PRIVATE_KEY_SEED_SIZE] = {0};
  UINT8 UDSPrivateKey[DICE_PRIVATE_KEY_SIZE] = {1};
  DiceResult Result;
  UINT8 BccEncodedConfigDesc[CONFIG_DESCRIPTOR_TOTAL_SIZE];
  size_t BccEncodedConfigDescValidSize = 0;
  UINT8 NextBccEncodedCDIs[DICE_ARTIFACTS_WO_BCC_TOTAL_SIZE] = {0};
  size_t NextBccEncodedCDIsValidSize = 0;
  struct CborOut Out;
  INTN Ret;

  if (FinalEncodedBccArtifacts == NULL ||
      BccArtifactsValidSize == NULL ||
      BccArtifactsBufferSize > DICE_ARTIFACTS_WITH_BCC_TOTAL_SIZE) {
      return ERR_INVALID_ARGS;
  }

 /* Used temporarly for dummy BCC generation */
  SetMem (&BccParamsRecvdFromAVB, sizeof (BccParamsRecvdFromAVB), 0);
  SetMem (&bccCDIsOnly, sizeof (bccCDIsOnly), 0);
  memcpy ((VOID *)BccParamsRecvdFromAVB.ChildImage.componentName, "pvmfw", 5);
  BccParamsRecvdFromAVB.Mode = kDiceModeDebug;

  /* Populate BCC Root Data Structure with parameters received from AVB */
  SetMem (&BccRoot, sizeof (BccRoot), 0);
  memcpy (BccRoot.UDS, BccParamsRecvdFromAVB.UDS, DICE_CDI_SIZE);

  memcpy (BccRoot.FRS, BccParamsRecvdFromAVB.FRS, DICE_HIDDEN_SIZE);
  memcpy (BccRoot.ChildImage.codeHash,
         BccParamsRecvdFromAVB.ChildImage.codeHash,
         DICE_HIDDEN_SIZE);

  memcpy (BccRoot.ChildImage.authorityHash,
         BccParamsRecvdFromAVB.ChildImage.authorityHash,
         DICE_HIDDEN_SIZE);

  /* Populate BCC Config Descriptor Values */
  BccRoot.ChildImage.bccCfgDesc.component_name =
         BccParamsRecvdFromAVB.ChildImage.componentName;
  BccRoot.ChildImage.bccCfgDesc.component_version =
         BccParamsRecvdFromAVB.ChildImage.componentVersion;
  BccRoot.Mode = BccParamsRecvdFromAVB.Mode;
  BccRoot.ChildImage.bccCfgDesc.inputs =  BCC_INPUT_COMPONENT_NAME |
                                          BCC_INPUT_COMPONENT_VERSION;

  /* Derive Private Key Seed from UDS */
  Result = DiceDeriveCdiPrivateKeySeed (NULL,
                                        BccRoot.UDS,
                                        UDSPrivateKeySeed);
  Ret = BccDiceToBccResult (Result);
  if (Ret != NO_ERROR) {
    DEBUG ((EFI_D_ERROR, "Failed to derive a seed for UDS key pair.\n"));
    return Ret;
  }

  /* Derive UDS Key Pair */
  /* UDS public key is kept in root to construct the certificate
   * chain for the child nodes. UDS private key is derived in every
   * DICE operation which uses it.
   */
  Result = DiceKeypairFromSeed (NULL, UDSPrivateKeySeed,
                                BccRoot.UDSPubKey,
                                UDSPrivateKey);
  Ret = BccDiceToBccResult (Result);
  if (Ret != NO_ERROR) {
    DEBUG ((EFI_D_ERROR, "Failed to derive UDS key pair.\n"));
    return Ret;
  }

  /* CBOR Encode BCC Config Descriptor Parameters */
  Result = BccFormatConfigDescriptor (&(BccRoot.ChildImage.bccCfgDesc),
                                      sizeof (BccEncodedConfigDesc),
                                      BccEncodedConfigDesc,
                                      &BccEncodedConfigDescValidSize);

  Ret = BccDiceToBccResult (Result);
  if (Ret != NO_ERROR) {
    DEBUG ((EFI_D_ERROR, "Failed to format config descriptor : %d\n", Ret));
    return Ret;
  }
  DEBUG ((EFI_D_VERBOSE,
         "BccEncodedConfigDescValidSize = %x\n",
         BccEncodedConfigDescValidSize));

  /* Initialize the DICE input values */
  memcpy (BccInputValues.code_hash,
          BccRoot.ChildImage.codeHash,
          sizeof (BccRoot.ChildImage.codeHash));

  memcpy (BccInputValues.authority_hash,
          BccRoot.ChildImage.authorityHash,
          sizeof (BccRoot.ChildImage.authorityHash));

  /* Factory reset secret is mixed in only for the non-secure world. */
  memcpy (BccInputValues.hidden, BccRoot.FRS, sizeof (BccRoot.FRS));
  BccInputValues.config_type            = kDiceConfigTypeDescriptor;
  BccInputValues.config_descriptor      = BccEncodedConfigDesc;
  BccInputValues.config_descriptor_size = BccEncodedConfigDescValidSize;
  BccInputValues.mode = BccRoot.Mode;

  /* Generate Dice Artifacts Without BCC (CDI-Attest, CDI-Sealing only) */
  Result = DiceMainFlow (NULL,
                         BccRoot.UDS,
                         BccRoot.UDS,
                         &BccInputValues, 0,
                         NULL,
                         NULL,
                         bccCDIsOnly.nextCDIAttest,
                         bccCDIsOnly.nextCDISeal);
  Ret = BccDiceToBccResult (Result);
  if (Ret != NO_ERROR) {
    DEBUG ((EFI_D_ERROR, "Failed to derive DICE CDIs : %d\n", Ret));
    return Ret;
  }

  /* CBOR Encode Dice Artifacts (Without BCC) CDI-Attest/CDI-Sealing */
  CborOutInit (NextBccEncodedCDIs, DICE_ARTIFACTS_WO_BCC_TOTAL_SIZE, &Out);
  CborWriteMap (2, &Out);
  CborWriteInt (KcdiAttestLabel, &Out);
  CborWriteBstr (DICE_CDI_SIZE, bccCDIsOnly.nextCDIAttest, &Out);
  CborWriteInt (KcdiSealLabel, &Out);
  CborWriteBstr (DICE_CDI_SIZE, bccCDIsOnly.nextCDISeal, &Out);
  if (CborOutOverflowed (&Out)) {
    return kDiceResultBufferTooSmall;
  }
  NextBccEncodedCDIsValidSize = CborOutSize (&Out);
  DEBUG ((EFI_D_VERBOSE,
         "GetBccArtifacts: NextBccEncodedCDIsValidSize=0x%x\n",
         NextBccEncodedCDIsValidSize));

  /* Generate Dice Artifacts With BCC (CDI-Attest, CDI-Sealing, BCC) */
  Result = BccHandoverMainFlow (NULL /*context=*/,
                                NextBccEncodedCDIs,
                                NextBccEncodedCDIsValidSize,
                                &BccInputValues,
                                BccArtifactsBufferSize,
                                FinalEncodedBccArtifacts,
                                BccArtifactsValidSize);
  DEBUG ((EFI_D_VERBOSE,
         "GetBccArtifacts: BccArtifactsValidSize=0x%x\n",
         *BccArtifactsValidSize));

  return (BccDiceToBccResult (Result));
}
