// Copyright 2021 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not
// use this file except in compliance with the License. You may obtain a copy of
// the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations under
// the License.

/*
 * Changes from Qualcomm Innovation Center are provided under the following license:
 * Copyright (c) 2023 Qualcomm Innovation Center, Inc. All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */
#include "../../../opendice-util.h"

#include "dice/android/bcc.h"

#include "dice/cbor_reader.h"
#include "dice/cbor_writer.h"
#include "dice/dice.h"
#include "dice/ops.h"
#include "dice/ops/trait/cose.h"


// Completely gratuitous bit twiddling.
static size_t PopulationCount(uint32_t n) {
  n = n - ((n >> 1) & 0x55555555);
  n = (n & 0x33333333) + ((n >> 2) & 0x33333333);
  return (((n + (n >> 4)) & 0x0F0F0F0F) * 0x01010101) >> 24;
}

DiceResult BccFormatConfigDescriptor(const BccConfigValues* input_values,
                                     size_t buffer_size, uint8_t* buffer,
                                     size_t* actual_size) {
  static const int64_t kComponentNameLabel = -70002;
  static const int64_t kComponentVersionLabel = -70003;
  static const int64_t kResettableLabel = -70004;

  // BccConfigDescriptor = {
  //   ? -70002 : tstr,     ; Component name
  //   ? -70003 : int,      ; Component version
  //   ? -70004 : null,     ; Resettable
  // }
  struct CborOut out;
  CborOutInit(buffer, buffer_size, &out);
  CborWriteMap(PopulationCount(input_values->inputs), &out);
  if (input_values->inputs & BCC_INPUT_COMPONENT_NAME &&
      input_values->component_name) {
    CborWriteInt(kComponentNameLabel, &out);
    CborWriteTstr(input_values->component_name, &out);
  }
  if (input_values->inputs & BCC_INPUT_COMPONENT_VERSION) {
    CborWriteInt(kComponentVersionLabel, &out);
    CborWriteUint(input_values->component_version, &out);
  }
  if (input_values->inputs & BCC_INPUT_RESETTABLE) {
    CborWriteInt(kResettableLabel, &out);
    CborWriteNull(&out);
  }
  *actual_size = CborOutSize(&out);
  if (CborOutOverflowed(&out)) {
    return kDiceResultBufferTooSmall;
  }
  return kDiceResultOk;
}

DiceResult BccMainFlow(void* context,
                       const uint8_t current_cdi_attest[DICE_CDI_SIZE],
                       const uint8_t current_cdi_seal[DICE_CDI_SIZE],
                       const uint8_t* bcc, size_t bcc_size,
                       const DiceInputValues* input_values, size_t buffer_size,
                       uint8_t* buffer, size_t* actual_size,
                       uint8_t next_cdi_attest[DICE_CDI_SIZE],
                       uint8_t next_cdi_seal[DICE_CDI_SIZE]) {
  DiceResult result;
  enum CborReadResult res;
  struct CborIn in;
  size_t bcc_item_count;

  // The BCC has a more detailed internal structure, but those details aren't
  // relevant to the work of this function.
  //
  // Bcc = [
  //   COSE_Key,         ; Root public key
  //   + COSE_Sign1,     ; Bcc entries
  // ]
  CborInInit(bcc, bcc_size, &in);
  res = CborReadArray(&in, &bcc_item_count);
  if (res != CBOR_READ_RESULT_OK) {
    return kDiceResultInvalidInput;
  }

  if (bcc_item_count < 2 || bcc_item_count == SIZE_MAX) {
    // There should at least be the public key and one entry.
    return kDiceResultInvalidInput;
  }

  // Measure the existing BCC entries.
  size_t bcc_items_offset = CborInOffset(&in);
  for (size_t bcc_pos = 0; bcc_pos < bcc_item_count; ++bcc_pos) {
    res = CborReadSkip(&in);
    if (res != CBOR_READ_RESULT_OK) {
      return kDiceResultInvalidInput;
    }
  }
  size_t bcc_items_size = CborInOffset(&in) - bcc_items_offset;

  // Copy to the new buffer, with space in the BCC for one more entry.
  struct CborOut out;
  CborOutInit(buffer, buffer_size, &out);
  CborWriteArray(bcc_item_count + 1, &out);
  if (CborOutOverflowed(&out) ||
      bcc_items_size > buffer_size - CborOutSize(&out)) {
    // Continue with an empty buffer to measure the required size.
    buffer_size = 0;
  } else {
    memcpy(buffer + CborOutSize(&out), bcc + bcc_items_offset, bcc_items_size);
    buffer += CborOutSize(&out) + bcc_items_size;
    buffer_size -= CborOutSize(&out) + bcc_items_size;
  }

  size_t certificate_size;
  result = DiceMainFlow(context, current_cdi_attest, current_cdi_seal,
                        input_values, buffer_size, buffer, &certificate_size,
                        next_cdi_attest, next_cdi_seal);
  *actual_size = CborOutSize(&out) + bcc_items_size + certificate_size;
  return result;
}

static DiceResult BccMainFlowWithNewBcc(
    void* context, const uint8_t current_cdi_attest[DICE_CDI_SIZE],
    const uint8_t current_cdi_seal[DICE_CDI_SIZE],
    const DiceInputValues* input_values, size_t buffer_size, uint8_t* buffer,
    size_t* bcc_size, uint8_t next_cdi_attest[DICE_CDI_SIZE],
    uint8_t next_cdi_seal[DICE_CDI_SIZE]) {
  uint8_t current_cdi_private_key_seed[DICE_PRIVATE_KEY_SEED_SIZE];
  uint8_t attestation_public_key[DICE_PUBLIC_KEY_SIZE];
  uint8_t attestation_private_key[DICE_PRIVATE_KEY_SIZE];
  // Derive an asymmetric private key seed from the current attestation CDI
  // value.
  DiceResult result = DiceDeriveCdiPrivateKeySeed(context, current_cdi_attest,
                                                  current_cdi_private_key_seed);
  if (result != kDiceResultOk) {
    goto out;
  }
  // Derive attestation key pair.
  result = DiceKeypairFromSeed(context, current_cdi_private_key_seed,
                               attestation_public_key, attestation_private_key);
  if (result != kDiceResultOk) {
    goto out;
  }

  // Consruct the BCC from the attestation public key and the next CDI
  // certificate.
  struct CborOut out;
  CborOutInit(buffer, buffer_size, &out);
  CborWriteArray(2, &out);
  size_t encoded_size_used = CborOutSize(&out);
  if (CborOutOverflowed(&out)) {
    // Continue with an empty buffer to measure the required size.
    buffer_size = 0;
  } else {
    buffer += encoded_size_used;
    buffer_size -= encoded_size_used;
  }

  size_t encoded_pub_key_size = 0;
  result = DiceCoseEncodePublicKey(context, attestation_public_key, buffer_size,
                                   buffer, &encoded_pub_key_size);
  if (result == kDiceResultOk) {
    buffer += encoded_pub_key_size;
    buffer_size -= encoded_pub_key_size;
  } else if (result == kDiceResultBufferTooSmall) {
    // Continue with an empty buffer to measure the required size.
    buffer_size = 0;
  } else {
    goto out;
  }

  result = DiceMainFlow(context, current_cdi_attest, current_cdi_seal,
                        input_values, buffer_size, buffer, bcc_size,
                        next_cdi_attest, next_cdi_seal);
  *bcc_size += encoded_size_used + encoded_pub_key_size;
  if (result != kDiceResultOk) {
    return result;
  }

out:
  DiceClearMemory(context, sizeof(current_cdi_private_key_seed),
                  current_cdi_private_key_seed);
  DiceClearMemory(context, sizeof(attestation_private_key),
                  attestation_private_key);

  return result;
}

static const int64_t kCdiAttestLabel = 1;
static const int64_t kCdiSealLabel = 2;
static const int64_t kBccLabel = 3;

DiceResult BccHandoverMainFlow(void* context, const uint8_t* bcc_handover,
                               size_t bcc_handover_size,
                               const DiceInputValues* input_values,
                               size_t buffer_size, uint8_t* buffer,
                               size_t* actual_size) {
  DiceResult result;
  const uint8_t* current_cdi_attest;
  const uint8_t* current_cdi_seal;
  const uint8_t* bcc;
  size_t bcc_size;

  result =
      BccHandoverParse(bcc_handover, bcc_handover_size, &current_cdi_attest,
                       &current_cdi_seal, &bcc, &bcc_size);
  if (result != kDiceResultOk) {
    return kDiceResultInvalidInput;
  }

  // Write the new handover data.
  struct CborOut out;
  CborOutInit(buffer, buffer_size, &out);
  CborWriteMap(/*num_pairs=*/3, &out);
  CborWriteInt(kCdiAttestLabel, &out);
  uint8_t* next_cdi_attest = CborAllocBstr(DICE_CDI_SIZE, &out);
  CborWriteInt(kCdiSealLabel, &out);
  uint8_t* next_cdi_seal = CborAllocBstr(DICE_CDI_SIZE, &out);
  CborWriteInt(kBccLabel, &out);

  uint8_t ignored_cdi_attest[DICE_CDI_SIZE];
  uint8_t ignored_cdi_seal[DICE_CDI_SIZE];
  if (CborOutOverflowed(&out)) {
    // Continue with an empty buffer and placeholders for the output CDIs to
    // measure the required size.
    buffer_size = 0;
    next_cdi_attest = ignored_cdi_attest;
    next_cdi_seal = ignored_cdi_seal;
  } else {
    buffer += CborOutSize(&out);
    buffer_size -= CborOutSize(&out);
  }

  if (bcc_size != 0) {
    // If BCC is present in the bcc_handover, append the next certificate to the
    // existing BCC.
    result = BccMainFlow(context, current_cdi_attest, current_cdi_seal, bcc,
                         bcc_size, input_values, buffer_size, buffer, &bcc_size,
                         next_cdi_attest, next_cdi_seal);
  } else {
    // If BCC is not present in the bcc_handover, construct BCC from the public
    // key derived from the current CDI attest and the next CDI certificate.
    result = BccMainFlowWithNewBcc(
        context, current_cdi_attest, current_cdi_seal, input_values,
        buffer_size, buffer, &bcc_size, next_cdi_attest, next_cdi_seal);
  }
  *actual_size = CborOutSize(&out) + bcc_size;
  return result;
}

DiceResult BccHandoverParse(const uint8_t* bcc_handover,
                            size_t bcc_handover_size,
                            const uint8_t** cdi_attest,
                            const uint8_t** cdi_seal, const uint8_t** bcc,
                            size_t* bcc_size) {
  // Extract details from the handover data.
  //
  // BccHandover = {
  //   1 : bstr .size 32,     ; CDI_Attest
  //   2 : bstr .size 32,     ; CDI_Seal
  //   ? 3 : Bcc,             ; Certificate chain
  // }
  struct CborIn in;
  int64_t label;
  size_t num_pairs;
  size_t item_size;
  CborInInit(bcc_handover, bcc_handover_size, &in);
  if (CborReadMap(&in, &num_pairs) != CBOR_READ_RESULT_OK || num_pairs < 2 ||
      // Read the attestation CDI.
      CborReadInt(&in, &label) != CBOR_READ_RESULT_OK ||
      label != kCdiAttestLabel ||
      CborReadBstr(&in, &item_size, cdi_attest) != CBOR_READ_RESULT_OK ||
      item_size != DICE_CDI_SIZE ||
      // Read the sealing CDI.
      CborReadInt(&in, &label) != CBOR_READ_RESULT_OK ||
      label != kCdiSealLabel ||
      CborReadBstr(&in, &item_size, cdi_seal) != CBOR_READ_RESULT_OK ||
      item_size != DICE_CDI_SIZE) {
    return kDiceResultInvalidInput;
  }

  *bcc = NULL;
  *bcc_size = 0;
  if (num_pairs >= 3 && CborReadInt(&in, &label) == CBOR_READ_RESULT_OK) {
    if (label == kBccLabel) {
      // Calculate the BCC size, if the BCC is present in the BccHandover.
      size_t bcc_start = CborInOffset(&in);
      if (CborReadSkip(&in) != CBOR_READ_RESULT_OK) {
        return kDiceResultInvalidInput;
      }
      *bcc = bcc_handover + bcc_start;
      *bcc_size = CborInOffset(&in) - bcc_start;
    }
  }

  return kDiceResultOk;
}
