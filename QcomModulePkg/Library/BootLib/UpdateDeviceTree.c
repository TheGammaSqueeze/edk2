/* Copyright (c) 2015-2021, The Linux Foundation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 * * Redistributions of source code must retain the above copyright
 *  notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following
 * disclaimer in the documentation and/or other materials provided
 *  with the distribution.
 *   * Neither the name of The Linux Foundation nor the names of its
 * contributors may be used to endorse or promote products derived
 * from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED "AS IS" AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

/*
 * Changes from Qualcomm Innovation Center are provided under the following license:
 *
 * Copyright (c) 2022-2024 Qualcomm Innovation Center, Inc. All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted (subject to the limitations in the
 *  disclaimer below) provided that the following conditions are met:
 *
 *      * Redistributions of source code must retain the above copyright
 *        notice, this list of conditions and the following disclaimer.
 *
 *      * Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials provided
 *        with the distribution.
 *
 *      * Neither the name of Qualcomm Innovation Center, Inc. nor the names of its
 *        contributors may be used to endorse or promote products derived
 *        from this software without specific prior written permission.
 *
 *  NO EXPRESS OR IMPLIED LICENSES TO ANY PARTY'S PATENT RIGHTS ARE
 *  GRANTED BY THIS LICENSE. THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT
 *  HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED
 *   WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 *  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 *  IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
 *  ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 *  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 *  GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 *  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 *  IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 *  OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 *  IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/* Supporting function of UpdateDeviceTree()
 * Function adds memory map entries to the device tree binary
 * dev_tree_add_mem_info() is called at every time when memory type matches
 * conditions */

#include "UpdateDeviceTree.h"
#include "AutoGen.h"
#include "DisplayCtrl.h"
#include <Library/UpdateDeviceTree.h>
#include <Library/LocateDeviceTree.h>
#include <Library/BootLinux.h>
#include <Protocol/EFIChipInfoTypes.h>
#include <Protocol/EFIDDRGetConfig.h>
#include <Protocol/EFIRng.h>
#include <Protocol/EFIDisplayPwr.h>
#include <Library/PartialGoods.h>
#include <Library/FdtRw.h>

#define NUM_SPLASHMEM_PROP_ELEM 4
#define DEFAULT_CELL_SIZE 2
#define NUM_RNG_SEED_WORDS 512
#define NUM_RAMDUMP_PROP_ELEM   2
#define SCT_CONFIG_BASE_REVISION 0x0000000000070000

STATIC struct FstabNode FstabTable = {"/firmware/android/fstab", "dev",
                                      "/soc/"};
STATIC struct FstabNode DynamicFstabTable = {"/firmware/android/fstab",
                                              "status",
                                              ""};
STATIC struct DisplaySplashBufferInfo splashBuf;
STATIC UINTN splashBufSize = sizeof (splashBuf);

STATIC VOID
PrintSplashMemInfo (CONST CHAR8 *data, INT32 datalen)
{
  UINT32 i, val[NUM_SPLASHMEM_PROP_ELEM] = {0};

  for (i = 0; (i < NUM_SPLASHMEM_PROP_ELEM) && datalen; i++) {
    memcpy (&val[i], data, sizeof (UINT32));
    val[i] = fdt32_to_cpu (val[i]);
    data += sizeof (UINT32);
    datalen -= sizeof (UINT32);
  }

  DEBUG ((EFI_D_VERBOSE, "reg = <0x%08x 0x%08x 0x%08x 0x%08x>\n", val[0],
          val[1], val[2], val[3]));
}

STATIC EFI_STATUS
GetDDRInfo (struct ddr_details_entry_info *DdrInfo,  UINT64 *Revision)
{
  EFI_DDRGETINFO_PROTOCOL *DdrInfoIf;
  EFI_STATUS Status;

  Status = gBS->LocateProtocol (&gEfiDDRGetInfoProtocolGuid, NULL,
                                (VOID **)&DdrInfoIf);
  if (Status != EFI_SUCCESS) {
    DEBUG ((EFI_D_VERBOSE,
            "INFO: Unable to get DDR Info protocol:%r\n",
            Status));
    return Status;
  }

  Status = DdrInfoIf->GetDDRDetails (DdrInfoIf, DdrInfo);
  if (EFI_ERROR (Status)) {
    DEBUG ((EFI_D_ERROR, "INFO: GetDDR details failed\n"));
    return Status;
  }

  *Revision = DdrInfoIf->Revision;
  DEBUG ((EFI_D_VERBOSE, "GetDDRInfo: DDR Header Revision =0x%x\n", *Revision));

  return Status;
}

STATIC EFI_STATUS
GetSCTConfig (UINT8 *SCTConfig)
{
  EFI_DDRGETINFO_PROTOCOL *DdrInfoIf;
  EFI_STATUS Status;
  UINT64 Revision;

  Status = gBS->LocateProtocol (&gEfiDDRGetInfoProtocolGuid, NULL,
                                (VOID **)&DdrInfoIf);
  if (Status != EFI_SUCCESS) {
    DEBUG ((EFI_D_VERBOSE,
            "INFO: Unable to get DDR Info protocol:%r\n",
            Status));
    return Status;
  }

  Revision = DdrInfoIf->Revision;
  if (Revision < SCT_CONFIG_BASE_REVISION) {
    DEBUG ((EFI_D_VERBOSE,
            "SCTConfig not supported in Revision=0x%x\n", Revision));
    return EFI_UNSUPPORTED;
  }

  Status = DdrInfoIf->GetDDRSCTConfig (DdrInfoIf, SCTConfig);
  if (EFI_ERROR (Status)) {
    DEBUG ((EFI_D_ERROR, "INFO: GetSCTConfig failed\n"));
    return Status;
  }
    return Status;
}

STATIC EFI_STATUS
GetRandomSeed (UINT64 *RandomSeed)
{
  EFI_QCOM_RNG_PROTOCOL *RngIf;
  EFI_STATUS Status;

  Status = gBS->LocateProtocol (&gQcomRngProtocolGuid, NULL, (VOID **)&RngIf);
  if (Status != EFI_SUCCESS) {
    DEBUG ((EFI_D_VERBOSE,
            "Error locating PRNG protocol. Fail to generate random seed:%r\n",
            Status));
    return Status;
  }

  Status = RngIf->GetRNG (RngIf,
                          &gEfiRNGAlgRawGuid,
                          sizeof (UINTN),
                          (UINT8 *)RandomSeed);
  if (Status != EFI_SUCCESS) {
    DEBUG ((EFI_D_VERBOSE,
         "Error getting PRNG random number. Fail to generate Kaslr seed:%r\n",
         Status));
    *RandomSeed = 0;
    return Status;
  }

  return Status;
}

STATIC VOID
DisableDisplay (VOID)
{
  EFI_STATUS                     Status           = EFI_SUCCESS;
  EFI_DISPLAY_POWER_PROTOCOL    *pDispPwrProtocol = NULL;

  Status = gBS->LocateProtocol (&gEfiDisplayPowerStateProtocolGuid,
                                NULL,
                                (VOID **)&pDispPwrProtocol);

  if ((EFI_SUCCESS != Status) ||
      (NULL        == pDispPwrProtocol)) {
    DEBUG ((EFI_D_ERROR,
           "ERROR: Unable to get display power protocol,Status=%d\n", Status));
  }
  else {
    Status = pDispPwrProtocol->SetDisplayPowerState (pDispPwrProtocol,
                                                     EfiDisplayPowerStateOff);
    if (EFI_SUCCESS != Status) {
      DEBUG ((EFI_D_ERROR,
             "ERROR: Fail to turn display off,Status=%d\n", Status));
    }
  }
}

STATIC EFI_STATUS
UpdateRamDumpMemInfo (VOID *fdt)
{
  EFI_STATUS Status = EFI_SUCCESS;
  CONST struct fdt_property *Prop = NULL;
  INT32 PropLen = 0;
  INT32 Ret     = 0;
  INT32 OffSet  = 0;
  UINT32 CONST RamdumpMemPropSize = NUM_RAMDUMP_PROP_ELEM * sizeof (UINT32);

  /* Ramdump address same as splash */
  Status =
      gRT->GetVariable ((CHAR16 *)L"DisplaySplashBufferInfo",
                        &gQcomTokenSpaceGuid, NULL, &splashBufSize, &splashBuf);
  if (Status != EFI_SUCCESS) {
    DEBUG ((EFI_D_ERROR, "Unable to get splash buffer info, %r\n", Status));
    return Status;
  }

  /* Get offset of the ramdump memory reservation node */
  OffSet = FdtPathOffset (fdt, "/soc/disp_rdump_region");
  if (OffSet < 0) {
    DEBUG ((EFI_D_WARN, "ramdump region not found in device tree\n"));
    return EFI_NOT_FOUND;
  }

  /* Get the property that specifies the ramdump memory details */
  Prop = fdt_get_property (fdt, OffSet, "reg", &PropLen);
  if (!Prop) {
    DEBUG ((EFI_D_ERROR, "ERROR: Could not find the ramdump reg property\n"));
    return EFI_NOT_FOUND;
  }

   /*
   * The format of the "reg" field is as follows:
   *       <FBAddress FBSize>
   * The expected size of this property is 2 * sizeof(UINT32)
   */
  if (PropLen != RamdumpMemPropSize) {
    DEBUG (
        (EFI_D_ERROR,
         "ERROR: Ramdump mem reservation node size. Expected: %d, Actual: %d\n",
         RamdumpMemPropSize, PropLen));
    return EFI_BAD_BUFFER_SIZE;
  }

  /* First, update the FBAddress */
  if (CHECK_ADD64 ((UINT64)Prop->data, sizeof (UINT32))) {
    DEBUG ((EFI_D_ERROR, "ERROR: integer Overflow while updating FBAddress"));
    return EFI_BAD_BUFFER_SIZE;
  }
  splashBuf.uFrameAddr = cpu_to_fdt32 (splashBuf.uFrameAddr);
  memcpy ((CHAR8 *)Prop->data, &splashBuf.uFrameAddr, sizeof (UINT32));

  /* Update the property value in place */
  Ret = fdt_setprop_inplace (fdt, OffSet, "reg", Prop->data, PropLen);
  if (Ret < 0) {
    DEBUG ((EFI_D_ERROR, "ERROR: Could not update ramdump mem info\n"));
    return EFI_NO_MAPPING;
  }

  return Status;
}

STATIC EFI_STATUS
UpdateSplashMemInfo (VOID *fdt)
{
  EFI_STATUS Status;
  CONST struct fdt_property *Prop = NULL;
  INT32 PropLen = 0;
  INT32 ret = 0;
  UINT32 offset;
  CHAR8 *tmp = NULL;
  UINT32 CONST SplashMemPropSize = NUM_SPLASHMEM_PROP_ELEM * sizeof (UINT32);

  Status =
      gRT->GetVariable ((CHAR16 *)L"DisplaySplashBufferInfo",
                        &gQcomTokenSpaceGuid, NULL, &splashBufSize, &splashBuf);
  if (Status != EFI_SUCCESS) {
    DEBUG ((EFI_D_ERROR, "Unable to get splash buffer info, %r\n", Status));
    goto error;
  }

  DEBUG ((EFI_D_VERBOSE, "Version=%d\nAddr=0x%08x\nSize=0x%08x\n",
          splashBuf.uVersion, splashBuf.uFrameAddr, splashBuf.uFrameSize));

  /* Get offset of the splash memory reservation node */
  ret = FdtPathOffset (fdt, "/reserved-memory/splash_region");
  if (ret < 0) {
    DEBUG ((EFI_D_WARN, "Splash region not found in device tree, " \
                        "powering down the display and controller\n"));

    /*
     * This function call leads to the following:
     * 1) Turn off display power
     * 2) Disable display clocks
     * 3) Reset display TE/RST pin
     */
    DisableDisplay ();
    return EFI_NOT_FOUND;
  }

  offset = ret;
  DEBUG ((EFI_D_VERBOSE, "FB mem node name: %a\n",
          fdt_get_name (fdt, offset, NULL)));

  /* Get the property that specifies the splash memory details */
  Prop = fdt_get_property (fdt, offset, "reg", &PropLen);
  if (!Prop) {
    DEBUG ((EFI_D_ERROR, "ERROR: Could not find the splash reg property\n"));
    return EFI_NOT_FOUND;
  }

  /*
   * The format of the "reg" field is as follows:
   *       <0x0 FBAddress 0x0 FBSize>
   * The expected size of this property is 4 * sizeof(UINT32)
   */
  if (PropLen != SplashMemPropSize) {
    DEBUG (
        (EFI_D_ERROR,
         "ERROR: splash mem reservation node size. Expected: %d, Actual: %d\n",
         SplashMemPropSize, PropLen));
    return EFI_BAD_BUFFER_SIZE;
  }

  DEBUG ((EFI_D_VERBOSE, "Splash memory region before updating:\n"));
  PrintSplashMemInfo (Prop->data, PropLen);

  /* First, update the FBAddress */
  if (CHECK_ADD64 ((UINT64)Prop->data, sizeof (UINT32))) {
    DEBUG ((EFI_D_ERROR, "ERROR: integer Overflow while updating FBAddress"));
    return EFI_BAD_BUFFER_SIZE;
  }
  tmp = (CHAR8 *)Prop->data + sizeof (UINT32);
  splashBuf.uFrameAddr = cpu_to_fdt32 (splashBuf.uFrameAddr);
  memcpy (tmp, &splashBuf.uFrameAddr, sizeof (UINT32));

  /* Next, update the FBSize */
  if (CHECK_ADD64 ((UINT64)tmp, (2 * sizeof (UINT32)))) {
    DEBUG ((EFI_D_ERROR, "ERROR: integer Overflow while updating FBSize"));
    return EFI_BAD_BUFFER_SIZE;
  }
  tmp += (2 * sizeof (UINT32));
  splashBuf.uFrameSize = cpu_to_fdt32 (splashBuf.uFrameSize);
  memcpy (tmp, &splashBuf.uFrameSize, sizeof (UINT32));

  /* Update the property value in place */
  ret = fdt_setprop_inplace (fdt, offset, "reg", Prop->data, PropLen);
  if (ret < 0) {
    DEBUG ((EFI_D_ERROR, "ERROR: Could not update splash mem info\n"));
    return EFI_NO_MAPPING;
  }

  DEBUG ((EFI_D_VERBOSE, "Splash memory region after updating:\n"));
  PrintSplashMemInfo (Prop->data, PropLen);
error:
  return Status;
}

STATIC EFI_STATUS
UpdateDemuraRegion (VOID *fdt, CONST CHAR8 *Path,
                    UINT32 HFCAddr, UINT32 HFCSize)
{
  EFI_STATUS Status = EFI_SUCCESS;
  UINT32 DemuraInfoSize = 4 * sizeof (UINT32);
  CONST struct fdt_property *Prop = NULL;
  INT32 PropLen = 0;
  CHAR8 *tmp = NULL;
  INT32 ret = 0;
  UINT32 offset = 0;

  if (Path != NULL)
  {
    ret = FdtPathOffset (fdt, Path);
    if (ret < 0) {
      /* Just return success if demura node not exists */
      return EFI_SUCCESS;
    }

    offset = (UINT32)ret;
    Prop = fdt_get_property (fdt, offset, "reg", &PropLen);

    if (!Prop) {
      DEBUG ((EFI_D_WARN, "Could not find the demura reg property\n"));
      Status = EFI_NOT_FOUND;
    } else if (PropLen < DemuraInfoSize) {
      DEBUG ((EFI_D_WARN, "Invalid demura node size\n"));
      Status = EFI_INVALID_PARAMETER;
    } else {
      /* First, update the demura HFC Address */
      tmp = (CHAR8 *)Prop->data + sizeof (UINT32);
      HFCAddr = cpu_to_fdt32 (HFCAddr);
      memcpy (tmp, &HFCAddr, sizeof (UINT32));

      /* Next, update the demura HFC Size */
      tmp += (2 * sizeof (UINT32));
      HFCSize = cpu_to_fdt32 (HFCSize);
      memcpy (tmp, &HFCSize, sizeof (UINT32));

      /* Update the property value in place */
      ret = fdt_setprop_inplace (fdt, offset, "reg", Prop->data, PropLen);
      if (ret < 0) {
        DEBUG ((EFI_D_WARN, "Could not update demura info\n"));
        Status = EFI_NO_MAPPING;
      }
    }
  }

  return Status;
}

STATIC EFI_STATUS
UpdateDemuraPanelID (VOID *fdt, CONST CHAR8 *Path, UINT64 PanelID)
{
  EFI_STATUS Status = EFI_SUCCESS;
  UINT32 PanelIDSize = sizeof (UINT64);
  CONST struct fdt_property *Prop = NULL;
  INT32 PropLen = 0;
  CHAR8 *tmp = NULL;
  INT32 ret = 0;
  UINT32 offset = 0;

  if (Path != NULL)
  {
    /* Get offset of the display node */
    ret = FdtPathOffset (fdt, Path);
    if (ret < 0) {
      /* Just return success if display node not exists */
      return EFI_SUCCESS;
    }

    offset = (UINT32)ret;
    Prop = fdt_get_property (fdt, offset, "qcom,demura-panel-id", &PropLen);

    if (!Prop) {
      DEBUG ((EFI_D_WARN, "Could not find the panel id property\n"));
      Status = EFI_NOT_FOUND;
    } else if (PropLen < PanelIDSize) {
      DEBUG ((EFI_D_WARN, "Invalid panel ID size\n"));
      Status = EFI_INVALID_PARAMETER;
    } else {
      /* Update panel id */
      tmp = (CHAR8 *)Prop->data;
      PanelID = fdt64_to_cpu (PanelID);
      memcpy (tmp, &PanelID, sizeof (UINT64));

      /* Update the property value in place */
      ret = fdt_setprop_inplace (fdt,
                                 offset,
                                 "qcom,demura-panel-id",
                                 Prop->data,
                                 PropLen);
      if (ret < 0) {
        DEBUG ((EFI_D_WARN, "Could not update demura panel id\n"));
        Status = EFI_NO_MAPPING;
      }
    }
  }

  return Status;
}

STATIC EFI_STATUS
UpdateDemuraInfo (VOID *fdt)
{
  EFI_STATUS Status = EFI_SUCCESS;
  struct DisplayDemuraInfoType DemuraInfo;
  UINTN DemuraInfoSize = sizeof (DemuraInfo);

  memset (&DemuraInfo, 0, DemuraInfoSize);

  Status = gRT->GetVariable ((CHAR16 *)L"DisplayDemuraInfo",
                             &gQcomTokenSpaceGuid,
                             NULL,
                             &DemuraInfoSize,
                             &DemuraInfo);
  if ((Status == EFI_SUCCESS) &&
      (DemuraInfo.Version > 0)) {
    /* Update demura 0 region */
    if ((DemuraInfo.Demura0HFCAddr != 0) &&
        (DemuraInfo.Demura0HFCSize != 0)) {
      UpdateDemuraRegion(fdt,
                         "/reserved-memory/demura_region_0",
                         DemuraInfo.Demura0HFCAddr,
                         DemuraInfo.Demura0HFCSize);
    }

    /* Update demura 1 region */
    if ((DemuraInfo.Demura1HFCAddr != 0) &&
        (DemuraInfo.Demura1HFCSize != 0)) {
      UpdateDemuraRegion(fdt,
                         "/reserved-memory/demura_region_1",
                         DemuraInfo.Demura1HFCAddr,
                         DemuraInfo.Demura1HFCSize);
    }

    /* Update demura 0 panel id */
    if (DemuraInfo.Demura0PanelID != 0) {
      UpdateDemuraPanelID(fdt,
                          "/soc/qcom,dsi-display-primary",
                          DemuraInfo.Demura0PanelID);
    }

    /* Update demura 1 panel id */
    if (DemuraInfo.Demura1PanelID != 0) {

      UpdateDemuraPanelID(fdt,
                          "/soc/qcom,dsi-display-secondary",
                          DemuraInfo.Demura1PanelID);
    }
  }

  return Status;
}

UINT32
fdt_check_header_ext (VOID *fdt)
{
  UINT64 fdt_start, fdt_end;
  UINT32 sum;
  fdt_start = (UINT64)fdt;

  if (fdt_start + fdt_totalsize (fdt) <= fdt_start) {
    return FDT_ERR_BADOFFSET;
  }
  fdt_end = fdt_start + fdt_totalsize (fdt);

  if (!(sum = ADD_OF (fdt_off_dt_struct (fdt), fdt_size_dt_struct (fdt)))) {
    return FDT_ERR_BADOFFSET;
  } else {
    if (CHECK_ADD64 (fdt_start, sum))
      return FDT_ERR_BADOFFSET;
    else if (fdt_start + sum > fdt_end)
      return FDT_ERR_BADOFFSET;
  }
  if (!(sum = ADD_OF (fdt_off_dt_strings (fdt), fdt_size_dt_strings (fdt)))) {
    return FDT_ERR_BADOFFSET;
  } else {
    if (CHECK_ADD64 (fdt_start, sum))
      return FDT_ERR_BADOFFSET;
    else if (fdt_start + sum > fdt_end)
      return FDT_ERR_BADOFFSET;
  }
  if (fdt_start + fdt_off_mem_rsvmap (fdt) > fdt_end)
    return FDT_ERR_BADOFFSET;
  return 0;
}

STATIC
VOID
UpdateGranuleInfo (VOID *fdt)
{
  EFI_STATUS Status = EFI_SUCCESS;
  INT32 GranuleNodeOffset;
  UINT32 GranuleSize;
  INT32 Ret;

  Status = GetGranuleSize (&GranuleSize);
  if (EFI_ERROR (Status)) {
    DEBUG ((EFI_D_VERBOSE,
            "Unable to get Granule Size, Status = %r\r\n",
            Status));
    return;
  }

  GranuleNodeOffset = FdtPathOffset (fdt, "/mem-offline");
  if (GranuleNodeOffset < 0) {
    DEBUG ((EFI_D_VERBOSE, "INFO: Could not find mem-offline node.\n"));
    return;
  }

  FdtPropUpdateFunc (fdt, GranuleNodeOffset, "granule",
                     GranuleSize, fdt_setprop_u32, Ret);
  if (Ret) {
    DEBUG ((EFI_D_ERROR, "INFO: Granule size update failed.\n"));
  }
}

STATIC
EFI_STATUS
QueryMemoryCellSize (IN VOID *Fdt, OUT UINT32 *MemoryCellLen)
{
  INT32 RootOffset;
  INT32 PropLen;
  UINT32 AddrCellSize = 0;
  UINT32 SizeCellSize = 0;
  UINT32 *Prop = NULL;

  RootOffset = fdt_path_offset (Fdt, "/");
  if (RootOffset < 0) {
    DEBUG ((EFI_D_ERROR, "Error finding root offset\n"));
    return EFI_NOT_FOUND;
  }

  /* Find address-cells size */
  Prop = (UINT32 *) fdt_getprop (Fdt, RootOffset, "#address-cells", &PropLen);
  if (Prop &&
      PropLen > 0) {
    AddrCellSize = fdt32_to_cpu (*Prop);
  } else {
    DEBUG ((EFI_D_ERROR, "Error finding #address-cells property\n"));
    return EFI_NOT_FOUND;
  }

  /* Find size-cells size */
  Prop =(UINT32 *) fdt_getprop (Fdt, RootOffset, "#size-cells", &PropLen);
  if (Prop &&
      PropLen > 0) {
    SizeCellSize = fdt32_to_cpu (*Prop);
  } else {
    DEBUG ((EFI_D_ERROR, "Error finding #size-cells property\n"));
    return EFI_NOT_FOUND;
  }

  if (AddrCellSize > DEFAULT_CELL_SIZE ||
      SizeCellSize > DEFAULT_CELL_SIZE ||
      SizeCellSize == 0 ||
      AddrCellSize == 0) {
    DEBUG ((EFI_D_ERROR, "Error unsupported cell size value: #address-cell %d" \
              "#size-cell\n", AddrCellSize, SizeCellSize));
    return EFI_INVALID_PARAMETER;
  }

  /* Make sure memory cell size and address cell size are same */
  if (AddrCellSize == SizeCellSize) {
    *MemoryCellLen = AddrCellSize;
  } else {
    DEBUG ((EFI_D_ERROR, "Mismatch memory address cell and size cell size\n"));
    return EFI_INVALID_PARAMETER;
  }

  return EFI_SUCCESS;
}

#ifdef REMOVE_CARVEOUT_REGION
BOOLEAN IsCarveoutRemovalEnabled (VOID)
{
  return TRUE;
}
#else
BOOLEAN IsCarveoutRemovalEnabled (VOID)
{
  return FALSE;
}
#endif

STATIC
EFI_STATUS
GetNoMapRegions (VOID *Fdt,
                 struct CarveoutMemRegion *NoMapRegs,
                 UINT32 *NumNoMapReg)
{
  INT32 ResMemOffset = 0;
  INT32 SubNodeOffset = 0;
  INT32 NumReg = 0;
  CONST UINT64  *RegProp;
  CONST struct fdt_property *Prop = NULL;
  INT32 PropLen = 0;
  CONST CHAR8 *status = NULL;

  ResMemOffset = FdtPathOffset (Fdt, "/reserved-memory");
  if (ResMemOffset < 0) {
    DEBUG ((EFI_D_ERROR, "reserved-memory node not found in device tree\n"));
    return EFI_NOT_FOUND;
  }

  for (SubNodeOffset = fdt_first_subnode (Fdt, ResMemOffset);
       SubNodeOffset >= 0;
       SubNodeOffset = fdt_next_subnode (Fdt, SubNodeOffset)) {
    Prop = fdt_get_property (Fdt, SubNodeOffset, "no-map", &PropLen);
    if (Prop) {
      status = fdt_getprop (Fdt, SubNodeOffset, "status", &PropLen);
      if (status &&
          (AsciiStrnCmp (status, "disabled", PropLen) == 0)) {
        continue;
      }
      RegProp = fdt_getprop (Fdt, SubNodeOffset, "reg", &PropLen);
      if (RegProp) {
        if (NumReg >= NUM_NOMAP_REGIONS) {
          return EFI_OUT_OF_RESOURCES;
        }
        NoMapRegs[NumReg].StartAddr = fdt64_to_cpu (ReadUnaligned64 (RegProp));
        NoMapRegs[NumReg].Size = fdt64_to_cpu (ReadUnaligned64 (RegProp + 1));
        NumReg++;
      }
    }
  }

  *NumNoMapReg = NumReg;
  return EFI_SUCCESS;
}

STATIC
VOID
SortNoMapRegions (struct CarveoutMemRegion *NoMapRegions, UINT32 NumNoMapReg)
{
  UINT32 i = 0, j = 0;
  struct CarveoutMemRegion TempMemoryMap;
  BOOLEAN IsSorted = TRUE;

  for (i = 0; i < (NumNoMapReg - 1); i++) {
    for (j = 0; j < (NumNoMapReg - i - 1); j++) {
      if (NoMapRegions[j].StartAddr > NoMapRegions[j + 1].StartAddr) {
        IsSorted = FALSE;
        CopyMem (&TempMemoryMap, &NoMapRegions[j],
                 sizeof (struct CarveoutMemRegion));
        CopyMem (&NoMapRegions[j], &NoMapRegions[j + 1],
                 sizeof (struct CarveoutMemRegion));
        CopyMem (&NoMapRegions[j + 1], &TempMemoryMap,
                 sizeof (struct CarveoutMemRegion));
      }
    }
    if (IsSorted) {
      break;
    }
  }
  return;
}

STATIC
EFI_STATUS
CombineNoMapRegions (struct CarveoutMemRegion *NoMapRegions,
                     UINT32 NumNoMapReg,
                     struct CarveoutMemRegion *CombNoMapRegions,
                     UINT32 *NumCombNoMapReg)
{
  UINT64 Start, End;
  UINT32 i = 0;
  INT32 NumReg = 0;

  Start = NoMapRegions[0].StartAddr;
  End = NoMapRegions[0].StartAddr + NoMapRegions[0].Size;
  CombNoMapRegions[NumReg].StartAddr = Start;
  CombNoMapRegions[NumReg].Size = End - Start;

  for (i = 0; i < (NumNoMapReg - 1); i++) {
    if (NoMapRegions[i + 1].StartAddr ==
        (NoMapRegions[i].StartAddr + (NoMapRegions[i].Size))) {
      End = NoMapRegions[i + 1].StartAddr + NoMapRegions[i + 1].Size;
      CombNoMapRegions[NumReg].Size = End - Start;
    } else if (NoMapRegions[i + 1].StartAddr >
        (NoMapRegions[i].StartAddr + (NoMapRegions[i].Size))) {
      Start = NoMapRegions[i + 1].StartAddr;
      End = NoMapRegions[i + 1].StartAddr + NoMapRegions[i + 1].Size;
      NumReg++;
      if (NumReg >= NUM_NOMAP_REGIONS) {
        return EFI_OUT_OF_RESOURCES;
      }
      CombNoMapRegions[NumReg].StartAddr = Start;
      CombNoMapRegions[NumReg].Size = End - Start;
    } else if (NoMapRegions[i + 1].StartAddr <
        (NoMapRegions[i].StartAddr + (NoMapRegions[i].Size))) {
      DEBUG ((EFI_D_WARN, "Overlapping memory regions detected\n"));
      DEBUG ((EFI_D_WARN,
              "0x%016lx - 0x%016lx overlaps with 0x%016lx - 0x%016lx\n",
              NoMapRegions[i].StartAddr,
              NoMapRegions[i].StartAddr + NoMapRegions[i].Size,
              NoMapRegions[i + 1].StartAddr,
              NoMapRegions[i + 1].StartAddr + NoMapRegions[i + 1].Size));
      End = NoMapRegions[i + 1].StartAddr + NoMapRegions[i + 1].Size;
      CombNoMapRegions[NumReg].Size = End - Start;
    }
  }

  *NumCombNoMapReg = NumReg + 1;
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
UpdateRamPartitions (RamPartitionEntry *RamPartitionsList,
                     UINT32 NumPartitions,
                     struct CarveoutMemRegion *CombNoMapRegions,
                     UINT32 NumCombNoMapReg,
                     RamPartitionEntry *UpdatedRamPartitions,
                     UINT32 *NumUpdRamPartitions)
{
  UINT32 i = 0, j = 0;
  UINT32 NumModRamPartitions = 0;
  BOOLEAN  PtnChecked;
  RamPartitionEntry *RamPartitions = NULL;

  RamPartitions = AllocateZeroPool (
                        NumPartitions * sizeof (RamPartitionEntry));
  if (!RamPartitions) {
    DEBUG ((EFI_D_ERROR, "Failed to allocate memory for RamPartitions\n"));
    return EFI_OUT_OF_RESOURCES;
  }
  CopyMem (RamPartitions, RamPartitionsList,
           NumPartitions * sizeof (RamPartitionEntry));

  for (i = 0; i < NumPartitions; i++) {
    if (RamPartitions[i].AvailableLength == 0) {
      UpdatedRamPartitions[NumModRamPartitions].Base = RamPartitions[i].Base;
      UpdatedRamPartitions[NumModRamPartitions].AvailableLength =
          RamPartitions[i].AvailableLength;
      NumModRamPartitions++;
      continue;
    }

    PtnChecked = FALSE;

    for (j = 0; j < NumCombNoMapReg; j++) {
      if ((CombNoMapRegions[j].StartAddr <= RamPartitions[i].Base) &&
          ((CombNoMapRegions[j].StartAddr + CombNoMapRegions[j].Size) >=
          (RamPartitions[i].Base + RamPartitions[i].AvailableLength))) {
        PtnChecked = TRUE;
        break;
      } else if (CombNoMapRegions[j].StartAddr >
          (RamPartitions[i].Base + RamPartitions[i].AvailableLength)) {
        break;
      } else if ((CombNoMapRegions[j].StartAddr + CombNoMapRegions[j].Size) <
         RamPartitions[i].Base) {
        continue;
      } else if ((CombNoMapRegions[j].StartAddr >= RamPartitions[i].Base) &&
          ((CombNoMapRegions[j].StartAddr + CombNoMapRegions[j].Size) <=
          (RamPartitions[i].Base + RamPartitions[i].AvailableLength))) {
        if (CombNoMapRegions[j].StartAddr > RamPartitions[i].Base) {
          UpdatedRamPartitions[NumModRamPartitions].Base =
              RamPartitions[i].Base;
          UpdatedRamPartitions[NumModRamPartitions].AvailableLength =
              CombNoMapRegions[j].StartAddr - RamPartitions[i].Base;
          RamPartitions[i].AvailableLength =
              (RamPartitions[i].Base + RamPartitions[i].AvailableLength) -
              (CombNoMapRegions[j].StartAddr + CombNoMapRegions[j].Size);
          RamPartitions[i].Base =
              CombNoMapRegions[j].StartAddr + CombNoMapRegions[j].Size;
          NumModRamPartitions++;
          PtnChecked = TRUE;
        } else if (CombNoMapRegions[j].StartAddr == RamPartitions[i].Base) {
          RamPartitions[i].Base =
              CombNoMapRegions[j].StartAddr + CombNoMapRegions[j].Size;
          RamPartitions[i].AvailableLength =
              RamPartitions[i].AvailableLength - CombNoMapRegions[j].Size;
          PtnChecked = TRUE;
        }

        if (RamPartitions[i].AvailableLength == 0) {
          break;
        }

        if ((CombNoMapRegions[j].StartAddr + CombNoMapRegions[j].Size) <
            (RamPartitions[i].Base + RamPartitions[i].AvailableLength)) {
          PtnChecked = FALSE;
        }
      } else if ((CombNoMapRegions[j].StartAddr > RamPartitions[i].Base) &&
                 ((CombNoMapRegions[j].StartAddr + CombNoMapRegions[j].Size) >
                 (RamPartitions[i].Base + RamPartitions[i].AvailableLength))) {
        UpdatedRamPartitions[NumModRamPartitions].Base =
            RamPartitions[i].Base;
        UpdatedRamPartitions[NumModRamPartitions].AvailableLength =
            CombNoMapRegions[j].StartAddr - RamPartitions[i].Base;
        NumModRamPartitions++;
        PtnChecked = TRUE;
        break;
      } else if ((CombNoMapRegions[j].StartAddr < RamPartitions[i].Base) &&
                 ((CombNoMapRegions[j].StartAddr + CombNoMapRegions[j].Size) <
                 (RamPartitions[i].Base + RamPartitions[i].AvailableLength))) {
        RamPartitions[i].AvailableLength =
            (RamPartitions[i].Base + RamPartitions[i].AvailableLength) -
            (CombNoMapRegions[j].StartAddr + CombNoMapRegions[j].Size);
        RamPartitions[i].Base =
            CombNoMapRegions[j].StartAddr + CombNoMapRegions[j].Size;
      }
    }

    if (!PtnChecked) {
      UpdatedRamPartitions[NumModRamPartitions].Base = RamPartitions[i].Base;
      UpdatedRamPartitions[NumModRamPartitions].AvailableLength =
          RamPartitions[i].AvailableLength;
      NumModRamPartitions++;
    }

    if (NumModRamPartitions >= NUM_RAM_PARTITIONS) {
      return EFI_OUT_OF_RESOURCES;
    }
  }

  *NumUpdRamPartitions = NumModRamPartitions;
  FreePool (RamPartitions);
  RamPartitions  = NULL;

  return EFI_SUCCESS;
}

EFI_STATUS
GetUpdatedRamPartitions (VOID *Fdt,
                         RamPartitionEntry *RamPartitions,
                         UINT32 NumPartitions,
                         RamPartitionEntry *UpdatedRamPartitions,
                         UINT32 *NumUpdPartitions)
{
  EFI_STATUS Status = EFI_SUCCESS;
  UINT32 i = 0, NumNoMapReg = 0, NumCombNoMapReg = 0, NumModPartitions = 0;
  struct CarveoutMemRegion NoMapRegions[NUM_NOMAP_REGIONS];
  struct CarveoutMemRegion CombinedNoMapRegions[NUM_NOMAP_REGIONS];

  if ((!RamPartitions) ||
      (!UpdatedRamPartitions) ||
      (!NumUpdPartitions)) {
    return EFI_INVALID_PARAMETER;
  }

  /* Reading No-Map regions from FDT */
  Status = GetNoMapRegions (Fdt, NoMapRegions, &NumNoMapReg);
  if (Status != EFI_SUCCESS) {
    return Status;
  }
  DEBUG ((EFI_D_VERBOSE, "NoMap Regions\r\n"));
  for (i = 0; i < NumNoMapReg; i++) {
    DEBUG ((EFI_D_VERBOSE, "Base: 0x%016lx Size: 0x%016lx \n",
            NoMapRegions[i].StartAddr, NoMapRegions[i].Size));
  }

  /* Sort the No-Map regions */
  SortNoMapRegions (NoMapRegions, NumNoMapReg);
  DEBUG ((EFI_D_VERBOSE, "Sorted NoMap Regions\r\n"));
  for (i = 0; i < NumNoMapReg; i++) {
    DEBUG ((EFI_D_VERBOSE, "Base: 0x%016lx Size: 0x%016lx \n",
            NoMapRegions[i].StartAddr, NoMapRegions[i].Size));
  }

  /* Combine No-Map regions */
  Status = CombineNoMapRegions (NoMapRegions, NumNoMapReg,
                            CombinedNoMapRegions, &NumCombNoMapReg);
  if (Status != EFI_SUCCESS) {
    return Status;
  }

  DEBUG ((EFI_D_VERBOSE, "Combined NoMap Regions\r\n"));
  for (i = 0; i < NumCombNoMapReg; i++) {
    DEBUG ((EFI_D_VERBOSE, "Base:0x%016lx Size:0x%016lx\n",
            CombinedNoMapRegions[i].StartAddr, CombinedNoMapRegions[i].Size));
  }

  /* Remove combined No-Map regions from RAM Partitions */
  Status = UpdateRamPartitions (RamPartitions, NumPartitions,
                            CombinedNoMapRegions, NumCombNoMapReg,
                            UpdatedRamPartitions, &NumModPartitions);
  if (Status != EFI_SUCCESS) {
    return Status;
  }
  DEBUG ((EFI_D_VERBOSE, "Updated RAM Partitions\r\n"));
  for (i = 0; i < NumModPartitions; i++) {
    DEBUG ((EFI_D_VERBOSE, "Add Base: 0x%016lx Available Length: 0x%016lx \n",
            UpdatedRamPartitions[i].Base,
            UpdatedRamPartitions[i].AvailableLength));
  }

  *NumUpdPartitions = NumModPartitions;
  return Status;
}

STATIC
EFI_STATUS
AddMemMap (VOID *Fdt, UINT32 MemNodeOffset, BOOLEAN BootWith32Bit)
{
  EFI_STATUS Status = EFI_NOT_FOUND;
  INT32 ret = 0;
  RamPartitionEntry *RamPartitions = NULL;
  RamPartitionEntry *FinalRamPartitions = NULL;
  UINT32 NumPartitions = 0, NumFinalPartitions = 0;
  UINT32 i = 0;
  UINT32 MemoryCellLen = 0;

  Status = QueryMemoryCellSize (Fdt, &MemoryCellLen);
  if (EFI_ERROR (Status)) {
    DEBUG ((EFI_D_ERROR, "ERROR: Not a valid memory node found!\n"));
    return Status;
  }

  if (UpdRamPartitionsAvail) {
    FinalRamPartitions = UpdatedRamPartitions;
    NumFinalPartitions = NumUpdPartitions;
  } else {
    Status = ReadRamPartitions (&RamPartitions, &NumPartitions);
    if (EFI_ERROR (Status)) {
      DEBUG ((EFI_D_ERROR, "Error returned from ReadRamPartitions %r\n",
              Status));
      return Status;
    }
    DEBUG ((EFI_D_VERBOSE, "RAM Partitions\r\n"));
    for (i = 0; i < NumPartitions; i++) {
      DEBUG ((EFI_D_VERBOSE, "Add Base: 0x%016lx Available Length: 0x%016lx \n",
              RamPartitions[i].Base, RamPartitions[i].AvailableLength));
    }
    FinalRamPartitions = RamPartitions;
    NumFinalPartitions = NumPartitions;
  }

  DEBUG ((EFI_D_INFO, "Final RAM Partitions\r\n"));
  for (i = 0; i < NumFinalPartitions; i++) {
    DEBUG ((EFI_D_INFO, "Add Base: 0x%016lx Available Length: 0x%016lx \n",
            FinalRamPartitions[i].Base, FinalRamPartitions[i].AvailableLength));
    if (MemoryCellLen == 1) {
      ret = dev_tree_add_mem_info (Fdt, MemNodeOffset,
                                   FinalRamPartitions[i].Base,
                                   FinalRamPartitions[i].AvailableLength);
    } else {
      ret = dev_tree_add_mem_infoV64 (Fdt, MemNodeOffset,
                                      FinalRamPartitions[i].Base,
                                      FinalRamPartitions[i].AvailableLength);
    }

    if (ret) {
      DEBUG ((EFI_D_ERROR, "Add Base: 0x%016lx Length: 0x%016lx Fail\n",
              FinalRamPartitions[i].Base,
              FinalRamPartitions[i].AvailableLength));
    }
  }

  if (RamPartitions) {
    FreePool (RamPartitions);
  }
  RamPartitions = NULL;
  RamPartitionEntries = NULL;

  return EFI_SUCCESS;
}

/* Supporting function of UpdateDeviceTree()
 * Function first gets the RAM partition table, then passes the pointer to
 * AddMemMap() */
STATIC
EFI_STATUS
target_dev_tree_mem (VOID *fdt, UINT32 MemNodeOffset, BOOLEAN BootWith32Bit)
{
  EFI_STATUS Status;

  /* Get Available memory from partition table */
  Status = AddMemMap (fdt, MemNodeOffset, BootWith32Bit);
  if (EFI_ERROR (Status)) {
    DEBUG ((EFI_D_ERROR,
            "Invalid memory configuration, check memory partition table: %r\n",
            Status));
    goto out;
  }

  UpdateGranuleInfo (fdt);

out:
  return Status;
}

/* Supporting function of target_dev_tree_mem()
 * Function to add the subsequent RAM partition info to the device tree */
INT32
dev_tree_add_mem_info (VOID *fdt, UINT32 offset, UINT32 addr, UINT32 size)
{
  STATIC INT32 mem_info_cnt = 0;
  INT32 ret = 0;

  if (!mem_info_cnt) {
    /* Replace any other reg prop in the memory node. */
    mem_info_cnt = 1;
    FdtPropUpdateFunc (fdt, offset, "reg", addr, fdt_setprop_u32, ret);
  } else {
    /* Append the mem info to the reg prop for subsequent nodes.  */
    FdtPropUpdateFunc (fdt, offset, "reg", addr, fdt_appendprop_u32, ret);
  }

  if (ret) {
    DEBUG (
        (EFI_D_ERROR, "Failed to add the memory information addr: %d\n", ret));
  }

  FdtPropUpdateFunc (fdt, offset, "reg", size, fdt_appendprop_u32, ret);
  if (ret) {
    DEBUG (
        (EFI_D_ERROR, "Failed to add the memory information size: %d\n", ret));
  }

  return ret;
}

INT32
dev_tree_add_mem_infoV64 (VOID *fdt, UINT32 offset, UINT64 addr, UINT64 size)
{
  STATIC INT32 mem_info_cnt = 0;
  INT32 ret = 0;

  if (!mem_info_cnt) {
    /* Replace any other reg prop in the memory node. */
    mem_info_cnt = 1;
    FdtPropUpdateFunc (fdt, offset, "reg", addr, fdt_setprop_u64, ret);
  } else {
    /* Append the mem info to the reg prop for subsequent nodes.  */
    FdtPropUpdateFunc (fdt, offset, "reg", addr, fdt_appendprop_u64, ret);
  }

  if (ret) {
    DEBUG (
        (EFI_D_ERROR, "Failed to add the memory information addr: %d\n", ret));
  }

  FdtPropUpdateFunc (fdt, offset, "reg", size, fdt_appendprop_u64, ret);
  if (ret) {
    DEBUG (
        (EFI_D_ERROR, "Failed to add the memory information size: %d\n", ret));
  }

  return ret;
}

STATIC EFI_STATUS
GetDDrRegionsInfo (struct ddr_regions_data_info *DdrRegionsInfo)
{
  EFI_STATUS  Status = EFI_SUCCESS;
  EFI_DDRGETINFO_PROTOCOL *pDDrGetInfoProtocol = NULL;
  UINT64 Revision;

  Status = gBS->LocateProtocol (&gEfiDDRGetInfoProtocolGuid,
                                NULL,
                                (VOID **)&pDDrGetInfoProtocol);

  if ((EFI_SUCCESS != Status) ||
      (NULL == pDDrGetInfoProtocol)) {
    DEBUG ((EFI_D_ERROR,
           "ERROR: Unable to get DDR Info protocol:%r\n", Status));
    return Status;
  }

  Revision = pDDrGetInfoProtocol->Revision;
  DEBUG ((EFI_D_VERBOSE, "DDR Header Revision =0x%x\n", Revision));

  if (Revision < EFI_DDRGETINFO_PROTOCOL_REVISION_5) {
    DEBUG ((EFI_D_VERBOSE,
            "GetDDRMappedRegions not supported in Revision=0x%x\n", Revision));
    return EFI_UNSUPPORTED;
  }

  Status = pDDrGetInfoProtocol->GetDDRMappedRegions (pDDrGetInfoProtocol,
                                                     DdrRegionsInfo);
  if ((EFI_SUCCESS != Status) ||
      (NULL == DdrRegionsInfo)) {
    DEBUG ((EFI_D_ERROR,
           "ERROR: Get DDR Regions info failed=%r\n", Status));
    return EFI_OUT_OF_RESOURCES;
  }

  return Status;
}

STATIC INT32 AddDDrRegionNode (VOID *Fdt)
{
  INT32 Offset;

  Offset = FdtPathOffset (Fdt, "/ddr-regions");
  if (Offset < 0) {
    Offset = FdtPathOffset (Fdt, "/");
    if (Offset < 0) {
      DEBUG ((EFI_D_ERROR, "Error finding root offset\n"));
      return Offset;
    }

    Offset = FdtAddSubnode (Fdt, Offset, "ddr-regions");
    if (Offset < 0) {
      DEBUG ((EFI_D_ERROR, "Error adding ddr regions: %d\n", Offset));
    }
  } else {
    DEBUG ((EFI_D_VERBOSE,
         "Attempted to create a ddr-regions node which already exists\n"));
  }
  return Offset;
}

STATIC INT32 AddDDrRegionNodeProp (struct ddr_regions_data_info *DdrRegionsInfo,
                                    VOID *Fdt, UINT32 Offset)
{
  INT32 Ret;
  UINT32 Idx, Count;
  UINT32 MaxDDrRegions;
  CHAR8 RegionName[DDR_REGION_NAME_LEN] = {""};
  CHAR8 RegionNameSuffix[DDR_REGION_NAME_SUFFIX] = {""};
  UINT32 RegionPropArray[MAX_DDR_REGION_PROP_MEM];
  UINT32 RegionPropArraySize = 0;

  if (DdrRegionsInfo == NULL ||
      Fdt == NULL) {
    DEBUG ((EFI_D_ERROR, "Invalid input parameters\n"));
    return -1;
  }

  MaxDDrRegions = DdrRegionsInfo->no_of_ddr_regions;
  if (MaxDDrRegions > MAX_DDR_REGIONS) {
    DEBUG ((EFI_D_ERROR,
          "Incorrect DDr regions number: %d, please check the DDR info\n",
           MaxDDrRegions));
    return -1;
  }

  RegionPropArraySize = ARRAY_SIZE (RegionPropArray) *
                                    sizeof (RegionPropArray[0]);
  for (Idx = 0; Idx < MaxDDrRegions; Idx++) {
    AsciiStrnCpyS (RegionName, DDR_REGION_NAME_LEN, "region",
                   AsciiStrLen ("region"));
    AsciiSPrint (RegionNameSuffix, sizeof (RegionNameSuffix), "%d", Idx);
    AsciiStrnCatS (RegionName, DDR_REGION_NAME_LEN, RegionNameSuffix,
                   DDR_REGION_NAME_SUFFIX);

    Count = 0;
    gBS->SetMem (RegionPropArray, RegionPropArraySize, 0);
    /* Add StartAddr Property */
    RegionPropArray[Count] = cpu_to_fdt32 (
                   DdrRegionsInfo->ddr_region[Idx].start_address >>
                   DDR_REGIONS_MASK);
    Count++;
    RegionPropArray[Count] = cpu_to_fdt32 (
                   DdrRegionsInfo->ddr_region[Idx].start_address &
                   DDR_REGIONS_LOW_MASK);
    Count++;

    /* Add RegionsSize Property */
    RegionPropArray[Count] = cpu_to_fdt32 (
                   DdrRegionsInfo->ddr_region[Idx].size >>
                   DDR_REGIONS_MASK);
    Count++;
    RegionPropArray[Count] = cpu_to_fdt32 (
                   DdrRegionsInfo->ddr_region[Idx].size &
                   DDR_REGIONS_LOW_MASK);
    Count++;

    /* Add SegmentsStartOffset Property */
    RegionPropArray[Count] = cpu_to_fdt32 (
                   DdrRegionsInfo->ddr_region[Idx].segments_start_offset >>
                   DDR_REGIONS_MASK);
    Count++;
    RegionPropArray[Count] = cpu_to_fdt32 (
                   DdrRegionsInfo->ddr_region[Idx].segments_start_offset &
                   DDR_REGIONS_LOW_MASK);
    Count++;

    /* Add SegmentsStartIndex Property */
    RegionPropArray[Count] = 0;
    Count++;
    RegionPropArray[Count] = cpu_to_fdt32 (
                   DdrRegionsInfo->ddr_region[Idx].segments_start_index &
                   DDR_REGIONS_LOW_MASK);
    Count++;

    /* Add GranuleSize Property */
    RegionPropArray[Count] = 0;
    Count++;
    RegionPropArray[Count] = cpu_to_fdt32 (
                   DdrRegionsInfo->ddr_region[Idx].granule_size &
                   DDR_REGIONS_LOW_MASK);
    Count++;

    if (Count > MAX_DDR_REGION_PROP_MEM) {
       DEBUG ((EFI_D_ERROR, "ERROR: Wrong number of DDR Region member\n"));
       return -1;
    }

    Ret = FdtSetProp (Fdt, Offset, RegionName, RegionPropArray,
                      RegionPropArraySize);
    if (Ret) {
      DEBUG ((EFI_D_ERROR,
             "ERROR: Failed to add DDR Regions : %a\n", RegionName));
      return Ret;
    }
  }
  return 0;

}

STATIC EFI_STATUS
AddDDrRegion (VOID *Fdt)
{
  EFI_STATUS Status = EFI_NOT_FOUND;
  INT32 Ret = 0;
  INT32 Offset;
  struct ddr_regions_data_info *DdrRegionsDataInfo;

  DdrRegionsDataInfo = AllocateZeroPool (sizeof (struct ddr_regions_data_info));
  if (DdrRegionsDataInfo == NULL) {
    DEBUG ((EFI_D_ERROR, "DDR regions Buffer: Out of resources\n"));
    return EFI_OUT_OF_RESOURCES;
  }

  Status = GetDDrRegionsInfo (DdrRegionsDataInfo);
  if (Status != EFI_SUCCESS) {
    return Status;
  }

  Offset = AddDDrRegionNode (Fdt);
  if (Offset < 0) {
    DEBUG ((EFI_D_ERROR, "Failed to add ddr region node\n"));
    return EFI_OUT_OF_RESOURCES;
  }

  Ret = AddDDrRegionNodeProp (DdrRegionsDataInfo, Fdt, Offset);
  if (Ret) {
    DEBUG ((EFI_D_ERROR, "Failed to add ddr regions property\n"));
    return Ret;
  }

  return EFI_SUCCESS;
}

UINT8 GetDDRNumRank ()
{
  struct ddr_regions_data_info *DdrRegionsDataInfo = NULL;
  UINT8 NumRank = 0;
  EFI_STATUS Status;

  /* Get DDR regions info and NumRank*/
  DdrRegionsDataInfo = AllocateZeroPool (sizeof (struct ddr_regions_data_info));
  if (DdrRegionsDataInfo == NULL) {
    DEBUG ((EFI_D_ERROR, "DDR regions Buffer: Out of resources\n"));
    return DDR_MAX_RANKS;
  }

  Status = GetDDrRegionsInfo (DdrRegionsDataInfo);
  if (Status != EFI_SUCCESS) {
    DEBUG ((EFI_D_INFO,
            "Failed to update DDR regions info\n"));
    NumRank = DDR_MAX_RANKS;
    goto Out;
  } else {
    if (DdrRegionsDataInfo->ddr_rank0_size > 0) {
      NumRank ++;
    }

    if (DdrRegionsDataInfo->ddr_rank1_size > 0) {
      NumRank ++;
    }
  }

Out:
  if (DdrRegionsDataInfo) {
    FreePool (DdrRegionsDataInfo);
  }
  DdrRegionsDataInfo = NULL;

  return NumRank;
}

/* Top level function that updates the device tree. */
EFI_STATUS
UpdateDeviceTree (VOID *fdt,
                  CONST CHAR8 *cmdline,
                  VOID *ramdisk,
                  UINT32 RamDiskSize,
                  BOOLEAN BootWith32Bit)
{
  INT32 ret = 0;
  UINT32 offset;
  UINT32 LlccOffset;
  UINT32 PaddSize = 0;
  UINT64 RandomSeed = 0;
  UINT8 DdrDeviceType;
  /* Single space reserved for chan(0-9) */
  CHAR8 FdtRankProp[] = "ddr_device_rank_ch ";
  /* Single spaces reserved for chan(0-9), rank(0-9) */
  CHAR8 FdtHbbProp[] = "ddr_device_hbb_ch _rank ";
  struct ddr_details_entry_info *DdrInfo;
  UINT64 Revision;
  EFI_STATUS Status;
  EFI_RAMPARTITION_PROTOCOL *EfiRamPartProt;
  UINT8 NumRank = 0;
  UINT32 Hbb;
  UINT64 UpdateDTStartTime = GetTimerCountms ();
  UINT32 Index;
  UINT8 SCTConfig;


  /* Check the device tree header */
  ret = fdt_check_header (fdt) || fdt_check_header_ext (fdt);
  if (ret) {
    DEBUG ((EFI_D_ERROR, "ERROR: Invalid device tree header ...\n"));
    return EFI_NOT_FOUND;
  }

  /* Add padding to make space for new nodes and properties. */
  PaddSize = ADD_OF (fdt_totalsize (fdt),
                    DTB_PAD_SIZE + AsciiStrLen (cmdline));
  if (!PaddSize) {
    DEBUG ((EFI_D_ERROR, "ERROR: Integer Overflow: fdt size = %u\n",
            fdt_totalsize (fdt)));
    return EFI_BAD_BUFFER_SIZE;
  }
  ret = fdt_open_into (fdt, fdt, PaddSize);
  if (ret != 0) {
    DEBUG ((EFI_D_ERROR, "ERROR: Failed to move/resize dtb buffer ...\n"));
    return EFI_BAD_BUFFER_SIZE;
  }

#ifdef AUTO_VIRT_ABL
  goto OutofUpdateRankChannel;
#endif
  /* Get offset of the memory node */
  ret = FdtPathOffset (fdt, "/memory");
  if (ret < 0) {
    DEBUG ((EFI_D_ERROR, "ERROR: Could not find memory node ...\n"));
    return EFI_NOT_FOUND;
  }

  offset = ret;
  Status = target_dev_tree_mem (fdt, offset, BootWith32Bit);
  if (Status != EFI_SUCCESS) {
    DEBUG ((EFI_D_ERROR, "ERROR: Cannot update memory node\n"));
    return Status;
  }

  DdrInfo = AllocateZeroPool (sizeof (struct ddr_details_entry_info));
  if (DdrInfo == NULL) {
    DEBUG ((EFI_D_ERROR, "DDR Info Buffer: Out of resources\n"));
    return EFI_OUT_OF_RESOURCES;
  }
  Status = GetDDRInfo (DdrInfo, &Revision);
  if (Status == EFI_SUCCESS) {
    DdrDeviceType = DdrInfo->device_type;
    DEBUG ((EFI_D_VERBOSE, "DDR deviceType:%d\n", DdrDeviceType));

    FdtPropUpdateFunc (fdt, offset, (CONST char *)"ddr_device_type",
                       (UINT32)DdrDeviceType, fdt_appendprop_u32, ret);
    if (ret) {
      DEBUG ((EFI_D_ERROR,
              "ERROR: Cannot update memory node [ddr_device_type]:0x%x\n",
              ret));
    } else {
      DEBUG ((EFI_D_VERBOSE, "ddr_device_type is added to memory node\n"));
    }

    if (!IsDDRSupportsSCTConfig ()) {
      DEBUG ((EFI_D_VERBOSE, "DDR doesn't support SCT Config\n"));
    } else {
      Status = GetSCTConfig (&SCTConfig);
      if (Status != EFI_SUCCESS) {
        DEBUG ((EFI_D_ERROR, "INFO: Unable to get SCT Config:%r\n", Status));
        return EFI_UNSUPPORTED;
      } else {
        DEBUG ((EFI_D_VERBOSE, "SCT Config: %d\n", SCTConfig));
        ret = FdtPathOffset (fdt, "/soc/cache-controller");
        if (ret < 0) {
          DEBUG ((EFI_D_ERROR, "ERROR: Could not find LLCC node ...\n"));
          return EFI_NOT_FOUND;
        }

        LlccOffset = ret;
        FdtPropUpdateFunc (fdt, LlccOffset, (CONST char *)"qcom,sct-config",
                         (UINT32)SCTConfig, fdt_appendprop_u32, ret);
        if (ret) {
          DEBUG ((EFI_D_ERROR,
                "ERROR: Cannot update SCT Config [qcom,sct-config]:0x%x\n",
                 ret));
        } else {
          DEBUG ((EFI_D_VERBOSE, "qcom,sct-config is added to LLCC node\n"));
        }
      }
    }

    if (Revision < EFI_DDRGETINFO_PROTOCOL_REVISION) {
      DEBUG ((EFI_D_VERBOSE,
              "ddr_device_rank, HBB not supported in Revision=0x%x\n",
              Revision));
    } else {
      if (!FixedPcdGetBool (EnableUpdateRankChannel)) {
        DEBUG ((EFI_D_VERBOSE, "DDR rank is not enabled\n"));
        goto OutofUpdateRankChannel;
      }

      Status = gBS->LocateProtocol (&gEfiRamPartitionProtocolGuid, NULL,
                      (VOID **)&EfiRamPartProt);

      if (EFI_ERROR (Status)) {
        DEBUG ((EFI_D_ERROR,
                "Failed to get RamPartition Protocol: %d\n", Status));
        goto OutofUpdateRankChannel;
      }

      Status = EfiRamPartProt->GetHighestBankBit (EfiRamPartProt, &Hbb);

      if (EFI_ERROR (Status)) {
        DEBUG ((EFI_D_ERROR, "Failed to get Highest Bank Bit: %d\n", Status));
        goto OutofUpdateRankChannel;
      }

      NumRank = GetDDRNumRank ();
      DEBUG ((EFI_D_VERBOSE, "DdrInfo->num_channels:%d, NumRank:%d\n",
              DdrInfo->num_channels, NumRank));
      for (UINT8 Chan = 0; Chan < DdrInfo->num_channels; Chan++) {
        AsciiSPrint (FdtRankProp, sizeof (FdtRankProp),
                     "ddr_device_rank_ch%d", Chan);
        FdtPropUpdateFunc (fdt, offset, (CONST char *)FdtRankProp,
                           NumRank, fdt_appendprop_u32, ret);
        if (ret) {
          DEBUG ((EFI_D_ERROR,
                "ERROR: Cannot update memory node ddr_device_rank_ch%d:0x%x\n",
                Chan, ret));
        } else {
          DEBUG ((EFI_D_VERBOSE, "ddr_device_rank_ch%d added to memory node\n",
                  Chan));
        }
        for (UINT8 Rank = 0; Rank < NumRank; Rank++) {
          DEBUG ((EFI_D_VERBOSE, "ddr_device_hbb_ch%d_rank%d:%d\n",
                  Chan, Rank, Hbb));
          AsciiSPrint (FdtHbbProp, sizeof (FdtHbbProp),
                       "ddr_device_hbb_ch%d_rank%d", Chan, Rank);
          FdtPropUpdateFunc (fdt, offset, (CONST char *)FdtHbbProp,
                             Hbb, fdt_appendprop_u32, ret);
          if (ret) {
            DEBUG ((EFI_D_ERROR,
                    "ERROR: Cannot update memory node"
                    " ddr_device_hbb_ch%d_rank%d:0x%x\n", Chan, Rank, ret));
          } else {
            DEBUG ((EFI_D_VERBOSE,
                    "ddr_device_hbb_ch%d_rank%d added to memory node\n",
                    Chan, Rank));
          }
        }
      }
    }
  }

OutofUpdateRankChannel:

  UpdateSplashMemInfo (fdt);
  UpdateDemuraInfo (fdt);
  UpdatePLLCodesInfo (fdt);
  UpdateRamDumpMemInfo (fdt);

  /* Get offset of the chosen node */
  ret = FdtPathOffset (fdt, "/chosen");
  if (ret < 0) {
    DEBUG ((EFI_D_ERROR, "ERROR: Could not find chosen node ...\n"));
    return EFI_NOT_FOUND;
  }

  offset = ret;
  if (cmdline) {
    /* Adding the cmdline to the chosen node */
    FdtPropUpdateFunc (fdt, offset, (CONST char *)"bootargs",
                      (CONST VOID *)cmdline, fdt_appendprop_string, ret);
    if (ret) {
      DEBUG ((EFI_D_ERROR,
              "ERROR: Cannot update chosen node [bootargs] - 0x%x\n", ret));
      return EFI_LOAD_ERROR;
    }
  }

  if (!IsLEVariant ()) {
    for (Index = 0; Index < NUM_RNG_SEED_WORDS / sizeof (UINT64); Index++) {
      Status = GetRandomSeed (&RandomSeed);
      if (Status == EFI_SUCCESS) {

        /* Adding the RNG seed to the chosen node */
        FdtPropUpdateFunc (fdt, offset, (CONST CHAR8 *)"rng-seed",
                          (UINT64)RandomSeed, fdt_appendprop_u64, ret);
        if (ret) {
          DEBUG ((EFI_D_ERROR,
                "ERROR: Cannot update chosen node [rng-seed] - 0x%x\n", ret));
          break;
        }
      } else {
        DEBUG ((EFI_D_INFO, "ERROR: Cannot generate Random Seed - %r\n",
                                Status));
        break;
      }
    }
  }

  Status = GetRandomSeed (&RandomSeed);
  if (Status == EFI_SUCCESS) {
    /* Adding Kaslr Seed to the chosen node */
    FdtPropUpdateFunc (fdt, offset, (CONST CHAR8 *)"kaslr-seed",
                      (UINT64)RandomSeed, fdt_appendprop_u64, ret);
    if (ret) {
      DEBUG ((EFI_D_INFO,
              "ERROR: Cannot update chosen node [kaslr-seed] - 0x%x\n", ret));
    } else {
      DEBUG ((EFI_D_VERBOSE, "kaslr-Seed is added to chosen node\n"));
    }
  } else {
    DEBUG ((EFI_D_INFO, "ERROR: Cannot generate Kaslr Seed - %r\n", Status));
  }

  if (RamDiskSize) {
    /* Adding the initrd-start to the chosen node */
    FdtPropUpdateFunc (fdt, offset, (CONST CHAR8 *)"linux,initrd-start",
                       (UINT64)ramdisk, fdt_setprop_u64, ret);
    if (ret) {
      DEBUG ((EFI_D_ERROR,
              "ERROR: Cannot update chosen node [linux,initrd-start] - 0x%x\n",
              ret));
      return EFI_NOT_FOUND;
    }

    /* Adding the initrd-end to the chosen node */
    FdtPropUpdateFunc (fdt, offset, (CONST CHAR8 *)"linux,initrd-end",
                      (UINT64)ramdisk + RamDiskSize, fdt_setprop_u64, ret);
    if (ret) {
      DEBUG ((EFI_D_ERROR,
              "ERROR: Cannot update chosen node [linux,initrd-end] - 0x%x\n",
              ret));
      return EFI_NOT_FOUND;
    }
  }

  /* Update fstab node */
  DEBUG ((EFI_D_VERBOSE, "Start DT fstab node update: %lu ms\n",
          GetTimerCountms ()));
  UpdateFstabNode (fdt);
  DEBUG ((EFI_D_VERBOSE, "End DT fstab node update: %lu ms\n",
          GetTimerCountms ()));

  /* Check partial goods*/
  if (FixedPcdGetBool (EnablePartialGoods)) {
    ret = UpdatePartialGoodsNode (fdt);
    if (ret != EFI_SUCCESS) {
      DEBUG ((EFI_D_ERROR,
        "Failed to update device tree for partial goods, Status=%r\n",
           ret));
      return ret;
    }
  }

  if (!IsLEVariant ()) {
    /* Update DDR regions info */
    if (FixedPcdGetBool (EnableDdrRegion)) {
      DEBUG ((EFI_D_VERBOSE, "Start DT ddr regions update: %lu ms\n",
                          GetTimerCountms ()));
      Status =  AddDDrRegion (fdt);
      if (Status != EFI_SUCCESS &&
          Status != EFI_UNSUPPORTED) {
        DEBUG ((EFI_D_ERROR,
                "Failed to update DDR regions info, Status=%r\n", Status));
        return Status;
      }
      DEBUG ((EFI_D_VERBOSE, "End DT ddr regions update: %lu ms\n",
                           GetTimerCountms ()));
    }
  }

  fdt_pack (fdt);

  DEBUG ((EFI_D_INFO, "Update Device Tree total time: %lu ms \n",
        GetTimerCountms () - UpdateDTStartTime));
  return ret;
}

/* Update device tree for fstab node */
EFI_STATUS
UpdateFstabNode (VOID *fdt)
{
  INT32 ParentOffset = 0;
  INT32 SubNodeOffset = 0;
  CONST struct fdt_property *Prop = NULL;
  INT32 PropLen = 0;
  char *NodeName = NULL;
  EFI_STATUS Status = EFI_SUCCESS;
  CHAR8 *BootDevBuf = NULL;
  CHAR8 *ReplaceStr = NULL;
  CHAR8 *NextStr = NULL;
  struct FstabNode Table = IsDynamicPartitionSupport () ? DynamicFstabTable
                                                         : FstabTable;
  UINT32 DevNodeBootDevLen = 0;
  UINT32 Index = 0;
  UINT32 PaddingEnd = 0;

  /* Find the parent node */
  ParentOffset = FdtPathOffset (fdt, Table.ParentNode);
  if (ParentOffset < 0) {
    DEBUG ((EFI_D_VERBOSE, "Failed to Get parent node: fstab\terror: %d\n",
            ParentOffset));
    return EFI_NOT_FOUND;
  }
  DEBUG ((EFI_D_VERBOSE, "Node: %a found.\n",
          fdt_get_name (fdt, ParentOffset, NULL)));

  if (!IsDynamicPartitionSupport ()) {
    /* Get boot device type */
    BootDevBuf = AllocateZeroPool (sizeof (CHAR8) * BOOT_DEV_MAX_LEN);
    if (BootDevBuf == NULL) {
     DEBUG ((EFI_D_ERROR, "Boot device buffer: Out of resources\n"));
     return EFI_OUT_OF_RESOURCES;
    }

    Status = GetBootDevice (BootDevBuf, BOOT_DEV_MAX_LEN);
    if (Status != EFI_SUCCESS) {
      DEBUG ((EFI_D_ERROR, "Failed to get Boot Device: %r\n", Status));
      FreePool (BootDevBuf);
      BootDevBuf = NULL;
      return Status;
    }
  }

  /* Get properties of all sub nodes */
  for (SubNodeOffset = fdt_first_subnode (fdt, ParentOffset);
       SubNodeOffset >= 0;
       SubNodeOffset = fdt_next_subnode (fdt, SubNodeOffset)) {
    Prop = fdt_get_property (fdt, SubNodeOffset, Table.Property, &PropLen);
    NodeName = (char *)(uintptr_t)fdt_get_name (fdt, SubNodeOffset, NULL);
    if (!Prop) {
      DEBUG ((EFI_D_VERBOSE, "Property:%a is not found for sub-node:%a\n",
              Table.Property, NodeName));
    } else {
      DEBUG ((EFI_D_VERBOSE, "Property:%a found for sub-node:%a\tProperty:%a\n",
              Table.Property, NodeName, Prop->data));

      /* For Dynamic partition support disable firmware fstab nodes. */
      if (IsDynamicPartitionSupport ()) {
        DEBUG ((EFI_D_VERBOSE, "Disabling node status :%a\n", NodeName));
        Status = FdtSetProp (fdt, SubNodeOffset, Table.Property,
                          (CONST VOID *)"disabled",
                          (AsciiStrLen ("disabled") + 1));
        if (Status) {
         DEBUG ((EFI_D_ERROR, "ERROR: Failed to disable Node: %a\n", NodeName));
        }
        continue;
      }

      /* Pointer to fdt 'dev' property string that needs to update based on the
       * 'androidboot.bootdevice' */
      ReplaceStr = (CHAR8 *)Prop->data;
      ReplaceStr = AsciiStrStr (ReplaceStr, Table.DevicePathId);
      if (!ReplaceStr) {
        DEBUG ((EFI_D_VERBOSE, "Update property:%a value is not proper to "
                               "update for sub-node:%a\n",
                Table.Property, NodeName));
        continue;
      }
      ReplaceStr += AsciiStrLen (Table.DevicePathId);
      NextStr = AsciiStrStr ((ReplaceStr + 1), "/");
      if (NextStr != NULL) {
        DevNodeBootDevLen = NextStr - ReplaceStr;
        if (DevNodeBootDevLen >= AsciiStrLen (BootDevBuf)) {
          gBS->CopyMem (ReplaceStr, BootDevBuf, AsciiStrLen (BootDevBuf));
          PaddingEnd = DevNodeBootDevLen - AsciiStrLen (BootDevBuf);
          /* Update the property with new value */
          if (PaddingEnd) {
            gBS->CopyMem (ReplaceStr + AsciiStrLen (BootDevBuf), NextStr,
                          AsciiStrLen (NextStr));
            for (Index = 0; Index < PaddingEnd; Index++) {
              ReplaceStr[AsciiStrLen (BootDevBuf) + AsciiStrLen (NextStr) +
                         Index] = ' ';
            }
          }
        } else {
          DEBUG ((EFI_D_ERROR, "String length mismatch b/w DT Bootdevice string"
                               " (%d) and expected Bootdevice strings (%d)\n",
                  DevNodeBootDevLen, AsciiStrLen (BootDevBuf)));
        }
      }
    }
  }

  if (BootDevBuf) {
    FreePool (BootDevBuf);
  }
  BootDevBuf = NULL;
  return Status;
}
