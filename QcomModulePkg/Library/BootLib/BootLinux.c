/*
 * Copyright (c) 2009, Google Inc.
 * All rights reserved.
 *
 * Copyright (c) 2009-2021, The Linux Foundation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of The Linux Foundation nor
 *       the names of its contributors may be used to endorse or promote
 *       products derived from this software without specific prior written
 *       permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NON-INFRINGEMENT ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
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

#include <Library/DeviceInfo.h>
#include <Library/DrawUI.h>
#include <Library/PartitionTableUpdate.h>
#include <Library/ShutdownServices.h>
#include <Library/VerifiedBootMenu.h>
#include <Library/HypervisorMvCalls.h>
#include <Library/Rtic.h>
#include <Protocol/EFIMdtp.h>
#include <Protocol/EFIScmModeSwitch.h>
#include <Protocol/EFIRmVm.h>
#include <libufdt_sysdeps.h>
#include <FastbootLib/FastbootCmds.h>
#include "AutoGen.h"
#include "BootImage.h"
#include "BootLinux.h"
#include "BootStats.h"
#include "UpdateDeviceTree.h"
#include "Board.h"
#include <Protocol/EFIPlatformInfoTypes.h>
#include "libfdt.h"
#include "Bootconfig.h"
#include <ufdt_overlay.h>

#ifndef DISABLE_KERNEL_PROTOCOL
#include <Protocol/EFIKernelInterface.h>
#endif

#define HLOS_VMID   3
#define RM_VMID     255
#define PVMFW_CONFIG_MAX_BLOBS 2

STATIC QCOM_SCM_MODE_SWITCH_PROTOCOL *pQcomScmModeSwitchProtocol = NULL;
STATIC BOOLEAN BootDevImage;
STATIC BOOLEAN RecoveryHasNoKernel = FALSE;
RamPartitionEntry UpdatedRamPartitions[NUM_NOMAP_REGIONS];
UINT32 NumUpdPartitions;
BOOLEAN UpdRamPartitionsAvail = FALSE;

STATIC VOID
SetLinuxBootCpu (UINT32 BootCpu)
{
  EFI_STATUS Status;
  Status = gRT->SetVariable (L"DestinationCore",
      &gQcomTokenSpaceGuid,
      (EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_NON_VOLATILE |
       EFI_VARIABLE_RUNTIME_ACCESS),
       sizeof (UINT32),
       (VOID*)(UINT32*)&BootCpu);

  if (Status != EFI_SUCCESS) {
       DEBUG ((EFI_D_ERROR, "Error: Failed to set Linux boot cpu:%d\n",
                BootCpu));
   } else if (Status == EFI_SUCCESS) {
       DEBUG ((EFI_D_INFO, "Switching to physical CPU:%d for Booting Linux\n",
                BootCpu));
   }

  return;
}

#ifdef TARGET_LINUX_BOOT_CPU_ID
BOOLEAN
BootCpuSelectionEnabled (VOID)
{
  return TRUE;
}
#else
BOOLEAN
BootCpuSelectionEnabled (VOID)
{
  return FALSE;
}
#endif

/* To set load addresses, callers should make sure to initialize the
 * BootParamlistPtr before calling this function */
UINT64 SetandGetLoadAddr (BootParamlist *BootParamlistPtr, AddrType Type)
{
  STATIC UINT64 KernelLoadAddr;
  STATIC UINT64 RamdiskLoadAddr;

  if (BootParamlistPtr) {
    KernelLoadAddr = BootParamlistPtr->KernelLoadAddr;
    RamdiskLoadAddr = BootParamlistPtr->RamdiskLoadAddr;
  } else {
    switch (Type) {
      case LOAD_ADDR_KERNEL:
        return KernelLoadAddr;
        break;
      case LOAD_ADDR_RAMDISK:
        return RamdiskLoadAddr;
        break;
      default:
        DEBUG ((EFI_D_ERROR, "Invalid Type to GetLoadAddr():%d\n",
                Type));
        break;
    }
  }

  return 0;
}

STATIC BOOLEAN
QueryBootParams (UINT64 *KernelLoadAddr, UINT64 *KernelSizeReserved)
{
  EFI_STATUS Status;
  EFI_STATUS SizeStatus;
  UINTN DataSize = 0;

  DataSize = sizeof (*KernelLoadAddr);
  Status = gRT->GetVariable ((CHAR16 *)L"KernelBaseAddr", &gQcomTokenSpaceGuid,
                          NULL, &DataSize, KernelLoadAddr);

  DataSize = sizeof (*KernelSizeReserved);
  SizeStatus = gRT->GetVariable ((CHAR16 *)L"KernelSize", &gQcomTokenSpaceGuid,
                              NULL, &DataSize, KernelSizeReserved);

  return (Status == EFI_SUCCESS &&
          SizeStatus == EFI_SUCCESS);
}

#ifdef ENABLE_EARLY_SERVICES
STATIC VOID
QueryEarlyServiceBootParams (UINT64 *KernelLoadAddr, UINT64 *KernelSizeReserved)
{
  *KernelLoadAddr = KERNEL_LOAD_ADDRESS;
  *KernelSizeReserved = KERNEL_SIZE_RESERVED;
  return;
}
#else
STATIC VOID
QueryEarlyServiceBootParams (UINT64 *KernelLoadAddr, UINT64 *KernelSizeReserved)
{
  *KernelLoadAddr = 0;
  *KernelSizeReserved = 0;
  return;
}
#endif

#ifdef PVMFW_BCC
STATIC BOOLEAN
QueryPvmFwParams (UINT64 *PvmFwLoadAddr, UINT64 *PvmFwSizeReserved)
{
  EFI_STATUS Status;
  EFI_STATUS SizeStatus;
  UINTN DataSize = 0;

  DataSize = sizeof (*PvmFwLoadAddr);
  Status = gRT->GetVariable ((CHAR16 *)L"PvmFwBaseAddr", &gQcomTokenSpaceGuid,
                          NULL, &DataSize, PvmFwLoadAddr);

  DataSize = sizeof (*PvmFwSizeReserved);
  SizeStatus = gRT->GetVariable ((CHAR16 *)L"PvmFwSize", &gQcomTokenSpaceGuid,
                              NULL, &DataSize, PvmFwSizeReserved);

  return (Status == EFI_SUCCESS &&
          SizeStatus == EFI_SUCCESS);
}
#endif

STATIC EFI_STATUS
UpdateBootParams (BootParamlist *BootParamlistPtr)
{
  UINT64 KernelSizeReserved;
  UINT64 KernelLoadAddr;
#ifdef PVMFW_BCC
  UINT64 PvmFwSizeReserved;
  UINT64 PvmFwLoadAddr;
#endif
  Kernel64Hdr *Kptr = NULL;
  UINT64 KernelLoadAddr_new = 0;
  UINT64 KernelSizeReserved_new = 0;

  if (BootParamlistPtr == NULL ) {
    DEBUG ((EFI_D_ERROR, "Invalid input parameters\n"));
    return EFI_INVALID_PARAMETER;
  }
  QueryEarlyServiceBootParams (&KernelLoadAddr_new, &KernelSizeReserved_new);

  /* The three regions Kernel, Ramdisk and DT should be reserved in memory map
   * Query the kernel load address and size from UEFI core, if it's not
   * successful use the predefined load addresses */
  if (QueryBootParams (&KernelLoadAddr, &KernelSizeReserved)) {
    if (EarlyServicesEnabled ()) {
      BootParamlistPtr->KernelLoadAddr = KernelLoadAddr_new;
    } else {
      BootParamlistPtr->KernelLoadAddr = KernelLoadAddr;
    }
    if (BootParamlistPtr->BootingWith32BitKernel) {
      BootParamlistPtr->KernelLoadAddr += KERNEL_32BIT_LOAD_OFFSET;
    } else {
      Kptr = (Kernel64Hdr *) (BootParamlistPtr->ImageBuffer +
                                BootParamlistPtr->PageSize);
      if (!BootParamlistPtr->BootingWithGzipPkgKernel &&
          Kptr->ImageSize) {
          BootParamlistPtr->KernelLoadAddr += Kptr->TextOffset;
      } else {
        BootParamlistPtr->KernelLoadAddr += KERNEL_64BIT_LOAD_OFFSET;
      }
    }

    if (EarlyServicesEnabled ()) {
      BootParamlistPtr->KernelEndAddr =
          KernelLoadAddr_new + KernelSizeReserved_new;
    } else {
      BootParamlistPtr->KernelEndAddr = KernelLoadAddr + KernelSizeReserved;
    }
  } else {
    DEBUG ((EFI_D_VERBOSE, "QueryBootParams Failed: "));
    /* If Query of boot params fails, RamdiskEndAddress is end of the
    kernel buffer we have. Using same as size of total available buffer,
    for relocation of kernel */

    if (BootParamlistPtr->BootingWith32BitKernel) {
      /* For 32-bit Not all memory is accessible as defined by
         RamdiskEndAddress. Using pre-defined offset for backward
         compatability */
    if (EarlyServicesEnabled ()) {
      BootParamlistPtr->KernelLoadAddr =
            (EFI_PHYSICAL_ADDRESS) (KernelLoadAddr_new |
                                    PcdGet32 (KernelLoadAddress32));
    } else {
      BootParamlistPtr->KernelLoadAddr =
            (EFI_PHYSICAL_ADDRESS) (BootParamlistPtr->BaseMemory |
                                    PcdGet32 (KernelLoadAddress32));
    }
      KernelSizeReserved = PcdGet32 (RamdiskEndAddress32);
    } else {
      if (EarlyServicesEnabled ()) {
         BootParamlistPtr->KernelLoadAddr =
            (EFI_PHYSICAL_ADDRESS) (KernelLoadAddr_new |
                                    PcdGet32 (KernelLoadAddress));
      } else {
      BootParamlistPtr->KernelLoadAddr =
            (EFI_PHYSICAL_ADDRESS) (BootParamlistPtr->BaseMemory |
                                    PcdGet32 (KernelLoadAddress));
      }
      KernelSizeReserved = PcdGet32 (RamdiskEndAddress);
    }

    if (EarlyServicesEnabled ()) {
      BootParamlistPtr->KernelEndAddr = KernelLoadAddr_new +
                                       KernelSizeReserved;
    } else {
      BootParamlistPtr->KernelEndAddr = BootParamlistPtr->BaseMemory +
                                       KernelSizeReserved;
    }
    DEBUG ((EFI_D_VERBOSE, "calculating dynamic offsets\n"));
  }

  /* Allocate buffer for ramdisk and tags area, based on ramdisk actual size
     and DT maximum supported size. This allows best possible utilization
     of buffer for kernel relocation and take care of dynamic change in size
     of ramdisk. Add pagesize as a buffer space */
  BootParamlistPtr->RamdiskLoadAddr = (BootParamlistPtr->KernelEndAddr -
                            (LOCAL_ROUND_TO_PAGE (
                                          BootParamlistPtr->RamdiskSize +
                                          BootParamlistPtr->VendorRamdiskSize +
                                          BootParamlistPtr->RecoveryRamdiskSize,
                             BootParamlistPtr->PageSize) +
                             BootParamlistPtr->PageSize));
  BootParamlistPtr->DeviceTreeLoadAddr = (BootParamlistPtr->RamdiskLoadAddr -
                                          (DT_SIZE_2MB +
                                          BootParamlistPtr->PageSize));

  if (BootParamlistPtr->DeviceTreeLoadAddr <=
                      BootParamlistPtr->KernelLoadAddr) {
    DEBUG ((EFI_D_ERROR, "Not Enough space left to load kernel image\n"));
    return EFI_BUFFER_TOO_SMALL;
  }

#ifdef PVMFW_BCC
  if (QueryPvmFwParams (&PvmFwLoadAddr, &PvmFwSizeReserved)) {
    BootParamlistPtr->PvmFwLoadAddr = PvmFwLoadAddr;
    if (BootParamlistPtr->PvmFwSize > PvmFwSizeReserved) {
      DEBUG ((EFI_D_ERROR, "Not enough space left to load pvmfw\n"));
      return EFI_BUFFER_TOO_SMALL;
    }
  }
#endif

  return EFI_SUCCESS;
}

STATIC EFI_STATUS
SwitchTo32bitModeBooting (UINT64 KernelLoadAddr, UINT64 DeviceTreeLoadAddr)
{
  EFI_STATUS Status;
  EFI_HLOS_BOOT_ARGS HlosBootArgs;

  SetMem ((VOID *)&HlosBootArgs, sizeof (HlosBootArgs), 0);
  HlosBootArgs.el1_x2 = DeviceTreeLoadAddr;
  /* Write 0 into el1_x4 to switch to 32bit mode */
  HlosBootArgs.el1_x4 = 0;
  HlosBootArgs.el1_elr = KernelLoadAddr;
  Status = pQcomScmModeSwitchProtocol->SwitchTo32bitMode (HlosBootArgs);
  if (EFI_ERROR (Status)) {
    DEBUG ((EFI_D_ERROR, "ERROR: Failed to switch to 32 bit mode.Status= %r\n",
            Status));
    return Status;
  }
  /*Return Unsupported if the execution ever reaches here*/
  return EFI_NOT_STARTED;
}

STATIC EFI_STATUS
UpdateKernelModeAndPkg (BootParamlist *BootParamlistPtr)
{
  Kernel64Hdr *Kptr = NULL;

  if (BootParamlistPtr == NULL ) {
    DEBUG ((EFI_D_ERROR, "Invalid input parameters\n"));
    return EFI_INVALID_PARAMETER;
  }

  BootParamlistPtr->BootingWith32BitKernel = FALSE;
  Kptr = (Kernel64Hdr *) (BootParamlistPtr->ImageBuffer +
                            BootParamlistPtr->PageSize);

  if (is_gzip_package ((BootParamlistPtr->ImageBuffer +
                 BootParamlistPtr->PageSize), BootParamlistPtr->KernelSize)) {
      BootParamlistPtr->BootingWithGzipPkgKernel = TRUE;
  }
  else {
    if (!AsciiStrnCmp ((CHAR8 *) Kptr, PATCHED_KERNEL_MAGIC,
                       sizeof (PATCHED_KERNEL_MAGIC) - 1)) {
      BootParamlistPtr->BootingWithPatchedKernel = TRUE;
      Kptr = (struct kernel64_hdr *)((VOID *)Kptr +
                                     PATCHED_KERNEL_HEADER_SIZE);
    }

    if (Kptr->magic_64 != KERNEL64_HDR_MAGIC) {
      BootParamlistPtr->BootingWith32BitKernel = TRUE;
    }
  }

  return EFI_SUCCESS;
}

STATIC EFI_STATUS
CheckMDTPStatus (CHAR16 *PartitionName, BootInfo *Info)
{
  EFI_STATUS Status = EFI_SUCCESS;
  BOOLEAN MdtpActive = FALSE;
  CHAR8 StrPartition[MAX_GPT_NAME_SIZE];
  CHAR8 PartitionNameAscii[MAX_GPT_NAME_SIZE];
  UINT32 PartitionNameLen;
  QCOM_MDTP_PROTOCOL *MdtpProtocol;
  MDTP_VB_EXTERNAL_PARTITION ExternalPartition;

  SetMem ((VOID *)StrPartition, MAX_GPT_NAME_SIZE, 0);
  SetMem ((VOID *)PartitionNameAscii, MAX_GPT_NAME_SIZE, 0);

  if (FixedPcdGetBool (EnableMdtpSupport)) {
    Status = IsMdtpActive (&MdtpActive);
    if (EFI_ERROR (Status)) {
      DEBUG ((EFI_D_ERROR, "Failed to get activation state for MDTP, "
                           "Status=%r. Considering MDTP as active and "
                           "continuing \n",
              Status));

    if (Status != EFI_NOT_FOUND) {
      MdtpActive = TRUE;
    }
  }

    if (MdtpActive) {
      /* If MDTP is Active and Dm-Verity Mode is not Enforcing, Block */
      if (!IsEnforcing ()) {
        DEBUG ((EFI_D_ERROR,
                "ERROR: MDTP is active and verity mode is not enforcing \n"));
        return EFI_NOT_STARTED;
      }
      /* If MDTP is Active and Device is in unlocked State, Block */
      if (IsUnlocked ()) {
        DEBUG ((EFI_D_ERROR,
                "ERROR: MDTP is active and DEVICE is unlocked \n"));
        return EFI_NOT_STARTED;
      }
    }
  }

  UnicodeStrToAsciiStr (PartitionName, PartitionNameAscii);
  PartitionNameLen = AsciiStrLen (PartitionNameAscii);
  if (Info->MultiSlotBoot)
    PartitionNameLen -= (MAX_SLOT_SUFFIX_SZ - 1);
  AsciiStrnCpyS (StrPartition, MAX_GPT_NAME_SIZE, "/", AsciiStrLen ("/"));
  AsciiStrnCatS (StrPartition, MAX_GPT_NAME_SIZE, PartitionNameAscii,
                 PartitionNameLen);

  if (FixedPcdGetBool (EnableMdtpSupport)) {
    Status = gBS->LocateProtocol (&gQcomMdtpProtocolGuid, NULL,
                                  (VOID **)&MdtpProtocol);

    if (Status != EFI_NOT_FOUND) {
      if (EFI_ERROR (Status)) {
        DEBUG ((EFI_D_ERROR, "Failed in locating MDTP protocol, Status=%r\n",
                Status));
        return Status;
      }

      AsciiStrnCpyS (ExternalPartition.PartitionName, MAX_PARTITION_NAME_LEN,
                     StrPartition, AsciiStrLen (StrPartition));
      Status = MdtpProtocol->MdtpBootState (MdtpProtocol, &ExternalPartition);

      if (EFI_ERROR (Status)) {
        /* MdtpVerify should always handle errors internally, so when returned
         * back to the caller,
         * the return value is expected to be success only.
         * Therfore, we don't expect any error status here. */
        DEBUG ((EFI_D_ERROR, "MDTP verification failed, Status=%r\n", Status));
        return Status;
      }
    }

    else
      DEBUG (
          (EFI_D_ERROR, "Failed to locate MDTP protocol, Status=%r\n", Status));
  }

  return Status;
}

STATIC EFI_STATUS
ApplyOverlay (BootParamlist *BootParamlistPtr,
              VOID *AppendedDtHdr,
              struct fdt_entry_node *DtsList)
{
  VOID *FinalDtbHdr = AppendedDtHdr;
  VOID *TmpDtbHdr = NULL;
  UINT64 ApplyDTStartTime = GetTimerCountms ();

  if (BootParamlistPtr == NULL ||
      AppendedDtHdr == NULL) {
    DEBUG ((EFI_D_ERROR, "ApplyOverlay: Invalid input parameters\n"));
    return EFI_INVALID_PARAMETER;
  }
  if (DtsList == NULL) {
    DEBUG ((EFI_D_VERBOSE, "ApplyOverlay: Overlay DT is NULL\n"));
    goto out;
  }

  if (!pre_overlay_malloc ()) {
    DEBUG ((EFI_D_ERROR,
           "ApplyOverlay: Unable to Allocate Pre Buffer for Overlay\n"));
    return EFI_OUT_OF_RESOURCES;
  }

  TmpDtbHdr = ufdt_install_blob (AppendedDtHdr, fdt_totalsize (AppendedDtHdr));
  if (!TmpDtbHdr) {
    DEBUG ((EFI_D_ERROR, "ApplyOverlay: Install blob failed\n"));
    return EFI_NOT_FOUND;
  }

  FinalDtbHdr = ufdt_apply_multi_overlay (TmpDtbHdr,
                                    fdt_totalsize (TmpDtbHdr),
                                    DtsList);
  DeleteDtList (&DtsList);
  if (!FinalDtbHdr) {
    DEBUG ((EFI_D_ERROR, "ApplyOverlay: ufdt apply overlay failed\n"));
    return EFI_NOT_FOUND;
  }

out:
  if ((BootParamlistPtr->RamdiskLoadAddr -
       BootParamlistPtr->DeviceTreeLoadAddr) <
            fdt_totalsize (FinalDtbHdr)) {
    DEBUG ((EFI_D_ERROR,
           "ApplyOverlay: After overlay DTB size exceeded than supported\n"));
    return EFI_UNSUPPORTED;
  }
  /* If DeviceTreeLoadAddr == AppendedDtHdr
     CopyMem will not copy Source Buffer to Destination Buffer
     and return Destination BUffer.
  */
  gBS->CopyMem ((VOID *)BootParamlistPtr->DeviceTreeLoadAddr,
                FinalDtbHdr,
                fdt_totalsize (FinalDtbHdr));
  post_overlay_free ();
  DEBUG ((EFI_D_INFO, "Apply Overlay total time: %lu ms \n",
        GetTimerCountms () - ApplyDTStartTime));
  return EFI_SUCCESS;
}

STATIC UINT32
GetNumberOfPages (UINT32 ImageSize, UINT32 PageSize)
{
   return (ImageSize + PageSize - 1) / PageSize;
}

STATIC EFI_STATUS
DTBImgCheckAndAppendDT (BootInfo *Info, BootParamlist *BootParamlistPtr)
{
  VOID *SingleDtHdr = NULL;
  VOID *NextDtHdr = NULL;
  VOID *BoardDtb = NULL;
  VOID *SocDtb = NULL;
#ifndef AUTO_VIRT_ABL
  VOID *OverrideDtb = NULL;
#endif
  VOID *Dtb;
  BOOLEAN DtboCheckNeeded = FALSE;
  BOOLEAN DtboImgInvalid = FALSE;
  struct fdt_entry_node *DtsList = NULL;
  EFI_STATUS Status;
  UINT32 HeaderVersion = 0;
  struct boot_img_hdr_v1 *BootImgHdrV1;
  struct boot_img_hdr_v2 *BootImgHdrV2;
  vendor_boot_img_hdr_v3 *VendorBootImgHdrV3;
  UINT32 NumHeaderPages;
  UINT32 NumKernelPages;
  UINT32 NumSecondPages;
  UINT32 NumRamdiskPages;
  UINT32 NumVendorRamdiskPages;
  UINT32 NumRecoveryDtboPages;
  VOID* ImageBuffer = NULL;
  UINT32 ImageSize = 0;
  CHAR8 *TempHypBootInfo[HYP_MAX_NUM_DTBOS];
  CHAR8 *TempAvfDpDtbo = NULL;

  if (Info == NULL ||
      BootParamlistPtr == NULL) {
    DEBUG ((EFI_D_ERROR, "Invalid input parameters\n"));
    return EFI_INVALID_PARAMETER;
  }

  ImageBuffer = BootParamlistPtr->ImageBuffer +
                        BootParamlistPtr->PageSize +
                        BootParamlistPtr->PatchedKernelHdrSize;
  ImageSize = BootParamlistPtr->KernelSize;
  HeaderVersion = Info->HeaderVersion;

  if (HeaderVersion > BOOT_HEADER_VERSION_ONE) {
        BootImgHdrV1 = (struct boot_img_hdr_v1 *)
                ((UINT64) BootParamlistPtr->ImageBuffer +
                BOOT_IMAGE_HEADER_V1_RECOVERY_DTBO_SIZE_OFFSET);
        BootImgHdrV2 = (struct boot_img_hdr_v2 *)
            ((UINT64) BootParamlistPtr->ImageBuffer +
            BOOT_IMAGE_HEADER_V1_RECOVERY_DTBO_SIZE_OFFSET +
            BOOT_IMAGE_HEADER_V2_OFFSET);

        NumHeaderPages = 1;
        NumKernelPages =
                GetNumberOfPages (BootParamlistPtr->KernelSize,
                        BootParamlistPtr->PageSize);
        NumRamdiskPages =
                GetNumberOfPages (BootParamlistPtr->RamdiskSize,
                        BootParamlistPtr->PageSize);
        NumSecondPages =
                GetNumberOfPages (BootParamlistPtr->SecondSize,
                        BootParamlistPtr->PageSize);

       if (HeaderVersion  == BOOT_HEADER_VERSION_TWO) {
          NumRecoveryDtboPages =
                           GetNumberOfPages (BootImgHdrV1->recovery_dtbo_size,
                           BootParamlistPtr->PageSize);
          BootParamlistPtr->DtbOffset = BootParamlistPtr->PageSize *
                           (NumHeaderPages + NumKernelPages + NumRamdiskPages +
                            NumSecondPages + NumRecoveryDtboPages);
          ImageSize = BootImgHdrV2->dtb_size + BootParamlistPtr->DtbOffset;
          ImageBuffer = BootParamlistPtr->ImageBuffer;
        } else {
          VendorBootImgHdrV3 = BootParamlistPtr->VendorImageBuffer;

          NumVendorRamdiskPages = GetNumberOfPages (
                                           BootParamlistPtr->VendorRamdiskSize,
                                           BootParamlistPtr->PageSize);
          BootParamlistPtr->DtbOffset = BootParamlistPtr->PageSize *
                           (NumHeaderPages + NumVendorRamdiskPages);
          ImageSize = VendorBootImgHdrV3->dtb_size +
                      BootParamlistPtr->DtbOffset;

          // DTB is a part of vendor_boot image
          ImageBuffer = BootParamlistPtr->VendorImageBuffer;
        }
  }
  DtboImgInvalid = LoadAndValidateDtboImg (Info, BootParamlistPtr);
  if (!DtboImgInvalid) {
    // appended device tree
    Dtb = DeviceTreeAppended (ImageBuffer,
                             ImageSize,
                             BootParamlistPtr->DtbOffset,
                             (VOID *)BootParamlistPtr->DeviceTreeLoadAddr);
    if (!Dtb) {
      if (BootParamlistPtr->DtbOffset >= ImageSize) {
        DEBUG ((EFI_D_ERROR, "Dtb offset goes beyond the image size\n"));
        return EFI_BAD_BUFFER_SIZE;
      }
      SingleDtHdr = (BootParamlistPtr->ImageBuffer +
                     BootParamlistPtr->DtbOffset);

      if (HeaderVersion < BOOT_HEADER_VERSION_ONE) {
        SingleDtHdr += BootParamlistPtr->PageSize;
      }

      if (!fdt_check_header (SingleDtHdr)) {
        if ((ImageSize - BootParamlistPtr->DtbOffset) <
            fdt_totalsize (SingleDtHdr)) {
          DEBUG ((EFI_D_ERROR, "Dtb offset goes beyond the image size\n"));
          return EFI_BAD_BUFFER_SIZE;
        }

        NextDtHdr =
          (VOID *)((uintptr_t)SingleDtHdr + fdt_totalsize (SingleDtHdr));
        if (!fdt_check_header (NextDtHdr)) {
          DEBUG ((EFI_D_VERBOSE, "Not the single appended DTB\n"));
          return EFI_NOT_FOUND;
        }

        DEBUG ((EFI_D_VERBOSE, "Single appended DTB found\n"));
        if (CHECK_ADD64 (BootParamlistPtr->DeviceTreeLoadAddr,
                                fdt_totalsize (SingleDtHdr))) {
          DEBUG ((EFI_D_ERROR,
            "Integer Overflow: in single dtb header addition\n"));
          return EFI_BAD_BUFFER_SIZE;
        }

        gBS->CopyMem ((VOID *)BootParamlistPtr->DeviceTreeLoadAddr,
                      SingleDtHdr, fdt_totalsize (SingleDtHdr));
      } else {
        DEBUG ((EFI_D_ERROR, "Error: Device Tree blob not found\n"));
        return EFI_NOT_FOUND;
      }
      Dtb = SingleDtHdr;
    }

    /* If hypervisor boot info is present, append dtbo info passed from hyp */
    if (IsVmEnabled ()) {
      if (BootParamlistPtr->HypDtboBaseAddr == NULL) {
        DEBUG ((EFI_D_ERROR, "Error: HypOverlay DT is NULL\n"));
        return EFI_NOT_FOUND;
      }

      for (UINT32 i = 0; i < BootParamlistPtr->NumHypDtbos; i++) {
        /* Flag the invalid dtbos and overlay the valid ones */
        if (!BootParamlistPtr->HypDtboBaseAddr[i] ||
             fdt_check_header ((VOID *)BootParamlistPtr->HypDtboBaseAddr[i])) {
          DEBUG ((EFI_D_ERROR, "HypInfo: Not overlaying hyp dtbo"
                  "Dtbo :%d is null or Bad DT header\n", i));
          continue;
        }

        /* Allocate buffer temporarily */
        TempHypBootInfo[i] = AllocateZeroPool (fdt_totalsize
                                      (BootParamlistPtr->HypDtboBaseAddr[i]));

        if (!TempHypBootInfo[i]) {
          DEBUG ((EFI_D_ERROR,
                 "Failed to allocate memory for HypDtbo %d\n", i));
          return EFI_OUT_OF_RESOURCES;
        }

        /* Copy content from Hyp provided memory to temp buffer */
        gBS->CopyMem ((VOID *)TempHypBootInfo[i],
                      (VOID *)BootParamlistPtr->HypDtboBaseAddr[i],
                      fdt_totalsize (BootParamlistPtr->HypDtboBaseAddr[i]));

        if (!AppendToDtList (&DtsList,
                       (fdt64_t)TempHypBootInfo[i],
                       fdt_totalsize (BootParamlistPtr->HypDtboBaseAddr[i]))) {
          DEBUG ((EFI_D_ERROR,
                  "Unable to Allocate buffer for HypOverlay DT num: %d\n", i));
          FreePool ((VOID *)TempHypBootInfo[i]);
          DeleteDtList (&DtsList);
          return EFI_OUT_OF_RESOURCES;
        }
      }
    }

    Status = ApplyOverlay (BootParamlistPtr,
                           Dtb,
                           DtsList);
    if (Status != EFI_SUCCESS) {
      DEBUG ((EFI_D_ERROR, "Error: Dtb overlay failed\n"));
      SetVmDisable ();
    }
  } else {
#ifdef AUTO_VIRT_ABL
    /* For ABL running in a VM, we fetch SOC device tree address
     * from virtialized UEFI directly.
     */
    UINTN DataSize = 0;
    UINT64 U64SocDtb = 0;

    DataSize = sizeof (U64SocDtb);
    Status = gRT->GetVariable ((CHAR16 *)L"VmDeviceTreeBase",
                          &gQcomTokenSpaceGuid,
                          NULL, &DataSize, &U64SocDtb);
    SocDtb = (VOID *)U64SocDtb;
#else
    /*It is the case of DTB overlay Get the Soc specific dtb */
    SocDtb = GetSocDtb (ImageBuffer,
         ImageSize,
         BootParamlistPtr->DtbOffset,
         (VOID *)BootParamlistPtr->DeviceTreeLoadAddr);

    if (!SocDtb) {
      DEBUG ((EFI_D_ERROR,
                  "Error: Appended Soc Device Tree blob not found\n"));
      return EFI_NOT_FOUND;
    }
#endif

    /*Check do we really need to gothrough DTBO or not*/
    DtboCheckNeeded = GetDtboNeeded ();
    if (DtboCheckNeeded == TRUE) {
      BoardDtb = GetBoardDtb (Info, BootParamlistPtr->DtboImgBuffer);
      if (!BoardDtb) {
        DEBUG ((EFI_D_ERROR, "Error: Board Dtbo blob not found\n"));
        return EFI_NOT_FOUND;
      }

      if (!AppendToDtList (&DtsList,
                         (fdt64_t)BoardDtb,
                         fdt_totalsize (BoardDtb))) {
        DEBUG ((EFI_D_ERROR,
              "Unable to Allocate buffer for Overlay DT\n"));
        DeleteDtList (&DtsList);
        return EFI_OUT_OF_RESOURCES;
      }
    }

    /* If hypervisor boot info is present, append dtbo info passed from hyp */
    if (IsVmEnabled ()) {
      if (BootParamlistPtr->HypDtboBaseAddr == NULL) {
        DEBUG ((EFI_D_ERROR, "Error: HypOverlay DT is NULL\n"));
        return EFI_NOT_FOUND;
      }

      for (UINT32 i = 0; i < BootParamlistPtr->NumHypDtbos; i++) {
        /* Flag the invalid dtbos and overlay the valid ones */
        if (!BootParamlistPtr->HypDtboBaseAddr[i] ||
             fdt_check_header ((VOID *)BootParamlistPtr->HypDtboBaseAddr[i])) {
          DEBUG ((EFI_D_ERROR, "HypInfo: Not overlaying hyp dtbo"
                  "Dtbo :%d is null or Bad DT header\n", i));
          continue;
        }

        /* Allocate buffer temporarily */
        TempHypBootInfo[i] = AllocateZeroPool (fdt_totalsize
                                      (BootParamlistPtr->HypDtboBaseAddr[i]));

        if (!TempHypBootInfo[i]) {
          DEBUG ((EFI_D_ERROR,
                 "Failed to allocate memory for HypDtbo %d\n", i));
          return EFI_OUT_OF_RESOURCES;
        }

        /* Copy content from Hyp provided memory to temp buffer */
        gBS->CopyMem ((VOID *)TempHypBootInfo[i],
                      (VOID *)BootParamlistPtr->HypDtboBaseAddr[i],
                      fdt_totalsize (BootParamlistPtr->HypDtboBaseAddr[i]));

        if (!AppendToDtList (&DtsList,
                       (fdt64_t)TempHypBootInfo[i],
                       fdt_totalsize (BootParamlistPtr->HypDtboBaseAddr[i]))) {
          DEBUG ((EFI_D_ERROR,
                  "Unable to Allocate buffer for HypOverlay DT num: %d\n", i));
          FreePool ((VOID *)TempHypBootInfo[i]);
          DeleteDtList (&DtsList);
          return EFI_OUT_OF_RESOURCES;
        }
      }
    }

#ifndef AUTO_VIRT_ABL
    // Only enabled to debug builds.
    if (!TargetBuildVariantUser ()) {
      Status = GetOvrdDtb (&OverrideDtb);
      if (Status == EFI_SUCCESS &&
           OverrideDtb &&
          !AppendToDtList (&DtsList,
                              (fdt64_t)OverrideDtb,
                              fdt_totalsize (OverrideDtb))) {
        DEBUG ((EFI_D_ERROR,
                "Unable to allocate buffer for Override DT\n"));
        DeleteDtList (&DtsList);
        return EFI_OUT_OF_RESOURCES;
      }
    }
#endif

    // Add AVF DP dtbo to DtsList. This will be applied to HLOS DT.
   if (BootParamlistPtr->AvfDpDtboBaseAddr != NULL) {
     /* Allocate buffer temporarily */
     TempAvfDpDtbo = AllocateZeroPool (
                         fdt_totalsize (BootParamlistPtr->AvfDpDtboBaseAddr));
     if (!TempAvfDpDtbo) {
       DEBUG ((EFI_D_ERROR,
               "Failed to allocate temp memory for DP dtbo\n"));
       return EFI_OUT_OF_RESOURCES;
     }

     gBS-> CopyMem ((VOID *)TempAvfDpDtbo,
                    (VOID *)BootParamlistPtr->AvfDpDtboBaseAddr,
                    fdt_totalsize (BootParamlistPtr->AvfDpDtboBaseAddr));

     if (!AppendToDtList (&DtsList,
                          (fdt64_t)TempAvfDpDtbo,
                          fdt_totalsize (BootParamlistPtr->AvfDpDtboBaseAddr)
                         )) {
       DEBUG ((EFI_D_ERROR, "Unable to allocate buffer for DP dtbo\n"));
       FreePool ((VOID *)TempAvfDpDtbo);
       DeleteDtList (&DtsList);
       return EFI_OUT_OF_RESOURCES;
     }
   }

    Status = ApplyOverlay (BootParamlistPtr,
                           SocDtb,
                           DtsList);
    if (Status != EFI_SUCCESS) {
      DEBUG ((EFI_D_ERROR, "Error: Dtb overlay failed\n"));
      SetVmDisable ();
    }
  }
  return EFI_SUCCESS;
}

STATIC EFI_STATUS
GZipPkgCheck (BootParamlist *BootParamlistPtr)
{
  UINT32 OutLen = 0;
  UINT64 OutAvaiLen = 0;
  struct kernel64_hdr *Kptr = NULL;
  UINT64 DecompressStartTime;

  if (BootParamlistPtr == NULL) {

    DEBUG ((EFI_D_ERROR, "Invalid input parameters\n"));
    return EFI_INVALID_PARAMETER;
  }

  if (BootParamlistPtr->BootingWithGzipPkgKernel) {
    OutAvaiLen = BootParamlistPtr->DeviceTreeLoadAddr -
                 BootParamlistPtr->KernelLoadAddr;

    if (OutAvaiLen > MAX_UINT32) {
      DEBUG ((EFI_D_ERROR,
              "Integer Overflow: the length of decompressed data = %u\n",
      OutAvaiLen));
      return EFI_BAD_BUFFER_SIZE;
    }

    DecompressStartTime = GetTimerCountms ();
    if (decompress (
        (UINT8 *)(BootParamlistPtr->ImageBuffer +
        BootParamlistPtr->PageSize),               // Read blob using BlockIo
        BootParamlistPtr->KernelSize,              // Blob size
        (UINT8 *)BootParamlistPtr->KernelLoadAddr, // Load address, allocated
        (UINT32)OutAvaiLen,                        // Allocated Size
        &BootParamlistPtr->DtbOffset, &OutLen)) {
          DEBUG ((EFI_D_ERROR, "Decompressing kernel image failed!!!\n"));
          return RETURN_OUT_OF_RESOURCES;
    }

    if (OutLen <= sizeof (struct kernel64_hdr *)) {
      DEBUG ((EFI_D_ERROR,
              "Decompress kernel size is smaller than image header size\n"));
      return RETURN_OUT_OF_RESOURCES;
    }
    Kptr = (Kernel64Hdr *) BootParamlistPtr->KernelLoadAddr;
    DEBUG ((EFI_D_INFO, "Decompressing kernel image total time: %lu ms\n",
                         GetTimerCountms () - DecompressStartTime));
  } else {
    Kptr = (struct kernel64_hdr *)(BootParamlistPtr->ImageBuffer
                         + BootParamlistPtr->PageSize);
    /* Patch kernel support only for 64-bit */
    if (BootParamlistPtr->BootingWithPatchedKernel) {
      DEBUG ((EFI_D_VERBOSE, "Patched kernel detected\n"));

      /* The size of the kernel is stored at start of kernel image + 16
       * The dtb would start just after the kernel */
      gBS->CopyMem ((VOID *)&BootParamlistPtr->DtbOffset,
                    (VOID *) (BootParamlistPtr->ImageBuffer +
                               BootParamlistPtr->PageSize +
                               sizeof (PATCHED_KERNEL_MAGIC) - 1),
                               sizeof (BootParamlistPtr->DtbOffset));

      BootParamlistPtr->PatchedKernelHdrSize = PATCHED_KERNEL_HEADER_SIZE;
      Kptr = (struct kernel64_hdr *)((VOID *)Kptr +
                 BootParamlistPtr->PatchedKernelHdrSize);
      gBS->CopyMem ((VOID *)BootParamlistPtr->KernelLoadAddr, (VOID *)Kptr,
                 BootParamlistPtr->KernelSize);
    }

    if (Kptr->magic_64 != KERNEL64_HDR_MAGIC) {
      if (BootParamlistPtr->KernelSize <=
          DTB_OFFSET_LOCATION_IN_ARCH32_KERNEL_HDR) {
          DEBUG ((EFI_D_ERROR, "DTB offset goes beyond kernel size.\n"));
          return EFI_BAD_BUFFER_SIZE;
        }
      gBS->CopyMem ((VOID *)&BootParamlistPtr->DtbOffset,
           ((VOID *)Kptr + DTB_OFFSET_LOCATION_IN_ARCH32_KERNEL_HDR),
           sizeof (BootParamlistPtr->DtbOffset));
    }
    gBS->CopyMem ((VOID *)BootParamlistPtr->KernelLoadAddr, (VOID *)Kptr,
                 BootParamlistPtr->KernelSize);
  }

  if (Kptr->magic_64 != KERNEL64_HDR_MAGIC) {
    /* For GZipped 32-bit Kernel */
    BootParamlistPtr->BootingWith32BitKernel = TRUE;
  } else {
    if (Kptr->ImageSize >
          (BootParamlistPtr->DeviceTreeLoadAddr -
           BootParamlistPtr->KernelLoadAddr)) {
      DEBUG ((EFI_D_ERROR,
            "DTB header can get corrupted due to runtime kernel size\n"));
      return RETURN_OUT_OF_RESOURCES;
    }
  }
  return EFI_SUCCESS;
}

#ifdef PVMFW_BCC
STATIC EFI_STATUS
RmRegisterPvmFwRegion (BootInfo *Info, BootParamlist *BootParamlistPtr)
{
  RmVmProtocol *RmVmProtocol = NULL;
  RmMemAcl *PvmFwAclDesc = NULL;
  RmMemSgl *PvmFwSglDesc = NULL;
  UINT32 PvmFwMemHandle = 0;
  UINT64 PvmFwLoadAddr;
  UINT32 PvmFwSize;
  EFI_STATUS  Status;

  PvmFwLoadAddr = BootParamlistPtr->PvmFwLoadAddr;
  PvmFwSize = BootParamlistPtr->PvmFwSize;

  Status = gBS->LocateProtocol (&gEfiRmVmProtocolGuid,
                                NULL,
                                (VOID**)&RmVmProtocol);
  if (Status != EFI_SUCCESS)  {
    DEBUG ((EFI_D_ERROR, "RmVmProtocol not found: %r\n", Status));
    return Status;
  }

  PvmFwAclDesc = AllocateZeroPool (MAX_RPC_BUFF_SIZE_BYTES);
  if (PvmFwAclDesc == NULL) {
    DEBUG ((EFI_D_ERROR, "Failed to allocate PvmFwAclDesc: %r\n", Status));
    return Status;
  }

  PvmFwSglDesc = AllocateZeroPool (MAX_RPC_BUFF_SIZE_BYTES);
  if (PvmFwSglDesc == NULL) {
    DEBUG ((EFI_D_ERROR, "Failed to allocate PvmFwSglDesc: %r\n", Status));
    return Status;
  }

  PvmFwAclDesc->AclEntriesCount = 1;
  PvmFwAclDesc->AclEntries[0].Vmid = RM_VMID;
  PvmFwAclDesc->AclEntries[0].Rights = (RM_ACL_PERM_READ|
                                        RM_ACL_PERM_WRITE|
                                        RM_ACL_PERM_EXEC);

  PvmFwSglDesc->SglEntriesCount = 1;
  PvmFwSglDesc->SglEntries[0].BaseAddr = PvmFwLoadAddr;
  PvmFwSglDesc->SglEntries[0].Size = PvmFwSize;

  Status = RmVmProtocol->MemDonate (RmVmProtocol,
                                    RM_MEM_TYPE_NORMAL_MEMORY,
                                    0,
                                    0,
                                    PvmFwAclDesc,
                                    PvmFwSglDesc,
                                    NULL,
                                    HLOS_VMID,
                                    RM_VMID,
                                    &PvmFwMemHandle);
  if (Status != EFI_SUCCESS) {
    DEBUG ((EFI_D_ERROR, "pvmfw memory donation failed Status: %r\n", Status));
    return Status;
  }

  Status = RmVmProtocol->FwSetVmFirmware (RmVmProtocol,
                                    RM_VM_AUTH_ANDROID_PVM,
                                    PvmFwMemHandle,
                                    0,
                                    PvmFwSize);
  if (Status != EFI_SUCCESS) {
    DEBUG ((EFI_D_ERROR, "SetVmFirmware failed Status: %r\n", Status));
    return Status;
  }

  Status = RmVmProtocol->SetFwMilestone (RmVmProtocol);
  if (Status != EFI_SUCCESS) {
    DEBUG ((EFI_D_ERROR, "SetFwMilestone failed Status: %r\n", Status));
    return Status;
  }

  return EFI_SUCCESS;
}

STATIC VOID
CreatePvmFwConfig (PvmFwConfigHeader *Hdr, UINT32 *EntrySizes,
                   UINT32 NumEntries) {
  PvmFwConfigHeader Header;
  UINT32 EntryOffset = sizeof (Header);

  //ASCII of characters in "pvmf"
  Header.Magic = 0x666D7670;
  //version 1,0
  Header.Version = ((UINT32) 1 << 16) | (UINT32) 0;
  //Feature flags; currently reserved and must be zero.
  Header.Flags = 0;
  for (UINTN Index = 0 ; Index < NumEntries ; Index++ ) {
    Header.Entries[Index].Offset = EntryOffset;
    Header.Entries[Index].Size = EntrySizes[Index];
    // 8 byte aligned offset
    EntryOffset += (EntrySizes[Index] + 7) & ~7;
  }
  Header.TotalSize = Header.Entries[NumEntries - 1].Offset +
                      Header.Entries[NumEntries - 1].Size;
  memcpy (Hdr, &Header, sizeof (Header));
}

STATIC EFI_STATUS
AppendPvmFwConfig (BootInfo *Info, BootParamlist *BootParamlistPtr) {
  UINT8 *FinalEncodedBccArtifacts = NULL;
  UINT8 *PvmFwCfgLoadAddr = NULL;
  UINT32 EntrySizes[PVMFW_CONFIG_MAX_BLOBS] = {0};
  PvmFwConfigHeader PvmFwCgfHdr = {0};
  size_t  BccArtifactsValidSize = 0;
  UINT8 Ret;

  //TODO: Ensure there is enough room to append config data.

  /* Allocate BCC artifacts buffer */
  FinalEncodedBccArtifacts =
                         AllocateZeroPool (BCC_ARTIFACTS_WITH_BCC_TOTAL_SIZE);
  if (!FinalEncodedBccArtifacts) {
    DEBUG ((EFI_D_ERROR,
            ": Failed to allocate memory for BCC artifacts\n"));
    return EFI_OUT_OF_RESOURCES;
  }

  /* Generate BCC handover data*/
  Ret = GetBccArtifacts (FinalEncodedBccArtifacts,
                       BCC_ARTIFACTS_WITH_BCC_TOTAL_SIZE,
                       &BccArtifactsValidSize
#ifndef USE_DUMMY_BCC
                      , BccParamsRecvdFromAVB
#endif
        );
  if (Ret != 0) {
    DEBUG ((EFI_D_ERROR, "BCC handover data generation failed\n"));
    return EFI_FAILURE;
  }
  EntrySizes[0] = BccArtifactsValidSize;

  if (BootParamlistPtr->AvfDpDtboBaseAddr) {
    EntrySizes[1] = fdt_totalsize (BootParamlistPtr->AvfDpDtboBaseAddr);
  }

  CreatePvmFwConfig (&PvmFwCgfHdr, EntrySizes, PVMFW_CONFIG_MAX_BLOBS);
  PvmFwCfgLoadAddr = (UINT8*)((((BootParamlistPtr->PvmFwLoadAddr +
                     Info->PvmFwRawSize) / 4096) * 4096) + 4096);

  DEBUG ((EFI_D_VERBOSE, "PvmFwCfgLoadAddr: 0x%lx\n",
                          PvmFwCfgLoadAddr));
  for (UINT32 Index = 0; Index < PVMFW_CONFIG_MAX_BLOBS; Index++) {
    DEBUG ((EFI_D_VERBOSE, "PvmFwCgfHdr.Entries[%d].Offset: 0x%lx\n", Index,
           PvmFwCgfHdr.Entries[Index].Offset));
    DEBUG ((EFI_D_VERBOSE, "PvmFwCgfHdr.Entries[%d].Size: 0x%lx\n", Index,
           PvmFwCgfHdr.Entries[Index].Size));
  }

  /* Write PvmFwCgfHdr to the page alligned end of
   * pvmfw raw binary in golden region. */
  gBS->CopyMem ((CHAR8 *)PvmFwCfgLoadAddr,
                         &PvmFwCgfHdr,
                         sizeof (PvmFwCgfHdr));
  /* Write BCC blob to end of pVM firmware config header */
  gBS->CopyMem ((CHAR8 *)(PvmFwCfgLoadAddr +
                         PvmFwCgfHdr.Entries[0].Offset),
                         FinalEncodedBccArtifacts,
                         EntrySizes[0]);

  /* Write DP blob to pVM firmware config */
  if (PvmFwCgfHdr.Entries[1].Offset &&
      BootParamlistPtr->AvfDpDtboBaseAddr &&
      fdt_totalsize (BootParamlistPtr->AvfDpDtboBaseAddr)) {
    gBS->CopyMem ((CHAR8 *)(PvmFwCfgLoadAddr +
                           PvmFwCgfHdr.Entries[1].Offset),
                           (CHAR8 *)(BootParamlistPtr->AvfDpDtboBaseAddr),
                           fdt_totalsize (BootParamlistPtr->AvfDpDtboBaseAddr));
  }

  FreePool (FinalEncodedBccArtifacts);

  return EFI_SUCCESS;
}
#endif

STATIC EFI_STATUS
LoadAddrAndDTUpdate (BootInfo *Info, BootParamlist *BootParamlistPtr)
{
  EFI_STATUS Status;
  UINT64 RamdiskLoadAddr;
  UINT64 RamdiskEndAddr = 0;
  UINT64 RamdiskLoadAddrCopy = 0;
  UINT32 TotalRamdiskSize;
  UINT64 End = 0;
#ifdef PVMFW_BCC
  UINT64 PvmFwLoadAddr = 0;
#endif
  UINT32 VRamdiskSizePageAligned;
  UINT32 VDtbSizePageAligned;
  UINT32 VRamdiskTablesizePageAligned;
  VOID *RamdiskImageBuffer;

  if (BootParamlistPtr == NULL) {
    DEBUG ((EFI_D_ERROR, "Invalid input parameters\n"));
    return EFI_INVALID_PARAMETER;
  }

  VRamdiskSizePageAligned =
    LOCAL_ROUND_TO_PAGE (BootParamlistPtr->VendorRamdiskSize,
    BootParamlistPtr->PageSize);
  VDtbSizePageAligned =
    LOCAL_ROUND_TO_PAGE (BootParamlistPtr->DtSize,
    BootParamlistPtr->PageSize);
  VRamdiskTablesizePageAligned =
    LOCAL_ROUND_TO_PAGE (BootParamlistPtr->VendorRamdiskTableSize,
    BootParamlistPtr->PageSize);

  if ((Info->HasBootInitRamdisk) &&
         (Info->HeaderVersion >= BOOT_HEADER_VERSION_FOUR)) {
    RamdiskImageBuffer = BootParamlistPtr->RamdiskBuffer;
  } else {
    RamdiskImageBuffer = BootParamlistPtr->ImageBuffer;
  }

  RamdiskLoadAddr = BootParamlistPtr->RamdiskLoadAddr;

  TotalRamdiskSize = BootParamlistPtr->RamdiskSize +
                            BootParamlistPtr->VendorRamdiskSize +
                            BootParamlistPtr->RecoveryRamdiskSize;

  if (RamdiskEndAddr - RamdiskLoadAddr < TotalRamdiskSize) {
    DEBUG ((EFI_D_ERROR, "Error: Ramdisk size is over the limit\n"));
    return EFI_BAD_BUFFER_SIZE;
  }

  if (CHECK_ADD64 ((UINT64)RamdiskImageBuffer,
      BootParamlistPtr->RamdiskOffset)) {
    DEBUG ((EFI_D_ERROR, "Integer Overflow: ImageBuffer=%u, "
                         "RamdiskOffset=%u\n",
                         RamdiskImageBuffer,
                         BootParamlistPtr->RamdiskOffset));
    return EFI_BAD_BUFFER_SIZE;
  }
  RamdiskLoadAddrCopy = RamdiskLoadAddr;
  /* If the boot-image version is greater than 2, place the vendor-ramdisk
   * first in the memory, and then place ramdisk.
   * This concatination would result in an overlay for .gzip and .cpio formats.
   */
  if (Info->HeaderVersion >= BOOT_HEADER_VERSION_THREE) {
    gBS->CopyMem ((VOID *)RamdiskLoadAddr,
                  BootParamlistPtr->VendorImageBuffer +
                  BootParamlistPtr->PageSize,
                  BootParamlistPtr->VendorRamdiskSize);

    RamdiskLoadAddr += BootParamlistPtr->VendorRamdiskSize;

    if (Info->BootIntoRecovery &&
        IsRecoveryHasNoKernel () &&
        BootParamlistPtr->RecoveryRamdiskSize) {
      gBS->CopyMem ((VOID *)RamdiskLoadAddr,
                    BootParamlistPtr->RecoveryImageBuffer +
                    BootParamlistPtr->PageSize,
                    BootParamlistPtr->RecoveryRamdiskSize);
      RamdiskLoadAddr += BootParamlistPtr->RecoveryRamdiskSize;
    }
  }

  gBS->CopyMem ((CHAR8 *)RamdiskLoadAddr,
                RamdiskImageBuffer+
                BootParamlistPtr->RamdiskOffset,
                BootParamlistPtr->RamdiskSize);

  RamdiskLoadAddr +=BootParamlistPtr->RamdiskSize;

#ifdef PVMFW_BCC
  PvmFwLoadAddr = BootParamlistPtr->PvmFwLoadAddr;

  /* Write pvmfw to golden region and register
   * pvmfw region with RM.
   */
  if (Info->HasPvmFw &&
      BootParamlistPtr->PvmFwSize >= 0 &&
      PvmFwLoadAddr != 0) {
    gBS->CopyMem ((CHAR8 *)PvmFwLoadAddr,
                  BootParamlistPtr->PvmFwBuffer +
                  /* Skip boot image header */
                  BOOT_IMG_MAX_PAGE_SIZE,
                  BootParamlistPtr->PvmFwSize);
    DEBUG ((EFI_D_VERBOSE, "Copied pvmfw into golden region\n"));

    Status = AppendPvmFwConfig (Info, BootParamlistPtr);
    if (Status == EFI_SUCCESS) {
      Status = RmRegisterPvmFwRegion (Info, BootParamlistPtr);
      if (Status != EFI_SUCCESS) {
        DEBUG ((EFI_D_ERROR,
               "Failed to register pvmfw region with RM: %r\n", Status));
      }
    } else {
      DEBUG ((EFI_D_ERROR, "Failed to write pvmfw config: %r\n", Status));
    }
  }
#endif

  if (BootParamlistPtr->BootingWith32BitKernel) {
    if (CHECK_ADD64 (BootParamlistPtr->KernelLoadAddr,
        BootParamlistPtr->KernelSizeActual)) {
      DEBUG ((EFI_D_ERROR, "Integer Overflow: while Kernel image copy\n"));
      return EFI_BAD_BUFFER_SIZE;
    }
    if (BootParamlistPtr->KernelLoadAddr +
        BootParamlistPtr->KernelSizeActual >
        BootParamlistPtr->DeviceTreeLoadAddr) {
      DEBUG ((EFI_D_ERROR, "Kernel size is over the limit\n"));
      return EFI_INVALID_PARAMETER;
    }
    gBS->CopyMem ((CHAR8 *)BootParamlistPtr->KernelLoadAddr,
                  BootParamlistPtr->ImageBuffer +
                  BootParamlistPtr->PageSize,
                  BootParamlistPtr->KernelSizeActual);
  }


  if (Info->HeaderVersion > BOOT_HEADER_VERSION_THREE) {

    UINT64 *BootconfigAddr = (BootParamlistPtr->VendorImageBuffer+
        BootParamlistPtr->PageSize+
        VRamdiskSizePageAligned+
        VDtbSizePageAligned+
        VRamdiskTablesizePageAligned);

    /*Copy the static bootconfig params to mem*/
    gBS->CopyMem ((CHAR8 *)RamdiskLoadAddr,
        BootconfigAddr,
        BootParamlistPtr->VendorBootconfigSize);

    /*Copy the Dynamic bootconfig params to mem*/
    if (BootParamlistPtr->FinalBootConfig) {
      End =  AddBootconfigParameters (BootParamlistPtr->FinalBootConfig,
        BootParamlistPtr->FinalBootConfigLen, RamdiskLoadAddr,
        BootParamlistPtr->VendorBootconfigSize);
    } else {
      End =  AddBootconfigParameters ("\n",
        2, RamdiskLoadAddr,
        BootParamlistPtr->VendorBootconfigSize);
    }

    if (End == 0) {
      DEBUG ((EFI_D_INFO, "Failed to load Bootconfig \n"));
    } else {
      BootParamlistPtr->VendorBootconfigSize = (End - RamdiskLoadAddr);
      TotalRamdiskSize += BootParamlistPtr->VendorBootconfigSize;
    }
  }
  Status = UpdateDeviceTree ((VOID *)BootParamlistPtr->DeviceTreeLoadAddr,
                             BootParamlistPtr->FinalCmdLine,
                             (VOID *)RamdiskLoadAddrCopy, TotalRamdiskSize,
                             BootParamlistPtr->BootingWith32BitKernel);
  if (Status != EFI_SUCCESS) {
    DEBUG ((EFI_D_ERROR, "Device Tree update failed Status:%r\n", Status));
    return Status;
  }

  return EFI_SUCCESS;
}

STATIC EFI_STATUS
CatCmdLine (BootParamlist *BootParamlistPtr, BootInfo *Info)
{
  UINTN MaxCmdLineLen = BOOT_ARGS_SIZE +
                        BOOT_EXTRA_ARGS_SIZE + VENDOR_BOOT_ARGS_SIZE;
  boot_img_hdr_v3 *BootImgHdrV3;
  vendor_boot_img_hdr_v3 *VendorBootImgHdrV3;
  boot_img_hdr_v4 *BootImgHdrV4;
  vendor_boot_img_hdr_v4 *VendorBootImgHdrV4;

  BootParamlistPtr->CmdLine = AllocateZeroPool (MaxCmdLineLen);
  if (!BootParamlistPtr->CmdLine) {
    DEBUG ((EFI_D_ERROR,
            "CatCmdLine: Failed to allocate memory for cmdline\n"));
    return EFI_OUT_OF_RESOURCES;
  }

  /* Place the vendor_boot image cmdline first so that the cmdline
   * from boot image takes precedence in case of duplicates.
   */
  if (Info->HeaderVersion == BOOT_HEADER_VERSION_THREE) {
    BootImgHdrV3 = BootParamlistPtr->ImageBuffer;
    VendorBootImgHdrV3 = BootParamlistPtr->VendorImageBuffer;
    AsciiStrCpyS (BootParamlistPtr->CmdLine, MaxCmdLineLen,
      (CONST CHAR8 *)VendorBootImgHdrV3->cmdline);
    AsciiStrCatS (BootParamlistPtr->CmdLine, MaxCmdLineLen, " ");
    AsciiStrCatS (BootParamlistPtr->CmdLine, MaxCmdLineLen,
      (CONST CHAR8 *)BootImgHdrV3->cmdline);
  } else if (Info->HeaderVersion == BOOT_HEADER_VERSION_FOUR) {
    BootImgHdrV4 = BootParamlistPtr->ImageBuffer;
    VendorBootImgHdrV4 = BootParamlistPtr->VendorImageBuffer;
    AsciiStrCpyS (BootParamlistPtr->CmdLine, MaxCmdLineLen,
      (CONST CHAR8 *)VendorBootImgHdrV4->cmdline);
    AsciiStrCatS (BootParamlistPtr->CmdLine, MaxCmdLineLen, " ");
    AsciiStrCatS (BootParamlistPtr->CmdLine, MaxCmdLineLen,
      (CONST CHAR8 *)BootImgHdrV4->cmdline);
  }

  return EFI_SUCCESS;
}

STATIC EFI_STATUS
UpdateBootParamsSizeAndCmdLine (BootInfo *Info, BootParamlist *BootParamlistPtr)
{
  EFI_STATUS Status = EFI_SUCCESS;
  UINTN VendorBootImgSize;
  UINTN RecoveryBootImgSize;
  boot_img_hdr_v3 *BootImgHdrV3;
  vendor_boot_img_hdr_v3 *VendorBootImgHdrV3;
  boot_img_hdr_v3 *RecoveryBootImgHdrV3;
  boot_img_hdr_v4 *BootImgHdrV4;
  vendor_boot_img_hdr_v4 *VendorBootImgHdrV4;
  boot_img_hdr_v4 *RecoveryBootImgHdrV4;

  if (Info->HeaderVersion < BOOT_HEADER_VERSION_THREE) {
    BootParamlistPtr->KernelSize =
               ((boot_img_hdr *)(BootParamlistPtr->ImageBuffer))->kernel_size;
    BootParamlistPtr->RamdiskSize =
               ((boot_img_hdr *)(BootParamlistPtr->ImageBuffer))->ramdisk_size;
    BootParamlistPtr->SecondSize =
               ((boot_img_hdr *)(BootParamlistPtr->ImageBuffer))->second_size;
    BootParamlistPtr->PageSize =
               ((boot_img_hdr *)(BootParamlistPtr->ImageBuffer))->page_size;
    BootParamlistPtr->CmdLine = (CHAR8 *)&(((boot_img_hdr *)
                             (BootParamlistPtr->ImageBuffer))->cmdline[0]);
    BootParamlistPtr->CmdLine[BOOT_ARGS_SIZE - 1] = '\0';

    return EFI_SUCCESS;
  } else if (Info->HeaderVersion == BOOT_HEADER_VERSION_THREE) {
    BootImgHdrV3 = BootParamlistPtr->ImageBuffer;
    Status = GetImage (Info, (VOID **)&VendorBootImgHdrV3,
    &VendorBootImgSize, "vendor_boot");
    if (Status != EFI_SUCCESS) {
      DEBUG ((EFI_D_ERROR,
        "UpdateBootParamsSizeAndCmdLine: Failed to find vendor_boot image\n"));
      return Status;
    }

    if (Info->BootIntoRecovery &&
        IsRecoveryHasNoKernel ()) {
      Status = GetImage (Info, (VOID **)&RecoveryBootImgHdrV3,
                         &RecoveryBootImgSize, "recovery");

        if (Status != EFI_SUCCESS) {
          DEBUG ((EFI_D_ERROR,
          "UpdateBootParamsSizeAndCmdLine: Failed to find recovery image\n"));
          return Status;
        }

        BootParamlistPtr->RecoveryImageBuffer = RecoveryBootImgHdrV3;
        BootParamlistPtr->RecoveryImageSize = RecoveryBootImgSize;
        BootParamlistPtr->RecoveryRamdiskSize =
                          RecoveryBootImgHdrV3->ramdisk_size;
    } else {
      BootParamlistPtr->RecoveryImageBuffer = NULL;
      BootParamlistPtr->RecoveryImageSize = 0;
      BootParamlistPtr->RecoveryRamdiskSize = 0;
    }

    BootParamlistPtr->VendorImageBuffer = VendorBootImgHdrV3;
    BootParamlistPtr->VendorImageSize = VendorBootImgSize;
    BootParamlistPtr->KernelSize = BootImgHdrV3->kernel_size;
    BootParamlistPtr->RamdiskSize = BootImgHdrV3->ramdisk_size;
    BootParamlistPtr->VendorRamdiskSize =
    VendorBootImgHdrV3->vendor_ramdisk_size;
    BootParamlistPtr->PageSize = VendorBootImgHdrV3->page_size;
    BootParamlistPtr->SecondSize = 0;
  } else if (Info->HeaderVersion == BOOT_HEADER_VERSION_FOUR) {

    BootImgHdrV4 = BootParamlistPtr->ImageBuffer;

    Status = GetImage (Info, (VOID **)&VendorBootImgHdrV4,
    &VendorBootImgSize, "vendor_boot");
    if (Status != EFI_SUCCESS) {
      DEBUG ((EFI_D_ERROR,
        "UpdateBootParamsSizeAndCmdLine: vendor_boot"
                       " image header not found\n"));
      return Status;
    }

    if (Info->BootIntoRecovery &&
        IsRecoveryHasNoKernel ()) {
      Status = GetImage (Info, (VOID **)&RecoveryBootImgHdrV4,
                         &RecoveryBootImgSize, "recovery");

        if (Status != EFI_SUCCESS) {
          DEBUG ((EFI_D_ERROR,
          "UpdateBootParamsSizeAndCmdLine: Failed to find recovery image\n"));
          return Status;
        }

        BootParamlistPtr->RecoveryImageBuffer = RecoveryBootImgHdrV4;
        BootParamlistPtr->RecoveryImageSize = RecoveryBootImgSize;
        BootParamlistPtr->RecoveryRamdiskSize =
                          RecoveryBootImgHdrV4->ramdisk_size;
    } else {
      BootParamlistPtr->RecoveryImageBuffer = NULL;
      BootParamlistPtr->RecoveryImageSize = 0;
      BootParamlistPtr->RecoveryRamdiskSize = 0;
    }

    BootParamlistPtr->VendorImageBuffer = VendorBootImgHdrV4;
    BootParamlistPtr->VendorImageSize = VendorBootImgSize;
    BootParamlistPtr->KernelSize = BootImgHdrV4->kernel_size;
    BootParamlistPtr->RamdiskSize = BootImgHdrV4->ramdisk_size;
    BootParamlistPtr->VendorRamdiskSize =
    VendorBootImgHdrV4->vendor_ramdisk_size;
    BootParamlistPtr->PageSize = VendorBootImgHdrV4->page_size;
    BootParamlistPtr->DtSize = VendorBootImgHdrV4->dtb_size;
    BootParamlistPtr->VendorRamdiskTableSize =
      VendorBootImgHdrV4->VendorRamdiskTableSize;
    BootParamlistPtr->VendorBootconfigSize =
      VendorBootImgHdrV4->VendorBootconfigSize;
    BootParamlistPtr->SecondSize = 0;
  }

  Status = CatCmdLine (BootParamlistPtr, Info);
  if (Status != EFI_SUCCESS) {
    DEBUG ((EFI_D_ERROR,
           "UpdateBootParamsSizeAndCmdLine: Failed to cat cmdline\n"));
    return Status;
  }

  return EFI_SUCCESS;
}

EFI_STATUS
BootLinux (BootInfo *Info)
{

  EFI_STATUS Status;
  CHAR16 *PartitionName = NULL;
  BOOLEAN Recovery = FALSE;
  BOOLEAN AlarmBoot = FALSE;
  BOOLEAN FlashlessBoot;
  CHAR8 SilentBootMode;

  LINUX_KERNEL LinuxKernel;
  LINUX_KERNEL32 LinuxKernel32;
  UINT32 RamdiskSizeActual = 0;
  UINT32 SecondSizeActual = 0;

  /*Boot Image header information variables*/
  CHAR8 FfbmStr[FFBM_MODE_BUF_SIZE] = {'\0'};
  BOOLEAN IsModeSwitch = FALSE;

  BootParamlist BootParamlistPtr = {0};

#ifndef DISABLE_KERNEL_PROTOCOL
  UINT64 KernelSizeReserved = 0;
  UINTN DataSize;
  EFI_KERNEL_PROTOCOL *KernIntf = NULL;
  Thread *ThreadNum;
  VOID *StackBase = NULL;
  VOID **StackCurrent = NULL;
#endif

  RamPartitionEntry *RamPartitions = NULL;
  UINT32 NumPartitions = 0;
  UINT32 *Prop = NULL;
  VOID *Fdt;
  INT32 PropLen = 0;
  INT32 Fragment = 0;
  INT32 Node = 0;

  if (Info == NULL) {
    DEBUG ((EFI_D_ERROR, "BootLinux: invalid parameter Info\n"));
    return EFI_INVALID_PARAMETER;
  }

  FlashlessBoot = Info->FlashlessBoot;

  if (IsVmEnabled ()) {
    Status = CheckAndSetVmData (&BootParamlistPtr);
    if (Status != EFI_SUCCESS) {
      DEBUG ((EFI_D_ERROR, "Failed to update HypData!! Status:%r\n", Status));
      return Status;
    }
  }

  PartitionName = Info->Pname;
  Recovery = Info->BootIntoRecovery;
  AlarmBoot = Info->BootReasonAlarm;
  SilentBootMode = Info->SilentBootMode;

  if (SilentBootMode) {
    DEBUG ((EFI_D_INFO, "Silent Mode value: %d\n", SilentBootMode));
  }

  if (!FlashlessBoot) {
    if (!StrnCmp (PartitionName, (CONST CHAR16 *)L"boot",
                  StrLen ((CONST CHAR16 *)L"boot")) &&
                   !TargetBuildVariantUser ()) {
      Status = GetFfbmCommand (FfbmStr, FFBM_MODE_BUF_SIZE);
      if (Status != EFI_SUCCESS) {
        DEBUG ((EFI_D_VERBOSE, "No Ffbm cookie found, ignore: %r\n", Status));
        FfbmStr[0] = '\0';
      }
    }
  }

  Status = GetImage (Info,
                     &BootParamlistPtr.ImageBuffer,
                     (UINTN *)&BootParamlistPtr.ImageSize,
                     ((!Info->MultiSlotBoot ||
                        IsDynamicPartitionSupport ()) &&
                        (Recovery &&
                        !IsBuildUseRecoveryAsBoot () &&
                        !IsRecoveryHasNoKernel ()))?
                        "recovery" : "boot");
  if (Status != EFI_SUCCESS ||
      BootParamlistPtr.ImageBuffer == NULL ||
      BootParamlistPtr.ImageSize <= 0) {
    DEBUG ((EFI_D_ERROR, "BootLinux: Get%aImage failed!\n",
            (!Info->MultiSlotBoot &&
             (Recovery &&
             !IsBuildUseRecoveryAsBoot () &&
             !IsRecoveryHasNoKernel ()))? "Recovery" : "Boot"));
    return EFI_NOT_STARTED;
  }
  /* Find if MDTP is enabled and Active */

  Status = CheckMDTPStatus (PartitionName, Info);
  if (Status != EFI_SUCCESS) {
    return Status;
  }

  Info->HeaderVersion = ((boot_img_hdr *)
                         (BootParamlistPtr.ImageBuffer))->header_version;

  Status = UpdateBootParamsSizeAndCmdLine (Info, &BootParamlistPtr);
  if (Status != EFI_SUCCESS) {
    return Status;
  }

  /* When there is init_boot partition exist, use ramdisk
   * in init_boot anyway. note that BootHasNoKernel will be
   * only set true when there is init_boot partition.
   */
  BootParamlistPtr.RamdiskBuffer = NULL;

  if ((Info->HasBootInitRamdisk) &&
     (Info->HeaderVersion >= BOOT_HEADER_VERSION_FOUR)) {
    UINT32 InitBootSize;
    boot_img_hdr_v4 *InitBootHdr;

    Status = GetImage (Info,
                       &BootParamlistPtr.RamdiskBuffer,
                       (UINTN *)&InitBootSize,
                       "init_boot");

    if (Status ||
        InitBootSize <= 0) {

      DEBUG ((EFI_D_ERROR, "BootLinux: Get%aImage failed!\n",
             "init_boot"));
      return EFI_NOT_STARTED;
    }

    /*
     * Get the actual ramdisk offset and ramdisk size from
     * header.
     */
    InitBootHdr = BootParamlistPtr.RamdiskBuffer;

    if (InitBootHdr->header_size > InitBootSize ||
        InitBootHdr->ramdisk_size > InitBootSize ||
        InitBootHdr->ramdisk_size > InitBootSize - InitBootHdr->header_size) {
        DEBUG ((EFI_D_ERROR, "Wrong size in init boot header!\n"));
        return EFI_NOT_STARTED;
    }

    BootParamlistPtr.RamdiskOffset = ROUND_TO_PAGE (InitBootHdr->header_size,
            BOOT_IMG_MAX_PAGE_SIZE - 1);
    if (!BootParamlistPtr.RamdiskOffset &&
        InitBootHdr->header_size) {
          DEBUG ((EFI_D_ERROR, "Integer Overflow: Ramdisk offset = %u\n",
                     InitBootHdr->header_size));
          return EFI_BAD_BUFFER_SIZE;
    }
    BootParamlistPtr.RamdiskSize = ROUND_TO_PAGE (InitBootHdr->ramdisk_size,
            BOOT_IMG_MAX_PAGE_SIZE - 1);
    if (!BootParamlistPtr.RamdiskSize &&
        InitBootHdr->ramdisk_size) {
          DEBUG ((EFI_D_ERROR, "Integer Overflow: Ramdisk size = %u\n",
                     InitBootHdr->ramdisk_size));
          return EFI_BAD_BUFFER_SIZE;
    }
  }

  BootParamlistPtr.PvmFwBuffer = NULL;
  if (Info->HasPvmFw) {
    Status = GetImage (Info,
                      &BootParamlistPtr.PvmFwBuffer,
                      (UINTN *)&BootParamlistPtr.PvmFwSize,
                      "pvmfw");

    if (Status ||
        BootParamlistPtr.PvmFwSize <= 0) {
        DEBUG ((EFI_D_ERROR, "ERROR: BootLinux: Get pvmfw Image failed!\n"));
        return EFI_LOAD_ERROR;
    } else {
        DEBUG ((EFI_D_VERBOSE, "pvmfw size fetched from partition = 0x%x\n",
               BootParamlistPtr.PvmFwSize));
    }

    // Load DP DTBO if device is unlocked
    if (!TargetBuildVariantUser () &&
        IsUnlocked ()) {
      Status = GetAvfDpDtbo (&BootParamlistPtr.AvfDpDtboBaseAddr);
      if (Status == EFI_SUCCESS) {
        DEBUG ((EFI_D_VERBOSE, "Loaded DP dtbo partition\n"));
        /* AVF Ramdump is not supported.
         * So warn if ramdump property is enabled */
        Fdt = BootParamlistPtr.AvfDpDtboBaseAddr;
        /* Search fragments */
        fdt_for_each_subnode (Fragment, Fdt, 0) {
          if (Fragment >= 0) {
            //Search for ramdump property in each node of the fragment.
            for (Node = fdt_next_node (Fdt, Fragment, NULL);
                 Node >= 0;
                 Node = fdt_next_node (Fdt, Node, NULL)) {
              Prop = (UINT32*) fdt_getprop (Fdt, Node, "ramdump", &PropLen);
              if (Prop &&
                  *Prop != 0) {
                DEBUG ((EFI_D_ERROR,
                       "AVF debug dtbo: ramdump property is not supported\n"));
              }
            }
          }
        }
      } else {
        DEBUG ((EFI_D_INFO, "Not loading AVF debug policy\n"));
      }
    }
  }

  // Retrive Base Memory Address from Ram Partition Table
  Status = BaseMem (&BootParamlistPtr.BaseMemory);
  if (Status != EFI_SUCCESS) {
      DEBUG ((EFI_D_ERROR, "Base memory not found!!! Status:%r\n", Status));
      return Status;
  }

  Status = UpdateKernelModeAndPkg (&BootParamlistPtr);
  if (Status != EFI_SUCCESS) {
    return Status;
  }

  Status = UpdateBootParams (&BootParamlistPtr);
  if (Status != EFI_SUCCESS) {
    return Status;
  }
  SetandGetLoadAddr (&BootParamlistPtr, LOAD_ADDR_NONE);
  Status = GZipPkgCheck (&BootParamlistPtr);
  if (Status != EFI_SUCCESS) {
    return Status;
  }

  /*Finds out the location of device tree image and ramdisk image within the
   *boot image
   *Kernel, Ramdisk and Second sizes all rounded to page
   *The offset and the LOCAL_ROUND_TO_PAGE function is written in a way that it
   *is done the same in LK*/
  BootParamlistPtr.KernelSizeActual = LOCAL_ROUND_TO_PAGE (
                                          BootParamlistPtr.KernelSize,
                                          BootParamlistPtr.PageSize);
  RamdiskSizeActual = LOCAL_ROUND_TO_PAGE (BootParamlistPtr.RamdiskSize,
                                           BootParamlistPtr.PageSize);
  SecondSizeActual = LOCAL_ROUND_TO_PAGE (BootParamlistPtr.SecondSize,
                                          BootParamlistPtr.PageSize);

  /*Offsets are the location of the images within the boot image*/

 if ((!Info->HasBootInitRamdisk) ||
         (Info->HeaderVersion < BOOT_HEADER_VERSION_FOUR)) {
    BootParamlistPtr.RamdiskOffset = ADD_OF (BootParamlistPtr.PageSize,
                                             BootParamlistPtr.KernelSizeActual);
    if (!BootParamlistPtr.RamdiskOffset) {
        DEBUG ((EFI_D_ERROR,
                "Integer Overflow: PageSize=%u, KernelSizeActual=%u\n",
                BootParamlistPtr.PageSize, BootParamlistPtr.KernelSizeActual));
      return EFI_BAD_BUFFER_SIZE;
    }
 }

  DEBUG ((EFI_D_VERBOSE, "Kernel Load Address: 0x%x\n",
                                        BootParamlistPtr.KernelLoadAddr));
  DEBUG ((EFI_D_VERBOSE, "Kernel Size Actual: 0x%x\n",
                                      BootParamlistPtr.KernelSizeActual));
  DEBUG ((EFI_D_VERBOSE, "Second Size Actual: 0x%x\n", SecondSizeActual));
  DEBUG ((EFI_D_VERBOSE, "Ramdisk Load Address: 0x%x\n",
                                       BootParamlistPtr.RamdiskLoadAddr));
  DEBUG ((EFI_D_VERBOSE, "Ramdisk Size Actual: 0x%x\n", RamdiskSizeActual));
  DEBUG ((EFI_D_VERBOSE, "Ramdisk Offset: 0x%x\n",
                                       BootParamlistPtr.RamdiskOffset));
#ifdef PVMFW_BCC
  if (Info->HasPvmFw) {
        DEBUG ((EFI_D_VERBOSE, "PvmFw Load Address: 0x%x\n",
                        BootParamlistPtr.PvmFwLoadAddr));
  }
#endif
  DEBUG (
      (EFI_D_VERBOSE, "Device Tree Load Address: 0x%x\n",
                             BootParamlistPtr.DeviceTreeLoadAddr));

  if (AsciiStrStr (BootParamlistPtr.CmdLine, "root=")) {
    BootDevImage = TRUE;
  }

  Status = DTBImgCheckAndAppendDT (Info, &BootParamlistPtr);
  if (Status != EFI_SUCCESS) {
    return Status;
  }

  /* Updating Kernel start Physical address to KP which will be used
   * by QRKS service later.
   */
  GetQrksKernelStartAddress ();

  if (IsCarveoutRemovalEnabled ()) {
    Status = ReadRamPartitions (&RamPartitions, &NumPartitions);
    if (EFI_ERROR (Status)) {
      DEBUG ((EFI_D_ERROR, "Error returned from ReadRamPartitions %r\n",
              Status));
      return Status;
    }

    Status = GetUpdatedRamPartitions (
                            (VOID *)BootParamlistPtr.DeviceTreeLoadAddr,
                            RamPartitions, NumPartitions,
                            UpdatedRamPartitions, &NumUpdPartitions);
    if (Status == EFI_SUCCESS) {
      UpdRamPartitionsAvail = TRUE;
    } else {
      DEBUG ((EFI_D_ERROR, "Failed to update RAM Partitions Status:%r\r\n",
              Status));
    }
  }

  /* Updates the command line from boot image, appends device serial no.,
   * baseband information, etc.
   * Called before ShutdownUefiBootServices as it uses some boot service
   * functions
   */
  Status = UpdateCmdLine (&BootParamlistPtr, FfbmStr, Recovery, FlashlessBoot,
                    AlarmBoot, Info->VBCmdLine, Info->HeaderVersion,
                    SilentBootMode);
  if (EFI_ERROR (Status)) {
    DEBUG ((EFI_D_ERROR, "Error updating cmdline. Device Error %r\n", Status));
    return Status;
  }

  Status = LoadAddrAndDTUpdate (Info, &BootParamlistPtr);
  if (Status != EFI_SUCCESS &&
          BoardPlatformType () != EFI_PLATFORMINFO_TYPE_RUMI) {
       return Status;
  }

#ifdef VERFIEID_BOOT_LE
  FreeVerifiedBootResource (Info);
#endif

  /* Free the boot logo blt buffer before starting kernel */
  FreeBootLogoBltBuffer ();
  if (BootParamlistPtr.BootingWith32BitKernel &&
      sizeof (UINTN) != 4) {
    Status = gBS->LocateProtocol (&gQcomScmModeSwithProtocolGuid, NULL,
                                  (VOID **)&pQcomScmModeSwitchProtocol);
    if (!EFI_ERROR (Status))
      IsModeSwitch = TRUE;
  }

#ifndef DISABLE_KERNEL_PROTOCOL
  Status = gBS->LocateProtocol (&gEfiKernelProtocolGuid, NULL,
        (VOID **)&KernIntf);

  if ((Status != EFI_SUCCESS) ||
      (KernIntf == NULL)) {
    DEBUG ((EFI_D_ERROR, "Error getting kernel stack protocol. Error %r\n",
           Status));
    goto Exit;
  }

  if (KernIntf->Version >= EFI_KERNEL_PROTOCOL_VERSION) {
    ThreadNum = KernIntf->Thread->GetCurrentThread ();
    StackCurrent = KernIntf->Thread->ThreadGetUnsafeSPCurrent (ThreadNum);
    StackBase = KernIntf->Thread->ThreadGetUnsafeSPBase (ThreadNum);
  }

  DataSize = sizeof (KernelSizeReserved);
  Status = gRT->GetVariable ((CHAR16 *)L"KernelSize", &gQcomTokenSpaceGuid,
                               NULL, &DataSize, &KernelSizeReserved);

  if (Status != EFI_SUCCESS) {
    DEBUG ((EFI_D_INFO, "Failed to get size of kernel region\n"));
    return Status;
  }
#endif

  if (BootCpuSelectionEnabled ()) {
    SetLinuxBootCpu (BootCpuId);
  }

  DEBUG ((EFI_D_INFO, "\nShutting Down UEFI Boot Services: %lu ms\n",
          GetTimerCountms ()));
  /*Shut down UEFI boot services*/
  Status = ShutdownUefiBootServices ();
  if (EFI_ERROR (Status)) {
    DEBUG ((EFI_D_ERROR,
            "ERROR: Can not shutdown UEFI boot services. Status=0x%X\n",
            Status));
    goto Exit;
  }

#ifdef DISABLE_KERNEL_PROTOCOL
  PreparePlatformHardware ();
#else
  PreparePlatformHardware (KernIntf, (VOID *)BootParamlistPtr.KernelLoadAddr,
                  (UINTN)KernelSizeReserved,
                  (VOID *)BootParamlistPtr.RamdiskLoadAddr,
                  (UINTN)RamdiskSizeActual,
                  (VOID *)BootParamlistPtr.DeviceTreeLoadAddr, DT_SIZE_2MB,
                  (VOID *)StackCurrent, (UINTN)StackBase);
#endif
  BootStatsSetTimeStamp (BS_BL_END);

  //
  // Start the Linux Kernel
  //

  if (BootParamlistPtr.BootingWith32BitKernel) {
    if (IsModeSwitch) {
      Status = SwitchTo32bitModeBooting (
                     (UINT64)BootParamlistPtr.KernelLoadAddr,
                     (UINT64)BootParamlistPtr.DeviceTreeLoadAddr);
      if (EFI_ERROR (Status)) {
        goto Exit;
      }
    }

    // Booting into 32 bit kernel.
    LinuxKernel32 = (LINUX_KERNEL32) (UINT64)BootParamlistPtr.KernelLoadAddr;
    LinuxKernel32 (0, 0, (UINTN)BootParamlistPtr.DeviceTreeLoadAddr);

    // Should never reach here. After life support is not available
    goto Exit;
  }

  LinuxKernel = (LINUX_KERNEL) (UINT64)BootParamlistPtr.KernelLoadAddr;
  LinuxKernel ((UINT64)BootParamlistPtr.DeviceTreeLoadAddr, 0, 0, 0);

// Kernel should never exit
// After Life services are not provided

Exit:
  // Only be here if we fail to start Linux
  CpuDeadLoop ();
  return EFI_NOT_STARTED;
}

/**
  Check image header
  @param[in]  ImageHdrBuffer  Supplies the address where a pointer to the image
header buffer.
  @param[in]  ImageHdrSize    Supplies the address where a pointer to the image
header size.
  @param[in]  VendorImageHdrBuffer  Supplies the address where a pointer to
the image header buffer.
  @param[in]  VendorImageHdrSize    Supplies the address where a pointer to
the image header size.
  @param[out] ImageSizeActual The Pointer for image actual size.
  @param[out] PageSize        The Pointer for page size..
  @retval     EFI_SUCCESS     Check image header successfully.
  @retval     other           Failed to check image header.
**/
EFI_STATUS
CheckImageHeader (VOID *ImageHdrBuffer,
                  UINT32 ImageHdrSize,
                  VOID *VendorImageHdrBuffer,
                  UINT32 VendorImageHdrSize,
                  UINT32 *ImageSizeActual,
                  UINT32 *PageSize,
                  BOOLEAN BootIntoRecovery,
                  VOID *RecoveryHdrBuffer)
{
  EFI_STATUS Status = EFI_SUCCESS;

  struct boot_img_hdr_v2 *BootImgHdrV2;
  boot_img_hdr_v3 *BootImgHdrV3;
  vendor_boot_img_hdr_v3 *VendorBootImgHdrV3;
  boot_img_hdr_v3 *RecoveryImgHdrV3 = NULL;
  boot_img_hdr_v4 *BootImgHdrV4;
  vendor_boot_img_hdr_v4 *VendorBootImgHdrV4;
  boot_img_hdr_v4 *RecoveryImgHdrV4 = NULL;

  UINT32 KernelSizeActual = 0;
  UINT32 DtSizeActual = 0;
  UINT32 RamdiskSizeActual = 0;
  UINT32 VendorRamdiskSizeActual = 0;
  UINT32 RecoveryRamdiskSizeActual = 0;

  // Boot Image header information variables
  UINT32 HeaderVersion = 0;
  UINT32 KernelSize = 0;
  UINT32 RamdiskSize = 0;
  UINT32 VendorRamdiskSize = 0;
  UINT32 SecondSize = 0;
  UINT32 DtSize = 0;
  UINT32 tempImgSize = 0;
  UINT32 RecoveryRamdiskSize = 0;

  if (CompareMem ((VOID *)((boot_img_hdr *)(ImageHdrBuffer))->magic, BOOT_MAGIC,
                  BOOT_MAGIC_SIZE)) {
    DEBUG ((EFI_D_ERROR, "Invalid boot image header\n"));
    return EFI_NO_MEDIA;
  }

  HeaderVersion = ((boot_img_hdr *)(ImageHdrBuffer))->header_version;
  if (HeaderVersion < BOOT_HEADER_VERSION_THREE) {
    KernelSize = ((boot_img_hdr *)(ImageHdrBuffer))->kernel_size;
    RamdiskSize = ((boot_img_hdr *)(ImageHdrBuffer))->ramdisk_size;
    SecondSize = ((boot_img_hdr *)(ImageHdrBuffer))->second_size;
    *PageSize = ((boot_img_hdr *)(ImageHdrBuffer))->page_size;
  } else if (HeaderVersion == BOOT_HEADER_VERSION_THREE) {
    if (CompareMem ((VOID *)((vendor_boot_img_hdr_v3 *)
                     (VendorImageHdrBuffer))->magic,
                     VENDOR_BOOT_MAGIC, VENDOR_BOOT_MAGIC_SIZE)) {
      DEBUG ((EFI_D_ERROR, "Invalid vendor_boot image header\n"));
      return EFI_NO_MEDIA;
    }

    BootImgHdrV3 = ImageHdrBuffer;
    VendorBootImgHdrV3 = VendorImageHdrBuffer;

    KernelSize = BootImgHdrV3->kernel_size;
    RamdiskSize = BootImgHdrV3->ramdisk_size;
    VendorRamdiskSize = VendorBootImgHdrV3->vendor_ramdisk_size;
    *PageSize = VendorBootImgHdrV3->page_size;
    DtSize = VendorBootImgHdrV3->dtb_size;

    if (*PageSize > BOOT_IMG_MAX_PAGE_SIZE) {
      DEBUG ((EFI_D_ERROR, "Invalid vendor image pagesize. "
                           "MAX: %u. PageSize: %u and VendorImageHdrSize: %u\n",
                        BOOT_IMG_MAX_PAGE_SIZE, *PageSize, VendorImageHdrSize));
      return EFI_BAD_BUFFER_SIZE;
    }

    VendorRamdiskSizeActual = ROUND_TO_PAGE (VendorRamdiskSize, *PageSize - 1);
    if (VendorRamdiskSize &&
        !VendorRamdiskSizeActual) {
      DEBUG ((EFI_D_ERROR, "Integer Overflow: Vendor Ramdisk Size = %u\n",
              RamdiskSize));
      return EFI_BAD_BUFFER_SIZE;
    }

    if (BootIntoRecovery &&
        RecoveryHdrBuffer) {
      RecoveryImgHdrV3 = RecoveryHdrBuffer;
      RecoveryRamdiskSize = RecoveryImgHdrV3->ramdisk_size;
      RecoveryRamdiskSizeActual = ROUND_TO_PAGE (RecoveryRamdiskSize,
                      *PageSize - 1);
      if (RecoveryRamdiskSize &&
          !RecoveryRamdiskSizeActual) {
        DEBUG ((EFI_D_ERROR, "Integer Overflow checking Recovery Ramdisk\n"));
        return EFI_BAD_BUFFER_SIZE;
      }
    }
  } else if (HeaderVersion == BOOT_HEADER_VERSION_FOUR) {
    if (CompareMem ((VOID *)((vendor_boot_img_hdr_v4 *)
                    (VendorImageHdrBuffer))->magic,
                    VENDOR_BOOT_MAGIC, VENDOR_BOOT_MAGIC_SIZE)) {
      DEBUG ((EFI_D_ERROR, "Invalid vendor_boot image header\n"));
      return EFI_NO_MEDIA;
    }
    BootImgHdrV4 = ImageHdrBuffer;
    VendorBootImgHdrV4 = VendorImageHdrBuffer;

    KernelSize = BootImgHdrV4->kernel_size;
    RamdiskSize = BootImgHdrV4->ramdisk_size;
    VendorRamdiskSize = VendorBootImgHdrV4->vendor_ramdisk_size;
    *PageSize = VendorBootImgHdrV4->page_size;
    DtSize = VendorBootImgHdrV4->dtb_size;

    if (*PageSize > BOOT_IMG_MAX_PAGE_SIZE) {
      DEBUG ((EFI_D_ERROR, "Invalid vendor-img pagesize. "
                           "MAX: %u. PageSize: %u and VendorImageHdrSize: %u\n",
                        BOOT_IMG_MAX_PAGE_SIZE, *PageSize, VendorImageHdrSize));
      return EFI_BAD_BUFFER_SIZE;
    }

    VendorRamdiskSizeActual = ROUND_TO_PAGE (VendorRamdiskSize, *PageSize - 1);
    if (VendorRamdiskSize &&
        !VendorRamdiskSizeActual) {
      DEBUG ((EFI_D_ERROR, "Integer Overflow: Vendor Ramdisk Size = %u\n",
              RamdiskSize));
      return EFI_BAD_BUFFER_SIZE;
    }

    if (BootIntoRecovery &&
        RecoveryHdrBuffer) {
      RecoveryImgHdrV4 = RecoveryHdrBuffer;
      RecoveryRamdiskSize = RecoveryImgHdrV4->ramdisk_size;
      RecoveryRamdiskSizeActual = ROUND_TO_PAGE (RecoveryRamdiskSize,
                      *PageSize - 1);
      if (RecoveryRamdiskSize &&
          !RecoveryRamdiskSizeActual) {
        DEBUG ((EFI_D_ERROR, "Integer Overflow checking Recovery Ramdisk\n"));
        return EFI_BAD_BUFFER_SIZE;
      }
    }
  }

  if (!KernelSize || !*PageSize) {
    DEBUG ((EFI_D_ERROR, "Invalid image Sizes\n"));
    DEBUG (
        (EFI_D_ERROR, "KernelSize: %u, PageSize=%u\n", KernelSize, *PageSize));
    return EFI_BAD_BUFFER_SIZE;
  }

  if ((*PageSize != ImageHdrSize) && (*PageSize > BOOT_IMG_MAX_PAGE_SIZE)) {
    DEBUG ((EFI_D_ERROR, "Invalid image pagesize\n"));
    DEBUG ((EFI_D_ERROR, "MAX: %u. PageSize: %u and ImageHdrSize: %u\n",
            BOOT_IMG_MAX_PAGE_SIZE, *PageSize, ImageHdrSize));
    return EFI_BAD_BUFFER_SIZE;
  }

  KernelSizeActual = ROUND_TO_PAGE (KernelSize, *PageSize - 1);
  if (!KernelSizeActual) {
    DEBUG ((EFI_D_ERROR, "Integer Overflow: Kernel Size = %u\n", KernelSize));
    return EFI_BAD_BUFFER_SIZE;
  }

  RamdiskSizeActual = ROUND_TO_PAGE (RamdiskSize, *PageSize - 1);
  if (RamdiskSize && !RamdiskSizeActual) {
    DEBUG ((EFI_D_ERROR, "Integer Overflow: Ramdisk Size = %u\n", RamdiskSize));
    return EFI_BAD_BUFFER_SIZE;
  }

  if (HeaderVersion == BOOT_HEADER_VERSION_TWO) {
    BootImgHdrV2 = (struct boot_img_hdr_v2 *)
        ((UINT64) ImageHdrBuffer +
        BOOT_IMAGE_HEADER_V1_RECOVERY_DTBO_SIZE_OFFSET +
        BOOT_IMAGE_HEADER_V2_OFFSET);

     DtSize = BootImgHdrV2->dtb_size;
  }

  // DT size doesn't apply to header versions 0 and 1
  if (HeaderVersion >= BOOT_HEADER_VERSION_TWO) {
     DtSizeActual = ROUND_TO_PAGE (DtSize, *PageSize - 1);
      if (DtSize &&
          !DtSizeActual) {
        DEBUG ((EFI_D_ERROR, "Integer Overflow: dt Size = %u\n", DtSize));
        return EFI_BAD_BUFFER_SIZE;
     }
  }

  *ImageSizeActual = ADD_OF (*PageSize, KernelSizeActual);
  if (!*ImageSizeActual) {
    DEBUG ((EFI_D_ERROR, "Integer Overflow: Actual Kernel size = %u\n",
            KernelSizeActual));
    return EFI_BAD_BUFFER_SIZE;
  }

  tempImgSize = *ImageSizeActual;
  *ImageSizeActual = ADD_OF (*ImageSizeActual, RamdiskSizeActual);
  if (!*ImageSizeActual) {
    DEBUG ((EFI_D_ERROR,
            "Integer Overflow: ImgSizeActual=%u, RamdiskActual=%u\n",
            tempImgSize, RamdiskSizeActual));
    return EFI_BAD_BUFFER_SIZE;
  }

  tempImgSize = *ImageSizeActual;

  /*
   * As the DTB is not not a part of boot-images with header versions greater
   * than two, ignore considering its size for calculating the total image size
   */
  if (HeaderVersion < BOOT_HEADER_VERSION_THREE) {
    *ImageSizeActual = ADD_OF (*ImageSizeActual, DtSizeActual);
    if (!*ImageSizeActual) {
      DEBUG ((EFI_D_ERROR, "Integer Overflow: ImgSizeActual=%u,"
             " DtSizeActual=%u\n", tempImgSize, DtSizeActual));
      return EFI_BAD_BUFFER_SIZE;
    }
  }

  if (BootIntoRecovery &&
      HeaderVersion > BOOT_HEADER_VERSION_ZERO &&
      HeaderVersion < BOOT_HEADER_VERSION_THREE) {

    struct boot_img_hdr_v1 *Hdr1 =
      (struct boot_img_hdr_v1 *) (ImageHdrBuffer + sizeof (boot_img_hdr));
    UINT32 RecoveryDtboActual = 0;

    if (HeaderVersion == BOOT_HEADER_VERSION_ONE) {
        if ((Hdr1->header_size !=
          sizeof (struct boot_img_hdr_v1) + sizeof (boot_img_hdr))) {
           DEBUG ((EFI_D_ERROR,
             "Invalid boot image header: %d\n", Hdr1->header_size));
           return EFI_BAD_BUFFER_SIZE;
        }
    }
    else {
        UINT32 DtbActual = 0;
        struct boot_img_hdr_v2 *Hdr2 = (struct boot_img_hdr_v2 *)
            (ImageHdrBuffer +
            BOOT_IMAGE_HEADER_V1_RECOVERY_DTBO_SIZE_OFFSET +
            BOOT_IMAGE_HEADER_V2_OFFSET);
        DtbActual = ROUND_TO_PAGE (Hdr2->dtb_size,
                                        *PageSize - 1);
        if ((Hdr1->header_size !=
                        BOOT_IMAGE_HEADER_V1_RECOVERY_DTBO_SIZE_OFFSET +
                        BOOT_IMAGE_HEADER_V2_OFFSET +
                        sizeof (struct boot_img_hdr_v2))) {
           DEBUG ((EFI_D_ERROR,
              "Invalid boot image header: %d\n", Hdr1->header_size));
           return EFI_BAD_BUFFER_SIZE;
        }
        if (Hdr2->dtb_size && !DtbActual) {
           DEBUG ((EFI_D_ERROR,
               "DTB Image not present: DTB Size = %u\n", Hdr2->dtb_size));
           return EFI_BAD_BUFFER_SIZE;
        }
        tempImgSize = *ImageSizeActual;
        *ImageSizeActual = ADD_OF (*ImageSizeActual, DtbActual);
        if (!*ImageSizeActual) {
           DEBUG ((EFI_D_ERROR, "Integer Overflow: ImgSizeActual=%u,"
              " DtbActual=%u\n", tempImgSize, DtbActual));
           return EFI_BAD_BUFFER_SIZE;
        }
    }
    RecoveryDtboActual = ROUND_TO_PAGE (Hdr1->recovery_dtbo_size,
                                        *PageSize - 1);

    if (RecoveryDtboActual > DTBO_MAX_SIZE_ALLOWED) {
      DEBUG ((EFI_D_ERROR, "Recovery Dtbo Size too big %x, Allowed size %x\n",
              RecoveryDtboActual, DTBO_MAX_SIZE_ALLOWED));
      return EFI_BAD_BUFFER_SIZE;
    }

    if (CHECK_ADD64 (Hdr1->recovery_dtbo_offset, RecoveryDtboActual)) {
      DEBUG ((EFI_D_ERROR, "Integer Overflow: RecoveryDtboOffset=%u "
             "RecoveryDtboActual=%u\n",
             Hdr1->recovery_dtbo_offset, RecoveryDtboActual));
      return EFI_BAD_BUFFER_SIZE;
    }

    tempImgSize = *ImageSizeActual;
    *ImageSizeActual = ADD_OF (*ImageSizeActual, RecoveryDtboActual);
    if (!*ImageSizeActual) {
      DEBUG ((EFI_D_ERROR, "Integer Overflow: ImgSizeActual=%u,"
              " RecoveryDtboActual=%u\n", tempImgSize, RecoveryDtboActual));
      return EFI_BAD_BUFFER_SIZE;
    }
  }
  DEBUG ((EFI_D_VERBOSE, "Boot Image Header Info...\n"));
  DEBUG ((EFI_D_VERBOSE, "Image Header version     : 0x%x\n", HeaderVersion));
  DEBUG ((EFI_D_VERBOSE, "Kernel Size 1            : 0x%x\n", KernelSize));
  DEBUG ((EFI_D_VERBOSE, "Kernel Size 2            : 0x%x\n", SecondSize));
  DEBUG ((EFI_D_VERBOSE, "Ramdisk Size             : 0x%x\n", RamdiskSize));
  DEBUG ((EFI_D_VERBOSE, "DTB Size                 : 0x%x\n", DtSize));

  if (HeaderVersion >= BOOT_HEADER_VERSION_THREE) {
    DEBUG ((EFI_D_VERBOSE, "Vendor Ramdisk Size      : 0x%x\n",
            VendorRamdiskSize));
    if (BootIntoRecovery &&
        (RecoveryImgHdrV3 ||
         RecoveryImgHdrV4)) {
      DEBUG ((EFI_D_VERBOSE, "Recovery Ramdisk Size    : 0x%x\n",
              RecoveryRamdiskSize));
    }
  }

  return Status;
}

/**
  Load image header from partition
  @param[in]  Pname           Partition name.
  @param[out] ImageHdrBuffer  Supplies the address where a pointer to the image
buffer.
  @param[out] ImageHdrSize    The Pointer for image actual size.
  @retval     EFI_SUCCESS     Load image from partition successfully.
  @retval     other           Failed to Load image from partition.
**/
EFI_STATUS
LoadImageHeader (CHAR16 *Pname, VOID **ImageHdrBuffer, UINT32 *ImageHdrSize)
{
  if (ImageHdrBuffer == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  if (!ADD_OF (BOOT_IMG_MAX_PAGE_SIZE, ALIGNMENT_MASK_4KB - 1)) {
    DEBUG ((EFI_D_ERROR, "Integer Overflow: in ALIGNMENT_MASK_4KB addition\n"));
    return EFI_BAD_BUFFER_SIZE;
  }

  *ImageHdrBuffer =
      AllocatePages (ALIGN_PAGES (BOOT_IMG_MAX_PAGE_SIZE, ALIGNMENT_MASK_4KB));
  if (!*ImageHdrBuffer) {
    DEBUG ((EFI_D_ERROR, "Failed to allocate for Boot image Hdr\n"));
    return EFI_BAD_BUFFER_SIZE;
  }

  *ImageHdrSize = BOOT_IMG_MAX_PAGE_SIZE;
  return LoadImageFromPartition (*ImageHdrBuffer, ImageHdrSize, Pname);
}

/**
  Load image from partition
  @param[in]  Pname           Partition name.
  @param[in] ImageBuffer      Supplies the address where a pointer to the image
buffer.
  @param[in] ImageSizeActual  Actual size of the Image.
  @param[in] PageSize         The page size
  @retval     EFI_SUCCESS     Load image from partition successfully.
  @retval     other           Failed to Load image from partition.
**/
EFI_STATUS
LoadImage (CHAR16 *Pname, VOID **ImageBuffer,
           UINT32 ImageSizeActual, UINT32 PageSize)
{
  EFI_STATUS Status = EFI_SUCCESS;
  UINT32 ImageSize = 0;

  // Check for invalid ImageBuffer
  if (ImageBuffer == NULL) {
    return EFI_INVALID_PARAMETER;
  } else {
    *ImageBuffer = NULL;
  }

  ImageSize =
      ADD_OF (ROUND_TO_PAGE (ImageSizeActual, (PageSize - 1)), PageSize);
  if (!ImageSize) {
    DEBUG ((EFI_D_ERROR, "Integer Overflow: ImgSize=%u\n", ImageSizeActual));
    return EFI_BAD_BUFFER_SIZE;
  }

  if (!ADD_OF (ImageSize, ALIGNMENT_MASK_4KB - 1)) {
    DEBUG ((EFI_D_ERROR, "Integer Overflow: in ALIGNMENT_MASK_4KB addition\n"));
    return EFI_BAD_BUFFER_SIZE;
  }

  /* In case of fastboot continue command, data buffer are already allocated
   * and checked by fastboot, so just use this buffer for image buffer.
   */
  *ImageBuffer = FastbootDloadBuffer ();
  if (!*ImageBuffer) {
    *ImageBuffer = AllocatePages (ALIGN_PAGES (ImageSize, ALIGNMENT_MASK_4KB));
    if (!*ImageBuffer) {
      DEBUG ((EFI_D_ERROR, "No resources available for ImageBuffer\n"));
      return EFI_OUT_OF_RESOURCES;
    }
  }

  BootStatsSetTimeStamp (BS_KERNEL_LOAD_BOOT_START);
  Status = LoadImageFromPartition (*ImageBuffer, &ImageSize, Pname);
  BootStatsSetTimeStamp (BS_KERNEL_LOAD_BOOT_END);

  if (Status != EFI_SUCCESS) {
    DEBUG ((EFI_D_ERROR, "Failed Kernel Size   : 0x%x\n", ImageSize));
    return Status;
  }

  return Status;
}

EFI_STATUS
GetImage (CONST BootInfo *Info,
          VOID **ImageBuffer,
          UINTN *ImageSize,
          CHAR8 *ImageName)
{
  if (Info == NULL || ImageBuffer == NULL || ImageSize == NULL ||
      ImageName == NULL) {
    DEBUG ((EFI_D_ERROR, "GetImage: invalid parameters\n"));
    return EFI_INVALID_PARAMETER;
  }

  for (UINTN LoadedIndex = 0; LoadedIndex < Info->NumLoadedImages;
       LoadedIndex++) {
    if (!AsciiStrnCmp (Info->Images[LoadedIndex].Name, ImageName,
                       AsciiStrLen (ImageName))) {
      *ImageBuffer = Info->Images[LoadedIndex].ImageBuffer;
      *ImageSize = Info->Images[LoadedIndex].ImageSize;
      return EFI_SUCCESS;
    }
  }
  return EFI_NOT_FOUND;
}

/* Return Build variant */
#ifdef USER_BUILD_VARIANT
BOOLEAN TargetBuildVariantUser (VOID)
{
  return TRUE;
}
#else
BOOLEAN TargetBuildVariantUser (VOID)
{
  return FALSE;
}
#endif

#ifdef ENABLE_LE_VARIANT
BOOLEAN IsLEVariant (VOID)
{
  return TRUE;
}
#else
BOOLEAN IsLEVariant (VOID)
{
  return FALSE;
}
#endif

BOOLEAN IsBuildAsSystemRootImage (BootParamlist *BootParamlistPtr)
{
   return BootParamlistPtr->RamdiskSize == 0;
}

#ifdef ENABLE_EARLY_SERVICES
BOOLEAN EarlyServicesEnabled (VOID)
{
  return TRUE;
}
#else
BOOLEAN EarlyServicesEnabled (VOID)
{
  return FALSE;
}
#endif

#ifdef BUILD_USES_RECOVERY_AS_BOOT
BOOLEAN IsBuildUseRecoveryAsBoot (VOID)
{
  return TRUE;
}
#else
BOOLEAN IsBuildUseRecoveryAsBoot (VOID)
{
  return FALSE;
}
#endif

VOID SetRecoveryHasNoKernel (VOID)
{
  RecoveryHasNoKernel = TRUE;
}

BOOLEAN IsRecoveryHasNoKernel (VOID)
{
  return RecoveryHasNoKernel;
}

VOID
ResetBootDevImage (VOID)
{
  BootDevImage = FALSE;
}

VOID
SetBootDevImage (VOID)
{
  BootDevImage = TRUE;
}

BOOLEAN IsBootDevImage (VOID)
{
  return BootDevImage;
}

#ifdef AB_RETRYCOUNT_DISABLE
BOOLEAN IsABRetryCountDisabled (VOID)
{
  return TRUE;
}
#else
BOOLEAN IsABRetryCountDisabled (VOID)
{
  return FALSE;
}
#endif

BOOLEAN IsSuperPartitionExist (VOID)
{
  UINT32 PtnCount;
  INT32 PtnIdx;

  GetPartitionCount (&PtnCount);

  PtnIdx = GetPartitionIndex ((CHAR16 *)L"super");

  if (PtnIdx < PtnCount &&
      PtnIdx != INVALID_PTN) {
    return TRUE;
  } else {
    return FALSE;
  }
}
BOOLEAN IsDynamicPartitionSupport (VOID)
{
#if SUPPORT_AB_BOOT_LXC
  return FALSE;
#else
  return IsSuperPartitionExist ();
#endif
}

#if NAND_SQUASHFS_SUPPORT
BOOLEAN IsNANDSquashFsSupport (VOID)
{
  return TRUE;
}
#else
BOOLEAN IsNANDSquashFsSupport (VOID)
{
  return FALSE;
}
#endif

#if TARGET_BOARD_TYPE_AUTO
BOOLEAN IsEnableDisplayMenuFlagSupported (VOID)
{
  return FALSE;
}

BOOLEAN IsTargetAuto (VOID)
{
  return TRUE;
}
#else
BOOLEAN IsEnableDisplayMenuFlagSupported (VOID)
{
  return TRUE;
}

BOOLEAN IsTargetAuto (VOID)
{
  return FALSE;
}
#endif

#if HIBERNATION_SUPPORT_NO_AES
BOOLEAN IsHibernationEnabled (VOID)
{
  UINT32 PtnCount;
  INT32 PtnIdx;

  GetPartitionCount (&PtnCount);

  PtnIdx = GetPartitionIndex ((CHAR16 *)SWAP_PARTITION_NAME);

  if (PtnIdx < PtnCount &&
      PtnIdx != INVALID_PTN) {
    return TRUE;
  } else {
    return FALSE;
  }
}
#else
BOOLEAN IsHibernationEnabled (VOID)
{
  return FALSE;
}
#endif

#ifdef DDR_SUPPORTS_SCT_CONFIG
BOOLEAN IsDDRSupportsSCTConfig (VOID)
{
  return TRUE;
}
#else
BOOLEAN IsDDRSupportsSCTConfig (VOID)
{
  return FALSE;
}
#endif
