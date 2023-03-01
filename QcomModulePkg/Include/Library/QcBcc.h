/*
 * Copyright (c) 2023 Qualcomm Innovation Center, Inc. All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#ifndef __BCC_H__
#define __BCC_H__

#define BCC_ARTIFACTS_MAX_SIZE 4096

UINT8 GetBccArtifacts (UINT8 *FinalEncodedBccArtifacts,
                         size_t BccArtifactsBufferSize,
                         size_t *BccArtifactsValidSize);
#endif
