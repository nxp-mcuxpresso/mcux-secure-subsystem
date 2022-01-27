#if (defined(KW45_A0_SUPPORT) && KW45_A0_SUPPORT)
/*
 * Copyright 2018-2021 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef _FSL_SSS_SSCP_CONFIG_H_
#define _FSL_SSS_SSCP_CONFIG_H_

#define SSS_SSCP_KEY_STORE_CONTEXT_SIZE  8
#define SSS_SSCP_KEY_OBJECT_CONTEXT_SIZE 8
#define SSS_SSCP_SYMMETRIC_CONTEXT_SIZE  8
#define SSS_SSCP_DIGEST_CONTEXT_SIZE     8
#define SSS_SSCP_MAC_CONTEXT_SIZE        8
#define SSS_SSCP_AEAD_CONTEXT_SIZE       8

#endif /* _FSL_SSS_SSCP_CONFIG_H_ */
#else
/*
 * Copyright 2018-2021 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef FSL_SSS_SSCP_CONFIG_H
#define FSL_SSS_SSCP_CONFIG_H

#define SSS_SSCP_KEY_STORE_CONTEXT_SIZE  8
#define SSS_SSCP_KEY_OBJECT_CONTEXT_SIZE 8
#define SSS_SSCP_SYMMETRIC_CONTEXT_SIZE  8
#define SSS_SSCP_DIGEST_CONTEXT_SIZE     8
#define SSS_SSCP_MAC_CONTEXT_SIZE        8
#define SSS_SSCP_AEAD_CONTEXT_SIZE       8

#endif /* FSL_SSS_SSCP_CONFIG_H */
#endif /* KW45_A0_SUPPORT */
