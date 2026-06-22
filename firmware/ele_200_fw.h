/**
 * Copyright 2026 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/*******************************************************************************
 * EdgeLock Enclave Firmware - this file selects the correct FW for runtime apps
 ******************************************************************************/
#ifndef __ELE_FW_H__
#define __ELE_FW_H__

#if defined(ELEMU_HAS_LOADABLE_FW) && ELEMU_HAS_LOADABLE_FW

extern const uint8_t fw[];

/* We select the correct firmware based on build configuration */
#if defined(CONFIG_FIRMWARE_S200_EL2GO_KW45) && CONFIG_FIRMWARE_S200_EL2GO_KW45
#include "KW45_K32W1xx_MCXW71_SDKFW3.0_RFP1.h"
#elif defined(CONFIG_FIRMWARE_S200_EL2GO_KW47) && CONFIG_FIRMWARE_S200_EL2GO_KW47
#include "KW47_A2_1_SDKFW4_0.h"
#else
#error "Compile-time S200 firmware enabled, but no valid configuration selected"
#endif

#endif /* ELEMU_HAS_LOADABLE_FW */

#endif /* __ELE_FW_H__ */
