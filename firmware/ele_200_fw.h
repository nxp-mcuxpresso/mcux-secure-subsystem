/*
 * Copyright 2025 NXP
 *
 * NXP Proprietary. This software is owned or controlled by NXP and may only be
 * used strictly in accordance with the applicable license terms. By expressly
 * accepting such terms or by downloading, installing, activating and/or
 * otherwise using the software, you are agreeing that you have read, and that
 * you agree to comply with and are bound by, such license terms. If you do not
 * agree to be bound by the applicable license terms, then you may not retain,
 * install, activate or otherwise use the software.
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
#include "KW47_A2_1_SDKFW3_0.h"
#else
#error "Compile-time S200 firmware enabled, but no valid configuration selected"
#endif

#endif /* ELEMU_HAS_LOADABLE_FW */

#endif /* __ELE_FW_H__ */
