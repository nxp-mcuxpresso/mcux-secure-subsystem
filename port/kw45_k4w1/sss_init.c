/*! *********************************************************************************
 * Copyright 2022 NXP
 * All rights reserved.
 *
 * \file
 *
 * SPDX-License-Identifier: BSD-3-Clause
 ********************************************************************************** */

#include "sss_crypto.h"

sss_sscp_key_store_t g_keyStore;
sss_sscp_session_t g_sssSession;
sscp_context_t g_sscpContext;

static uint32_t g_isCryptoHWInitialized = SSS_CRYPTOHW_NONINITIALIZED;

/******************************************************************************/
/******************** CRYPTO_InitHardware **************************************/
/******************************************************************************/
/*!
 * @brief Application init for various Crypto blocks.
 *
 * This function is provided to be called by MCUXpresso SDK applications.
 * It calls basic init for Crypto Hw acceleration and Hw entropy modules.
 */
status_t CRYPTO_InitHardware(void)
{
    status_t ret;
    do {
        if (g_isCryptoHWInitialized == SSS_CRYPTOHW_INITIALIZED)
        {
           ret = kStatus_Success;
           break;
        }
        ret = kStatus_Fail;

        sss_sscp_rng_t rctx;
        if (SNT_mu_wait_for_ready(ELEMUA, SSS_MAX_SUBSYTEM_WAIT) != kStatus_Success)
        {
            break;
        }
#if (defined(SNT_HAS_LOADABLE_FW) && SNT_HAS_LOADABLE_FW)
        if (SNT_loadFwLocal(ELEMUA) != kStatus_SNT_Success)
        {
            break;
        }
#endif /* SNT_HAS_LOADABLE_FW */
        if (sscp_mu_init(&g_sscpContext, (MU_Type *)(uintptr_t)ELEMUA) != kStatus_SSCP_Success)
        {
            break;
        }
#if (defined(KW45_A0_SUPPORT) && KW45_A0_SUPPORT)
        if (sss_sscp_open_session(&g_sssSession,
                                  SSS_SUBSYSTEM,
                                  &g_sscpContext,
                                  0u,
                                  NULL) != kStatus_SSS_Success)
        {
            break;
        }
        if (sss_sscp_key_store_context_init(&g_keyStore, &g_sssSession) != kStatus_SSS_Success)
        {
            break;
        }
        if (sss_sscp_key_store_allocate(&g_keyStore, 0u) != kStatus_SSS_Success)
        {
            break;
        }
#else
        if (sss_sscp_open_session(&g_sssSession,
                                  0u,
                                  SSS_SUBSYSTEM,
                                  &g_sscpContext) != kStatus_SSS_Success)
        {
            break;
        }
        if (sss_sscp_key_store_init(&g_keyStore, &g_sssSession) != kStatus_SSS_Success)
        {
            break;
        }
#endif

        /* RNG call used to init Sentinel TRNG required e.g. by sss_sscp_key_store_generate_key service
        if TRNG initialization is no needed for used operations, the following code can be removed
        to increase the perfomance.*/
        if (sss_sscp_rng_context_init(&g_sssSession, &rctx, SSS_HIGH_QUALITY_RNG) != kStatus_SSS_Success)
        {
            break;
        }
        /*Providing NULL output buffer, as we just need to initialize TRNG, not get random data*/
        if (sss_sscp_rng_get_random(&rctx, NULL, 0x0u) != kStatus_SSS_Success)
        {
            break;
        }
        if (sss_sscp_rng_free(&rctx) != kStatus_SSS_Success)
        {
            break;
        }
        g_isCryptoHWInitialized = SSS_CRYPTOHW_INITIALIZED;
        ret  = kStatus_Success;

    } while (0);
    return ret;
}

/*!
 * @brief Application reinit for various Crypto blocks.
 *
 * This function is provided to be called after wake up from low power Power Down
 * or Deep Power Down modes to reinit Crypto HW blocks.
 */
status_t CRYPTO_ReinitHardware(void)
{
    status_t ret;

    g_isCryptoHWInitialized = SSS_CRYPTOHW_NONINITIALIZED;
    ret = CRYPTO_InitHardware();

    return ret;
}

/*!
 * @brief This function will allow reinitizialize the cryptographic HW acceleration 
 * next time we need it, typically after lowpower mode.
 */
void CRYPTO_DeinitHardware(void)
{
    g_isCryptoHWInitialized = SSS_CRYPTOHW_NONINITIALIZED;
}