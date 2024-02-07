/*
 * Copyright 2024 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "fsl_device_registers.h"
#include "fsl_debug_console.h"
#include "board.h"
#include "app.h"

#include "fsl_sss_mgmt.h"
#include "fsl_sss_sscp.h"
#include "fsl_sscp_mu.h"

/*******************************************************************************
 * Definitions
 ******************************************************************************/
#define ELE_MAX_SUBSYSTEM_WAIT (0xFFFFFFFFu)
#define ELE_SUBSYSTEM          (kType_SSS_Ele200)
#define KEY_ID                 (0u)
/*******************************************************************************
 * Prototypes
 ******************************************************************************/

/*******************************************************************************
 * Code
 ******************************************************************************/

sss_status_t test_symmetric(void)
{
    /*
     * This code example demonstrates EdgeLock usage for AES CBC operation via SSSAPI. The AES CBC operation is
     * performed in following steps:
     * 1. Open EdgeLock session
     * 2. Create key store
     * 3. Create and allocate key object
     * 4. Set the key
     * 5. Initialize AES CBC operation context
     * 6. Perform AES CBC operation
     * 7. Close all opened contexts and created objects
     * Note: This example does not close already opened contexts or objects in case of failed command.
     */

    /* KEY = 1f8e4973953f3fb0bd6b16662e9a3c17 */
    uint8_t symKeyData[16] = {0x1f, 0x8e, 0x49, 0x73, 0x95, 0x3f, 0x3f, 0xb0,
                              0xbd, 0x6b, 0x16, 0x66, 0x2e, 0x9a, 0x3c, 0x17};
    /* IV = 2fe2b333ceda8f98f4a99b40d2cd34a8 */
    uint8_t ivData[16] = {0x2f, 0xe2, 0xb3, 0x33, 0xce, 0xda, 0x8f, 0x98,
                          0xf4, 0xa9, 0x9b, 0x40, 0xd2, 0xcd, 0x34, 0xa8};
    /* PLAINTEXT = 45cf12964fc824ab76616ae2f4bf0822 */
    uint8_t plainData[16] = {0x45, 0xcf, 0x12, 0x96, 0x4f, 0xc8, 0x24, 0xab,
                             0x76, 0x61, 0x6a, 0xe2, 0xf4, 0xbf, 0x08, 0x22};
    /* CIPHERTEXT = 0f61c4d44c5147c03c195ad7e2cc12b2 */
    uint8_t cipherDataRef[16] = {0x0f, 0x61, 0xc4, 0xd4, 0x4c, 0x51, 0x47, 0xc0,
                                 0x3c, 0x19, 0x5a, 0xd7, 0xe2, 0xcc, 0x12, 0xb2};

    uint8_t cipherData[16] = {0};

    status_t status = kStatus_Fail;

    sscp_context_t sscpContext    = {0};
    sss_sscp_session_t sssSession = {0};
    sss_sscp_key_store_t keyStore = {0};
    sss_sscp_object_t sssKey      = {0};
    sss_sscp_symmetric_t ctx      = {0};

    do
    {
        status = ELEMU_mu_wait_for_ready(ELEMUA, ELE_MAX_SUBSYSTEM_WAIT);
        if (status != kStatus_Success)
        {
            break;
        }

        /****************** Start   ***********************/
        status = sscp_mu_init(&sscpContext, (ELEMU_Type *)(uintptr_t)ELEMUA);
        if (status != kStatus_SSCP_Success)
        {
            break;
        }
        /* open session to specific security subsystem */
        status = sss_sscp_open_session(&sssSession, 0u, ELE_SUBSYSTEM, &sscpContext);
        if (status != kStatus_SSS_Success)
        {
            return status;
        }

        /* init keystore  */
        status = sss_sscp_key_store_init(&keyStore, &sssSession);
        if (status != kStatus_SSS_Success)
        {
            break;
        }

        /* init keystore  */
        status = sss_sscp_key_object_init(&sssKey, &keyStore);
        if (status != kStatus_SSS_Success)
        {
            break;
        }
        /* Allocate keystore handle */
        status = sss_sscp_key_object_allocate_handle(&sssKey, KEY_ID, /* key id */
                                                     kSSS_KeyPart_Default, kSSS_CipherType_AES, 16u,
                                                     kSSS_KeyProp_CryptoAlgo_AES);
        if (status != kStatus_SSS_Success)
        {
            (void)sss_sscp_key_object_free(&sssKey, kSSS_keyObjFree_KeysStoreDefragment);
            break;
        }

        /* Set key into*/
        status = sss_sscp_key_store_set_key(&keyStore, &sssKey, symKeyData, sizeof(symKeyData),
                                            (sizeof(symKeyData) * 8U), kSSS_KeyPart_Default);
        if (status != kStatus_SSS_Success)
        {
            (void)sss_sscp_key_object_free(&sssKey, kSSS_keyObjFree_KeysStoreDefragment);
            break;
        }

        /* init digest context */
        status = sss_sscp_symmetric_context_init(&ctx, &sssSession, &sssKey, kAlgorithm_SSS_AES_CBC, kMode_SSS_Encrypt);
        if (status != kStatus_SSS_Success)
        {
            (void)sss_sscp_key_object_free(&sssKey, kSSS_keyObjFree_KeysStoreDefragment);
            break;
        }

        /* RUN AES */
        status = sss_sscp_cipher_one_go(&ctx, ivData, sizeof(ivData), plainData, cipherData, sizeof(plainData));
        if (status != kStatus_SSS_Success)
        {
            (void)sss_sscp_symmetric_context_free(&ctx);
            (void)sss_sscp_key_object_free(&sssKey, kSSS_keyObjFree_KeysStoreDefragment);
            break;
        }

        /* Cleanup Close all context, objects and sessions which were opened before */
        /* Close AES context*/
        status = sss_sscp_symmetric_context_free(&ctx);

        /* Free Key object */
        status = sss_sscp_key_object_free(&sssKey, kSSS_keyObjFree_KeysStoreDefragment);
        /* Free Keystore*/
        status = sss_sscp_key_store_free(&keyStore);
        /* Close session */
        status = sss_sscp_close_session(&sssSession);
    } while (0);

    if (status == kStatus_SSS_Success)
    {
        if (memcmp((void *)cipherDataRef, (void *)cipherData, sizeof(cipherDataRef)))
        {
            PRINTF(
                "ERROR: expected result of AES CBC encrypted data is different from value returned by Security "
                "Sub-System!\r\n");
        }
        else
        {
            PRINTF(
                "SUCCESS: expected result of AES CBC encrypted data is equal to value returned by Security "
                "Sub-System!!\r\n");
        }
    }
    else
    {
        PRINTF("ERROR: execution of commands on Security Sub-System failed!\r\n");
    }

    return kStatus_Success;
}

/*!
 * @brief Main function
 */
int main(void)
{
    char ch;

    /* Init board hardware. */
    BOARD_InitHardware();

    PRINTF("ELE Symmetric via SSSAPI Example\r\n");

    test_symmetric();

    PRINTF("Example end\r\n");

    while (1)
    {
        ch = GETCHAR();
        PUTCHAR(ch);
    }
}
