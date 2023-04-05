/*
 * Copyright (c) 2013 - 2015, Freescale Semiconductor, Inc.
 * Copyright 2016-2018 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "fsl_device_registers.h"
#include "fsl_debug_console.h"
#include "board.h"
#include "app.h"
#include "fsl_sss_api.h"

/*******************************************************************************
 * Definitions
 ******************************************************************************/
#define SSS_KEY_ID_SESSION_KEY0  0x0
#define SSS_KEY_OPTION_TRANSIENT 0x1

/*******************************************************************************
 * Prototypes
 ******************************************************************************/

/*******************************************************************************
 * Code
 ******************************************************************************/

/* SSS APIs stubs */
sss_status_t sss_key_store_context_init(sss_key_store_t *keyStore, sss_session_t *session)
{
    return kStatus_SSS_InvalidArgument;
}

sss_status_t sss_key_store_allocate(sss_key_store_t *keyStore, uint32_t keyStoreId)
{
    return kStatus_SSS_InvalidArgument;
}

sss_status_t sss_key_store_set_key(sss_key_store_t *keyStore,
                                   sss_object_t *keyObject,
                                   const uint8_t *key,
                                   uint32_t keyBitLen,
                                   void *options,
                                   size_t optionsLen)
{
    return kStatus_SSS_InvalidArgument;
}

sss_status_t sss_key_object_init(sss_object_t *keyObject, sss_key_store_t *keyStore)
{
    return kStatus_SSS_InvalidArgument;
}

sss_status_t sss_key_object_allocate_handle(
    sss_object_t *keyObject, uint32_t keyId, sss_key_type_t keyType, uint32_t keyByteLenMax, uint32_t options)
{
    return kStatus_SSS_InvalidArgument;
}

sss_status_t sss_open_session(sss_session_t *session,
                              sss_type_t subsystem,
                              uint32_t additionalApplicationId,
                              uint32_t connectionMethod,
                              const void *connectionData)
{
    return kStatus_SSS_InvalidArgument;
}

sss_status_t sss_symmetric_context_init(sss_symmetric_t *context,
                                        sss_session_t *session,
                                        sss_object_t *keyObject,
                                        sss_algorithm_t algorithm,
                                        sss_mode_t mode)
{
    return kStatus_SSS_InvalidArgument;
}

sss_status_t sss_cipher_one_go(
    sss_symmetric_t *context, uint8_t *iv, size_t ivLen, const uint8_t *srcData, uint8_t *destData, size_t dataLen)
{
    return kStatus_SSS_InvalidArgument;
}

void sss_symmetric_context_free(sss_symmetric_t *context)
{
    memset(context, 0, sizeof(sss_symmetric_t));
}

void sss_key_object_free(sss_object_t *keyObject)
{
    memset(keyObject, 0, sizeof(sss_object_t));
}

void sss_key_store_context_free(sss_key_store_t *keyStore)
{
    memset(keyStore, 0, sizeof(keyStore));
}

void sss_close_session(sss_session_t *session)
{
    memset(session, 0, sizeof(sss_session_t));
}

sss_status_t test_digest(void)
{
    sss_status_t status = kStatus_SSS_Fail;

    uint8_t myKey[16] = {0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a,
                         0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a};
    uint8_t myIv[16] = {0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a};
    uint8_t myPlaintext[64]  = {0x0};
    uint8_t myCiphertext[64] = {0x0};

    sss_key_store_t myKeyStore;
    sss_object_t myKeyObject;
    sss_session_t mySession;
    sss_symmetric_t mySymmetricCtx;

    /* open session to specific security subsystem */
    status = sss_open_session(&mySession, kType_SSS_Software, 0, 0, NULL);
    if (status != kStatus_SSS_Success)
    {
        return status;
    }

    /* key store init */
    status = sss_key_store_context_init(&myKeyStore, &mySession);
    if (status != kStatus_SSS_Success)
    {
        return status;
    }

    status = sss_key_store_allocate(&myKeyStore, 0);
    if (status != kStatus_SSS_Success)
    {
        return status;
    }

    /* key object init */
    status = sss_key_object_init(&myKeyObject, &myKeyStore);
    if (status != kStatus_SSS_Success)
    {
        return status;
    }

    /* reserve a space for max 32 byte symmetric key and it's properties */
    status = sss_key_object_allocate_handle(&myKeyObject, SSS_KEY_ID_SESSION_KEY0, kSSS_KeyType_AES, 32,
                                            SSS_KEY_OPTION_TRANSIENT);
    if (status != kStatus_SSS_Success)
    {
        return status;
    }

    /* load the key to key store */
    status = sss_key_store_set_key(&myKeyStore, &myKeyObject, myKey, 128, NULL, 0);
    if (status != kStatus_SSS_Success)
    {
        return status;
    }

    /* the key can be discarded in app level now */
    memset(myKey, 0, sizeof(myKey));

    /* init symmetric crypto context */
    status = sss_symmetric_context_init(&mySymmetricCtx, &mySession, &myKeyObject, kAlgorithm_SSS_AES_CBC,
                                        kMode_SSS_Encrypt);
    if (status != kStatus_SSS_Success)
    {
        return status;
    }

    /* encrypt */
    status = sss_cipher_one_go(&mySymmetricCtx, myIv, sizeof(myIv), myPlaintext, myCiphertext, sizeof(myPlaintext));
    if (status != kStatus_SSS_Success)
    {
        return status;
    }

    /* clean up */
    sss_close_session(&mySession);
    sss_symmetric_context_free(&mySymmetricCtx);
    sss_key_object_free(&myKeyObject);
    sss_key_store_context_free(&myKeyStore);

    return kStatus_SSS_Success;
}

/*!
 * @brief Main function
 */
int main(void)
{
    char ch;

    /* Init board hardware. */
    BOARD_InitHardware();

    PRINTF("hello world.\r\n");

    test_digest();

    while (1)
    {
        ch = GETCHAR();
        PUTCHAR(ch);
    }
}
