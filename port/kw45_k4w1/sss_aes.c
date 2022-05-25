/*! *********************************************************************************
* Copyright 2022 NXP
* All rights reserved.
*
* \file
*
* SPDX-License-Identifier: BSD-3-Clause
********************************************************************************** */

#include "sss_crypto.h"


/*
LTK ciphering stuff
sss_sscp_key_store_open_key_id(&g_keyStore, ELKE_PKB__NBU_DKEY_SK)
sss_sscp_key_object_init(&keyObj__bleLTK, &g_keyStore)
sss_sscp_key_object_allocate_handle(&keyObj__bleLTK,
                                        NBU_BLE_LTK,
                                        kSSS_KeyPart_Default,
                                        kSSS_CipherType_AES,
                                        16u,
                                        SSS_KEY_STORE_GET_PLAIN_KEY_ALLOW_MASK_NONE)
*/

status_t SSS_set_aes_key(aes_context_t *ctx, const unsigned char * key, const size_t key_byte_len)
{
    status_t ret = kStatus_SSS_Fail;
    uint8_t ramKey[32];
    do {
        if (key_byte_len != 16u && key_byte_len != 24u && key_byte_len != 32u)
            RAISE_ERROR(ret, kStatus_SSS_InvalidArgument);
        memcpy(ramKey, key, key_byte_len);

        if ((ret = sss_sscp_key_object_init(&ctx->sssKey, &g_keyStore)) != kStatus_SSS_Success)
        {
            break;
        }

        if ((ret = SSS_KEY_ALLOCATE_HANDLE(&ctx->sssKey,
                                           1u, /* key id */
                                           kSSS_KeyPart_Default,
                                           kSSS_CipherType_AES,
                                           key_byte_len,
                                           0u)) != kStatus_SSS_Success)
        {
            break;
        }
        if ((ret = sss_sscp_key_store_set_key(&g_keyStore,
                                              &ctx->sssKey,
                                              ramKey,
                                              key_byte_len,
                                              key_byte_len<<3,
                                              kSSS_KeyPart_Default)) != kStatus_SSS_Success)
        {
            break;
        }
    } while (0);
    return ret;
}


status_t SSS_aes_init
(
    aes_context_t *ctx,
    const unsigned char *key,
    size_t keybits
)
{
    status_t ret = kStatus_SSS_Fail;
    do {
        if ((CRYPTO_InitHardware()) != kStatus_Success)
            break;
        ret = SSS_set_aes_key(ctx, key, keybits>>3);

    } while (0);
    return ret;
}


status_t SSS_aes_operation
(
    aes_context_t *ctx,
    const unsigned char*  input,
    size_t  inputLen,
    unsigned char * iv,
    const unsigned char * key,
    size_t key_bitlen,
    unsigned char*  output,
    bool encrypt_nDecrypt,
    sss_algorithm_t algo
)
{
    status_t ret;
    size_t iv_len;
    do {
        sss_mode_t mode;
        ret = SSS_aes_init(ctx, key, key_bitlen);
        if (ret != kStatus_SSS_Success)
            break;
        mode = encrypt_nDecrypt ? kMode_SSS_Encrypt : kMode_SSS_Decrypt;
        if ((ret = sss_sscp_symmetric_context_init(&ctx->cipher_ctx,
                                            &g_sssSession,
                                            &ctx->sssKey,
                                            algo, mode)) != kStatus_SSS_Success)
            break;
        iv_len = (iv == NULL) ? 0 : 16;
        if ((ret = sss_sscp_cipher_one_go(&ctx->cipher_ctx,
                                     iv, iv_len,
                                     input,
                                     output,
                                     inputLen)) != kStatus_SSS_Success)
            break;

    } while (0);

    return ret;
}

status_t SSS_aes128_CTR_operation
(
    aes_context_t *ctx,
    const unsigned char*  input,
    size_t  inputLen,
    unsigned char * initialCounter,
    const unsigned char * key,
    unsigned char*  output,
    bool encrypt_nDecrypt,
    unsigned char * stream_block,
    size_t        * offset_sz_left
)
{
    status_t ret;
    do {
        sss_mode_t mode;
        if ((ret = SSS_aes_init(ctx, key, 128u)) != kStatus_SSS_Success)
            break;
        mode = encrypt_nDecrypt ? kMode_SSS_Encrypt : kMode_SSS_Decrypt;
        if ((ret =sss_sscp_symmetric_context_init(&ctx->cipher_ctx,
                                            &g_sssSession,
                                            &ctx->sssKey,
                                            kAlgorithm_SSS_AES_CTR, mode)) != kStatus_SSS_Success)
            break;
        if ((ret = sss_sscp_cipher_crypt_ctr(&ctx->cipher_ctx, input, output, inputLen,
                                 initialCounter, stream_block,
                                 offset_sz_left)) != kStatus_SSS_Success)
            break;
    } while (0);

    return ret;
}



