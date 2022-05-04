
#include "fsl_debug_console.h"
#include "sss_crypto.h"

#define BITLEN2BYTELEN(x) (((x) + 7u) >> 3)


#define AES_128_KEY_BITS         128u
#define AES_128_KEY_BYTE_LEN     BITLEN2BYTELEN(AES_128_KEY_BITS)
#define AES_192_KEY_BITS         192u
#define AES_192_KEY_BYTE_LEN     BITLEN2BYTELEN(AES_192_KEY_BITS)
#define AES_256_KEY_BITS         256u
#define AES_256_KEY_BYTE_LEN     BITLEN2BYTELEN(AES_256_KEY_BITS)

#if 0
#if (defined(KW45_A0_SUPPORT) && KW45_A0_SUPPORT)
#define SSS_KEY_OBJ_FREE(_KEY_OBJ_)  \
              sss_sscp_key_object_free(_KEY_OBJ_)

#define SSS_AES_CMAC_KEY_OBJ_ALLOCATE_HDL(_KEY_OBJ_, _KEY_BYTE_LEN_)        \
              sss_sscp_key_object_allocate_handle(_KEY_OBJ_,                \
                                                   1u,                      \
                                                   kSSS_KeyPart_Default,    \
                                                   kSSS_CipherType_AES,     \
                                                   _KEY_BYTE_LEN_,          \
                                                   0u)
#define SSS_AES_CMAC_KEY_STORE_SET_KEY(_KEY_OBJ_, _KEY_, _KEY_BYTE_LEN_) \
              sss_sscp_key_store_set_key(&g_keyStore,                       \
                                          _KEY_OBJ_,                        \
                                          _KEY_,                            \
                                          _KEY_BYTE_LEN_,                   \
                                          _KEY_BYTE_LEN_*8u,                \
                                          NULL)
#else
#define SSS_KEY_OBJ_FREE(_KEY_OBJ_)                                         \
              sss_sscp_key_object_free(_KEY_OBJ_,                           \
                SSS_SSCP_KEY_OBJECT_FREE_DYNAMIC)

#define SSS_AES_CMAC_KEY_OBJ_ALLOCATE_HDL(_KEY_OBJ_, _KEY_BYTE_LEN_)        \
              sss_sscp_key_object_allocate_handle(_KEY_OBJ_,                \
                                                   1u,                      \
                                                   kSSS_KeyPart_Default,    \
                                                   kSSS_CipherType_AES,     \
                                                   _KEY_BYTE_LEN_,          \
                                                   SSS_KEYPROP_OPERATION_MAC)
#define SSS_AES_CMAC_KEY_STORE_SET_KEY(_KEY_OBJ_, _KEY_, _KEY_BYTE_LEN_)    \
              sss_sscp_key_store_set_key(&g_keyStore,                       \
                                          _KEY_OBJ_,                        \
                                          _KEY_,                            \
                                          _KEY_BYTE_LEN_,                   \
                                          _KEY_BYTE_LEN_*8u,                \
                                          kSSS_KeyPart_Default)
#endif
#endif

/******************************************************************************
*******************************************************************************
* Public functions
*******************************************************************************
******************************************************************************/
status_t SSS_aes_cmac_starts(cmac_aes_context_t *ctx, const unsigned char *key, size_t key_bytelen)
{
    status_t ret;
    do {
        if ((ret = CRYPTO_InitHardware()) != kStatus_Success)
        {
            break;
        }
        if ((ret = SSS_set_aes_key_cmac(ctx, key, key_bytelen)) != kStatus_SSS_Success)
        {
            break;
        }
            /* CMAC OPERATION INIT */
        ret = sss_sscp_mac_context_init(&ctx->sscp_mac,
                                      &g_sssSession,
                                      &ctx->sssKey, kAlgorithm_SSS_CMAC_AES, kMode_SSS_Mac);

    } while (0);
    return ret;
}

status_t SSS_aes_cmac_update(cmac_aes_context_t *ctx, const unsigned char *input, size_t ilen)
{
    status_t ret;
    do {
        if (ctx == NULL || input == NULL)
        {
            RAISE_ERROR(ret, kStatus_SSS_InvalidArgument);
        }

        ret = sss_sscp_mac_update(&ctx->sscp_mac, input, ilen);

    } while (0);

    return (ret);
}

status_t SSS_aes_cmac_finish(cmac_aes_context_t *ctx, unsigned char *output)
{
    status_t ret;
    size_t olen = 0;
    do {
        if (ctx == NULL || output == NULL)
        {
            RAISE_ERROR(ret,  kStatus_SSS_InvalidArgument);
        }
        ret = sss_sscp_mac_finish(&ctx->sscp_mac, output, &olen);

    } while (0);

    return (ret);
}





void SSS_aes_cmac_free(cmac_aes_context_t *ctx)
{
    if (ctx->sscp_mac_was_set)
    {
        sss_sscp_mac_context_free(&ctx->sscp_mac);
        ctx->sscp_mac_was_set = false;
    }

    SSS_KEY_OBJ_FREE(&ctx->sssKey);

}
status_t SSS_aes_cmac
(
    cmac_aes_context_t *pCtx,
    const unsigned char *key,
    size_t keylen,
    const unsigned char *input,
    size_t ilen,
    unsigned char *output
)
{
    size_t macSize = 16u;
    sss_algorithm_t sssType = kAlgorithm_SSS_CMAC_AES;
    size_t key_bytelen = (keylen + 7u) / 8u;

    status_t ret = kStatus_SSS_Fail;
    memset(pCtx, 0, sizeof(cmac_aes_context_t));
    uint8_t ramKey[32];
    (void)memcpy(ramKey, key, key_bytelen);

    //bool sscp_mac_was_set = false;
    //sss_sscp_object_t sssKey;
    //sss_sscp_mac_t sscp_mac;
    pCtx->sscp_mac_was_set = false;
    do {
        if (CRYPTO_InitHardware() != kStatus_Success)
        {
            break;
        }
        if ((ret = sss_sscp_key_object_init(&pCtx->sssKey, &g_keyStore)) != kStatus_SSS_Success)
        {
            break;
        }

        if ((ret = SSS_KEY_ALLOCATE_HANDLE(&pCtx->sssKey, 1u,
                                           kSSS_KeyPart_Default,
                                           kSSS_CipherType_AES,
                                           key_bytelen,
                                           SSS_KEYPROP_OPERATION_MAC)) != kStatus_SSS_Success)
        {
            break;
        }
        if ((ret = SSS_KEY_STORE_SET_KEY(&pCtx->sssKey, ramKey, key_bytelen, keylen, kSSS_KeyPart_Default)) != kStatus_SSS_Success)
        {
            break;
        }
        /* CMAC OPERATION INIT */
        if ((ret = sss_sscp_mac_context_init(&pCtx->sscp_mac,
                                             &g_sssSession,
                                             &pCtx->sssKey,
                                             sssType,
                                             kMode_SSS_Mac)) != kStatus_SSS_Success)
        {
            break;
        }
        pCtx->sscp_mac_was_set = true;
        /* RUN CMAC ONE GO */
        if ((ret = sss_sscp_mac_one_go(&pCtx->sscp_mac,
                                       (const uint8_t *)input,
                                       ilen,
                                       (uint8_t *)output,
                                       &macSize)) != kStatus_SSS_Success)
        {
            break;
        }

        /* Free MAC context only if its init has been successful */
        (void)sss_sscp_mac_context_free(&pCtx->sscp_mac);
    } while (0);
    /* CLEAN UP */
    /* KEYOBJECT FREE*/
    SSS_aes_cmac_free(pCtx);

    return (ret);
}




/*
 * Implementation of AES-CMAC-PRF-128 defined in RFC 4615
 */
status_t SSS_aes_cmac_prf_128
(
    cmac_aes_context_t *pCtx,
    const unsigned char *key,
    size_t key_len,
    const unsigned char *input,
    size_t in_len,
    unsigned char output[16]
)
{
    status_t ret;
    unsigned char zero_key[AES_128_KEY_BYTE_LEN];
    unsigned char int_key[AES_128_KEY_BYTE_LEN];

    do {
        if (key == NULL || input == NULL || output == NULL)
        {
            RAISE_ERROR(ret, kStatus_SSS_InvalidArgument);
        }
        if (key_len == AES_128_KEY_BYTE_LEN)
        {
            /* Use key as is */
            memcpy(int_key, key, AES_128_KEY_BYTE_LEN);
        }
        else
        {
            memset(zero_key, 0, AES_128_KEY_BYTE_LEN);

            ret = SSS_aes_cmac(pCtx, zero_key, AES_128_KEY_BITS, key, key_len, int_key);
            if (ret != kStatus_SSS_Success)
            {
                break;
            }
        }
        ret = SSS_aes_cmac(pCtx, int_key, AES_128_KEY_BITS, input, in_len, output);
    } while (0);

    memset(int_key, 0, sizeof(int_key));

    return (ret);
}

status_t SSS_set_aes_key_cmac(cmac_aes_context_t *ctx, const unsigned char * key, size_t key_bytelen)
{
    status_t ret;
    do {
        size_t keylen = key_bytelen*8u;

        if ((ret = sss_sscp_key_object_init(&ctx->sssKey, &g_keyStore)) != kStatus_SSS_Success)
        {
            break;
        }

        if ((ret = SSS_KEY_ALLOCATE_HANDLE(&ctx->sssKey, 1u,
                                           kSSS_KeyPart_Default,
                                           kSSS_CipherType_AES,
                                           key_bytelen,
                                           SSS_KEYPROP_OPERATION_MAC)) != kStatus_SSS_Success)
        {
            break;
        }
        ret = SSS_KEY_STORE_SET_KEY(&ctx->sssKey, key, key_bytelen, keylen, kSSS_KeyPart_Default);

    } while (0);
    return ret;
}

