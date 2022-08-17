/*! *********************************************************************************
 * Copyright 2022 NXP
 * All rights reserved.
 *
 * \file
 *
 * SPDX-License-Identifier: BSD-3-Clause
 ********************************************************************************** */
/*
 *  Elliptic curve Diffie-Hellman
 *
 * References:
 *
 * SEC1 http://www.secg.org/index.php?action=secg,docs_secg
 * RFC 4492
 *
 * Note: This file restricts the implementation to EC P256 R1.
 */

#include "sss_crypto.h"
#include "fsl_sss_config_snt.h"

/************************************************************************************
*************************************************************************************
* Private functions
*************************************************************************************
************************************************************************************/
static void ecp_p256_copy(uint8_t *XY, const uint8_t *src)
{
    const uint8_t *pCoord = &src[0];
    memcpy(&XY[0], pCoord, ECP256_COORDINATE_LEN);
    pCoord += ECP256_COORDINATE_LEN;
    memcpy(&XY[ECP256_COORDINATE_LEN], pCoord, ECP256_COORDINATE_LEN);
}

/*
 * Setup and export the client public value
 *
 */
status_t sss_ecdh_make_public_ecp256_key(sss_ecp256_context_t *K_ctx, unsigned char *wrk_buf, size_t wrk_buf_len)
{
    status_t ret = kStatus_Fail;

    size_t coordinateLen     = ECP256_COORDINATE_LEN;
    size_t coordinateBitsLen = ECP256_COORDINATE_BITLEN;
    size_t keySize           = 2u * coordinateLen; /* X and Y coordinates of EC point */

    memset(wrk_buf, 0, keySize);
    do
    {
        if ((CRYPTO_InitHardware()) != kStatus_Success)
        {
            break;
        }
        if ((sss_sscp_key_object_init(&K_ctx->OwnKey, &g_keyStore)) != kStatus_SSS_Success)
        {
            (void)SSS_KEY_OBJ_FREE(&K_ctx->OwnKey);
            break;
        }
        /* Allocate key handle */
        if ((sss_sscp_key_object_allocate_handle(&K_ctx->OwnKey, K_ctx->keyId, kSSS_KeyPart_Pair,
                                                       kSSS_CipherType_EC_NIST_P, 3u * coordinateLen,
#if (defined(KW45_A0_SUPPORT) && KW45_A0_SUPPORT)
                                                       SSS_PUBLIC_KEY_PART_EXPORTABLE
#else
                                                       SSS_KEYPROP_OPERATION_KDF
#endif
                                                       )) != kStatus_SSS_Success)

        {
            (void)SSS_KEY_OBJ_FREE(&K_ctx->OwnKey);
            break;
        }

        if ((SSS_ECP_GENERATE_KEY(&K_ctx->OwnKey, coordinateBitsLen)) != kStatus_SSS_Success)
        {
            break;
        }
        if ((SSS_KEY_STORE_GET_PUBKEY(&K_ctx->OwnKey, wrk_buf, &keySize, &coordinateBitsLen)) !=
            kStatus_SSS_Success)
        {
            break;
        }

        ecp_p256_copy((uint8_t *)&K_ctx->OwnPublicKey[0], &wrk_buf[0]);
#if (defined(KW45_A0_SUPPORT) && KW45_A0_SUPPORT)
        memcpy(&K_ctx->PrivateKey, &wrk_buf[2u * coordinateLen], ECP256_COORDINATE_LEN);
#endif

        ret = kStatus_Success;

    } while (false);
    return ret;
}

/*
 * Derive and export the shared secret
 */
status_t sss_ecdh_calc_secret(sss_ecdh_context_t *pEcdh_ctx, unsigned char *wrk_buf, size_t wrk_buf_lg)
{
    status_t ret = kStatus_Fail;

    sss_sscp_derive_key_t dCtx;
    sss_sscp_derive_key_t *pderivCtx = NULL;
    size_t coordinateLen     = ECP256_COORDINATE_LEN;
    size_t coordinateBitsLen = ECP256_COORDINATE_BITLEN;
    size_t key_sz            = 2 * coordinateLen;
    assert(wrk_buf != NULL);
    assert(wrk_buf_lg >= coordinateLen * 3u);
    sss_sscp_object_t *pPubKey = NULL;
    sss_sscp_object_t *pSharedSecret = NULL;
    do
    {
        if ((CRYPTO_InitHardware()) != kStatus_Success)
        {
            break;
        }
        if ((sss_sscp_key_object_init(&pEcdh_ctx->peerPublicKey, &g_keyStore)) != kStatus_SSS_Success)
        {
            break;
        }
#if (defined(KW45_A0_SUPPORT) && KW45_A0_SUPPORT)
        key_sz += coordinateLen;
        if ((ret = sss_sscp_key_object_allocate_handle(&pEcdh_ctx->peerPublicKey, 1u, kSSS_KeyPart_Pair,
                                                       kSSS_CipherType_EC_NIST_P, key_sz,
                                                       SSS_PUBLIC_KEY_PART_EXPORTABLE)) != kStatus_SSS_Success)
#else
        if ((ret = sss_sscp_key_object_allocate_handle(&pEcdh_ctx->peerPublicKey, 1u, kSSS_KeyPart_Public,
                                                       kSSS_CipherType_EC_NIST_P, key_sz, SSS_KEYPROP_OPERATION_KDF)) !=
            kStatus_SSS_Success)
#endif
        {
            break;
        }
        pPubKey = &pEcdh_ctx->peerPublicKey;
        /* Copy the Peer Public Key to the work buffer */
        memcpy(&wrk_buf[0], &pEcdh_ctx->Qp[0], ECP256_COORDINATE_LEN);
        memcpy(&wrk_buf[ECP256_COORDINATE_LEN], &pEcdh_ctx->Qp[ECP256_COORDINATE_WLEN], ECP256_COORDINATE_LEN);

        if ((ret = SSS_KEY_STORE_SET_KEY(pPubKey, (const uint8_t *)wrk_buf, key_sz, coordinateBitsLen,
                                         kSSS_KeyPart_Public)) != kStatus_SSS_Success)
        {
            break;
        }
        if ((ret = sss_sscp_key_object_init(&pEcdh_ctx->sharedSecret, &g_keyStore)) != kStatus_SSS_Success)
        {
            break;
        }
        if ((ret = sss_sscp_key_object_allocate_handle(&pEcdh_ctx->sharedSecret, 2u, kSSS_KeyPart_Default,
                                                       kSSS_CipherType_AES, coordinateLen,
#if (defined(KW45_A0_SUPPORT) && KW45_A0_SUPPORT)
                                                       SSS_FULL_KEY_EXPORTABLE
#else
                                                       SSS_KEYPROP_OPERATION_NONE
#endif
                                                       )) != kStatus_SSS_Success)
        {
            break;
        }
        pSharedSecret = &pEcdh_ctx->sharedSecret;
        if ((ret = sss_sscp_derive_key_context_init(&dCtx, &g_sssSession, &pEcdh_ctx->ecdh_key_pair->OwnKey,
                                                    kAlgorithm_SSS_ECDH, kMode_SSS_ComputeSharedSecret)) !=
            kStatus_SSS_Success)
        {
            break;
        }
        pderivCtx = &dCtx;
        if ((ret = sss_sscp_asymmetric_dh_derive_key(&dCtx, pPubKey, pSharedSecret)) !=
            kStatus_SSS_Success)
        {
            break;
        }
        if ((ret = SSS_KEY_STORE_GET_PUBKEY(pSharedSecret, wrk_buf, &coordinateLen,
                                              &coordinateBitsLen)) != kStatus_SSS_Success)
        {
            break;
        }

        ecp_p256_copy((uint8_t *)&pEcdh_ctx->z[0], wrk_buf);

        ret = kStatus_Success;

    } while (false);
    if (pderivCtx != NULL)
    {
        (void)sss_sscp_derive_key_context_free(pderivCtx);
    }
    if (pPubKey != NULL)
    {
        (void)SSS_KEY_OBJ_FREE(pPubKey);
    }
    if (pSharedSecret != NULL)
    {
        if (pEcdh_ctx->keepSharedSecret == false)
        {
            (void)SSS_KEY_OBJ_FREE(pSharedSecret);
        }
    }

    return ret;
}
