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



#include "fsl_component_mem_manager.h"

#include "CryptoLibSW.h"
#include "sss_crypto.h"
#include "FunctionLib.h"
#include "fsl_sss_config_snt.h"


/************************************************************************************
*************************************************************************************
* Private functions
*************************************************************************************
************************************************************************************/

/* Needed to convert endian, and MSB/LSB swap */

static void ecp_coordinate_copy(ec_p256_coordinate* dest, const uint8_t *src)
{
    FLib_MemCpy(dest->raw_8bit, src, ECP256_COORDINATE_LEN);
}

static void ecp_coordinate_copy_and_change_endiannes(ec_p256_coordinate* dest, const uint8_t *src)
{
    FLib_MemCpyReverseOrder(dest->raw_8bit, src, ECP256_COORDINATE_LEN);
}

static void ecp_p256_copy(ecdhPoint_t* XY, const uint8_t *src)
{
    ecp_coordinate_copy(&XY->coord.X, &src[0]);
    ecp_coordinate_copy(&XY->coord.Y, &src[ECP256_COORDINATE_LEN]);
}

static void ecp_p256_copy_and_change_endiannes(ecdhPoint_t* XY, const uint8_t *src)
{
    ecp_coordinate_copy_and_change_endiannes(&XY->coord.X, &src[0]);
    ecp_coordinate_copy_and_change_endiannes(&XY->coord.Y, &src[ECP256_COORDINATE_LEN]);
}

void ecp_coordinate_change_endianness(ec_p256_coordinate* coord)
{
    FLib_ReverseByteOrderInPlace(coord->raw_8bit, ECP256_COORDINATE_LEN);
}




/*
 * Setup and export the client public value
*
 */
status_t sss_ecdh_make_public_ecp256_key(sss_ecdh_context_t *ecdh_ctx,
                                         unsigned char *wrk_buf,
                                         size_t wrk_buf_len,
                                          ecdhPublicKey_t*    pOutPublicKey,
                                          ecdhPrivateKey_t*   pOutPrivateKey)
{
    status_t ret =  kStatus_SSS_Fail;

    size_t coordinateLen      = ECP256_COORDINATE_LEN;
    size_t coordinateBitsLen  = ECP256_COORDINATE_BITLEN;
    size_t keySize            = 2u * coordinateLen;             /* X and Y coordinates of EC point */

    FLib_MemSet(wrk_buf, 0, keySize);
    do {
        if ((CRYPTO_InitHardware()) != kStatus_Success)
            break;

        if (ecdh_ctx->isKeyInitialized == false)
        {
            if ((ret = sss_sscp_key_object_init(&ecdh_ctx->key, &g_keyStore)) != kStatus_SSS_Success)
            {
                (void)SSS_KEY_OBJ_FREE(&ecdh_ctx->key);
                break;
            }
            /* Allocate key handle */
            if ((ret = sss_sscp_key_object_allocate_handle(&ecdh_ctx->key,
                                                    0u,
                                                    kSSS_KeyPart_Pair,
                                                    kSSS_CipherType_EC_NIST_P,
                                                    3u * coordinateLen,
#if (defined(KW45_A0_SUPPORT) && KW45_A0_SUPPORT)
                                                    SSS_PUBLIC_KEY_PART_EXPORTABLE
#else
                                                    SSS_KEYPROP_OPERATION_KDF
#endif
                                                    )) != kStatus_SSS_Success)

            {
                (void)SSS_KEY_OBJ_FREE(&ecdh_ctx->key);
                break;
            }
            else
            {
                ecdh_ctx->isKeyInitialized = true;
            }
        }

        if ((ret = SSS_ECP_GENERATE_KEY(&ecdh_ctx->key,
                                        coordinateBitsLen)) != kStatus_SSS_Success)
        {
            break;
        }
        if ((ret =  SSS_KEY_STORE_GET_PUBKEY(&ecdh_ctx->key,
                                             wrk_buf,
                                             &keySize,
                                             &coordinateBitsLen)) != kStatus_SSS_Success)
        {
            break;
        }

        ecp_p256_copy(&ecdh_ctx->OwnPublicKey, &wrk_buf[0]);
        /* pubKey returned by SSS in big-endian format: return it as Low Endian */
        ecp_p256_copy_and_change_endiannes(pOutPublicKey, &wrk_buf[0]);


        ret = kStatus_SSS_Success;

    } while (0);
    return ret;
}


/*
 * Derive and export the shared secret
 */
status_t sss_ecdh_calc_secret(sss_ecdh_context_t *ecdh_ctx,
                              unsigned char *wrk_buf, size_t wrk_buf_lg,
                              ecdhDhKey_t* pOutDhKey)
{
    status_t ret =  kStatus_SSS_Fail;

    sss_sscp_derive_key_t dCtx;
    size_t coordinateLen      = ECP256_COORDINATE_LEN;
    size_t coordinateBitsLen  = ECP256_COORDINATE_BITLEN;
    size_t key_sz = 2*coordinateLen;
    assert(wrk_buf != NULL);
    assert(wrk_buf_lg >= coordinateLen*3u);
    do {
        if ((CRYPTO_InitHardware()) != kStatus_Success)
            break;
        if ((ret = sss_sscp_key_object_init(&ecdh_ctx->peerPublicKey, &g_keyStore)) != kStatus_SSS_Success)
            break;
#if (defined(KW45_A0_SUPPORT) && KW45_A0_SUPPORT)
        key_sz += coordinateLen;
        if ((ret = sss_sscp_key_object_allocate_handle(&ecdh_ctx->peerPublicKey,
                                                 1u,
                                                 kSSS_KeyPart_Pair,
                                                 kSSS_CipherType_EC_NIST_P,
                                                 key_sz,
                                                 SSS_PUBLIC_KEY_PART_EXPORTABLE)) != kStatus_SSS_Success)
#else
        if ((ret = sss_sscp_key_object_allocate_handle(&ecdh_ctx->peerPublicKey,
                                                 1u,
                                                 kSSS_KeyPart_Public,
                                                 kSSS_CipherType_EC_NIST_P,
                                                 key_sz,
                                                 SSS_KEYPROP_OPERATION_KDF)) != kStatus_SSS_Success)
#endif
        {
            break;
        }

        /* Copy the Peer Public Key to the work buffer */
        memcpy(&wrk_buf[0],                     &ecdh_ctx->Qp.components_8bit.x, ECP256_COORDINATE_LEN);
        memcpy(&wrk_buf[ECP256_COORDINATE_LEN], &ecdh_ctx->Qp.components_8bit.y, ECP256_COORDINATE_LEN);

        if ((ret = SSS_KEY_STORE_SET_KEY(&ecdh_ctx->peerPublicKey,
                                         (const uint8_t *)wrk_buf,
                                         key_sz,
                                         coordinateBitsLen,
                                         kSSS_KeyPart_Public)) != kStatus_SSS_Success)
        {
            break;
        }
        if ((ret = sss_sscp_key_object_init(&ecdh_ctx->sharedSecret,
                                            &g_keyStore)) != kStatus_SSS_Success)
        {
            break;
        }
        if ((ret = sss_sscp_key_object_allocate_handle(
                                           &ecdh_ctx->sharedSecret,
                                           2u,
                                           kSSS_KeyPart_Default,
                                           kSSS_CipherType_AES,
                                           coordinateLen,
#if (defined(KW45_A0_SUPPORT) && KW45_A0_SUPPORT)
                                           SSS_FULL_KEY_EXPORTABLE
#else
                                           SSS_KEYPROP_OPERATION_NONE
#endif
                                           ))!= kStatus_SSS_Success)
            break;
        if ((ret = sss_sscp_derive_key_context_init(&dCtx,
                                                    &g_sssSession,
                                                    &ecdh_ctx->key,
                                                    kAlgorithm_SSS_ECDH,
                                                    kMode_SSS_ComputeSharedSecret)) != kStatus_SSS_Success)
        {
            break;
        }
        if ((ret = sss_sscp_asymmetric_dh_derive_key(&dCtx,
                                              &ecdh_ctx->peerPublicKey,
                                              &ecdh_ctx->sharedSecret)) != kStatus_SSS_Success)
        {
            break;
        }
        if ((ret = sss_sscp_key_store_get_key(&g_keyStore,
                                              &ecdh_ctx->sharedSecret,
                                              wrk_buf,
                                              &coordinateLen,
                                              &coordinateBitsLen,
                                              NULL)) != kStatus_SSS_Success)

            break;

        ecp_p256_copy(&ecdh_ctx->z, wrk_buf);
        if (pOutDhKey != NULL)
        {
            ecp_p256_copy_and_change_endiannes(pOutDhKey, wrk_buf);
        }
        ret = kStatus_SSS_Success;

    } while (0);
    (void)sss_sscp_derive_key_context_free(&dCtx);
    (void)SSS_KEY_OBJ_FREE(&ecdh_ctx->peerPublicKey);
    (void)SSS_KEY_OBJ_FREE(&ecdh_ctx->sharedSecret);

    return ret;
}

#define ECDH_SELF_TEST  2

/* test suite functions*/
#if defined(ECDH_SELF_TEST)

int EC_P256_GenerateKeys(ecdhPublicKey_t* pOutPublicKey, ecdhPrivateKey_t* pOutPrivateKey)
{
    int result = -1;

    do {
        void* pMultiplicationBuffer = MEM_BufferAlloc(gEcP256_MultiplicationBufferSize_c);
        if ((void*)NULL == pMultiplicationBuffer)
        {
            RAISE_ERROR(result, -2);
        }

        if (gEcdhSuccess_c == Ecdh_GenerateNewKeys(pOutPublicKey, pOutPrivateKey, pMultiplicationBuffer))
        {
            result = 0;
        }
        (void)MEM_BufferFree(pMultiplicationBuffer);
    } while (0);
    return result;
}

int EC_P256_ComputeDhKey(ecdhPrivateKey_t*   pPrivateKey,
                         ecdhPublicKey_t*    pPeerPublicKey,
                         ecdhDhKey_t*        pOutDhKey)
{
    int result = -1;
    ecdhStatus_t ecdhStatus;

    void* pMultiplicationBuffer = MEM_BufferAlloc(gEcP256_MultiplicationBufferSize_c);
    if ((void*)NULL != pMultiplicationBuffer)
    {

        ecdhStatus = Ecdh_ComputeDhKey(pPrivateKey, pPeerPublicKey, pOutDhKey, pMultiplicationBuffer);

        if (gEcdhInvalidPublicKey_c == ecdhStatus)
        {
            result = -2;
        }
        else if (gEcdhSuccess_c != ecdhStatus)
        {
            result = -3;
        }
        else
        {
            result = 0;
        }
        ecp_coordinate_change_endianness(&pOutDhKey->coord.X);
        ecp_coordinate_change_endianness(&pOutDhKey->coord.Y); /* not really used */
        (void)MEM_BufferFree(pMultiplicationBuffer);
    }
    return result;
}


#if defined(ECDH_SELF_TEST) && (ECDH_SELF_TEST == 1)


#include "fsl_debug_console.h"
sss_ecdh_context_t ecdhClient;
sss_ecdh_context_t ecdhServer;
#define  TRACE(...) { if (verbose) PRINTF(...);}
int sss_ecdh_self_test(bool verbose)
{
    int ret = -1;
    uint8_t * wrk_buf = NULL;

    do {

        FLib_MemSet(&ecdhClient, 0, sizeof(ecdhClient));
        FLib_MemSet(&ecdhServer, 0, sizeof(ecdhServer));

        if (EC_P256_GenerateKeys(&ecdhServer.OwnPublicKey, &ecdhServer.PrivateKey) != 0)
        {
            TRACE("Server: Error generating SW ECDH Key Pair\n");
            break;
        }
        size_t wrk_buf_sz = 3 * ECP256_COORDINATE_LEN;
        wrk_buf = MEM_BufferAlloc(wrk_buf_sz);
        if (wrk_buf == NULL)
        {
            TRACE("Allocation failure\n");
            break;
        }
        FLib_MemSet(wrk_buf, 0, sizeof(wrk_buf_sz));
        if (sss_ecdh_make_public_ecp256_key(&ecdhClient,
                                        wrk_buf, sizeof(ecdhPublicKey_t),
                                        &ecdhClient.OwnPublicKey, &ecdhClient.PrivateKey)
            != kStatus_SSS_Success)
        {
            TRACE("Client: Error generating SSS ECDH Key Pair\n");
            break;
        }
        /* At this stage ecdhServer key pair is stored in LE format but ecdhClient in BE
            We have no visibility on the ecdhClient private key.
          */
        ecp_p256_copy(&ecdhServer.Qp, (const uint8_t*)&ecdhClient.OwnPublicKey.raw[0]);
        ecp_p256_copy_and_change_endiannes(&ecdhClient.Qp, (const uint8_t*)&ecdhServer.OwnPublicKey.raw[0]);

        FLib_MemSet(wrk_buf, 0, sizeof(wrk_buf_sz));

        if(sss_ecdh_calc_secret(&ecdhClient, wrk_buf, 3 * ECP256_COORDINATE_LEN, &ecdhClient.z) != kStatus_SSS_Success)
        {
            TRACE("Client: Error computing DH secret\n");
            break;
        }

        if(EC_P256_ComputeDhKey(&ecdhServer.PrivateKey,
                                &ecdhServer.Qp,
                                &ecdhServer.z) != 0)
        {
            TRACE("Server: Error computing DH secret\n");
            break;
        }
        ecp_coordinate_change_endianness(&ecdhServer.z.coord.X);


        if (FLib_MemCmp(&ecdhClient.z.coord.X, &ecdhServer.z.coord.X, ECP256_COORDINATE_LEN) != TRUE)
        {
            TRACE("DH failure\n");
            break;
        }

        TRACE("passed\n");
        ret = 0;
    } while (0);
    return ret;
}
#endif /* MBEDTLS_SELF_TEST == 1 */
#endif /* defined MBEDTLS_SELF_TEST */

