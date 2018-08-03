/*
 * The Clear BSD License
 * Copyright 2018 NXP
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted (subject to the limitations in the disclaimer below) provided
 *  that the following conditions are met:
 *
 * o Redistributions of source code must retain the above copyright notice, this list
 *   of conditions and the following disclaimer.
 *
 * o Redistributions in binary form must reproduce the above copyright notice, this
 *   list of conditions and the following disclaimer in the documentation and/or
 *   other materials provided with the distribution.
 *
 * o Neither the name of the copyright holder nor the names of its
 *   contributors may be used to endorse or promote products derived from this
 *   software without specific prior written permission.
 *
 * NO EXPRESS OR IMPLIED LICENSES TO ANY PARTY'S PATENT RIGHTS ARE GRANTED BY THIS LICENSE.
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
 * ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef _FSL_SSS_SSCP_H_
#define _FSL_SSS_SSCP_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "fsl_sss_api.h"
#include "sscp/fsl_sscp.h"

#if !defined(SSS_SSCP_CONFIG_FILE)
#include "sscp/fsl_sss_sscp_config.h"
#else
#include SSS_SSCP_CONFIG_FILE
#endif

typedef struct _sss_sscp_session
{
    sss_type_t subsystem; /*! Indicates which security subsystem is selected to be used. */

    /*! Implementation specific part */
    sscp_operation_t op;
    sscp_context_t *sscp;
} sss_sscp_session_t;

typedef struct _sss_sscp_key_store
{
    sss_sscp_session_t
        *session; /*! Virtual connection between application (user context) and specific security subsystem
                and function thereof. */

    /*! Implementation specific part */
    uint32_t keyStoreId;
    sscp_operation_t op;
} sss_sscp_key_store_t;

typedef struct _sss_sscp_object
{
    sss_sscp_key_store_t *keyStore; /*! key store holding the data and other properties */

    uint32_t objectType; /*! TODO define object types */
    uint32_t
        keyId; /*! Application specific key identifier. The keyId is kept in the key store along with the key data and
                  other properties. */

    /*! Implementation specific part */
    sscp_operation_t op;
} sss_sscp_object_t;

typedef struct _sss_sscp_symmetric
{
    sss_sscp_session_t
        *session; /*! Virtual connection between application (user context) and specific security subsystem
                and function thereof. */
    sss_sscp_object_t *keyObject; /*! Reference to key and it's properties. */
    sss_algorithm_t algorithm;    /*!  */
    sss_mode_t mode;              /*!  */

    /*! Implementation specific part */
    sscp_operation_t op;
    struct
    {
        uint8_t data[SSS_SSCP_SYMMETRIC_CONTEXT_SIZE];
    } context;
} sss_sscp_symmetric_t;

typedef struct _sss_sscp_digest
{
    sss_sscp_session_t
        *session;              /*! Virtual connection between application (user context) and specific security subsystem
                             and function thereof. */
    sss_algorithm_t algorithm; /*!  */
    sss_mode_t mode;           /*!  */
    size_t digestFullLen;      /*! Full digest length per algorithm definition. This field is initialized along with
                                  algorithm. */

    /*! Implementation specific part */
    sscp_operation_t op;
    struct
    {
        uint8_t data[SSS_SSCP_DIGEST_CONTEXT_SIZE];
    } context;
} sss_sscp_digest_t;

typedef struct _sss_sscp_asymmetric
{
    sss_sscp_session_t *session;
    sss_sscp_object_t *keyObject;
    sss_algorithm_t algorithm; /*!  */
    sss_mode_t mode;           /*!  */
    size_t signatureFullLen;

    /*! Implementation specific part */
    sscp_operation_t op;
} sss_sscp_asymmetric_t;

typedef struct _sss_sscp_derive_key
{
    sss_sscp_session_t *session;
    sss_sscp_object_t *keyObject;
    sss_algorithm_t algorithm; /*!  */
    sss_mode_t mode;           /*!  */

    /*! Implementation specific part */
    sscp_operation_t op;
} sss_sscp_derive_key_t;

/*******************************************************************************
 * API
 ******************************************************************************/
#if defined(__cplusplus)
extern "C" {
#endif

sss_status_t sss_sscp_cipher_one_go(sss_sscp_symmetric_t *context,
                                    uint8_t *iv,
                                    size_t ivLen,
                                    const uint8_t *srcData,
                                    uint8_t *destData,
                                    size_t dataLen);

sss_status_t sss_sscp_digest_one_go(
    sss_sscp_digest_t *context, const uint8_t *message, size_t messageLen, uint8_t *digest, size_t *digestLen);

sss_status_t sss_sscp_digest_init(sss_sscp_digest_t *context);

sss_status_t sss_sscp_asymmetric_sign_digest(
    sss_sscp_asymmetric_t *context, uint8_t *digest, size_t digestLen, uint8_t *signature, size_t *signatureLen);

sss_status_t sss_sscp_asymmetric_verify_digest(
    sss_sscp_asymmetric_t *context, uint8_t *digest, size_t digestLen, uint8_t *signature, size_t signatureLen);

sss_status_t sss_sscp_asymmetric_dh_derive_key(sss_sscp_derive_key_t *context,
                                               sss_sscp_object_t *otherPartyKeyObject,
                                               sss_sscp_object_t *derivedKeyObject);

sss_status_t sss_sscp_key_store_allocate(sss_sscp_key_store_t *keyStore, uint32_t keyStoreId);

sss_status_t sss_sscp_key_object_allocate_handle(
    sss_sscp_object_t *keyObject, uint32_t keyId, sss_key_type_t keyType, uint32_t keyByteLenMax, uint32_t options);

sss_status_t sss_sscp_key_store_set_key(sss_sscp_key_store_t *keyStore,
                                        sss_sscp_object_t *keyObject,
                                        const uint8_t *key,
                                        uint32_t keyBitLen,
                                        void *options,
                                        size_t optionsLen);

#if defined(__cplusplus)
}
#endif

#endif /* _FSL_SSS_SSCP_H_ */
