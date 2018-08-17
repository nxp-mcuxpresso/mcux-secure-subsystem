/*
 * The Clear BSD License
 * Copyright 2018 NXP
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted (subject to the limitations in the disclaimer
 * below) provided that the following conditions are met:
 *
 * o Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer.
 *
 * o Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * o Neither the name of the copyright holder nor the names of its
 *   contributors may be used to endorse or promote products derived from this
 *   software without specific prior written permission.
 *
 * NO EXPRESS OR IMPLIED LICENSES TO ANY PARTY'S PATENT RIGHTS ARE GRANTED BY
 * THIS LICENSE. THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
 * CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT
 * NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef SSS_APIS_INC_FSL_SSS_SSCP_TYPES_H_
#define SSS_APIS_INC_FSL_SSS_SSCP_TYPES_H_

/* ************************************************************************** */
/* Includes                                                                   */
/* ************************************************************************** */

#include <fsl_sscp_commands.h>
#include <fsl_sss_api.h>
#if !defined(SSS_FTR_FILE)
#include "fsl_sss_ftr_default.h"
#else
#include SSS_FTR_FILE
#endif

#if SSS_HAVE_SSCP
#include <fsl_sscp.h>

#if SSS_HAVE_A71CH || SSS_HAVE_SE050_EAR
#include <HLSETypes.h>
#include <fsl_sss_keyid_map.h>
#endif

/**
 * @addtogroup sss_sscp
 * @{
 */

/* ************************************************************************** */
/* Defines                                                                    */
/* ************************************************************************** */

#define SSS_SSCP_CONNECTIONTYPE_SOCKET 0x01
#define SSS_SSCP_CONNECTIONTYPE_VCOM 0x02
#define SSS_SSCP_CONNECTIONTYPE_SCI2C 0x03

#define SSS_SUBSYSTEM_TYPE_IS_SSCP(subsystem) ((subsystem == kType_SSS_SE_A71CH) || (subsystem == kType_SSS_SE_SE050))

/* ************************************************************************** */
/* Structrues and Typedefs                                                    */
/* ************************************************************************** */

struct _sss_sscp_key_store;

typedef struct _sss_sscp_session
{
    /* Implementation defined */
    sss_type_t subsystem;
    sscp_context_t *sscp_context;
} sss_sscp_session_t;

typedef struct _sss_sscp_key_store
{
    sss_sscp_session_t *session;
    /*! Implementation specific part */
} sss_sscp_key_store_t;

typedef struct _sss_sscp_object
{
    /*! key store holding the data and other properties */
    sss_sscp_key_store_t *keyStore;
    /*! TODO define object types */
    uint32_t objectType;
    /*! Application specific key identifier. The keyId is kept in the key  store
     * along with the key data and other properties. */
    uint32_t keyId;

    void *transientObject;
    uint32_t transientObjectLen;

} sss_sscp_object_t;

typedef struct _sss_sscp_derive_key
{
    sss_sscp_session_t *session;
    sss_sscp_object_t *keyObject;
    sss_algorithm_t algorithm; /*!  */
    sss_mode_t mode;           /*!  */

    /*! Implementation specific part */
    uint32_t sessionId; /*!  */
} sss_sscp_derive_key_t;

typedef struct _sss_sscp_asymmetric
{
    sss_sscp_session_t *session;
    sss_sscp_object_t *keyObject;
    sss_algorithm_t algorithm; /*!  */
    sss_mode_t mode;           /*!  */

    uint32_t sessionId; /*!  */
} sss_sscp_asymmetric_t;

typedef struct _sss_sscp_symmetric
{
    /*! Virtual connection between application (user context) and specific
     * security subsystem and function thereof. */
    sss_sscp_session_t *session;
    sss_sscp_object_t *keyObject; /*!< Reference to key and it's properties. */
    sss_algorithm_t algorithm;    /*!  */
    sss_mode_t mode;              /*!  */
    uint32_t sessionId;           /*!  */

} sss_sscp_symmetric_t;

/* ************************************************************************** */
/* Global Variables                                                           */
/* ************************************************************************** */

/* ************************************************************************** */
/* Functions                                                                  */
/* ************************************************************************** */

#endif /* SSS_HAVE_SSCP */

#define SSS_SESSION_TYPE_IS_SSCP(session) (session && SSS_SUBSYSTEM_TYPE_IS_SSCP(session->subsystem))

#define SSS_KEY_STORE_TYPE_IS_SSCP(keyStore) (keyStore && SSS_SESSION_TYPE_IS_SSCP(keyStore->session))

#define SSS_OBJECT_TYPE_IS_SSCP(pObject) (pObject && SSS_KEY_STORE_TYPE_IS_SSCP(pObject->keyStore))

#define SSS_DERIVE_KEY_TYPE_IS_SSCP(context) (context && SSS_SESSION_TYPE_IS_SSCP(context->session))

#define SSS_ASYMMETRIC_TYPE_IS_SSCP(context) (context && SSS_SESSION_TYPE_IS_SSCP(context->session))

#define SSS_SYMMETRIC_TYPE_IS_SSCP(context) (context && SSS_SESSION_TYPE_IS_SSCP(context->session))

/** @} */

#endif /* SSS_APIS_INC_FSL_SSS_SSCP_TYPES_H_ */
