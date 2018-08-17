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

#ifndef SSS_APIS_INC_FSL_SSS_OPENSSL_TYPES_H_
#define SSS_APIS_INC_FSL_SSS_OPENSSL_TYPES_H_

/* ************************************************************************** */
/* Includes                                                                   */
/* ************************************************************************** */

#include <fsl_sss_api.h>
#if !defined(SSS_FTR_FILE)
#include "fsl_sss_ftr_default.h"
#else
#include SSS_FTR_FILE
#endif

/**
 * @addtogroup sss_sw_openssl
 * @{
 */

/* ************************************************************************** */
/* Defines                                                                    */
/* ************************************************************************** */

#define SSS_SUBSYSTEM_TYPE_IS_OPENSSL(subsystem) (subsystem == kType_SSS_OpenSSL)

#define SSS_SESSION_TYPE_IS_OPENSSL(session) (SSS_SUBSYSTEM_TYPE_IS_OPENSSL(session->subsystem))

#define SSS_OBJECT_TYPE_IS_OPENSSL(pObject) SSS_SUBSYSTEM_TYPE_IS_OPENSSL(pObject->keyStore->session->subsystem)

#define SSS_KEY_STORE_TYPE_IS_OPENSSL(keyStore) SSS_SUBSYSTEM_TYPE_IS_OPENSSL(keyStore->session->subsystem)

/* ************************************************************************** */
/* Structrues and Typedefs                                                    */
/* ************************************************************************** */

typedef struct _sss_openssl_session
{
    /*! Indicates which security subsystem is selected to be used. */
    sss_type_t subsystem;

} sss_openssl_session_t;

typedef struct _sss_openssl_key_store
{
    sss_openssl_session_t *session;
    /*! Implementation specific part */
} sss_openssl_key_store_t;

typedef struct _sss_openssl_object
{
    SSS_OBJECT_MEMBERS(_openssl_);

    /*! Implementation specific part */
} sss_openssl_object_t;

typedef struct _sss_openssl_asymmetric
{
    SSS_ASYMMETRIC_MEMBERS(_openssl_)

} sss_openssl_asymmetric_t;

/* ************************************************************************** */
/* Global Variables                                                           */
/* ************************************************************************** */

/* ************************************************************************** */
/* Functions                                                                  */
/* ************************************************************************** */

/** @} */

#endif /* SSS_APIS_INC_FSL_SSS_OPENSSL_TYPES_H_ */
