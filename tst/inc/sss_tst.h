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
 *   list of conditions and the following disclaimer.
 *
 * o Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * o Neither the name of the copyright holder nor the names of its
 *   contributors may be used to endorse or promote products derived from this
 *   software without specific prior written permission.
 *
 * NO EXPRESS OR IMPLIED LICENSES TO ANY PARTY'S PATENT RIGHTS ARE GRANTED BY
 * THIS LICENSE.
 * @brief This SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#ifndef SECUREIOTMW_SSS_TST_INC_SSS_TST_H_
#define SECUREIOTMW_SSS_TST_INC_SSS_TST_H_

/* ************************************************************************** */
/* Includes                                                                   */
/* ************************************************************************** */

#include <unity_fixture.h>
#include "fsl_sss_api.h"
#include "fsl_sss_ftr.h"

#if SSS_HAVE_MBEDTLS
#include "fsl_sss_mbedtls_apis.h"
#include "mbedtls/version.h"
#endif

#if SSS_HAVE_OPENSSL
#include "openssl/opensslv.h"
#endif

#if SSS_HAVE_SSCP
#include "fsl_sss_sscp_types.h"
#include "sm_types.h"
#endif

/* ************************************************************************** */
/* Defines                                                                    */
/* ************************************************************************** */

#define TEST_ASSERT_T(condition) TEST_ASSERT_MESSAGE(condition, #condition " : Failed")

#define RUN_TEST_SCENARIO(group, name)   \
    /* (forward) declare */              \
    void TEST_##group##_##name##_(void); \
    /* call */                           \
    TEST_##group##_##name##_()

/* ************************************************************************** */
/* Structrues and Typedefs                                                    */
/* ************************************************************************** */

typedef struct testCtx_t
{
    uint8_t fixture_setup_done;
    sss_session_t session;
    sss_key_store_t ks;
    sss_object_t key;
    sss_asymmetric_t asymm;
    sss_symmetric_t symm;
    sss_derive_key_t derv;
#if SSS_HAVE_SSCP
    sscp_context_t sscp;
#endif
} testCtx_t;

/* ************************************************************************** */
/* Global Variables                                                           */
/* ************************************************************************** */

extern const char *gszA71COMPortDefault;
extern const char *gszA71SocketPortDefault;

extern testCtx_t gtCtx;

/* ************************************************************************** */
/* Functions                                                                  */
/* ************************************************************************** */

void DoFixtureSetupIfNeeded(bool withFactoryReset);
void DoCommonSetUp(void);
void DoCommonTearDown(void);
void DoFixtureTearDownIfNeeded(void);
void DoFactoryReset(void);

#endif /* SECUREIOTMW_SSS_TST_INC_SSS_TST_H_ */
