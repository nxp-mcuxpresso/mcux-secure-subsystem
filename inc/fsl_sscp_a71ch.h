
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

#ifndef _FSL_SSCP_A71CH_H_
#define _FSL_SSCP_A71CH_H_

#include "fsl_sscp.h"
#include "fsl_sss_sscp_types.h"

#if SSS_HAVE_A71CH || SSS_HAVE_SE050_EAR

/*******************************************************************************
 * API
 ******************************************************************************/
#if defined(__cplusplus)
extern "C" {
#endif

/*!
 * @addtogroup sscp_a71ch
 * @{
 */

/**
 * struct _sscp_a71ch_context - SSCP context struct for A71 CH implementation
 *
 * This data type is used to keep context of the SSCP link.
 * It is completely implementation specific.
 *
 * @param context Container for the implementation specific data.
 */
typedef struct _sss_a71ch_key_store
{
    sss_sscp_session_t *session;
    /*! Implementation specific part */

    keyStoreTable_t *keystore_shadow;
    HLSE_OBJECT_HANDLE shadow_handle;

} sss_a71ch_key_store_t;

typedef struct _sscp_a71ch_context
{
    fn_sscp_invoke_command_t invoke;
    /*! Implementation specific part */
    sss_a71ch_key_store_t *keyStore;
} sscp_a71ch_context_t;

/*! @brief Initializes the SSCP link
 *
 * This function initializes the SSCP for operation - e.g.underlaying hardware
 * is initialized and prepared for data exchange.
 *
 * @param context Context structure for the SSCP.
 * @param base The A71ch peripheral base address to be used for communication
 *
 * @returns Status of the operation
 * @retval kStatus_SSCP_Success SSCP init success
 * @retval kStatus_SSCP_Fail SSCP init failure
 */
sss_status_t sscp_a71ch_init(sscp_a71ch_context_t *context, sss_a71ch_key_store_t *keyStore);

/*! @brief Close the SSCP link
 *
 * This function closes the SSCP link - e.g.underlying hardware is disabled.
 *
 * @param context Context structure for the SSCP.
 */
void sscp_a71ch_free(sscp_a71ch_context_t *context);

/*! @brief Sends a command and associated parameters to security sub-system
 *
 *  The commandID and operation content is serialized and sent over to the
 * selected security sub-system. This is implementation specific function. The
 * function can invoke both blocking and non-blocking secure functions in the
 * selected security sub-system.
 *
 * @param context Initialized SSCP context
 * @param commandID Command - an id of a remote secure function to be invoked
 * @param op Description of function arguments as a sequence of buffers and
 * values
 * @param ret Return code of the remote secure function (application layer
 * return value)
 *
 * @returns Status of the operation
 * @retval kStatus_SSCP_Success A blocking command has completed or a
 * non-blocking command has been accepted.
 * @retval kStatus_SSCP_Fail Operation failure, for example hardware fail.
 * @retval kStatus_SSCP_InvalidArgument One of the arguments is invalid for the
 * function to execute.
 */
sscp_status_t sscp_a71ch_invoke_command(sscp_context_t *context,
                                        uint32_t commandID,
                                        sscp_operation_t *op,
                                        uint32_t *ret);

#if defined(__cplusplus)
}
#endif

/*!
 *@}
 */ /* end of sscp_a71ch */

#endif /* SSS_HAVE_A71CH */
#endif /* _FSL_SSCP_A71CH_H_ */
