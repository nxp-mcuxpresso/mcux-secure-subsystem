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

#ifndef _FSL_SSCP_MU_H_
#define _FSL_SSCP_MU_H_

//#include "fsl_mu.h"
#include "fsl_sscp.h"
typedef uint32_t MU_Type;

/*!
@defgroup sscp_mu SSCP over MU
@details This section describes definition of the messages for the MU to invoke services
and MU implementation specific functions to initialize SSCP MU link, deinitialize SSCP MU link
and MU invoke command.
@ingroup sscp

# MU commands

## Symmetric cipher

| kSSCP_CMD_SSS_SymmetricCipherOneGo | TX | MU TXn register value                                |
| ---------------------------------- | -- | ---------------------------------------------------- |
| Command                            | 0  | kSSCP_CMD_SSS_SymmetricCipherOneGo                   |
| paramTypes                         | 1  | Aggregate, MemrefInput, MemrefInput, MemrefOutput    |
| word                               | 2  | Pointer to ::sss_sscp_symmetric_t                    |
| word                               | 3  | Pointer to iv                                        |
| word                               | 4  | ivLen                                                |
| word                               | 5  | Pointer to srcData                                   |
| word                               | 6  | dataLen                                              |
| word                               | 7  | Pointer to destData                                  |
| word                               | 8  | Pointer to dataLen                                   |

## Digest

| kSSCP_CMD_SSS_DigestOneGo          | TX | MU TXn register value                                |
| ---------------------------------- | -- | ---------------------------------------------------- |
| Command                            | 0  | kSSCP_CMD_SSS_DigestOneGo                            |
| paramTypes                         | 1  | Aggregate, MemrefInput, MemrefOutput                 |
| word                               | 2  | Pointer to ::sss_sscp_digest_t                       |
| word                               | 3  | Pointer to message                                   |
| word                               | 4  | messageLen                                           |
| word                               | 5  | Pointer to digest                                    |
| word                               | 6  | Pointer to dataLen                                   |

| kSSCP_CMD_SSS_DigestInit           | TX | MU TXn register value                                |
| ---------------------------------- | -- | ---------------------------------------------------- |
| Command                            | 0  | kSSCP_CMD_SSS_DigestInit                             |
| paramTypes                         | 1  | Aggregate                                            |
| word                               | 2  | Pointer to ::sss_sscp_digest_t                       |

| kSSCP_CMD_SSS_DigestUpdate         | TX | MU TXn register value                                |
| ---------------------------------- | -- | ---------------------------------------------------- |
| Command                            | 0  | kSSCP_CMD_SSS_DigestUpdate                           |
| paramTypes                         | 1  | Aggregate, MemrefInput                               |
| word                               | 2  | Pointer to ::sss_sscp_digest_t                       |
| word                               | 3  | Pointer to message                                   |
| word                               | 4  | messageLen                                           |

| kSSCP_CMD_SSS_DigestFinish         | TX | MU TXn register value                                |
| ---------------------------------- | -- | ---------------------------------------------------- |
| Command                            | 0  | kSSCP_CMD_SSS_DigestFinish                           |
| paramTypes                         | 1  | Aggregate, MemrefOutput                              |
| word                               | 2  | Pointer to ::sss_sscp_digest_t                       |
| word                               | 3  | Pointer to digest                                    |
| word                               | 4  | Pointer to dataLen                                   |

## Asymmetric

| kSSCP_CMD_SSS_AsymmetricSignDigest | TX | MU TXn register value                                |
| ---------------------------------- | -- | ---------------------------------------------------- |
| Command                            | 0  | kSSCP_CMD_SSS_AsymmetricSignDigest                   |
| paramTypes                         | 1  | Aggregate, MemrefInput, MemrefOutput                 |
| word                               | 2  | Pointer to ::sss_sscp_asymmetric_t                   |
| word                               | 3  | Pointer to digest                                    |
| word                               | 4  | digestLen                                            |
| word                               | 5  | Pointer to signature                                 |
| word                               | 6  | Pointer to signatureLen                              |



*/

/*******************************************************************************
 * API
 ******************************************************************************/
#if defined(__cplusplus)
extern "C" {
#endif

/*!
 * @addtogroup sscp_mu
 * @{
 */

/**
 * struct _sscp_mu_context - SSCP context struct for MU implementation
 *
 * This data type is used to keep context of the SSCP link.
 * It is completely implementation specific.
 *
 * @param context Container for the implementation specific data.
 */
typedef struct _sscp_mu_context
{
    fn_sscp_invoke_command_t sscp_invoke_command;

    /*! Implementation specific part */
    MU_Type *base;
} sscp_mu_context_t;

/*! @brief Initializes the SSCP link
 *
 * This function initializes the SSCP for operation - e.g.underlaying hardware is initialized
 * and prepared for data exchange.
 *
 * @param context Context structure for the SSCP.
 * @param base The MU peripheral base address to be used for communication
 *
 * @returns Status of the operation
 * @retval kStatus_SSCP_Success SSCP init success
 * @retval kStatus_SSCP_Fail SSCP init failure
 */
sscp_status_t sscp_mu_init(sscp_context_t *context, MU_Type *base);

/*! @brief Close the SSCP link
 *
 * This function closes the SSCP link - e.g.underlying hardware is disabled.
 *
 * @param context Context structure for the SSCP.
 */
void sscp_mu_deinit(sscp_context_t *context);

/*! @brief Sends a command and associated parameters to security sub-system
 *
 *  The commandID and operation content is serialized and sent over to the selected security sub-system.
 *  This is implementation specific function.
 *  The function can invoke both blocking and non-blocking secure functions in the selected security sub-system.
 *
 * @param context Initialized SSCP context
 * @param commandID Command - an id of a remote secure function to be invoked
 * @param op Description of function arguments as a sequence of buffers and values
 * @param ret Return code of the remote secure function (application layer return value)
 *
 * @returns Status of the operation
 * @retval kStatus_SSCP_Success A blocking command has completed or a non-blocking command has been accepted.
 * @retval kStatus_SSCP_Fail Operation failure, for example hardware fail.
 * @retval kStatus_SSCP_InvalidArgument One of the arguments is invalid for the function to execute.
 */
sscp_status_t sscp_mu_invoke_command(sscp_context_t *context, uint32_t commandID, sscp_operation_t *op, uint32_t *ret);

#if defined(__cplusplus)
}
#endif

/*!
 *@}
 */ /* end of sscp_mu */

#endif /* _FSL_SSCP_MU_H_ */
