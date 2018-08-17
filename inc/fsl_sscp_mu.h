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

<table width="60%" class="markdownTable">
<tr class="markdownTableHead">
<th class="markdownTableHeadNone" width="30%"> Symmetric Cipher One Go <th class="markdownTableHeadNone" width="10%"> TX
<th class="markdownTableHeadNone" width="60%"> MU TXn register value
<tr><td> Command     <td> 0  <td> kSSCP_CMD_SSS_SymmetricCipherOneGo
<tr><td> paramTypes  <td> 1  <td> Aggregate, MemrefInput, MemrefInput, MemrefOutput
<tr><td> word        <td> 2  <td> Pointer to ::_sss_sscp_symmetric
<tr><td> word        <td> 3  <td> Pointer to iv
<tr><td> word        <td> 4  <td> ivLen
<tr><td> word        <td> 5  <td> Pointer to srcData
<tr><td> word        <td> 6  <td> dataLen
<tr><td> word        <td> 7  <td> Pointer to destData
<tr><td> word        <td> 8  <td> Pointer to dataLen
</table>

## Digest

<table width="60%" class="markdownTable">
<tr class="markdownTableHead">
<th class="markdownTableHeadNone" width="30%"> Digest One Go <th class="markdownTableHeadNone" width="10%"> TX  <th
class="markdownTableHeadNone" width="60%"> MU TXn register value
<tr><td> Command     <td> 0  <td> kSSCP_CMD_SSS_DigestOneGo
<tr><td> paramTypes  <td> 1  <td> Aggregate, MemrefInput, MemrefOutput
<tr><td> word        <td> 2  <td> Pointer to ::_sss_sscp_digest
<tr><td> word        <td> 3  <td> Pointer to message
<tr><td> word        <td> 4  <td> messageLen
<tr><td> word        <td> 5  <td> Pointer to digest
<tr><td> word        <td> 6  <td> Pointer to dataLen
</table>

<table width="60%" class="markdownTable">
<tr class="markdownTableHead">
<th class="markdownTableHeadNone" width="30%"> Digest Init <th class="markdownTableHeadNone" width="10%"> TX  <th
class="markdownTableHeadNone" width="60%"> MU TXn register value
<tr><td> Command     <td> 0  <td> kSSCP_CMD_SSS_DigestInit
<tr><td> paramTypes  <td> 1  <td> Aggregate
<tr><td> word        <td> 2  <td> Pointer to ::_sss_sscp_digest
</table>

<table width="60%" class="markdownTable">
<tr class="markdownTableHead">
<th class="markdownTableHeadNone" width="30%"> Digest Update <th class="markdownTableHeadNone" width="10%"> TX  <th
class="markdownTableHeadNone" width="60%"> MU TXn register value
<tr><td> Command     <td> 0  <td> kSSCP_CMD_SSS_DigestUpdate
<tr><td> paramTypes  <td> 1  <td> Aggregate, MemrefInput
<tr><td> word        <td> 2  <td> Pointer to ::_sss_sscp_digest
<tr><td> word        <td> 3  <td> Pointer to message
<tr><td> word        <td> 4  <td> messageLen
</table>

<table width="60%" class="markdownTable">
<tr class="markdownTableHead">
<th class="markdownTableHeadNone" width="30%"> Digest Finish <th class="markdownTableHeadNone" width="10%"> TX  <th
class="markdownTableHeadNone" width="60%"> MU TXn register value
<tr><td> Command     <td> 0  <td> kSSCP_CMD_SSS_DigestFinish
<tr><td> paramTypes  <td> 1  <td> Aggregate, MemrefOutput
<tr><td> word        <td> 2  <td> Pointer to ::_sss_sscp_digest
<tr><td> word        <td> 3  <td> Pointer to digest
<tr><td> word        <td> 4  <td> Pointer to dataLen
</table>

## Asymmetric

<table width="60%" class="markdownTable">
<tr class="markdownTableHead">
<th class="markdownTableHeadNone" width="30%"> Asymmetric Sign Digest <th class="markdownTableHeadNone" width="10%"> TX
<th class="markdownTableHeadNone" width="60%"> MU TXn register value
<tr><td> Command     <td> 0  <td> kSSCP_CMD_SSS_AsymmetricSignDigest
<tr><td> paramTypes  <td> 1  <td> Aggregate, MemrefInput, MemrefOutput
<tr><td> word        <td> 2  <td> Pointer to ::_sss_sscp_asymmetric
<tr><td> word        <td> 3  <td> Pointer to digest
<tr><td> word        <td> 4  <td> digestLen
<tr><td> word        <td> 5  <td> Pointer to signature
<tr><td> word        <td> 6  <td> Pointer to signatureLen
</table>

<table width="60%" class="markdownTable">
<tr class="markdownTableHead">
<th class="markdownTableHeadNone" width="30%"> Asymmetric Verify Digest <th class="markdownTableHeadNone" width="10%">
TX  <th class="markdownTableHeadNone" width="60%"> MU TXn register value
<tr><td> Command     <td> 0  <td> kSSCP_CMD_SSS_AsymmetricVerifyDigest
<tr><td> paramTypes  <td> 1  <td> Aggregate, MemrefInput, MemrefInput
<tr><td> word        <td> 2  <td> Pointer to ::_sss_sscp_asymmetric
<tr><td> word        <td> 3  <td> Pointer to digest
<tr><td> word        <td> 4  <td> digestLen
<tr><td> word        <td> 5  <td> Pointer to signature
<tr><td> word        <td> 6  <td> signatureLen
</table>

<table width="60%" class="markdownTable">
<tr class="markdownTableHead">
<th class="markdownTableHeadNone" width="30%"> Asymmetric Derive Key <th class="markdownTableHeadNone" width="10%"> TX
<th class="markdownTableHeadNone" width="60%"> MU TXn register value
<tr><td> Command     <td> 0  <td> kSSCP_CMD_SSS_AsymmetricDeriveKey
<tr><td> paramTypes  <td> 1  <td> Aggregate, Aggregate, Aggregate
<tr><td> word        <td> 2  <td> Pointer to ::_sss_sscp_derive_key
<tr><td> word        <td> 3  <td> Pointer to ::_sss_sscp_object
<tr><td> word        <td> 4  <td> Pointer to ::_sss_sscp_object
</table>

## Key Object

<table width="60%" class="markdownTable">
<tr class="markdownTableHead">
<th class="markdownTableHeadNone" width="30%"> Key Object Allocate Handle <th class="markdownTableHeadNone" width="10%">
TX  <th class="markdownTableHeadNone" width="60%"> MU TXn register value
<tr><td> Command     <td> 0  <td> kSSCP_CMD_SSS_KeyObjectAllocateHandle
<tr><td> paramTypes  <td> 1  <td> Aggregate, ValueInput, ValueInput
<tr><td> word        <td> 2  <td> Pointer to ::_sss_sscp_object
<tr><td> word        <td> 3  <td> keyId
<tr><td> word        <td> 4  <td> keyType
<tr><td> word        <td> 5  <td> keyByteLenMax
<tr><td> word        <td> 6  <td> options
</table>

## Key Store

<table width="60%" class="markdownTable">
<tr class="markdownTableHead">
<th class="markdownTableHeadNone" width="30%"> Key Store Allocate <th class="markdownTableHeadNone" width="10%"> TX  <th
class="markdownTableHeadNone" width="60%"> MU TXn register value
<tr><td> Command     <td> 0  <td> kSSCP_CMD_SSS_KeyStoreAllocate
<tr><td> paramTypes  <td> 1  <td> Aggregate, ValueInput
<tr><td> word        <td> 2  <td> Pointer to ::_sss_sscp_key_store
<tr><td> word        <td> 3  <td> keyStoreId
<tr><td> word        <td> 4  <td> Zero
</table>

<table width="60%" class="markdownTable">
<tr class="markdownTableHead">
<th class="markdownTableHeadNone" width="30%"> Key Store Set Key <th class="markdownTableHeadNone" width="10%"> TX  <th
class="markdownTableHeadNone" width="60%"> MU TXn register value
<tr><td> Command     <td> 0  <td> kSSCP_CMD_SSS_KeyStoreSetKey
<tr><td> paramTypes  <td> 1  <td> Aggregate, Aggregate, MemrefInput, ValueInput, MemrefInput
<tr><td> word        <td> 2  <td> Pointer to ::_sss_sscp_key_store
<tr><td> word        <td> 3  <td> Pointer to ::_sss_sscp_object
<tr><td> word        <td> 4  <td> Pointer to key buffer
<tr><td> word        <td> 5  <td> Length of key buffer in bytes
<tr><td> word        <td> 6  <td> Key Length in bits
<tr><td> word        <td> 7  <td> Zero
<tr><td> word        <td> 8  <td> Pointer to options buffer
<tr><td> word        <td> 9  <td> Length of the options buffer in bytes
</table>

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
    fn_sscp_invoke_command_t invoke;

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
