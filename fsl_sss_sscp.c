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

#include "fsl_sss_sscp.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "fsl_sss_api.h"
#include "sscp/fsl_sscp.h"
#include "sscp/fsl_sscp_commands.h"

sss_status_t sss_sscp_cipher_one_go(
    sss_sscp_symmetric_t *context, uint8_t *iv, size_t ivLen, const uint8_t *srcData, uint8_t *destData, size_t dataLen)
{
    SSCP_BUILD_ASSURE(sizeof(sss_symmetric_t) >= sizeof(sss_sscp_symmetric_t), _sss_sscp_symmetric_size);
    sscp_operation_t op = {0};
    sscp_status_t status = kStatus_SSCP_Fail;
    uint32_t ret = 0;

    op.paramTypes = SSCP_OP_SET_PARAM(kSSCP_ParamType_Aggregate, kSSCP_ParamType_MemrefInput,
                                      kSSCP_ParamType_MemrefInput, kSSCP_ParamType_MemrefOutput, kSSCP_ParamType_None,
                                      kSSCP_ParamType_None, kSSCP_ParamType_None);

    op.params[0].aggregate.op = &context->op;
    op.params[1].memref.buffer = iv;
    op.params[1].memref.size = ivLen;
    op.params[2].memref.buffer = (void *)(uintptr_t)srcData;
    op.params[2].memref.size = dataLen;
    op.params[3].memref.buffer = destData;
    op.params[3].memref.size = dataLen;

    sscp_context_t *sscpCtx = context->session->sscp;
    status = sscpCtx->sscp_invoke_command(sscpCtx, kSSCP_CMD_SSS_SymmetricCipherOneGo, &op, &ret);
    if (status != kStatus_SSCP_Success)
    {
        return kStatus_SSS_Fail;
    }

    return (sss_status_t)ret;
}

sss_status_t sss_sscp_digest_one_go(
    sss_sscp_digest_t *context, const uint8_t *message, size_t messageLen, uint8_t *digest, size_t *digestLen)
{
    SSCP_BUILD_ASSURE(sizeof(sss_digest_t) >= sizeof(sss_sscp_digest_t), _sss_sscp_digest_size);
    sscp_operation_t op = {0};
    sscp_status_t status = kStatus_SSCP_Fail;
    uint32_t ret = 0;

    /* if the caller gives NULL pointer to digestLen, it is assumed that digest[] buffer is big enough to hold full
     * digest */
    size_t len = (digestLen != NULL) ? *digestLen : context->digestFullLen;

    /* if the *digestLen cannot hold full digest (per algorithm spec) return error */
    if (len < context->digestFullLen)
    {
        return kStatus_SSS_Fail;
    }

    op.paramTypes =
        SSCP_OP_SET_PARAM(kSSCP_ParamType_Aggregate, kSSCP_ParamType_MemrefInput, kSSCP_ParamType_MemrefOutput,
                          kSSCP_ParamType_None, kSSCP_ParamType_None, kSSCP_ParamType_None, kSSCP_ParamType_None);

    op.params[0].aggregate.op = &context->op;
    op.params[1].memref.buffer = (void *)(uintptr_t)message;
    op.params[1].memref.size = messageLen;
    op.params[2].memref.buffer = digest;
    op.params[2].memref.size = len;

    sscp_context_t *sscpCtx = context->session->sscp;
    status = sscpCtx->sscp_invoke_command(sscpCtx, kSSCP_CMD_SSS_DigestOneGo, &op, &ret);
    if (status != kStatus_SSCP_Success)
    {
        if (digestLen)
        {
            *digestLen = 0;
        }
        return kStatus_SSS_Fail;
    }

    /* update the size member of kSSCP_ParamType_MemrefOutput param with the actual byte length written to output buffer
     */
    if (digestLen)
    {
        *digestLen = op.params[2].memref.size;
    }

    return (sss_status_t)ret;
}

sss_status_t sss_sscp_digest_init(sss_sscp_digest_t *context)
{
    sscp_operation_t op = {0};
    sscp_status_t status = kStatus_SSCP_Fail;
    uint32_t ret = 0;

    op.paramTypes =
        SSCP_OP_SET_PARAM(kSSCP_ParamType_Aggregate, kSSCP_ParamType_None, kSSCP_ParamType_None, kSSCP_ParamType_None,
                          kSSCP_ParamType_None, kSSCP_ParamType_None, kSSCP_ParamType_None);

    op.params[0].aggregate.op = &context->op;

    sscp_context_t *sscpCtx = context->session->sscp;
    status = sscpCtx->sscp_invoke_command(sscpCtx, kSSCP_CMD_SSS_DigestInit, &op, &ret);
    if (status != kStatus_SSCP_Success)
    {
        return kStatus_SSS_Fail;
    }

    return (sss_status_t)ret;
}

sss_status_t sss_sscp_digest_update(sss_sscp_digest_t *context, const uint8_t *message, size_t messageLen)
{
    sscp_operation_t op = {0};
    sscp_status_t status = kStatus_SSCP_Fail;
    uint32_t ret = 0;

    op.paramTypes =
        SSCP_OP_SET_PARAM(kSSCP_ParamType_Aggregate, kSSCP_ParamType_MemrefInput, kSSCP_ParamType_None,
                          kSSCP_ParamType_None, kSSCP_ParamType_None, kSSCP_ParamType_None, kSSCP_ParamType_None);

    op.params[0].aggregate.op = &context->op;
    op.params[1].memref.buffer = (void *)(uintptr_t)message;
    op.params[1].memref.size = messageLen;

    sscp_context_t *sscpCtx = context->session->sscp;
    status = sscpCtx->sscp_invoke_command(sscpCtx, kSSCP_CMD_SSS_DigestUpdate, &op, &ret);
    if (status != kStatus_SSCP_Success)
    {
        return kStatus_SSS_Fail;
    }

    return (sss_status_t)ret;
}

sss_status_t sss_sscp_digest_finish(sss_sscp_digest_t *context, uint8_t *digest, size_t *digestLen)
{
    sscp_operation_t op = {0};
    sscp_status_t status = kStatus_SSCP_Fail;
    uint32_t ret = 0;

    /* if the caller gives NULL pointer to digestLen, it is assumed that digest[] buffer is big enough to hold full
     * digest */
    size_t len = (digestLen != NULL) ? *digestLen : context->digestFullLen;

    /* if the *digestLen cannot hold full digest (per algorithm spec) return error */
    if (len < context->digestFullLen)
    {
        return kStatus_SSS_Fail;
    }

    op.paramTypes =
        SSCP_OP_SET_PARAM(kSSCP_ParamType_Aggregate, kSSCP_ParamType_MemrefOutput, kSSCP_ParamType_None,
                          kSSCP_ParamType_None, kSSCP_ParamType_None, kSSCP_ParamType_None, kSSCP_ParamType_None);

    op.params[0].aggregate.op = &context->op;
    op.params[1].memref.buffer = digest;
    op.params[1].memref.size = len;

    sscp_context_t *sscpCtx = context->session->sscp;
    status = sscpCtx->sscp_invoke_command(sscpCtx, kSSCP_CMD_SSS_DigestFinish, &op, &ret);
    if (status != kStatus_SSCP_Success)
    {
        if (digestLen)
        {
            *digestLen = 0;
        }
        return kStatus_SSS_Fail;
    }

    /* the size member of kSSCP_ParamType_MemrefOutput param is updated with the actual byte length written to output
     * buffer
     */
    if (digestLen)
    {
        *digestLen = op.params[1].memref.size;
    }

    return (sss_status_t)ret;
}

sss_status_t sss_sscp_asymmetric_sign_digest(
    sss_sscp_asymmetric_t *context, uint8_t *digest, size_t digestLen, uint8_t *signature, size_t *signatureLen)
{
    SSCP_BUILD_ASSURE(sizeof(sss_asymmetric_t) >= sizeof(sss_sscp_asymmetric_t), _sss_sscp_asymmetric_size);
    sscp_operation_t op = {0};
    sscp_status_t status = kStatus_SSCP_Fail;
    uint32_t ret = 0;

    /* if the caller gives NULL pointer to signatureLen, it is assumed that signature[] buffer is big enough to hold
     * full
     * signature */
    size_t len = (signatureLen != NULL) ? *signatureLen : context->signatureFullLen;

    /* if the *signatureLen cannot hold full signature (per algorithm spec) return error */
    if (len < context->signatureFullLen)
    {
        return kStatus_SSS_Fail;
    }

    op.paramTypes =
        SSCP_OP_SET_PARAM(kSSCP_ParamType_Aggregate, kSSCP_ParamType_MemrefInput, kSSCP_ParamType_MemrefOutput,
                          kSSCP_ParamType_None, kSSCP_ParamType_None, kSSCP_ParamType_None, kSSCP_ParamType_None);

    op.params[0].aggregate.op = &context->op;
    op.params[1].memref.buffer = digest;
    op.params[1].memref.size = digestLen;
    op.params[2].memref.buffer = signature;
    op.params[2].memref.size = len;

    sscp_context_t *sscpCtx = context->session->sscp;
    status = sscpCtx->sscp_invoke_command(sscpCtx, kSSCP_CMD_SSS_AsymmetricSignDigest, &op, &ret);
    if (status != kStatus_SSCP_Success)
    {
        return kStatus_SSS_Fail;
    }

    /* the size member of kSSCP_ParamType_MemrefOutput param is updated with the actual byte length written to output
     * buffer
     */
    if (signatureLen)
    {
        *signatureLen = op.params[2].memref.size;
    }

    return (sss_status_t)ret;
}

sss_status_t sss_sscp_asymmetric_verify_digest(
    sss_sscp_asymmetric_t *context, uint8_t *digest, size_t digestLen, uint8_t *signature, size_t signatureLen)
{
    sscp_operation_t op = {0};
    sscp_status_t status = kStatus_SSCP_Fail;
    uint32_t ret = 0;

    op.paramTypes =
        SSCP_OP_SET_PARAM(kSSCP_ParamType_Aggregate, kSSCP_ParamType_MemrefInput, kSSCP_ParamType_MemrefInput,
                          kSSCP_ParamType_None, kSSCP_ParamType_None, kSSCP_ParamType_None, kSSCP_ParamType_None);

    op.params[0].aggregate.op = &context->op;
    op.params[1].memref.buffer = digest;
    op.params[1].memref.size = digestLen;
    op.params[2].memref.buffer = signature;
    op.params[2].memref.size = signatureLen;

    sscp_context_t *sscpCtx = context->session->sscp;
    status = sscpCtx->sscp_invoke_command(sscpCtx, kSSCP_CMD_SSS_AsymmetricVerifyDigest, &op, &ret);
    if (status != kStatus_SSCP_Success)
    {
        return kStatus_SSS_Fail;
    }

    return (sss_status_t)ret;
}

sss_status_t sss_sscp_asymmetric_dh_derive_key(sss_sscp_derive_key_t *context,
                                               sss_sscp_object_t *otherPartyKeyObject,
                                               sss_sscp_object_t *derivedKeyObject)
{
    SSCP_BUILD_ASSURE(sizeof(sss_derive_key_t) >= sizeof(sss_sscp_derive_key_t), _sss_sscp_derive_key_size);
    sscp_operation_t op = {0};
    sscp_status_t status = kStatus_SSCP_Fail;
    uint32_t ret = 0;

    op.paramTypes =
        SSCP_OP_SET_PARAM(kSSCP_ParamType_Aggregate, kSSCP_ParamType_Aggregate, kSSCP_ParamType_Aggregate,
                          kSSCP_ParamType_None, kSSCP_ParamType_None, kSSCP_ParamType_None, kSSCP_ParamType_None);

    op.params[0].aggregate.op = &context->op;
    op.params[1].aggregate.op = &otherPartyKeyObject->op;
    op.params[2].aggregate.op = &derivedKeyObject->op;

    sscp_context_t *sscpCtx = context->session->sscp;
    status = sscpCtx->sscp_invoke_command(sscpCtx, kSSCP_CMD_SSS_AsymmetricDeriveKey, &op, &ret);
    if (status != kStatus_SSCP_Success)
    {
        return kStatus_SSS_Fail;
    }

    return (sss_status_t)ret;
}

sss_status_t sss_sscp_key_store_allocate(sss_sscp_key_store_t *keyStore, uint32_t keyStoreId)
{
    SSCP_BUILD_ASSURE(sizeof(sss_key_store_t) >= sizeof(sss_sscp_key_store_t), _sss_sscp_key_store_size);
    sscp_operation_t op = {0};
    sscp_status_t status = kStatus_SSCP_Fail;
    uint32_t ret = 0;

    op.paramTypes =
        SSCP_OP_SET_PARAM(kSSCP_ParamType_Aggregate, kSSCP_ParamType_ValueInput, kSSCP_ParamType_None,
                          kSSCP_ParamType_None, kSSCP_ParamType_None, kSSCP_ParamType_None, kSSCP_ParamType_None);

    op.params[0].aggregate.op = &keyStore->op;
    op.params[1].value.a = keyStoreId;
    op.params[1].value.b = 0;

    sscp_context_t *sscpCtx = keyStore->session->sscp;
    status = sscpCtx->sscp_invoke_command(sscpCtx, kSSCP_CMD_SSS_KeyStoreAllocate, &op, &ret);
    if (status != kStatus_SSCP_Success)
    {
        return kStatus_SSS_Fail;
    }

    return (sss_status_t)ret;
}

sss_status_t sss_sscp_key_object_allocate_handle(
    sss_sscp_object_t *keyObject, uint32_t keyId, sss_key_type_t keyType, uint32_t keyByteLenMax, uint32_t options)
{
    SSCP_BUILD_ASSURE(sizeof(sss_object_t) >= sizeof(sss_sscp_object_t), _sss_sscp_object_size);
    sscp_operation_t op = {0};
    sscp_status_t status = kStatus_SSCP_Fail;
    uint32_t ret = 0;

    op.paramTypes =
        SSCP_OP_SET_PARAM(kSSCP_ParamType_Aggregate, kSSCP_ParamType_ValueInput, kSSCP_ParamType_ValueInput,
                          kSSCP_ParamType_None, kSSCP_ParamType_None, kSSCP_ParamType_None, kSSCP_ParamType_None);

    op.params[0].aggregate.op = &keyObject->op;
    op.params[1].value.a = keyId;
    op.params[1].value.b = (uint32_t)keyType;
    op.params[2].value.a = keyByteLenMax;
    op.params[2].value.b = (uint32_t)options;

    sscp_context_t *sscpCtx = keyObject->keyStore->session->sscp;
    status = sscpCtx->sscp_invoke_command(sscpCtx, kSSCP_CMD_SSS_KeyObjectAllocateHandle, &op, &ret);
    if (status != kStatus_SSCP_Success)
    {
        return kStatus_SSS_Fail;
    }

    return (sss_status_t)ret;
}

sss_status_t sss_sscp_key_store_set_key(sss_sscp_key_store_t *keyStore,
                                        sss_sscp_object_t *keyObject,
                                        const uint8_t *key,
                                        uint32_t keyBitLen,
                                        void *options,
                                        size_t optionsLen)
{
    sscp_operation_t op = {0};
    sscp_status_t status = kStatus_SSCP_Fail;
    uint32_t ret = 0;

    op.paramTypes = SSCP_OP_SET_PARAM(kSSCP_ParamType_Aggregate, kSSCP_ParamType_Aggregate, kSSCP_ParamType_MemrefInput,
                                      kSSCP_ParamType_ValueInput, kSSCP_ParamType_MemrefInput, kSSCP_ParamType_None,
                                      kSSCP_ParamType_None);

    op.params[0].aggregate.op = &keyStore->op;
    op.params[1].aggregate.op = &keyObject->op;
    op.params[2].memref.buffer = (void *)(uintptr_t)key;
    op.params[2].memref.size = (keyBitLen + 7u) / 8u;
    op.params[3].value.a = keyBitLen;
    op.params[3].value.b = 0;
    op.params[4].memref.buffer = options;
    op.params[4].memref.size = optionsLen;

    sscp_context_t *sscpCtx = keyStore->session->sscp;
    status = sscpCtx->sscp_invoke_command(sscpCtx, kSSCP_CMD_SSS_KeyStoreSetKey, &op, &ret);
    if (status != kStatus_SSCP_Success)
    {
        return kStatus_SSS_Fail;
    }

    return (sss_status_t)ret;
}
