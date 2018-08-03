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

#include "fsl_sscp_mu.h"
// #include "fsl_sscp_mu.h"
#define MU_Init (void)
#define MU_Deinit (void)

uint32_t MU_ReceiveMsg(MU_Type *base, uint32_t msg[16])
{
    return 0;
}

void MU_SendMsg(MU_Type *base, uint32_t msg[16], uint32_t wordNum)
{
    return;
}

sscp_status_t sscp_mu_init(sscp_context_t *context, MU_Type *base)
{
    sscp_mu_context_t *muContext = (sscp_mu_context_t *)(uintptr_t)context;

    muContext->base = base;
    MU_Init(base);

    /* assign MU implementation of ::sscp_invoke_command() */
    muContext->sscp_invoke_command = sscp_mu_invoke_command;
    return kStatus_SSCP_Success;
}

void sscp_mu_deinit(sscp_context_t *context)
{
    sscp_mu_context_t *muContext = (sscp_mu_context_t *)(uintptr_t)context;

    MU_Deinit(muContext->base);
}

sscp_status_t sscp_mu_invoke_command(sscp_context_t *context, uint32_t commandID, sscp_operation_t *op, uint32_t *ret)
{
    sscp_mu_context_t *muContext = (sscp_mu_context_t *)(uintptr_t)context;

    /* parse the operation to create message */
    uint32_t msg[16] = {0};

    msg[0] = commandID;
    msg[1] = op->paramTypes;
    int wrIdx = 2;

    bool done = false;
    for (int i = 0; !done && (i < SSCP_OPERATION_PARAM_COUNT); i++)
    {
        switch (SSCP_OP_GET_PARAM(i, op->paramTypes))
        {
            case kSSCP_ParamType_Aggregate:
                /* for MU, the aggregate SSCP operation defines one kSSCP_ParamType_MemrefInOut */
                msg[wrIdx++] = (uint32_t)(op->params[i].aggregate.op->params[0].memref.buffer);
                break;

            case kSSCP_ParamType_MemrefInput:
            case kSSCP_ParamType_MemrefInOut:
                msg[wrIdx++] = (uint32_t)(op->params[i].memref.buffer);
                msg[wrIdx++] = op->params[i].memref.size;
                break;

            case kSSCP_ParamType_MemrefOutput:
                msg[wrIdx++] = (uint32_t)(op->params[i].memref.buffer);
                msg[wrIdx++] = (uint32_t) & (op->params[i].memref.size);
                break;

            case kSSCP_ParamType_ValueInput:
                msg[wrIdx++] = op->params[i].value.a;
                msg[wrIdx++] = op->params[i].value.b;
                break;

            case kSSCP_ParamType_None:
                done = true; /* break the for loop */
                break;

            default:
                break;
        }

        if (wrIdx >= 16)
        {
            break;
        }
    }

    MU_SendMsg(muContext->base, msg, wrIdx);
    
    /* poll for response */
    MU_ReceiveMsg(muContext->base, msg);
    *ret = msg[1];

    return kStatus_SSCP_Success;
}
