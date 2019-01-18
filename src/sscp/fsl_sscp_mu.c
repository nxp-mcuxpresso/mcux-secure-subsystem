/*
 * Copyright 2018 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include <stdint.h>
#include <stdio.h>

#include "fsl_sscp_mu.h"
#include "msgunit_driver.h"

#define MU_Deinit (void)
/*TODO: should be redesigned to more generic solution*/
void MU_Init() {
  k4mu_init();
}
/*TODO: should be redesigned to more generic solution*/
sscp_status_t MU_ReceiveMsg(MU_Type *base, uint32_t msg[MU_RR_COUNT], size_t wordNum)
{
  if (k4mu_get_response(msg, wordNum) != MU_SUCCESS_RESULT) {
    return kStatus_SSCP_Fail;
  }
  return kStatus_SSCP_Success;
}
/*TODO: should be redesigned to more generic solution*/
sscp_status_t MU_SendMsg(MU_Type *base, uint32_t msg[MU_TR_COUNT], size_t wordNum)
{
  if (k4mu_send_message(msg, wordNum) != MU_SUCCESS_RESULT) {
    return kStatus_SSCP_Fail;
  }
  return kStatus_SSCP_Success;
}

sscp_status_t sscp_mu_init(sscp_context_t *context, MU_Type *base)
{
    sscp_mu_context_t *muContext = (sscp_mu_context_t *)(uintptr_t)context;

    muContext->base = base;
    MU_Init();

    /* assign MU implementation of ::sscp_invoke_command() */
    muContext->invoke = sscp_mu_invoke_command;
    return kStatus_SSCP_Success;
}

void sscp_mu_deinit(sscp_context_t *context)
{
    sscp_mu_context_t *muContext = (sscp_mu_context_t *)(uintptr_t)context;

    MU_Deinit(muContext->base);
}

sscp_status_t sscp_mu_invoke_command(sscp_context_t *context, sscp_command_t commandID, sscp_operation_t *op, uint32_t *ret)
{
    sscp_mu_context_t *muContext = (sscp_mu_context_t *)(uintptr_t)context;
    /* parse the operation to create message */
    uint32_t msg[MU_TR_COUNT] = {0}; 
    int wrIdx = 1;

    bool done = false;
    for (int i = 0; !done && (i < SSCP_OPERATION_PARAM_COUNT); i++)
    {
        switch (SSCP_OP_GET_PARAM(i, op->paramTypes))
        {
            case kSSCP_ParamType_ContextReference:
                msg[wrIdx++] = (uint32_t)(op->params[i].context.ptr);
                break;

            case kSSCP_ParamType_Aggregate:
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
      
            case kSSCP_ParamType_SingleValueInput:
              msg[wrIdx++] = op->params[i].value.a;
              break;
    
            case kSSCP_ParamType_None:
                done = true; /* break the for loop */
                break;

            default:
                break;
        }
        if (wrIdx >= MU_TR_COUNT)
        {
            break;
        }
    }
    /*TODO: should be redesigned to more generic solution*/
    mu_hdr_t muHeader;
    muHeader.check_bits = STATIC_CHECK_BITS;
    muHeader.tag_sts = MESSAGING_TAG_COMMAND;
    muHeader.command = commandID;
    muHeader.size = wrIdx - 1;
    msg[0] = *((uint32_t*)&muHeader);

    if (MU_SendMsg(muContext->base, msg, wrIdx) != kStatus_SSCP_Success) {
      return kStatus_SSCP_Fail;
    }
    /* poll for response */
    if (MU_ReceiveMsg(muContext->base, msg, 1) != kStatus_SSCP_Success) {
      return kStatus_SSCP_Fail;
    }
    *ret = msg[0];

    return kStatus_SSCP_Success;
}
