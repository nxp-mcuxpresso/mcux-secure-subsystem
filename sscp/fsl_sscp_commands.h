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
#ifndef _FSL_SSCP_COMMANDS_H_
#define _FSL_SSCP_COMMANDS_H_

/*!
@defgroup sscp_cmd SSCP commands
@details This section describes the SSCP commands and parameters.
@ingroup sscp
*/

/*!
 * @addtogroup sscp_cmd
 * @{
 */

/*! @brief SSCP common commands */
typedef enum _sscp_command
{
    kSSCP_CMD_SSS_OpenSession,
    kSSCP_CMD_SSS_CloseSession,
    kSSCP_CMD_SSS_SymmetricCipherOneGo,
    kSSCP_CMD_SSS_SymmetricCipherInit,
    kSSCP_CMD_SSS_SymmetricCipherUpdate,
    kSSCP_CMD_SSS_SymmetricCipherFinish,
    kSSCP_CMD_SSS_SymmetricCryptCtr,
    kSSCP_CMD_SSS_AeadOneGo,
    kSSCP_CMD_SSS_AeadOneInit,
    kSSCP_CMD_SSS_AeadOneUpdateAad,
    kSSCP_CMD_SSS_AeadOneUpdate,
    kSSCP_CMD_SSS_AeadOneFinish,
    kSSCP_CMD_SSS_DigestOneGo,
    kSSCP_CMD_SSS_DigestInit,
    kSSCP_CMD_SSS_DigestUpdate,
    kSSCP_CMD_SSS_DigestFinish,
    kSSCP_CMD_SSS_MacOneGo,
    kSSCP_CMD_SSS_MacOneInit,
    kSSCP_CMD_SSS_MacOneUpdate,
    kSSCP_CMD_SSS_MacOneFinish,
    kSSCP_CMD_SSS_AsymmetricEncrypt,
    kSSCP_CMD_SSS_AsymmetricDecrypt,
    kSSCP_CMD_SSS_AsymmetricSignDigest,
    kSSCP_CMD_SSS_AsymmetricVerifyDigest,
    kSSCP_CMD_SSS_Tunnel,
    kSSCP_CMD_SSS_DeriveKey,
    kSSCP_CMD_SSS_AsymmetricDeriveKey,
    kSSCP_CMD_SSS_KeyObjectAllocateHandle,
    kSSCP_CMD_SSS_KeyObjectGetHandle,
    kSSCP_CMD_SSS_KeyStoreAllocate,
    kSSCP_CMD_SSS_KeyStoreSave,
    kSSCP_CMD_SSS_KeyStoreLoad,
    kSSCP_CMD_SSS_KeyStoreSetKey,
    kSSCP_CMD_SSS_KeyStoreGenerateKey,
    kSSCP_CMD_SSS_KeyStoreGetKey,
    kSSCP_CMD_SSS_KeyStoreOpenKey,
    kSSCP_CMD_SSS_KeyStoreFreezeKey,
    kSSCP_CMD_SSS_KeyStoreEraseKey,
    kSSCP_CMD_SSS_KeyStoreEraseAll,
} sscp_command_t;

enum _sscp_context_type
{
    kSSCP_ParamContextType_SSS_Symmetric = 1u,
    kSSCP_ParamContextType_SSS_Digest,
    kSSCP_ParamContextType_SSS_Asymmetric,
    kSSCP_ParamContextType_SSS_DeriveKey,
    kSSCP_ParamContextType_SSS_Object,
    kSSCP_ParamContextType_SSS_KeyStore,
};

/*!
 *@}
 */ /* end of sscp */

#endif /* _FSL_SSCP_COMMANDS_H_ */
