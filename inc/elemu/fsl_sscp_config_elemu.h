/*
 * Copyright 2018-2021 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef FSL_SSCP_CONFIG_ELEMU_H
#define FSL_SSCP_CONFIG_ELEMU_H

#define SSCP_COMMAND_ENUM_ALT
typedef uint8_t sscp_command_t;
#define kSSCP_CMD_SSS_OpenSession                   ((sscp_command_t)0x13)
#define kSSCP_CMD_SSS_CloseSession                  ((sscp_command_t)0x14)
#define kSSCP_CMD_SSS_Ping                          ((sscp_command_t)0x11)
#define kSSCP_CMD_SSS_ContextFree                   ((sscp_command_t)0x15)
#define kSSCP_CMD_SSS_SymmetricContextInit          ((sscp_command_t)0x25)
#define kSSCP_CMD_SSS_SymmetricCipherOneGo          ((sscp_command_t)0x23)
#define kSSCP_CMD_SSS_SymmetricCipherInit           ((sscp_command_t)0x22)
#define kSSCP_CMD_SSS_SymmetricCipherUpdate         ((sscp_command_t)0x24)
#define kSSCP_CMD_SSS_SymmetricCipherFinish         ((sscp_command_t)0x21)
#define kSSCP_CMD_SSS_SymmetricCryptCtr             ((sscp_command_t)0x20)
#define kSSCP_CMD_SSS_AeadContextInit               ((sscp_command_t)0x26)
#define kSSCP_CMD_SSS_AeadOneGo                     ((sscp_command_t)0x29)
#define kSSCP_CMD_SSS_AeadInit                      ((sscp_command_t)0x28)
#define kSSCP_CMD_SSS_AeadUpdateAead                ((sscp_command_t)0x2b)
#define kSSCP_CMD_SSS_AeadUpdate                    ((sscp_command_t)0x2a)
#define kSSCP_CMD_SSS_AeadFinish                    ((sscp_command_t)0x27)
#define kSSCP_CMD_SSS_DigestContextInit             ((sscp_command_t)0x2c)
#define kSSCP_CMD_SSS_DigestOneGo                   ((sscp_command_t)0x2f)
#define kSSCP_CMD_SSS_DigestInit                    ((sscp_command_t)0x2e)
#define kSSCP_CMD_SSS_DigestUpdate                  ((sscp_command_t)0x30)
#define kSSCP_CMD_SSS_DigestFinish                  ((sscp_command_t)0x2d)
#define kSSCP_CMD_SSS_DigestClone                   ((sscp_command_t)0x81)
#define kSSCP_CMD_SSS_MacContextInit                ((sscp_command_t)0x32)
#define kSSCP_CMD_SSS_MacOneGo                      ((sscp_command_t)0x35)
#define kSSCP_CMD_SSS_MacInit                       ((sscp_command_t)0x34)
#define kSSCP_CMD_SSS_MacUpdate                     ((sscp_command_t)0x36)
#define kSSCP_CMD_SSS_MacFinish                     ((sscp_command_t)0x33)
#define kSSCP_CMD_SSS_AsymetricContextInit          ((sscp_command_t)0x37)
#define kSSCP_CMD_SSS_AsymmetricEncrypt             ((sscp_command_t)0x39)
#define kSSCP_CMD_SSS_AsymmetricDecrypt             ((sscp_command_t)0x38)
#define kSSCP_CMD_SSS_AsymmetricSignDigest          ((sscp_command_t)0x3a)
#define kSSCP_CMD_SSS_AsymmetricVerifyDigest        ((sscp_command_t)0x3b)
#define kSSCP_CMD_SSS_TunnelContextInit             ((sscp_command_t)0x3d)
#define kSSCP_CMD_SSS_Tunnel                        ((sscp_command_t)0x3e)
#define kSSCP_CMD_SSS_DeriveKeyContextInit          ((sscp_command_t)0x40)
#define kSSCP_CMD_SSS_DeriveKey                     ((sscp_command_t)0x3f)
#define kSSCP_CMD_SSS_AsymmetricDhDeriveKey         ((sscp_command_t)0x3c)
#define kSSCP_CMD_SSS_AsymmetricSpake2PlusDeriveKey ((sscp_command_t)0x86)
#define kSSCP_CMD_SSS_KeyObjectContextInit          ((sscp_command_t)0x41)
#define kSSCP_CMD_SSS_KeyObjectAllocateHandle       ((sscp_command_t)0x42)
#define kSSCP_CMD_SSS_KeyObjectGetHandle            ((sscp_command_t)0x43)
#define kSSCP_CMD_SSS_KeyObjectSetProperties        ((sscp_command_t)0x44)
#define kSSCP_CMD_SSS_KeyObjectGetProperties        ((sscp_command_t)0x45)
#define kSSCP_CMD_SSS_KeyObjectContextFree          ((sscp_command_t)0x47)
#define kSSCP_CMD_SSS_KeyStoreContextInit           ((sscp_command_t)0x49)
#define kSSCP_CMD_SSS_KeyStoreContextFree           ((sscp_command_t)0x76)
#define kSSCP_CMD_SSS_KeyStoreAllocate              ((sscp_command_t)0x48)
#define kSSCP_CMD_SSS_KeyStoreSave                  ((sscp_command_t)0x4a)
#define kSSCP_CMD_SSS_KeyStoreLoad                  ((sscp_command_t)0x4b)
#define kSSCP_CMD_SSS_KeyStoreSetKey                ((sscp_command_t)0x4c)
#define kSSCP_CMD_SSS_KeyStoreGenerateKey           ((sscp_command_t)0x4d)
#define kSSCP_CMD_SSS_KeyStoreGetKey                ((sscp_command_t)0x4e)
#define kSSCP_CMD_SSS_KeyStoreOpenKey               ((sscp_command_t)0x4f)
#define kSSCP_CMD_SSS_KeyStoreFreezeKey             ((sscp_command_t)0x50)
#define kSSCP_CMD_SSS_KeyStoreEraseKey              ((sscp_command_t)0x51)
#define kSSCP_CMD_SSS_KeyStoreGetProperty           ((sscp_command_t)0x77)
#define KSSCP_CMD_SSS_RngGet                        ((sscp_command_t)0x73)
#define kSSCP_CMD_SSS_MGMT_ContextInit              ((sscp_command_t)0x65)
#define kSSCP_CMD_SSS_MGMT_FuseRead                 ((sscp_command_t)0x68)
#define kSSCP_CMD_SSS_MGMT_FuseShadowRegisterRead   ((sscp_command_t)0x6a)
#define kSSCP_CMD_SSS_MGMT_FuseProgram              ((sscp_command_t)0x67)
#define kSSCP_CMD_SSS_MGMT_PropertyGet              ((sscp_command_t)0x6c)
#define kSSCP_CMD_SSS_MGMT_LifeCycleGet             ((sscp_command_t)0x6b)
#define kSSCP_CMD_SSS_MGMT_PropertySet              ((sscp_command_t)0x71)
#define kSSCP_CMD_SSS_MGMT_AdvanceLifecycle         ((sscp_command_t)0x60)
#define kSSCP_CMD_SSS_MGMT_SecretImport             ((sscp_command_t)0x6e)
#define kSSCP_CMD_SSS_MGMT_SecretExport             ((sscp_command_t)0x66)
#define kSSCP_CMD_SSS_MGMT_Attest                   ((sscp_command_t)0x61)
#define kSSCP_CMD_SSS_MGMT_SecretBlobLoad           ((sscp_command_t)0x64)
#define kSSCP_CMD_SSS_MGMT_SecretBlobExport         ((sscp_command_t)0x62)
#define kSSCP_CMD_SSS_MGMT_SecretBlobImport         ((sscp_command_t)0x63)
#define kSSCP_CMD_SSS_MGMT_SoftwareVersionGet       ((sscp_command_t)0x6d)
#define kSSCP_CMD_SSS_MGMT_ReturnFaSet              ((sscp_command_t)0x72)
#define kSSCP_CMD_SSS_MGMT_HostAccessPermissionSet  ((sscp_command_t)0x70)
#define kSSCP_CMD_SSS_MGMT_IntegrityCheckEnable     ((sscp_command_t)0x6f)
#define kSSCP_CMD_SSS_MGMT_ClearAllKeys             ((sscp_command_t)0x74)
#define kSSCP_CMD_SSS_KeyStoreImportKey             ((sscp_command_t)0x78)
#define kSSCP_CMD_SSS_KeyStoreExportKey             ((sscp_command_t)0x79)
/* kSSCP_CMD_SSS_KeyStoreEraseAll command ID have to be updated once value will be defined in elke specification */
#define kSSCP_CMD_SSS_KeyStoreEraseAll ((sscp_command_t)0xff)

#define SSCP_PARAMCONTEXTTYPE_ENUM_ALT
/*! @brief SSCP ParamContextType list */
#define kSSCP_ParamContextType_SSS_Session    (0x1u)
#define kSSCP_ParamContextType_SSS_Symmetric  (0x2u)
#define kSSCP_ParamContextType_SSS_Aead       (0x3u)
#define kSSCP_ParamContextType_SSS_Digest     (0x4u)
#define kSSCP_ParamContextType_SSS_Mac        (0x5u)
#define kSSCP_ParamContextType_SSS_Asymmetric (0x6u)
#define kSSCP_ParamContextType_SSS_Tunnel     (0x7u)
#define kSSCP_ParamContextType_SSS_DeriveKey  (0x8u)
#define kSSCP_ParamContextType_SSS_Object     (0x9u)
#define kSSCP_ParamContextType_SSS_KeyStore   (0xau)
/*#define kSSCP_ParamContextType_SSS_KeyStoreCtx (0xbu)*/
#define kSSCP_ParamContextType_SSS_Mgmt (0xcu)
#define kSSCP_ParamContextType_SSS_Rng  (0xdu)

#endif /* FSL_SSCP_CONFIG_ELEMU */
