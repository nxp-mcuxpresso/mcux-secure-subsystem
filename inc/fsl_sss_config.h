/*
 * Copyright 2018 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef _FSL_SSS_CONFIG_H_
#define _FSL_SSS_CONFIG_H_

#include "sab.h"

/* clang-format off */
#define SSS_SESSION_MAX_CONTEXT_SIZE        (16)
#define SSS_KEY_STORE_MAX_CONTEXT_SIZE      (16 + 80)
#define SSS_KEY_OBJECT_MAX_CONTEXT_SIZE     (16)
#define SSS_SYMMETRIC_MAX_CONTEXT_SIZE      (16 + 80)
#define SSS_AEAD_MAX_CONTEXT_SIZE           (16)
#define SSS_DIGEST_MAX_CONTEXT_SIZE         (16 + 80)
#define SSS_MAC_MAX_CONTEXT_SIZE            (16 + 16)
#define SSS_ASYMMETRIC_MAX_CONTEXT_SIZE     (16)
#define SSS_TUNNEL_MAX_CONTEXT_SIZE         (16)
#define SSS_DERIVE_KEY_MAX_CONTEXT_SIZE     (16)
/* clang-format on */

#define SSS_TYPE_ENUM_ALT
typedef enum _sss_type
{
    kType_SSS_Software = SAB_SE_TYPE_Software,
    kType_SSS_SECO = SAB_SE_TYPE_SECO,
    kType_SSS_Sentinel200 = SAB_SE_TYPE_S200,
    kType_SSS_Sentinel300 = SAB_SE_TYPE_S300,
    kType_SSS_Sentinel400 = SAB_SE_TYPE_S400,
    kType_SSS_Sentinel500 = SAB_SE_TYPE_S500,
    kType_SSS_SecureElement = SAB_SE_TYPE_SECURE_ELEMENT,
} sss_type_t;

#define SSS_MODE_ENUM_ALT
typedef enum _sss_mode
{
    kMode_SSS_Encrypt = SAB_MODE_ENCRYPT,
    kMode_SSS_Decrypt = SAB_MODE_DECRYPT,
    kMode_SSS_Sign = SAB_MODE_SIGN,
    kMode_SSS_Verify  = SAB_MODE_VERIFY,
    kMode_SSS_ComputeSharedSecret = SAB_MODE_COMPUTE_SHARED_SECRET,
    kMode_SSS_Digest = SAB_MODE_DIGEST,
    kMode_SSS_Mac = SAB_MODE_MAC,
} sss_mode_t;

#define SSS_ALGORITHM_ENUM_ALT
typedef enum _sss_algorithm
{
    /* AES */
    kAlgorithm_SSS_AES_ECB = SAB_ALGO_AES_ECB,
    kAlgorithm_SSS_AES_CBC = SAB_ALGO_AES_CBC,
    kAlgorithm_SSS_AES_CTR = SAB_ALGO_AES_CTR,
    kAlgorithm_SSS_AES_GCM = SAB_ALGO_AES_GCM,
    kAlgorithm_SSS_AES_CCM = SAB_ALGO_AES_CCM,
    /* CHACHA_POLY */
    kAlgorithm_SSS_CHACHA_POLY = SAB_ALGO_CHACHA_POLY,
    /* DES3 */
    kAlgorithm_SSS_DES3_ECB = SAB_ALGO_DES3_ECB,
    kAlgorithm_SSS_DES3_CBC = SAB_ALGO_DES3_CBC,
    /* digest */
    kAlgorithm_SSS_SHA1 = SAB_ALGO_SHA1,
    kAlgorithm_SSS_SHA224 = SAB_ALGO_SHA224,
    kAlgorithm_SSS_SHA256 = SAB_ALGO_SHA256,
    kAlgorithm_SSS_SHA384 = SAB_ALGO_SHA384,
    kAlgorithm_SSS_SHA512 = SAB_ALGO_SHA512,
    /* MAC */
    kAlgorithm_SSS_CMAC_AES = SAB_ALGO_CMAC_AES,
    kAlgorithm_SSS_HMAC_SHA256 = SAB_ALGO_HMAC_SHA256,
    /* Diffie-Helmann */
    kAlgorithm_SSS_DH = SAB_ALGO_DH,
    kAlgorithm_SSS_ECDH = SAB_ALGO_ECDH,
    /* DSA */
    kAlgorithm_SSS_DSA_SHA1 = SAB_ALGO_DSA_SHA1,
    kAlgorithm_SSS_DSA_SHA224 = SAB_ALGO_DSA_SHA224,
    kAlgorithm_SSS_DSA_SHA256 = SAB_ALGO_DSA_SHA256,
    /* RSA */
    kAlgorithm_SSS_RSASSA_PKCS1_V1_5_SHA1 = SAB_ALGO_RSASSA_PKCS1_V1_5_SHA1,
    kAlgorithm_SSS_RSASSA_PKCS1_V1_5_SHA224 = SAB_ALGO_RSASSA_PKCS1_V1_5_SHA224,
    kAlgorithm_SSS_RSASSA_PKCS1_V1_5_SHA256 = SAB_ALGO_RSASSA_PKCS1_V1_5_SHA256,
    kAlgorithm_SSS_RSASSA_PKCS1_V1_5_SHA384 = SAB_ALGO_RSASSA_PKCS1_V1_5_SHA384,
    kAlgorithm_SSS_RSASSA_PKCS1_V1_5_SHA512 = SAB_ALGO_RSASSA_PKCS1_V1_5_SHA512,
    kAlgorithm_SSS_RSASSA_PKCS1_PSS_MGF1_SHA1 = SAB_ALGO_RSASSA_PKCS1_PSS_MGF1_SHA1,
    kAlgorithm_SSS_RSASSA_PKCS1_PSS_MGF1_SHA224 = SAB_ALGO_RSASSA_PKCS1_PSS_MGF1_SHA224,
    kAlgorithm_SSS_RSASSA_PKCS1_PSS_MGF1_SHA256 = SAB_ALGO_RSASSA_PKCS1_PSS_MGF1_SHA256,
    kAlgorithm_SSS_RSASSA_PKCS1_PSS_MGF1_SHA384 = SAB_ALGO_RSASSA_PKCS1_PSS_MGF1_SHA384,
    kAlgorithm_SSS_RSASSA_PKCS1_PSS_MGF1_SHA512 = SAB_ALGO_RSASSA_PKCS1_PSS_MGF1_SHA512,
    /* ECDSA */
    kAlgorithm_SSS_ECDSA_SHA1 = SAB_ALGO_ECDSA_SHA1,
    kAlgorithm_SSS_ECDSA_SHA224 = SAB_ALGO_ECDSA_SHA224,
    kAlgorithm_SSS_ECDSA_SHA256 = SAB_ALGO_ECDSA_SHA256,
    kAlgorithm_SSS_ECDSA_SHA384 = SAB_ALGO_ECDSA_SHA384,
    kAlgorithm_SSS_ECDSA_SHA512 = SAB_ALGO_ECDSA_SHA512,
} sss_algorithm_t;

#define SSS_KEY_TYPE_ENUM_ALT
typedef enum _sss_key_type
{
    kSSS_KeyType_NONE = SAB_KEY_TYPE_SYMMETRIC,
    kSSS_KeyType_Certificate = SAB_KEY_TYPE_SYMMETRIC,
    kSSS_KeyType_AES = SAB_KEY_TYPE_SYMMETRIC,
    kSSS_KeyType_DES = SAB_KEY_TYPE_SYMMETRIC,
    kSSS_KeyType_MAC = SAB_KEY_TYPE_SYMMETRIC,
    kSSS_KeyType_RSA_Public  = SAB_KEY_TYPE_ASYMMETRIC,
    kSSS_KeyType_ECC_Public = SAB_KEY_TYPE_ASYMMETRIC, /*! Weierstrass form elliptic curve public key  */
    kSSS_KeyType_ECM_Public = SAB_KEY_TYPE_ASYMMETRIC, /*! Montgomery form elliptic curve public key  */
    kSSS_KeyType_ECT_Public = SAB_KEY_TYPE_ASYMMETRIC, /*! twisted Edwards form elliptic curve public key  */
    kSSS_KeyType_RSA_Private = SAB_KEY_TYPE_ASYMMETRIC,
    kSSS_KeyType_ECC_Private = SAB_KEY_TYPE_ASYMMETRIC,
    kSSS_KeyType_ECM_Private = SAB_KEY_TYPE_ASYMMETRIC,
    kSSS_KeyType_ECT_Private = SAB_KEY_TYPE_ASYMMETRIC,
    kSSS_KeyType_RSA_Pair = SAB_KEY_TYPE_ASYMMETRIC,
    kSSS_KeyType_ECC_Pair = SAB_KEY_TYPE_ASYMMETRIC,
    kSSS_KeyType_ECM_Pair = SAB_KEY_TYPE_ASYMMETRIC,
    kSSS_KeyType_ECT_Pair = SAB_KEY_TYPE_ASYMMETRIC,
} sss_key_type_t;

#endif /* _FSL_SSS_CONFIG_H_ */
