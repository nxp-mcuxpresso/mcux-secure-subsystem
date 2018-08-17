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

/* Mapping between key id and physical key store */

#ifndef SSS_INC_KEYID_MAP_H_
#define SSS_INC_KEYID_MAP_H_

/* ************************************************************************** */
/* Includes                                                                   */
/* ************************************************************************** */

#include <fsl_sss_api.h>
#include <stdint.h>

/* ************************************************************************** */
/* Defines                                                                    */
/* ************************************************************************** */

/* Physical index */
/* clang-format off */
#define K_INDEX_MASK    (0xFFFFu << 0u)
#define K_TYPE_MASK     (0xFFu << 24u)
#define K_TYPE_ECC_KP   (0x01u << 24u)
#define K_TYPE_ECC_PUB  (0x02u << 24u)
#define K_TYPE_AES      (0x03u << 24u)
#define K_TYPE_CERT     (0x04u << 24u)

/* Key store N Count */
#define KS_N_ECC_KEY_PAIRS  4
#define KS_N_ECC_PUB_KEYS   3
#define KS_N_AES_KEYS       8
#define KS_N_CERTIFCATES    4
/* clang-format on */

#define KS_N_ENTIRES (0 + KS_N_ECC_KEY_PAIRS + KS_N_ECC_PUB_KEYS + KS_N_AES_KEYS + KS_N_CERTIFCATES)

/* ************************************************************************** */
/* Structrues and Typedefs                                                    */
/* ************************************************************************** */

/* Generic entry of a Key ID Mapping inside the secure element */
typedef struct
{
    /** External index */
    uint32_t extKeyId;
    uint8_t keyType; /* Of type sss_key_type_t */
    uint8_t RFU;
    /** Internal index */
    uint16_t keyIntIndex;
} keyIdAndTypeIndexLookup_t;

typedef struct _keyStoreTable_t
{
    /** Fixed - Unique 32bit magic number.
     *
     * In case some one over-writes we can know. */
    uint32_t magic;
    /** Fixed - constant based on version number */
    uint16_t version;
    /**
     * maxEntries  Fixed - constant in the Layout. Should be equal to
     * KS_N_ENTIRES This will help in porting between A71CH with less memory and
     * SE050 with more memory
     */
    uint16_t maxEntries;
    /** Dynamic entries */
    keyIdAndTypeIndexLookup_t entries[KS_N_ENTIRES];
} keyStoreTable_t;

/* ************************************************************************** */
/* Global Variables                                                           */
/* ************************************************************************** */

/* ************************************************************************** */
/* Functions                                                                  */
/* ************************************************************************** */

/**
 * Initialize the File allocation table entry
 *
 * @param keystore_shadow Shadow structure (to be persisted later to EEPROM or
 * File System)
 */
void ks_common_init_fat(keyStoreTable_t *keystore_shadow);

/**
 * Update the File Allocation Table for the key.
 *
 * @param[out] keystore_shadow
 * @param[in] sss_key The key object.
 * @param[in] intIndex internal index.
 *
 * @return Fail if not able to add the entry.
 */
sss_status_t ks_common_update_fat(keyStoreTable_t *keystore_shadow,
                                  uint32_t extKeyId,
                                  uint8_t objType,
                                  uint16_t intIndex);

/**
 * check if the internal slot is availble for the key type.
 *
 * @param[in] keystore_shadow
 * @param[in] object_type type of key Object
 * @param[out] next_free_index availbale internal index for a particular key
 * type
 *
 * @return Fail if internal index is not available.
 */
sss_status_t ks_common_check_available_int_index(keyStoreTable_t *keystore_shadow,
                                                 uint8_t object_type,
                                                 uint16_t *next_free_index);

sss_status_t ks_common_extId_to_int_index(keyStoreTable_t *keystore_shadow, uint32_t extId, uint16_t *intIndex);
/**
 * check if the internal slot is availble for the key type.
 *
 * @param[in] keystore_shadow
 * @param[in] keyId key id for getting key object
 * @param[out] keyType type of keyobject retrieved from keyId* type
 *
 * @return Fail if keyId not found
 */
sss_status_t ks_common_get_keyType_from_keyid(keyStoreTable_t *keystore_shadow, uint32_t keyId, uint32_t *keyType);
/**
 * remove entry from shadow keystore.
 *
 * @param[in] keystore_shadow
 * @param[in] extId key id for getting key object
 *
 * @return Fail if keyId not found
 */
sss_status_t ks_common_remove_fat(keyStoreTable_t *keystore_shadow, uint32_t extId);

#endif /* SSS_INC_KEYID_MAP_H_ */
