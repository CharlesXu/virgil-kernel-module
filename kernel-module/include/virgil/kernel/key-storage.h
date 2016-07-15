/**
 * Copyright (C) 2016 Virgil Security Inc.
 *
 * Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     (1) Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *     (2) Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *
 *     (3) Neither the name of the copyright holder nor the names of its
 *     contributors may be used to endorse or promote products derived from
 *     this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/**
 * @file key-storage.h
 * @brief API to key storage and caching functions.
 * Save, load and revoke keys. Can be used encryption for any key.
 * Synchronous calls.
 */

#ifndef VIRGIL_KEY_STORAGE_H
#define VIRGIL_KEY_STORAGE_H

#include <virgil/kernel/foundation/data.h>

// TODO: Make these parameters configurable
#define VIRGIL_KEYSTORAGE_ID_MAX_SIZE 				100				/**< Maximum size of key identifier */
#define VIRGIL_KEYSTORAGE_PERMANENT_KEYS_MAX_COUNT	30				/**< Maximum count of permanent keys */
#define VIRGIL_KEYSTORAGE_PERMANENT_KEY_MAX_SIZE 	(2048 - 512)	/**< Maximum size of permanent key in bytes */
#define VIRGIL_KEYSTORAGE_TEMPORARY_KEYS_MAX_COUNT	200				/**< Maximum count of temporary keys */

#define VIRGIL_KEY_PERMANENT    1               /**< Key type id PERMANENT. Key with current type should be saved immediately and won't be deleted if no space in storage. */
#define VIRGIL_KEY_TEMPORARY    2               /**< Key type id TEMPORARY. Key with current type won't be saved immediately and can be deleted if no space in storage. */

/**
 * @brief Save key with encryption.
 *
 * @param[in] key_id        - unique of key identifier.
 * @param[in] key           - key for save.
 * @param[in] key_type      - key type (permanent key or temporary).
 * @param[in] key_password  - password for key encryption before save.
 *
 * @return VIRGIL_OPERATION_OK or error code.
 */
extern int virgil_save_encrypted_key(const char * key_id,
        data_t key, __u16 key_type, const char * key_password);

/**
 * @brief Save key.
 *
 * @param[in] key_id        - unique of key identifier.
 * @param[in] key           - key for save.
 * @param[in] key_type      - key type (own key or not).
 *
 * @return VIRGIL_OPERATION_OK or error code.
 */
extern int virgil_save_key(const char * key_id, data_t key, __u16 key_type);

/**
 * @brief Load encrypted key.
 *
 * @param[in] key_id        - unique of key identifier.
 * @param[in] key_password  - password for key decryption.
 * @param[out] loaded_key   - loaded key.
 *
 * @return VIRGIL_OPERATION_OK or error code.
 */
extern int virgil_load_encrypted_key(const char * key_id,
        const char * key_password, data_t * loaded_key);

/**
 * @brief Load key.
 *
 * @param[in] key_id        - unique of key identifier.
 * @param[out] loaded_key   - loaded key.
 *
 * @return VIRGIL_OPERATION_OK or error code.
 */
extern int virgil_load_key(const char * key_id, data_t * loaded_key);

/**
 * @brief Revoke key.
 *
 * @param[in] key_id        - unique of key identifier.
 * @param[out] loaded_key   - loaded key.
 *
 * @return VIRGIL_OPERATION_OK or error code.
 */
extern int virgil_revoke_key(const char * key_id);

#endif /* VIRGIL_KEY_STORAGE_H */
