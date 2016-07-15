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
 * @file key-value.h
 * @brief Helpers for work with key/value arrays. Keys aren't unique.
 * Clear, create/free, set/get value for key, serialize/deserialize to/from raw data.
 */

#ifndef KEY_VALUE_H
#define KEY_VALUE_H

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>

#include <virgil/kernel/types.h>

#pragma pack(push,1)

/** Structure represents one key/value element */
typedef struct {
    __u8 key[VIRGIL_KV_KEY_MAX_SZ];     /**< Key in key-value pair */
    __u16 value_sz;                     /**< Size of data field in bytes */
    ptr_with_pad_t value;               /**< Value data */
} kv_pair_t;

/** Container for key/value array */
typedef struct {
    __u16 kv_count;         /**< Count of key/value pairs */
    ptr_with_pad_t ar;    	/**< Pointer to array of key/value pairs */
} kv_container_t;

#pragma pack(pop)

/**
 * @brief Create key/value array with need count of empty elements.
 *
 * @param[in] container     - pointer to key/value container.
 * @param[in] kv_pairs_cnt  - need count of key/value pairs.
 *
 * @return VIRGIL_OPERATION_OK or VIRGIL_OPERATION_ERROR.
 */
extern int virgil_kv_prepare(kv_container_t * container, __u16 kv_pairs_cnt);

/**
 * @brief Clear key/value container (init container).
 *
 * @param[in] container        - pointer to container structure.
 * @return VIRGIL_OPERATION_OK or VIRGIL_OPERATION_ERROR.
 */
extern int virgil_kv_reset(kv_container_t * container);

/**
 * @brief Free key/value container and all elements.
 *
 * @param[in] container        - pointer to container structure.
 * @return VIRGIL_OPERATION_OK or VIRGIL_OPERATION_ERROR.
 */
extern void virgil_kv_free(kv_container_t * container);

/**
 * @brief Set value for key container at need position in array.
 *
 * @param[in] container        - pointer to container structure.
 * @return VIRGIL_OPERATION_OK or VIRGIL_OPERATION_ERROR.
 */
extern int virgil_kv_set(kv_container_t * container, int pos, const char * key, data_t value);

/**
 * @brief Get first value by key.
 *
 * @param[in] container        	- pointer to container structure.
 * @param[in] key        		- key for value get.
 * @return data structure with value or empty data. Should be free'd by a caller.
 */
extern data_t virgil_kv_value(kv_container_t * container, const char * key);

/**
 * @brief Serialize key/value container to raw data.
 *
 * @param[in] container        	- pointer to container structure.
 * @return data structure with raw data.
 */
extern data_t virgil_kv_serialize(kv_container_t * container);

/**
 * @brief Deserialize raw data to key/value container.
 *
 * @param[in] data        		- raw data.
 * @param[in] key        		- key for value get.
 * @return Key/value container. Should be free'd by a caller.
 */
extern kv_container_t virgil_kv_deserialize(data_t data);

#endif // KEY_VALUE_H
