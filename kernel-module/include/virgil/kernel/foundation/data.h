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
 * @file data.h
 * @brief Helpers for safe work with data.
 * Init data structure, free, duplicate.
 */

#ifndef DATA_H
#define DATA_H

#include <linux/module.h>

/**
 * @struct data_t
 * Piece of data
 */
typedef struct {
    void * data;            /**< Pointer to data */
    __u32 sz;               /**< Size of data*/
} data_t;

/**
 * @brief Clear data structure.
 *
 * @param[in] data        - pointer to data structure.
 * @return VIRGIL_OPERATION_OK or VIRGIL_OPERATION_ERROR.
 */
extern int virgil_data_reset(data_t * data);

/**
 * @brief Free data (if possible) and reset to empty state.
 *
 * @param[in] data        - pointer to data structure.
 */
extern void virgil_data_free(data_t * data);

/**
 * @brief Duplicate data from other data structure.
 *
 * @param[in] dst        - pointer to destination data structure.
 * @param[in] src        - source data structure.
 * @return VIRGIL_OPERATION_OK or VIRGIL_OPERATION_ERROR.
 */
extern int virgil_data_dup(data_t * dst, data_t src);

/**
 * @brief Duplicate data from raw data.
 *
 * @param[in] dst        - pointer to destination data structure.
 * @param[in] sz         - count of bytes to be copied.
 * @param[in] src        - pointer to source raw data.
 * @return VIRGIL_OPERATION_OK or VIRGIL_OPERATION_ERROR.
 */
extern int virgil_data_dup_ar(data_t * dst, __u32 sz, const void * src);

#endif // DATA_H
