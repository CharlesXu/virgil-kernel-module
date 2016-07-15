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
 * @file data.c
 * @brief Helpers for safe work with data.
 * Init data structure, free, duplicate.
 */


#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/slab.h>

#include <virgil/kernel/types.h>
#include <virgil/kernel/private/log.h>
#include <virgil/kernel/private/fields.h>

/******************************************************************************/
int virgil_data_reset(data_t * data) {
    if (!data) return VIRGIL_OPERATION_ERROR;
    memset(data, 0, sizeof(data_t));
    return VIRGIL_OPERATION_OK;
}

/******************************************************************************/
void virgil_data_free(data_t * data) {
    if (data->data) {
        kfree(data->data);
        virgil_data_reset(data);
    }
}

/******************************************************************************/
int virgil_data_dup_ar(data_t * dst, __u32 sz, const void * src) {
    int res;
    dst->sz = sz;
    dst->data =  kmemdup(src, sz, GFP_KERNEL);
    res = dst->data ? VIRGIL_OPERATION_OK : VIRGIL_OPERATION_ERROR;

    if (VIRGIL_OPERATION_ERROR == res) {
        virgil_data_reset(dst);
    }

    return res;
}

/******************************************************************************/
int virgil_data_dup(data_t * dst, data_t src) {
    return virgil_data_dup_ar(dst, src.sz, src.data);
}

EXPORT_SYMBOL( virgil_data_reset);
EXPORT_SYMBOL( virgil_data_free);
EXPORT_SYMBOL( virgil_data_dup);
EXPORT_SYMBOL( virgil_data_dup_ar);
