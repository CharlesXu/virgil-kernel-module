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
 * @file fields.c
 * @brief Data wrapper for communication with user-space.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/slab.h>

#include <virgil/kernel/types.h>
#include <virgil/kernel/private/log.h>
#include <virgil/kernel/private/fields.h>

/******************************************************************************/
int fields_reset(fields_t * fields) {
    if (!fields) return VIRGIL_OPERATION_ERROR;

    memset(fields, 0, sizeof(fields_t));
    return VIRGIL_OPERATION_OK;
}

/******************************************************************************/
void fields_free(fields_t * fields) {
    int i;

    if (!fields || !fields->ar) return;

    for (i = 0; i < fields->count; ++i) {
        if (fields->ar[i].data.p) {
            kfree(fields->ar[i].data.p);
        }
    }

    if (fields->ar) {
        kfree(fields->ar);
    }

    fields_reset(fields);
}

/******************************************************************************/
int fields_by_type(__u16 field_type,
        fields_t fields,
        __u16 res_limit,
        __u16 * res_cnt, struct package_field_t ** res) {

    int i;

    *res_cnt = 0;

    for (i = 0; i < fields.count; ++i) {
        if (fields.ar[i].type == field_type) {
            if (res_limit <= *res_cnt) break;
            res[*res_cnt] = &fields.ar[i];
            (*res_cnt)++;
        }
    }

    return VIRGIL_OPERATION_OK;
}

/******************************************************************************/
int fields_result(fields_t fields, __s16 * result) {
    data_t result_data;

    virgil_data_reset(&result_data);

    CHECK(fields_dup_first(VIRGIL_FIELD_RES, fields, &result_data));

    if (result_data.sz != sizeof(*result)) return VIRGIL_OPERATION_OK;
    memcpy(result, result_data.data, sizeof(*result));

    virgil_data_free(&result_data);

    return VIRGIL_OPERATION_OK;
}

/******************************************************************************/
int fields_dup(fields_t * dst, fields_t src) {
    int i, is_ok;

    dst->count = src.count;
    dst->ar =  kcalloc(src.count, sizeof(struct package_field_t), GFP_KERNEL);
    if (!dst->ar) return VIRGIL_OPERATION_ERROR;

    is_ok = 1;
    for (i = 0; i < src.count; ++i) {
        dst->ar[i].type = src.ar[i].type;
        dst->ar[i].data_sz = src.ar[i].data_sz;
        dst->ar[i].data.p = kmemdup(src.ar[i].data.p, src.ar[i].data_sz, GFP_KERNEL);
        if (!dst->ar[i].data.p) {
            is_ok = 0;
            break;
        }
    }

    // Clear mem in case of error
    if (!is_ok) {
        fields_free(dst);
        kfree(dst->ar);
        dst->ar = 0;
    }

    return VIRGIL_OPERATION_OK;
}

/******************************************************************************/
int fields_dup_first(int field_type, fields_t fields, data_t * dst) {
    struct package_field_t * res_fields[1] = { 0 };
    __u16 res_cnt = 0;

    fields_by_type(field_type,
            fields,
            1,
            &res_cnt, (struct package_field_t **)res_fields);

    if (!res_cnt) return VIRGIL_OPERATION_ERROR;

    if (VIRGIL_OPERATION_ERROR == virgil_data_dup_ar(dst, res_fields[0]->data_sz, res_fields[0]->data.p)) {
        return VIRGIL_OPERATION_ERROR;
    }

    return VIRGIL_OPERATION_OK;
}
