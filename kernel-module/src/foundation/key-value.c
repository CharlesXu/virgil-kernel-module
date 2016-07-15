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
 * @file key-value.c
 * @brief Helpers for work with key/value arrays. Keys aren't unique.
 * Clear, create/free, set/get value for key, serialize/deserialize to/from raw data.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/slab.h>

#include <virgil/kernel/foundation/data.h>
#include <virgil/kernel/foundation/key-value.h>
#include <virgil/kernel/private/log.h>
#include <virgil/kernel/private/fields.h>

#define AR(CONTAINER)((kv_pair_t *)(CONTAINER)->ar.p)

/******************************************************************************/
int virgil_kv_reset(kv_container_t * container) {
    if (!container) return VIRGIL_OPERATION_ERROR;
    memset(container, 0, sizeof(kv_container_t));
    return VIRGIL_OPERATION_OK;
}

/******************************************************************************/
int virgil_kv_prepare(kv_container_t * container, __u16 kv_pairs_cnt) {
    if (!container) return VIRGIL_OPERATION_ERROR;

    virgil_kv_reset(container);

    container->ar.p = kcalloc(kv_pairs_cnt, sizeof(kv_pair_t), GFP_KERNEL);
    if (!container->ar.p) return VIRGIL_OPERATION_ERROR;

    container->kv_count = kv_pairs_cnt;

    return VIRGIL_OPERATION_OK;
}

/******************************************************************************/
void virgil_kv_free(kv_container_t * container) {
    int i;

    if (!container) return;

    for (i = 0; i < container->kv_count; ++i) {
        if (AR(container)[i].value.p)
            kfree(AR(container)[i].value.p);
    }

    if (container->ar.p) kfree(container->ar.p);
    virgil_kv_reset(container);
}

/******************************************************************************/
int virgil_kv_set(kv_container_t * container, int pos, const char * key, data_t value) {
    int key_sz;
    if (!container || pos >= container->kv_count) return VIRGIL_OPERATION_ERROR;

    key_sz = strlen(key) + 1;
    if (key_sz >= VIRGIL_KV_KEY_MAX_SZ) return VIRGIL_OPERATION_ERROR;

    memset(AR(container)[pos].key, 0, VIRGIL_KV_KEY_MAX_SZ);
    strncpy(AR(container)[pos].key, key, VIRGIL_KV_KEY_MAX_SZ);
    AR(container)[pos].value_sz = value.sz;
    AR(container)[pos].value.p = kmemdup(value.data, value.sz, GFP_KERNEL);

    return VIRGIL_OPERATION_OK;
}

/******************************************************************************/
data_t virgil_kv_value(kv_container_t * container, const char * key) {
    int i;
    data_t res;

    virgil_data_reset(&res);

    if (!container) return res;

    for (i = 0; i < container->kv_count; ++i) {
        if (0 == strcmp(key, AR(container)[i].key)) {
            res.sz = AR(container)[i].value_sz;
            res.data = AR(container)[i].value.p;
        }
    }

    return res;
}

/******************************************************************************/
data_t virgil_kv_serialize(kv_container_t * container) {
    data_t res;
    __u32 need_size = 0;
    __u32 pos = 0, data_pos = 0;
    int i;

    virgil_data_reset(&res);

    need_size = sizeof(kv_container_t);
    need_size += container->kv_count * sizeof(kv_pair_t);

    for (i = 0; i < container->kv_count; ++i) {
        need_size += AR(container)[i].value_sz;
    }

    res.data = kmalloc(need_size, GFP_KERNEL);
    if (!res.data) return res;
    res.sz = need_size;

    memcpy((__u8 *)res.data + pos, container, sizeof(kv_container_t));
    pos += sizeof(kv_container_t);

    data_pos = sizeof(kv_container_t) + container->kv_count * sizeof(kv_pair_t);

    for (i = 0; i < container->kv_count; ++i) {
        memcpy((__u8 *)res.data + pos, &AR(container)[i], sizeof(kv_pair_t));
        pos += sizeof(kv_pair_t);

        memcpy((__u8 *)res.data + data_pos, AR(container)[i].value.p, AR(container)[i].value_sz);
        data_pos += AR(container)[i].value_sz;
    }

    return res;
}

/******************************************************************************/
kv_container_t virgil_kv_deserialize(data_t data) {
    kv_container_t res;
    kv_container_t * p_container;
    data_t data_helper;
    __u32 data_pos = 0;
    int i;

    virgil_kv_reset(&res);
    if (!data.data) return res;

    p_container = (kv_container_t *) data.data;

    if (VIRGIL_OPERATION_OK != virgil_kv_prepare(&res, p_container->kv_count)) {
        LOG("ERROR: virgil_kv_deserialize");
        return res;
    }

    p_container->ar.p = (kv_pair_t *)((__u8*)data.data + sizeof(kv_container_t));
    data_pos = sizeof(kv_container_t) + res.kv_count * sizeof(kv_pair_t);

    for (i = 0; i < p_container->kv_count; ++i) {
        data_helper.sz = AR(p_container)[i].value_sz;
        data_helper.data = (__u8*)data.data + data_pos;
        virgil_kv_set(&res, i, AR(p_container)[i].key, data_helper);
        data_pos += AR(p_container)[i].value_sz;
    }

    return res;
}

EXPORT_SYMBOL( virgil_kv_prepare);
EXPORT_SYMBOL( virgil_kv_reset);
EXPORT_SYMBOL( virgil_kv_free);
EXPORT_SYMBOL( virgil_kv_set);
EXPORT_SYMBOL( virgil_kv_value);
EXPORT_SYMBOL( virgil_kv_serialize);
EXPORT_SYMBOL( virgil_kv_deserialize);
