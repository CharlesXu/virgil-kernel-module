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
 * @file data-waiter.c
 * @brief Functionality to wait response from user-space.
 * Data waiter connected to user-space communicator and receives data. After receive need command data waiter will wake up.
 * If data not received, then time out will be produced.
 */

#include <linux/module.h>
#include <linux/skbuff.h>

#include <virgil/kernel/private/log.h>
#include <virgil/kernel/private/fields.h>
#include <virgil/kernel/private/data-waiter.h>
#include <virgil/kernel/private/usermode-communicator.h>

static data_wait_element_t data_waiters[VIRGIL_DATA_WAITER_COUNT];
static int is_prepared = 0;

static DECLARE_WAIT_QUEUE_HEAD( wait_queue);

/******************************************************************************/
static void prepare(void) {
    int i;

    if (!is_prepared) {
        is_prepared = 1;

        for (i = 0; i < VIRGIL_DATA_WAITER_COUNT; ++i) {
            data_waiters[i].id = VIRGIL_INVALID_ID;
            data_waiters[i].condition = 0;
        }
    }
}

/******************************************************************************/
int data_waiter_command_processor(__u32 request_id, __u16 command_type, fields_t fields) {
    int i, res;

    prepare();

    res = VIRGIL_OPERATION_ERROR;
    if (VIRGIL_INVALID_ID == request_id) {
        return VIRGIL_OPERATION_ERROR;
    }

    for (i = 0; i < VIRGIL_DATA_WAITER_COUNT; ++i) {
        if (data_waiters[i].id == request_id) {
            res = fields_dup(&data_waiters[i].fields, fields);
            if (VIRGIL_OPERATION_OK == res) {
                data_waiters[i].condition = 1;
                wake_up_interruptible(&wait_queue);
            }
            break;
        }
    }

    return VIRGIL_OPERATION_OK;
}

/******************************************************************************/
static int data_waiter_push(__u32 id) {
    int i;

    prepare();

    if (VIRGIL_INVALID_ID == id) {
        return -1;
    }

    for (i = 0; i < VIRGIL_DATA_WAITER_COUNT; ++i) {
        if (VIRGIL_INVALID_ID == data_waiters[i].id) {
            data_waiters[i].id = id;
            data_waiters[i].condition = 0;
            fields_reset(&data_waiters[i].fields);
            return i;
        }
    }

    return -1;
}

/******************************************************************************/
static int data_waiter_pop(__u32 id, fields_t * fields) {
    int i;

    prepare();

    if (VIRGIL_INVALID_ID == id || !fields) {
        return VIRGIL_OPERATION_ERROR;
    }

    for (i = 0; i < VIRGIL_DATA_WAITER_COUNT; ++i) {
        if (data_waiters[i].id == id) {
            fields->count = data_waiters[i].fields.count;
            fields->ar = data_waiters[i].fields.ar;
            data_waiters[i].id = VIRGIL_INVALID_ID;
            return VIRGIL_OPERATION_OK;
        }
    }

    return VIRGIL_OPERATION_ERROR;
}

/******************************************************************************/
int data_waiter_execute(__u32 id, fields_t * fields, __u16 timeout_ms) {
    int pos = -1;

    pos = data_waiter_push(id);
    if (pos < 0)
        return VIRGIL_OPERATION_ERROR;

    wait_event_interruptible_timeout(wait_queue,
            data_waiters[pos].condition == 1, timeout_ms * HZ / 1000);

    return data_waiter_pop(id, fields);
}
