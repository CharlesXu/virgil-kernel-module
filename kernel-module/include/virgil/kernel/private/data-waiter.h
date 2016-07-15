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
 * @file data-waiter.h
 * @brief Functionality to wait response from user-space.
 * Data waiter connected to user-space communicator and receives data. After receive need command data waiter will wake up.
 * If data not received, then time out will be produced.
 */

#ifndef DATA_WAITER_H
#define DATA_WAITER_H

#include <linux/module.h>

#include <virgil/kernel/types.h>
#include <virgil/kernel/private/log.h>
#include <virgil/kernel/private/fields.h>

#define VIRGIL_DATA_WAITER_COUNT  100 /**< Maximum count data waiters */

/** Data waiter element */
typedef struct {
    __u32 id;                           /**< id of operation */
    int condition;                      /**< wait queue */
    fields_t fields;                    /**< data fields */
} data_wait_element_t;

/**
 * @brief Start wait for data with timeout.
 * wait_event_interruptible_timeout used inside.
 *
 * @param[in] id        	- id of sent request.
 * @param[out] fields      	- returned data fields.
 * @param[in] timeout_ms    - data wait timeout.
 *
 * @return [VIRGIL_OPERATION_OK or VIRGIL_OPERATION_ERROR].
 */
extern int data_waiter_execute(__u32 id, fields_t * fields, __u16 timeout_ms);

/**
 * @brief Callback used to receive data from communication layer.
 * Process received data and wake up corresponding data waiter if need.
 *
 * @param[in] request_id    - id of sent request.
 * @param[in] command_type  - received command type.
 * @param[in] fields    	- received data.
 *
 * @return [VIRGIL_OPERATION_OK or VIRGIL_OPERATION_ERROR].
 */
extern int data_waiter_command_processor(__u32 request_id, __u16 command_type, fields_t fields);

#endif /* DATA_WAITER_H */
