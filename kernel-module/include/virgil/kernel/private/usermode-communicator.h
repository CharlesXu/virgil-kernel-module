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
 * @file usermode-communicator.h
 * @brief Communicator with user-space service.
 */

#ifndef USERMODE_COMMUNICATOR_H
#define USERMODE_COMMUNICATOR_H

#include <linux/module.h>

#include <virgil/kernel/types.h>
#include <virgil/kernel/private/log.h>
#include <virgil/kernel/private/fields.h>

#define VIRGIL_CMD_PROCESSORS_MAX   20      /**< Maximum count of command processors */

/** Macros for data send result checking. */
#define SEND_WITH_CHECK(CMD, FIELDS, RES, MESSAGE) do {                 \
        RES = communicator_send_data(CMD, FIELDS);                      \
        if (VIRGIL_INVALID_ID == RES) {                                 \
            LOG(MESSAGE);                                               \
            return VIRGIL_INVALID_ID;                                   \
        }                                                               \
        } while(0);

/** Check result of request to user-space service. */
#define REQUEST_CHECK(ID, REQUEST) do {                 				\
        ID = (REQUEST);                      							\
        if (VIRGIL_INVALID_ID == ID) {                                 	\
            return VIRGIL_OPERATION_ERROR;                              \
        }                                                               \
        } while(0);

/** Check data for non zero value and return error in other case. */
#define NOT_ZERO(VAL) do {                 								\
        if (!VAL) {                                 						\
            return VIRGIL_OPERATION_ERROR;                              \
        }                                                               \
        } while(0);

/** Check data for zero value and return error in other case. */
#define ZERO(VAL) do {                 									\
        if (!(VAL)) {                                 					\
            return VIRGIL_OPERATION_ERROR;                              \
        }                                                               \
        } while(0);

#define STR_MAX_SIZE 2048			/**< Maximum size of string value */

/** Check is string valid and return error in other case. */
#define VALID_STR(STR) do {                 							\
        NOT_ZERO(STR);													\
		if (!strnlen(STR, STR_MAX_SIZE) || strnlen(STR, STR_MAX_SIZE) >= STR_MAX_SIZE) {                                 					\
            return VIRGIL_OPERATION_ERROR;                              \
        }                                                               \
        } while(0);

/**
 * @brief Command processor callback.
 *
 * @param[in] request_id            - id of user space request.
 * @param[in] command_type          - command type
 * @param[in] fields                - array of field structures
 *
 * @return VIRGIL_OPERATION_ERROR - data not hasn't been processed, VIRGIL_OPERATION_OK - data processing done.
 */
typedef int (*command_processor_cb)(__u32 request_id, __u16 command_type, fields_t fields);

/**
 * @brief Callback for received data processing (comming from netlink).
 *
 * @param[in] data                  - response data
 * @param[in] data_sz               - response data size.
 */
extern void communicator_parser_data(void * data, __u32 data_sz);

/**
 * @brief Add callback for parsed response (can be set up to VIRGIL_CMD_PROCESSORS_MAX callbacks).
 *
 * @param[in] callback              - command processor callback.
 *
 * @return VIRGIL_OPERATION_OK - if callback has been set successfully.
 */
extern int communicator_add_processor_callback(command_processor_cb callback);

/**
 * @brief Send data to user space.
 *
 * @param[in] command_type          - command code
 * @param[in] fields                - fields data
 */
extern __u32 communicator_send_data(__u16 command, fields_t fields);

/**
 * @brief Start communication.
 * @return [VIRGIL_OPERATION_OK or VIRGIL_OPERATION_ERROR].
 */
extern int communicator_start(void);

/**
 * @brief Stop communication.
 */
extern void communicator_stop(void);

#endif /* USERMODE_COMMUNICATOR_H */
