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
 * @file netlink.h
 * @brief Communication through NetLink.
 */

#ifndef NETLINK_H
#define NETLINK_H

#include <linux/module.h>

#include <virgil/kernel/types.h>
#include <virgil/kernel/private/log.h>

typedef void (*netlink_processor_cb)(void * data, __u32 data_sz);

/**
 * @brief Set data processor callback.
 *
 * @param[in] processor             - pointer to data processing function
 */
extern void netlink_set_processor(netlink_processor_cb processor);

/**
 * @brief Start netlink communication.
 */
extern void netlink_start(void);

/**
 * @brief Stop netlink communication.
 */
extern void netlink_stop(void);

/**
 * @brief Send data using NetLink.
 *
 * @param[in] data                - data to be sent
 * @param[in] data_sz             - size of data to be sent
 *
 * @return [VIRGIL_OPERATION_OK or VIRGIL_OPERATION_ERROR].
 */
extern bool netlink_send(const void * data, __u32 data_sz);

/**
 * @brief Check is ready for communication.
 * @return true if is ready for communication.
 */
extern bool netlink_is_valid(void);

#endif /* NETLINK_H */
