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
 * @file usermode-communicator.c
 * @brief Communicator with user-space service.
 */

#include <linux/module.h>
#include <linux/slab.h>

#include <virgil/kernel/types.h>
#include <virgil/kernel/private/log.h>
#include <virgil/kernel/private/usermodehelper.h>
#include <virgil/kernel/private/usermode-communicator.h>
#include <virgil/kernel/private/netlink.h>
#include <virgil/kernel/private/fields.h>

static __u32 id_counter = 0;

static command_processor_cb processors[VIRGIL_CMD_PROCESSORS_MAX];
static int processors_count = 0;
static struct timer_list timer;

#if !defined(VIRGIL_COMMUNICATOR_DEBUG)
//#define VIRGIL_COMMUNICATOR_DEBUG
#endif

/******************************************************************************/
static int launch_user_space_service(bool wait) {
	char *argv_start[] = { "/usr/bin/virgil-service", 0 };
	usermode_exec(argv_start, wait);
	return VIRGIL_OPERATION_OK;
}

/******************************************************************************/
static int terminate_user_space_service(bool wait) {
	char *argv_terminate[] = { "/usr/bin/killall", "-9", "virgil-service", 0 };
	usermode_exec(argv_terminate, wait);
	return VIRGIL_OPERATION_OK;
}

/******************************************************************************/
static void restart_user_space_service(bool wait) {
	LOG("Restart user-space service ...");
	terminate_user_space_service(wait);
	launch_user_space_service(wait);
}
/******************************************************************************/
static void timer_action(unsigned long arg) {
	static char dummy = 0x00;

	netlink_send(&dummy, 1);

	if (! netlink_is_valid()) {
		restart_user_space_service(false);
	}
	timer.expires = jiffies + 2 * HZ;
	add_timer(&timer);
}

/******************************************************************************/
static void start_controll_timer(void) {
	init_timer(&timer);
	timer.function = timer_action;
	timer.expires = jiffies + 2 * HZ;
	timer.data = 0;
	add_timer(&timer);
}

/******************************************************************************/
void communicator_parser_data(void * data, __u32 data_sz) {
	char * payload = 0;
	int i, pos;
	__u32 id;
	__u16 command;
	__u16 fields_cnt;
	__u32 min_sz;
	fields_t fields;

	struct package_field_t * fields_ar;

#if defined(VIRGIL_COMMUNICATOR_DEBUG)
	LOG("Response parse ...");
#endif

	min_sz = sizeof(id) + sizeof(command) + sizeof(fields_cnt);
	if (!data || data_sz < min_sz) {
		return;
	}

	pos = 0;

	id = *((__u32 *) data), pos += sizeof(id);
	command = *((__u16 *) ((__u8 *)data + pos)), pos += sizeof(command);
	fields_cnt = *((__u16 *) ((__u8 *)data + pos)), pos += sizeof(fields_cnt);

	fields_ar = (struct package_field_t *)((__u8 *)data + min_sz);
	payload = (void *)fields_ar + sizeof(struct package_field_t) * fields_cnt;
	pos = 0;

	// Restore pointers in structs
	for (i = 0; i < fields_cnt; ++ i) {
		fields_ar[i].data.p = payload + pos;
		pos += fields_ar[i].data_sz;
	}

#if defined(VIRGIL_COMMUNICATOR_DEBUG)
	LOG("id : %llu", (unsigned long long)id);
	LOG("command : %d", (int) command);
	LOG("fields count : %d", (int) fields_cnt);

	for (i = 0; i < fields_cnt; ++ i) {
		LOG("Field  [%d] : ", i);
		LOG("      Type : %d", (int)fields_ar[i].type);
		LOG("      Size : %d", (int)fields_ar[i].data_sz);
	}

	LOG("Response parse done");
#endif

	if (VIRGIL_CMD_PING == command) {
		LOG("Ping from user space");
	} else {
		fields.count = fields_cnt;
		fields.ar = fields_ar;
		for (i = 0; i < processors_count; ++i) {
			if (VIRGIL_OPERATION_OK == (*processors[i])(id, command, fields)) {
				break;
			}
		}
	}
}

/******************************************************************************/
int communicator_add_processor_callback(command_processor_cb callback) {
	if (!callback || processors_count >= VIRGIL_CMD_PROCESSORS_MAX) {
		return VIRGIL_OPERATION_ERROR;
	}

	processors[processors_count++] = callback;

	return VIRGIL_OPERATION_OK;
}

/******************************************************************************/
int communicator_start(void) {
	launch_user_space_service(true);

	// Prepare netlink communication
	netlink_set_processor(&communicator_parser_data);
	netlink_start();

	start_controll_timer();

	return VIRGIL_OPERATION_OK;
}

/******************************************************************************/
void communicator_stop(void) {
	// Stop timer
	del_timer(&timer);

	// Terminate user space service
	terminate_user_space_service(true);
}

/******************************************************************************/
__u32 communicator_send_data(__u16 command, fields_t fields) {

	__u32 header_sz, res;
	int i, pos, cnt;
	void * data_for_send;
	__u32 data_for_send_sz, payload_sz = 0;


	for (cnt = 0; cnt < 3; ++ cnt) {
		++id_counter;

		header_sz = sizeof(id_counter) + sizeof(command) + sizeof(fields.count);

		for (i = 0; i < fields.count; ++i) {
			payload_sz += fields.ar[i].data_sz;
		}
		data_for_send_sz = header_sz +
				sizeof(struct package_field_t) * fields.count +
				payload_sz;

		data_for_send = kmalloc(data_for_send_sz, GFP_KERNEL);
		if (!data_for_send) {
			LOG("ERROR: No memory for data send");
			return VIRGIL_INVALID_ID;
		}

		pos = 0;
		memcpy((__u8 *)data_for_send, &id_counter, sizeof(id_counter)),
				pos += sizeof(id_counter);
		memcpy((__u8 *)data_for_send + pos, &command, sizeof(command)),
				pos += sizeof(command);
		memcpy((__u8 *)data_for_send + pos, &fields.count, sizeof(fields.count)),
				pos += sizeof(fields.count);

		for (i = 0; i < fields.count; ++i) {
			memcpy((__u8 *)data_for_send + pos, &fields.ar[i].type, sizeof(fields.ar[i].type)),
					pos += sizeof(fields.ar[i].type);
			memcpy((__u8 *)data_for_send + pos, &fields.ar[i].data_sz, sizeof(fields.ar[i].data_sz)),
					pos += sizeof(fields.ar[i].data_sz);
			memcpy((__u8 *)data_for_send + pos, &fields.ar[i].data.pad, 8),
					pos += 8;
		}

		for (i = 0; i < fields.count; ++i) {
			memcpy((__u8 *)data_for_send + pos, fields.ar[i].data.p, fields.ar[i].data_sz),
					pos += fields.ar[i].data_sz;
		}

		if (netlink_send(data_for_send, data_for_send_sz)) {
			res = id_counter;
		} else {
			res = VIRGIL_INVALID_ID;
		}

		kfree(data_for_send);

		if (VIRGIL_INVALID_ID != res) {
			return res;
		}
	}

	return VIRGIL_INVALID_ID;
}

