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
 * @file key-storage.c
 * @brief API to key storage and caching functions.
 * Save, load and revoke keys. Can be used encryption for any key.
 * Synchronous calls.
 */

#include <linux/module.h>

#include <virgil/kernel/private/log.h>
#include <virgil/kernel/private/fields.h>
#include <virgil/kernel/private/data-waiter.h>
#include <virgil/kernel/private/usermode-communicator.h>
#include <virgil/kernel/key-storage.h>

/******************************************************************************/
static __u32 save_encrypted_key_request(const char * key_id,
		data_t key, __u16 key_type, const char * key_password) {
	fields_t fields;
	struct package_field_t fields_ar[4];
	__u32 res;

	fields.count = 3;
	fields.ar = fields_ar;

	FILL_FIELD_STR(fields_ar[0], VIRGIL_FIELD_IDENTITY, key_id);
	FILL_FIELD(fields_ar[1], VIRGIL_FIELD_DATA, key);
	FILL_FIELD_AR(fields_ar[2], VIRGIL_FIELD_KEY_TYPE, &key_type, sizeof(key_type));

	if (key_password) {
		FILL_FIELD_STR(fields_ar[fields.count], VIRGIL_FIELD_PASSWORD, key_password);
		fields.count ++;
	}

	SEND_WITH_CHECK(VIRGIL_CMD_STORAGE_STORE,
			fields,
			res,
			"ERROR: Save key with encryption can't be processed");

	return res;
}

/******************************************************************************/
int virgil_save_encrypted_key(const char * key_id,
		data_t key, __u16 key_type, const char * key_password) {
	__u32 id;
	__s16 err_res;
	fields_t fields;

	// Check input parameters
	VALID_STR(key_id);

	if (strnlen(key_id, VIRGIL_KEYSTORAGE_ID_MAX_SIZE * 2) >= VIRGIL_KEYSTORAGE_ID_MAX_SIZE) {
		LOG("Save key error: identifier too big. Maximum size is %d bytes", VIRGIL_KEYSTORAGE_ID_MAX_SIZE);
		return VIRGIL_OPERATION_ERROR;
	}

	if (key.sz > VIRGIL_KEYSTORAGE_PERMANENT_KEY_MAX_SIZE) {
		LOG("Save key error: data for save too big. Maximum size is %d bytes", VIRGIL_KEYSTORAGE_PERMANENT_KEY_MAX_SIZE);
		return VIRGIL_OPERATION_ERROR;
	}

	// Send request and wait for response
	REQUEST_CHECK(id, save_encrypted_key_request(key_id, key, key_type, key_password));
	CHECK(data_waiter_execute(id, &fields, VIRGIL_OPERATION_TIMEOUT_MS));

	// Parse response
	CHECK_ERROR(fields, err_res);

	fields_free(&fields);

	return VIRGIL_OPERATION_OK;
}

/******************************************************************************/
int virgil_save_key(const char * key_id, data_t key, __u16 key_type) {
	return virgil_save_encrypted_key(key_id, key, key_type, 0);
}

/******************************************************************************/
static __u32 load_encrypted_key_request(const char * key_id, const char * key_password) {
	fields_t fields;
	struct package_field_t fields_ar[2];
	__u32 res;

	fields.count = 1;
	fields.ar = fields_ar;

	FILL_FIELD_STR(fields_ar[0], VIRGIL_FIELD_IDENTITY, key_id);

	if (key_password) {
		FILL_FIELD_STR(fields_ar[fields.count], VIRGIL_FIELD_PASSWORD, key_password);
		fields.count ++;
	}

	SEND_WITH_CHECK(VIRGIL_CMD_STORAGE_LOAD,
			fields,
			res,
			"ERROR: Load encrypted key can't be processed");

	return res;
}

/******************************************************************************/
int virgil_load_encrypted_key(const char * key_id,
		const char * key_password, data_t * loaded_key) {
	__u32 id;
	__s16 err_res;
	fields_t fields;

	// Check input parameters
	VALID_STR(key_id);
	NOT_ZERO(loaded_key);

	// Send request and wait for response
	REQUEST_CHECK(id, load_encrypted_key_request(key_id, key_password));
	CHECK(data_waiter_execute(id, &fields, VIRGIL_OPERATION_TIMEOUT_MS));

	// Clear output data
	virgil_data_reset(loaded_key);

	// Parse response
	CHECK_ERROR(fields, err_res);
	CHECK(fields_dup_first(VIRGIL_FIELD_DATA, fields, loaded_key));

	fields_free(&fields);

	return VIRGIL_OPERATION_OK;
}

/******************************************************************************/
int virgil_load_key(const char * key_id, data_t * loaded_key) {
	return virgil_load_encrypted_key(key_id, 0, loaded_key);
}

/******************************************************************************/
static __u32 revoke_key_request(const char * key_id) {
	fields_t fields;
	struct package_field_t fields_ar[1];
	__u32 res;

	fields.count = 1;
	fields.ar = fields_ar;

	FILL_FIELD_STR(fields_ar[0], VIRGIL_FIELD_IDENTITY, key_id);

	SEND_WITH_CHECK(VIRGIL_CMD_STORAGE_REMOVE,
			fields,
			res,
			"ERROR: Key revoke can't be processed");

	return res;
}

/******************************************************************************/
int virgil_revoke_key(const char * key_id) {
	__u32 id;
	__s16 err_res;
	fields_t fields;

	// Check input parameters
	VALID_STR(key_id);

	// Send request and wait for response
	REQUEST_CHECK(id, revoke_key_request(key_id));
	CHECK(data_waiter_execute(id, &fields, VIRGIL_OPERATION_TIMEOUT_MS));

	// Parse response
	CHECK_ERROR(fields, err_res);

	fields_free(&fields);

	return VIRGIL_OPERATION_OK;
}

EXPORT_SYMBOL( virgil_save_encrypted_key);
EXPORT_SYMBOL( virgil_save_key);

EXPORT_SYMBOL( virgil_load_encrypted_key);
EXPORT_SYMBOL( virgil_load_key);

EXPORT_SYMBOL( virgil_revoke_key);
