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

#include <linux/module.h>
#include <linux/slab.h>

#include <virgil/kernel/key-storage.h>
#include <virgil/kernel/foundation/data.h>

#include "macro.h"

static const char * key_password = "key-password";
static const char * key_id = "own_key";
static const char * wrong_key_id = "!@#$%^*(*)_";

static data_t data_for_save, loaded_data;
static __u16 i;
static char id[10];

/******************************************************************************/
static void _fillData(data_t * data, __u16 fill_size) {
	__u16 i;

	virgil_data_reset(data);

	data->sz = fill_size;
	data->data =  kmalloc(fill_size, GFP_KERNEL);

	for (i = 0; i < fill_size; ++i) {
		((__u8 *)data->data)[i] = i & 0xFF;
	}
}

/******************************************************************************/
static void save_load_test(void) {
	virgil_data_reset(&data_for_save);
	virgil_data_reset(&loaded_data);

	_fillData(&data_for_save, VIRGIL_KEYSTORAGE_PERMANENT_KEY_MAX_SIZE);

	TEST_CASE_OK("Save data",
			virgil_save_key(key_id, data_for_save, VIRGIL_KEY_PERMANENT));

	TEST_CASE_OK("Load data",
			virgil_load_key(key_id, &loaded_data));

	TEST_CASE("Compare data",
			0 == memcmp(data_for_save.data, loaded_data.data, loaded_data.sz) && data_for_save.sz == loaded_data.sz);

	terminate:
	virgil_data_free(&data_for_save);
	virgil_data_free(&loaded_data);
}

/******************************************************************************/
static void update_test(void) {
	virgil_data_free(&loaded_data);
	_fillData(&data_for_save, VIRGIL_KEYSTORAGE_PERMANENT_KEY_MAX_SIZE / 2);

	TEST_CASE_OK("Update data",
			virgil_save_key(key_id, data_for_save, VIRGIL_KEY_PERMANENT));

	TEST_CASE_OK("Load updated data",
			virgil_load_key(key_id, &loaded_data));

	TEST_CASE("Compare data",
			0 == memcmp(data_for_save.data, loaded_data.data, loaded_data.sz) && data_for_save.sz == loaded_data.sz);

	terminate:
	virgil_data_free(&data_for_save);
	virgil_data_free(&loaded_data);
}

/******************************************************************************/
static void abnormal_params_test(void) {
	virgil_data_free(&loaded_data);

	TEST_CASE_ERROR("Load data by wrong id. (Should be received error code)",
			virgil_load_key(wrong_key_id, &loaded_data));

	_fillData(&data_for_save, VIRGIL_KEYSTORAGE_PERMANENT_KEY_MAX_SIZE * 2);

	TEST_CASE_ERROR("Try to Save bigger chunk of data than possible. (Should be received error code)",
			virgil_save_key(key_id, data_for_save, VIRGIL_KEY_PERMANENT));

	terminate:
	virgil_data_free(&data_for_save);
	virgil_data_free(&loaded_data);
}

/******************************************************************************/
static void remove_test(void) {
	TEST_CASE_OK("Remove saved key", virgil_revoke_key(key_id));

	TEST_CASE_ERROR("Try to load removed key. (Should be received error code)",
			virgil_load_key(key_id, &loaded_data));

	terminate:
	virgil_data_free(&data_for_save);
	virgil_data_free(&loaded_data);
}

/******************************************************************************/
static void permanent_container_stress_test(void) {
	LOG("Start test of cyclic rewrite of PERMANENT keys container ...");
	for (i = 0; i < VIRGIL_KEYSTORAGE_PERMANENT_KEYS_MAX_COUNT * 2; ++i) {
		snprintf(id, 10, "%d", (int)i);

		virgil_data_free(&data_for_save);
		virgil_data_free(&loaded_data);

		_fillData(&data_for_save, i + 100);

		if (VIRGIL_OPERATION_OK != virgil_save_key(id, data_for_save, VIRGIL_KEY_PERMANENT)
				|| VIRGIL_OPERATION_OK != virgil_load_key(id, &loaded_data)
				|| data_for_save.sz != loaded_data.sz
				|| 0 != memcmp(data_for_save.data, loaded_data.data, loaded_data.sz)) {
			RESULT_ERROR;
			goto terminate;
		}

	}
	RESULT_OK;

	terminate:
	virgil_data_free(&data_for_save);
	virgil_data_free(&loaded_data);
}

/******************************************************************************/
static void encrypted_save_load_test(void) {
	virgil_data_free(&data_for_save);
	virgil_data_free(&loaded_data);

	_fillData(&data_for_save, VIRGIL_KEYSTORAGE_PERMANENT_KEY_MAX_SIZE);

	TEST_CASE_OK("Save encrypted data",
			virgil_save_encrypted_key(key_id, data_for_save, VIRGIL_KEY_PERMANENT, key_password));

	TEST_CASE_OK("Load encrypted data",
			virgil_load_encrypted_key(key_id, key_password, &loaded_data));

	TEST_CASE("Compare data",
			0 == memcmp(data_for_save.data, loaded_data.data, loaded_data.sz) && data_for_save.sz == loaded_data.sz);

	terminate:
	virgil_data_free(&data_for_save);
	virgil_data_free(&loaded_data);
}

/******************************************************************************/
static void temporary_container_stress_test(void) {
	LOG("Start test of cyclic rewrite of TEMPORARY keys container ...");
	for (i = 0; i < VIRGIL_KEYSTORAGE_TEMPORARY_KEYS_MAX_COUNT * 2; ++i) {
		snprintf(id, 10, "%d", (int)i);

		virgil_data_free(&data_for_save);
		virgil_data_free(&loaded_data);

		_fillData(&data_for_save, i + 100);

		if (VIRGIL_OPERATION_OK != virgil_save_key(id, data_for_save, VIRGIL_KEY_TEMPORARY)
				|| VIRGIL_OPERATION_OK != virgil_load_key(id, &loaded_data)
				|| data_for_save.sz != loaded_data.sz
				|| 0 != memcmp(data_for_save.data, loaded_data.data, loaded_data.sz)) {
			RESULT_ERROR;
			goto terminate;
		}

	}
	RESULT_OK;

	terminate:
	virgil_data_free(&data_for_save);
	virgil_data_free(&loaded_data);
}

/******************************************************************************/
void key_storage_test(void) {
	START_TEST("KEY STORAGE");

	save_load_test();
	update_test();
	abnormal_params_test();
	remove_test();
	encrypted_save_load_test();
	permanent_container_stress_test();
	temporary_container_stress_test();
}
