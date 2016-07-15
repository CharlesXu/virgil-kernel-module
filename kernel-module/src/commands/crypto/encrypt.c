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
 * @file encrypt.c
 * @brief Functions for data encryption.
 */

#include <linux/module.h>

#include <virgil/kernel/private/usermode-communicator.h>
#include <virgil/kernel/private/data-waiter.h>
#include <virgil/kernel/private/fields.h>

#include <virgil/kernel/crypto.h>

/******************************************************************************/
static __u32 encrypt_with_password_request(const char * password, data_t data) {
	fields_t fields;
	struct package_field_t fields_ar[2];
	__u32 res;

	fields.count = 2;
	fields.ar = fields_ar;

	FILL_FIELD_STR(fields_ar[0], VIRGIL_FIELD_PASSWORD, password);
	FILL_FIELD(fields_ar[1], VIRGIL_FIELD_DATA, data);

	SEND_WITH_CHECK(VIRGIL_CMD_CRYPTO_ENCRYPT_PASS,
			fields,
			res,
			"ERROR: Encrypt with password can't be processed");

	return res;
}

/******************************************************************************/
int virgil_encrypt_with_password(const char * password, data_t data, data_t * enc_data) {
	__u32 id;
	__s16 err_res;
	fields_t fields;

	// Check input parameters
	VALID_STR(password);
	NOT_ZERO(enc_data);

	// Send request and wait for response
	REQUEST_CHECK(id, encrypt_with_password_request(password, data));
	CHECK(data_waiter_execute(id, &fields, VIRGIL_OPERATION_TIMEOUT_MS));

	// Clear output data
	virgil_data_reset(enc_data);

	// Parse response
	CHECK_ERROR(fields, err_res);
	CHECK(fields_dup_first(VIRGIL_FIELD_DATA, fields, enc_data));

	fields_free(&fields);

	return VIRGIL_OPERATION_OK;
}

/******************************************************************************/
static __u32 encrypt_with_pub_key_request(__u32 recipients_count,
		const data_t * pub_keys, const char ** identities, data_t data) {
	fields_t fields;
	struct package_field_t fields_ar[VIRGIL_RECIPIENTS_COUNT_MAX * 2 + 1];
	__u32 res;
	int i;

	if (!recipients_count || recipients_count > 50) return VIRGIL_INVALID_ID;

	fields.count = recipients_count * 2 + 1;
	fields.ar = fields_ar;

	// Fill all data fields
	for (i = 0; i < recipients_count; ++i) {
		FILL_FIELD(fields.ar[i * 2], VIRGIL_FIELD_PUBLIC_KEY, pub_keys[i]);
		FILL_FIELD_STR(fields.ar[i * 2 + 1], VIRGIL_FIELD_IDENTITY, identities[i]);
	}

	FILL_FIELD(fields.ar[recipients_count * 2], VIRGIL_FIELD_DATA, data);
	// ~ Fill all data fields

	SEND_WITH_CHECK(VIRGIL_CMD_CRYPTO_ENCRYPT,
			fields,
			res,
			"ERROR: Encrypt data with public keys can't be processed");

	return res;
}

/******************************************************************************/
int virgil_encrypt_with_pubkey(__u32 recipients_count,
        const data_t * public_keys, const char ** identities,
        data_t data, data_t * enc_data) {
	__u32 id;
	__s16 err_res;
	fields_t fields;

	// Check input parameters
	NOT_ZERO(public_keys);
	NOT_ZERO(identities);
	NOT_ZERO(enc_data);

	// Send request and wait for response
	REQUEST_CHECK(id, encrypt_with_pub_key_request(recipients_count, public_keys, identities, data));
	CHECK(data_waiter_execute(id, &fields, VIRGIL_OPERATION_TIMEOUT_MS));

	// Clear output data
	virgil_data_reset(enc_data);

	// Parse response
	CHECK_ERROR(fields, err_res);
	CHECK(fields_dup_first(VIRGIL_FIELD_DATA, fields, enc_data));

	fields_free(&fields);

	return VIRGIL_OPERATION_OK;
}

/******************************************************************************/
static __u32 encrypt_with_cert_request(__u32 recipients_count, const data_t * certs, data_t data) {
	fields_t fields;
	struct package_field_t fields_ar[VIRGIL_RECIPIENTS_COUNT_MAX + 1];
	__u32 res;
	int i;

	if (!recipients_count || recipients_count > 50) return VIRGIL_INVALID_ID;

	fields.count = recipients_count + 1;
	fields.ar = fields_ar;

	// Fill all data fields
	for (i = 0; i < recipients_count; ++i) {
		FILL_FIELD(fields.ar[i], VIRGIL_FIELD_CERT, certs[i]);
	}

	FILL_FIELD(fields.ar[recipients_count], VIRGIL_FIELD_DATA, data);
	// ~ Fill all data fields

	SEND_WITH_CHECK(VIRGIL_CMD_CRYPTO_ENCRYPT,
			fields,
			res,
			"ERROR: Encrypt data with certificates can't be processed");

	return res;
}

/******************************************************************************/
int virgil_encrypt_with_cert(__u32 recipients_count,
		const data_t * certs, data_t data, data_t * enc_data) {
	__u32 id;
	__s16 err_res;
	fields_t fields;

	// Check input parameters
	NOT_ZERO(certs);
	NOT_ZERO(enc_data);

	// Send request and wait for response
	REQUEST_CHECK(id, encrypt_with_cert_request(recipients_count, certs, data));
	CHECK(data_waiter_execute(id, &fields, VIRGIL_OPERATION_TIMEOUT_MS));

	// Clear output data
	virgil_data_reset(enc_data);

	// Parse response
	CHECK_ERROR(fields, err_res);
	CHECK(fields_dup_first(VIRGIL_FIELD_DATA, fields, enc_data));

	fields_free(&fields);

	return VIRGIL_OPERATION_OK;
}

EXPORT_SYMBOL( virgil_encrypt_with_password);
EXPORT_SYMBOL( virgil_encrypt_with_pubkey);
EXPORT_SYMBOL( virgil_encrypt_with_cert);
