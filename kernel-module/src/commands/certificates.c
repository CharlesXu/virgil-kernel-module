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
 * @file certificates.c
 * @brief API certificates specific functions.
 */

#include <linux/module.h>
#include <linux/slab.h>

#include <virgil/kernel/private/usermode-communicator.h>
#include <virgil/kernel/private/data-waiter.h>
#include <virgil/kernel/private/fields.h>
#include <virgil/kernel/foundation/key-value.h>

const char * KEY_IDENTITY = "v__IdentityKey";
const char * KEY_PUBLIC_KEY = "v__PublicKeyKey";

/******************************************************************************/
static __u32 certificate_create_request(int ec_type,
		const char * identifier,
		kv_container_t addition_data) {
	fields_t fields;
	struct package_field_t fields_ar[3];
	__u32 res;
	data_t serialized_data;
	const __u8 _ec_type = ec_type;

	virgil_data_reset(&serialized_data);

	fields.count = 3;
	fields.ar = fields_ar;
	serialized_data = virgil_kv_serialize(&addition_data);

	FILL_FIELD_STR(fields_ar[0], VIRGIL_FIELD_IDENTITY, identifier);
	FILL_FIELD(fields_ar[1], VIRGIL_FIELD_DATA, serialized_data);
	FILL_FIELD_AR(fields_ar[2], VIRGIL_FIELD_CURVE_TYPE, &_ec_type, sizeof(_ec_type));

	SEND_WITH_CHECK(VIRGIL_CMD_CERTIFICATE_CREATE,
			fields,
			res,
			"ERROR: Certificate creation can't be processed");

	virgil_data_free(&serialized_data);

	return res;
}

/******************************************************************************/
int virgil_certificate_create(int ec_type, const char * identifier,
		kv_container_t addition_data, data_t * private_key,
		data_t * certificate) {
	__u32 id;
	__s16 err_res;
	fields_t fields;

	// Check input parameters
	VALID_STR(identifier);
	NOT_ZERO(private_key);
	NOT_ZERO(certificate);

	// Send request and wait for response
	REQUEST_CHECK(id, certificate_create_request(ec_type, identifier, addition_data));
	CHECK(data_waiter_execute(id, &fields, VIRGIL_OPERATION_TIMEOUT_MS));

	// Clear output data
	virgil_data_reset(private_key);
	virgil_data_reset(certificate);

	// Parse response
	CHECK_ERROR(fields, err_res);
	CHECK(fields_dup_first(VIRGIL_FIELD_CERT, fields, certificate));
	CHECK(fields_dup_first(VIRGIL_FIELD_PRIVATE_KEY, fields, private_key));

	fields_free(&fields);

	return VIRGIL_OPERATION_OK;
}

/******************************************************************************/
static __u32 certificate_get_request(const char * identifier) {
	fields_t fields;
	__u32 res;
	struct package_field_t fields_ar[1];

	fields.count = 1;
	fields.ar = fields_ar;

	FILL_FIELD_STR(fields_ar[0], VIRGIL_FIELD_IDENTITY, identifier);

	SEND_WITH_CHECK(VIRGIL_CMD_CERTIFICATE_GET,
			fields,
			res,
			"ERROR: Certificate request can't be processed");

	return res;
}

/******************************************************************************/
int virgil_certificate_get(const char * identifier, data_t * certificate) {
	__u32 id;
	__s16 err_res;
	fields_t fields;

	// Check input parameters
	VALID_STR(identifier);
	NOT_ZERO(certificate);

	// Send request and wait for response
	REQUEST_CHECK(id, certificate_get_request(identifier));
	CHECK(data_waiter_execute(id, &fields, VIRGIL_OPERATION_TIMEOUT_MS));

	// Clear output data
	virgil_data_reset(certificate);

	// Parse response
	CHECK_ERROR(fields, err_res);
	CHECK(fields_dup_first(VIRGIL_FIELD_CERT, fields, certificate));

	fields_free(&fields);

	return VIRGIL_OPERATION_OK;
}

/******************************************************************************/
static __u32 certificate_verify_request(data_t certificate, data_t root_certificate) {
	fields_t fields;
	__u32 res;
	struct package_field_t fields_ar[2];

	fields.count = 2;
	fields.ar = fields_ar;

	FILL_FIELD(fields_ar[0], VIRGIL_FIELD_CERT, certificate);
	FILL_FIELD(fields_ar[1], VIRGIL_FIELD_ROOT_CERT, root_certificate);

	SEND_WITH_CHECK(VIRGIL_CMD_CERTIFICATE_VERIFY,
			fields,
			res,
			"ERROR: Certificate verification can't be processed");

	return res;
}

/******************************************************************************/
int virgil_certificate_verify(data_t certificate, data_t root_certificate, bool * is_ok) {
	__u32 id;
	__s16 result;
	fields_t fields;
	int res = 0;

	// Check input parameters
	NOT_ZERO(is_ok);

	// Send request and wait for response
	REQUEST_CHECK(id, certificate_verify_request(certificate, root_certificate));
	CHECK(data_waiter_execute(id, &fields, VIRGIL_OPERATION_TIMEOUT_MS));

	// Parse response
	res = fields_result(fields, &result);

	if (VIRGIL_OPERATION_ERROR == res) {
		result = res;
	}

	*is_ok = VIRGIL_OPERATION_OK == result;

	fields_free(&fields);

	return VIRGIL_OPERATION_OK;
}

/******************************************************************************/
static __u32 certificate_parse_request(data_t certificate) {
	fields_t fields;
	struct package_field_t fields_ar[1];
	__u32 res;

	fields.count = 1;
	fields.ar = fields_ar;

	FILL_FIELD(fields_ar[0], VIRGIL_FIELD_CERT, certificate);

	SEND_WITH_CHECK(VIRGIL_CMD_CERTIFICATE_PARSE,
			fields,
			res,
			"ERROR: Certificate parse can't be processed");

	return res;
}

/******************************************************************************/
int virgil_certificate_parse(data_t certificate, kv_container_t * cert_data) {
	__u32 id;
	__s16 err_res;
	fields_t fields;
	data_t kv_raw;

	// Check input parameters
	NOT_ZERO(cert_data);

	// Send request and wait for response
	REQUEST_CHECK(id, certificate_parse_request(certificate));
	CHECK(data_waiter_execute(id, &fields, VIRGIL_OPERATION_TIMEOUT_MS));

	// Clear output data
	virgil_kv_reset(cert_data);
	virgil_data_reset(&kv_raw);

	// Parse response
	CHECK_ERROR(fields, err_res);
	CHECK(fields_dup_first(VIRGIL_FIELD_DATA, fields, &kv_raw));

	*cert_data = virgil_kv_deserialize(kv_raw);

	// Free data
	fields_free(&fields);
	virgil_data_free(&kv_raw);

	return VIRGIL_OPERATION_OK;
}

/******************************************************************************/
static __u32 certificate_revoke_request(const char * identifier,
		data_t private_key) {
	fields_t fields;
	struct package_field_t fields_ar[2];
	__u32 res;

	fields.count = 2;
	fields.ar = fields_ar;

	FILL_FIELD_STR(fields_ar[0], VIRGIL_FIELD_IDENTITY, identifier);
	FILL_FIELD(fields_ar[1], VIRGIL_FIELD_PRIVATE_KEY, private_key);

	SEND_WITH_CHECK(VIRGIL_CMD_CERTIFICATE_REVOKE,
			fields,
			res,
			"ERROR: Certificate revocation can't be processed");

	return res;
}

/******************************************************************************/
int virgil_certificate_revoke(const char * identifier, data_t private_key,
		bool * is_ok) {
	__u32 id;
	__s16 result;
	fields_t fields;
	int res = 0;

	// Check input parameters
	VALID_STR(identifier);
	NOT_ZERO(is_ok);

	// Send request and wait for response
	REQUEST_CHECK(id, certificate_revoke_request(identifier, private_key));
	CHECK(data_waiter_execute(id, &fields, VIRGIL_OPERATION_TIMEOUT_MS));

	// Parse response
	res = fields_result(fields, &result);

	if (VIRGIL_OPERATION_ERROR == res) {
		result = res;
	}

	*is_ok = VIRGIL_OPERATION_OK == result;

	fields_free(&fields);

	return VIRGIL_OPERATION_OK;
}

/******************************************************************************/
static __u32 crl_info_request(void) {
	fields_t fields;
	__u32 res;

	fields_reset(&fields);

	SEND_WITH_CHECK(VIRGIL_CMD_CERTIFICATE_CRL_INFO,
			fields,
			res,
			"ERROR: CRL Can't be requested");

	return res;
}

/******************************************************************************/
int virgil_certificate_crl_info(time_t * last, time_t * next) {
	__u32 id;
	__s16 err_res;
	fields_t fields;
	data_t data;

	// Check input parameters
	NOT_ZERO(last);
	NOT_ZERO(next);

	// Send request and wait for response
	REQUEST_CHECK(id, crl_info_request());
	CHECK(data_waiter_execute(id, &fields, VIRGIL_OPERATION_TIMEOUT_MS));

	// Parse response
	CHECK_ERROR(fields, err_res);
	CHECK(fields_dup_first(VIRGIL_FIELD_CRL_LAST, fields, &data));
	memcpy(last, data.data, sizeof(time_t));
	virgil_data_free(&data);

	CHECK(fields_dup_first(VIRGIL_FIELD_CRL_NEXT, fields, &data));
	memcpy(next, data.data, sizeof(time_t));

	fields_free(&fields);
	virgil_data_free(&data);

	return VIRGIL_OPERATION_OK;
}

/******************************************************************************/
static __u32 certificate_is_revoked_request(data_t certificate) {
	fields_t fields;
	struct package_field_t fields_ar[1];
	__u32 res;

	fields.count = 1;
	fields.ar = fields_ar;

	FILL_FIELD(fields_ar[0], VIRGIL_FIELD_CERT, certificate);

	SEND_WITH_CHECK(VIRGIL_CMD_CERTIFICATE_CHECK_IS_REVOKED,
			fields,
			res,
			"ERROR: Certificate check can't be processed");

	return res;
}

/******************************************************************************/
int virgil_certificate_is_revoked(data_t certificate, bool * is_revoked) {
	__u32 id;
	fields_t fields;
	data_t data;

	// Check input parameters
	NOT_ZERO(is_revoked);

	// Send request and wait for response
	REQUEST_CHECK(id, certificate_is_revoked_request(certificate));
	CHECK(data_waiter_execute(id, &fields, VIRGIL_OPERATION_TIMEOUT_MS));

	// Parse response
	CHECK(fields_dup_first(VIRGIL_FIELD_OPTIONAL_1, fields, &data));
	*is_revoked = !!((char *) data.data)[0];

	virgil_data_free(&data);
	fields_free(&fields);

	return VIRGIL_OPERATION_OK;
}

/******************************************************************************/
int virgil_certificate_get_identity(data_t certificate, char ** identity) {
	kv_container_t cert_data;
	int i, val_sz;
	const char * p_key;
	const void * p_val;

	*identity = 0;
	virgil_kv_reset(&cert_data);

	CHECK(virgil_certificate_parse(certificate, &cert_data));

	for (i = 0; i < cert_data.kv_count; ++i) {
		p_key = ((kv_pair_t *) cert_data.ar.p)[i].key;
		val_sz = ((kv_pair_t *) cert_data.ar.p)[i].value_sz;
		p_val = ((kv_pair_t *) cert_data.ar.p)[i].value.p;

		if (0 == strncmp(p_key, KEY_IDENTITY, VIRGIL_KV_KEY_MAX_SZ)) {
			*identity = kmalloc(val_sz, GFP_KERNEL);
			if (*identity) {
				memcpy(*identity, p_val, val_sz);
				return VIRGIL_OPERATION_OK;
			}
		}
	}
	return VIRGIL_OPERATION_ERROR;
}

EXPORT_SYMBOL( virgil_certificate_create);
EXPORT_SYMBOL( virgil_certificate_get);
EXPORT_SYMBOL( virgil_certificate_verify);
EXPORT_SYMBOL( virgil_certificate_parse);
EXPORT_SYMBOL( virgil_certificate_revoke);
EXPORT_SYMBOL( virgil_certificate_crl_info);
EXPORT_SYMBOL( virgil_certificate_is_revoked);
EXPORT_SYMBOL( virgil_certificate_get_identity);
