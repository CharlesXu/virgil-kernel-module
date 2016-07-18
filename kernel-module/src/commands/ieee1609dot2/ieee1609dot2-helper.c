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
 * @file ieee1609dot2-helper.c
 * @brief IEEE1609.2 helper functions.
 */

#include <linux/module.h>
#include <linux/slab.h>

#include <virgil/kernel/private/usermode-communicator.h>
#include <virgil/kernel/private/data-waiter.h>
#include <virgil/kernel/private/fields.h>
#include <virgil/kernel/foundation/key-value.h>

#include <virgil/kernel/crypto.h>
#include <virgil/kernel/certificates.h>
#include <virgil/kernel/ieee1609dot2/ieee1609dot2-helper.h>

const char * KEY_SUFFIX_PRIV = "PRIV_";
const char * KEY_SUFFIX_PUB = "PUBL_";
const char * KEY_SUFFIX_CERT = "CERT_";
const char * KEY_SUFFIX_SYM = "SYMM_";

#define ID_SIZE (sizeof(cmh_t) * 2 + 1)
#define KEY_PREFIX_SIZE 5

#define KEY_IDENTITY_SIZE (ID_SIZE + KEY_PREFIX_SIZE)

/******************************************************************************/
static int algotithm2ec_type(int algorithm) {
	if (algorithm == ALGORITHM_ECDSA_BP256R1_SHA256 || algorithm == ALGORITHM_ECIES_BP256R1) {
		return EC_BP_256;
	}
	return EC_NIST256;
}
/******************************************************************************/
static char calc_char_shift(__u8 ch) {
	return ch < 0x0A ? '0' : ('A' - 0x0A);
}
/******************************************************************************/
static void cmh2str(cmh_t cmh, char str[ID_SIZE]) {
	int i;
	cmh_t val = cmh;
	char el;

	memset(str, 0, ID_SIZE);

	if (cmh) {
		for (i = 0; i < sizeof(cmh_t); ++i) {
			el = val & 0x0F;
			str[i << 1] = el + calc_char_shift(el);
			val >>= 4;

			el = val & 0x0F;
			str[(i << 1) + 1] = el + calc_char_shift(el);
			val >>= 4;
		}
	} else {
		strcpy(str, ROOT_CERTIFICATE_IDENTITY);
	}
}

/******************************************************************************/
static void id_composition(cmh_t cmh, const char * prefix,
		char str[ID_SIZE + KEY_PREFIX_SIZE]) {
	memset(str, 0, ID_SIZE + KEY_PREFIX_SIZE);
	memcpy(str, prefix, KEY_PREFIX_SIZE);
	cmh2str(cmh, &str[KEY_PREFIX_SIZE]);
}

/******************************************************************************/
int virgil_ieee1609_create_material(cmh_t cmh, int algorithm, kv_container_t addition_data,
		data_t * private_key, data_t * certificate) {
	char str_id[ID_SIZE];
	cmh2str(cmh, str_id);

	return virgil_certificate_create(
			algotithm2ec_type(algorithm),
			str_id,
			addition_data,
			private_key,
			certificate);
}

/******************************************************************************/
int virgil_ieee1609_request_cert(cmh_t cmh, data_t * certificate) {
	char str_id[ID_SIZE];
	cmh2str(cmh, str_id);

	return virgil_certificate_get(str_id, certificate);
}

/******************************************************************************/
int virgil_ieee1609_verify_cert(data_t certificate, bool * is_ok) {
	data_t root_cert;
	int res;

	virgil_data_reset(&root_cert);

	CHECK(virgil_ieee1609_load_key(ROOT_CERTIFICATE_CMH, KEY_TYPE_CERTIFICATE, &root_cert));

	res = virgil_certificate_verify(certificate, root_cert, is_ok);

	virgil_data_free(&root_cert);

	return res;
}

/******************************************************************************/
int virgil_ieee1609_revoke_cert(cmh_t cmh, data_t private_key, bool * is_ok) {
	char str_id[ID_SIZE];
	cmh2str(cmh, str_id);

	return virgil_certificate_revoke(str_id, private_key, is_ok);
}

/******************************************************************************/
int virgil_ieee1609_add_cert(data_t certificate, bool is_root) {
	char str_id[VIRGIL_KEYSTORAGE_ID_MAX_SIZE - KEY_PREFIX_SIZE];
	char * identity = 0;
	int res, identity_len, copy_sz;

	memset(str_id, 0, VIRGIL_KEYSTORAGE_ID_MAX_SIZE - KEY_PREFIX_SIZE);
	memcpy(str_id, KEY_SUFFIX_CERT, KEY_PREFIX_SIZE);
	if (is_root) {
		cmh2str(ROOT_CERTIFICATE_CMH, str_id);
	} else {
		res = virgil_certificate_get_identity(certificate, &identity);
		if (VIRGIL_OPERATION_OK != res || !identity) {
			return res;
		}
		identity_len = strlen(identity);
		copy_sz = (identity_len >= (VIRGIL_KEYSTORAGE_ID_MAX_SIZE - KEY_PREFIX_SIZE)) ? (VIRGIL_KEYSTORAGE_ID_MAX_SIZE - 1) : identity_len;
		memcpy(&str_id[KEY_PREFIX_SIZE], identity, copy_sz);
	}

	res = virgil_save_key(str_id, certificate, is_root ? VIRGIL_KEY_PERMANENT : VIRGIL_KEY_TEMPORARY);

	return res;
}

/******************************************************************************/
int virgil_ieee1609_delete_cert(data_t certificate) {
	char str_id[VIRGIL_KEYSTORAGE_ID_MAX_SIZE - KEY_PREFIX_SIZE];
	char * identity = 0;
	int res, identity_len, copy_sz;

	memset(str_id, 0, VIRGIL_KEYSTORAGE_ID_MAX_SIZE - KEY_PREFIX_SIZE);
	memcpy(str_id, KEY_SUFFIX_CERT, KEY_PREFIX_SIZE);
	res = virgil_certificate_get_identity(certificate, &identity);
	if (VIRGIL_OPERATION_OK != res || !identity) {
		return res;
	}
	identity_len = strlen(identity);
	copy_sz = (identity_len >= (VIRGIL_KEYSTORAGE_ID_MAX_SIZE - KEY_PREFIX_SIZE)) ? (VIRGIL_KEYSTORAGE_ID_MAX_SIZE - 1) : identity_len;
	memcpy(&str_id[KEY_PREFIX_SIZE], identity, copy_sz);

	res = virgil_revoke_key(str_id);

	return res;
}

/******************************************************************************/
int virgil_ieee1609_load_key(cmh_t cmh, int key_type, data_t * loaded_key) {
	char str_id[ID_SIZE + KEY_PREFIX_SIZE];
	const char * suffix = KEY_SUFFIX_PUB;

	if (ROOT_CERTIFICATE_CMH == cmh) {
		cmh2str(ROOT_CERTIFICATE_CMH, str_id);
	} else {
		if (KEY_TYPE_PRIVATE == key_type)
			suffix = KEY_SUFFIX_PRIV;
		else if (KEY_TYPE_CERTIFICATE == key_type)
			suffix = KEY_SUFFIX_CERT;
		else if (KEY_TYPE_SYMMETRIC == key_type)
			suffix = KEY_SUFFIX_SYM;

		id_composition(cmh, suffix, str_id);
	}
	return virgil_load_key(str_id, loaded_key);
}

/******************************************************************************/
int virgil_ieee1609_decrypt_with_cmh(cmh_t cmh, data_t data,
		data_t * decrypted_data) {
	char * identity = 0;
	data_t private_key, own_cert;
	int res;

	virgil_data_reset(&private_key);
	virgil_data_reset(decrypted_data);

	CHECK(virgil_ieee1609_load_key(cmh, KEY_TYPE_PRIVATE, &private_key));
	CHECK(virgil_ieee1609_load_key(cmh, KEY_TYPE_CERTIFICATE, &own_cert));

	res = virgil_certificate_get_identity(own_cert, &identity);
	if (VIRGIL_OPERATION_OK != res) {
		virgil_data_free(&private_key);
		virgil_data_free(&own_cert);
		return res;
	}

	res = virgil_decrypt_with_key(private_key, data, identity, decrypted_data);

	virgil_data_free(&private_key);
	virgil_data_free(&own_cert);
	kfree(identity);

	return res;
}

/******************************************************************************/
int virgil_ieee1609_parse_cert(data_t certificate, kv_container_t * kv_data,
		char ** geo_scope, time_t * last_crl_time, time_t * next_crl_time,
		bool * is_root_cert) {
	data_t root_cert;

	virgil_data_reset(&root_cert);
	*geo_scope = 0;

	CHECK(virgil_ieee1609_get_crl_info(last_crl_time, next_crl_time));
	CHECK(virgil_certificate_parse(certificate, kv_data));
	CHECK(virgil_ieee1609_load_key(ROOT_CERTIFICATE_CMH, KEY_TYPE_CERTIFICATE, &root_cert));

	*is_root_cert = 0 == memcmp(certificate.data, root_cert.data, certificate.sz);

	virgil_data_free(&root_cert);

	return VIRGIL_OPERATION_OK;
}

/******************************************************************************/
int virgil_ieee1609_cmh_create(cmh_t * cmh) {
	struct timespec ts;

	getnstimeofday(&ts);
	*cmh = ts.tv_sec;
	*cmh <<= sizeof(cmh_t) * 4;
	*cmh |= ts.tv_nsec;

	return VIRGIL_OPERATION_OK;
}

/******************************************************************************/
int virgil_ieee1609_cmh_gen_keypair(cmh_t cmh, int algorithm,
		data_t * public_key, data_t * private_key) {
	return virgil_create_keypair(algotithm2ec_type(algorithm), private_key, public_key);
}

/******************************************************************************/
int virgil_ieee1609_cmh_store_keypair(cmh_t cmh, int algorithm,
		data_t public_key, data_t private_key) {
	char str_id[ID_SIZE + KEY_PREFIX_SIZE];

	id_composition(cmh, KEY_SUFFIX_PUB, str_id);
	CHECK(virgil_save_key(str_id, public_key, VIRGIL_KEY_PERMANENT));

	id_composition(cmh, KEY_SUFFIX_PRIV, str_id);
	return virgil_save_key(str_id, private_key, VIRGIL_KEY_PERMANENT);
}

/******************************************************************************/
int virgil_ieee1609_cmh_store_cert(cmh_t cmh, data_t certificate,
		data_t priv_key_transform) {
	char str_id[ID_SIZE + KEY_PREFIX_SIZE];

	id_composition(cmh, KEY_SUFFIX_CERT, str_id);
	return virgil_save_key(str_id, certificate, VIRGIL_KEY_PERMANENT);
}

/******************************************************************************/
int virgil_ieee1609_cmh_store_cert_and_key(cmh_t cmh, data_t certificate,
		data_t private_key) {
	char str_id[KEY_IDENTITY_SIZE];

	id_composition(cmh, KEY_SUFFIX_CERT, str_id);
	CHECK(virgil_save_key(str_id, certificate, VIRGIL_KEY_PERMANENT));

	id_composition(cmh, KEY_SUFFIX_PRIV, str_id);
	return virgil_save_key(str_id, private_key, VIRGIL_KEY_PERMANENT);
}

/******************************************************************************/
int virgil_ieee1609_cmh_delete(cmh_t cmh) {
	char str_id[KEY_IDENTITY_SIZE];

	id_composition(cmh, KEY_SUFFIX_PRIV, str_id);
	virgil_revoke_key(str_id);

	id_composition(cmh, KEY_SUFFIX_PUB, str_id);
	virgil_revoke_key(str_id);

	id_composition(cmh, KEY_SUFFIX_CERT, str_id);
	virgil_revoke_key(str_id);

	id_composition(cmh, KEY_SUFFIX_SYM, str_id);
	virgil_revoke_key(str_id);

	return VIRGIL_OPERATION_OK;
}

/******************************************************************************/
int virgil_ieee1609_cmh_sign(cmh_t cmh, data_t data, data_t * signature) {
	data_t private_key;
	int res;

	virgil_data_reset(&private_key);
	virgil_data_reset(signature);

	CHECK(virgil_ieee1609_load_key(cmh, KEY_TYPE_PRIVATE, &private_key));

	res = virgil_sign(private_key, data, signature);

	virgil_data_free(&private_key);

	return res;
}

/******************************************************************************/
int virgil_ieee1609_hashed_id8(data_t data, data_t * hashed_id8) {
	virgil_data_reset(hashed_id8);
	return VIRGIL_OPERATION_OK;
}

/******************************************************************************/
int virgil_ieee1609_transform_private_key(data_t private_key, data_t * priv_key_transform) {
	// TODO: Need low level implementation
	return virgil_data_dup_ar(priv_key_transform, private_key.sz, private_key.data);
}

EXPORT_SYMBOL( virgil_ieee1609_create_material);
EXPORT_SYMBOL( virgil_ieee1609_request_cert);
EXPORT_SYMBOL( virgil_ieee1609_revoke_cert);

EXPORT_SYMBOL( virgil_ieee1609_add_cert);
EXPORT_SYMBOL( virgil_ieee1609_delete_cert);
EXPORT_SYMBOL( virgil_ieee1609_load_key);
EXPORT_SYMBOL( virgil_ieee1609_decrypt_with_cmh);
EXPORT_SYMBOL( virgil_ieee1609_cmh_create);
EXPORT_SYMBOL( virgil_ieee1609_cmh_gen_keypair);
EXPORT_SYMBOL( virgil_ieee1609_cmh_store_keypair);
EXPORT_SYMBOL( virgil_ieee1609_cmh_store_cert);
EXPORT_SYMBOL( virgil_ieee1609_cmh_store_cert_and_key);
EXPORT_SYMBOL( virgil_ieee1609_cmh_delete);
EXPORT_SYMBOL( virgil_ieee1609_cmh_sign);
EXPORT_SYMBOL( virgil_ieee1609_hashed_id8);
EXPORT_SYMBOL( virgil_ieee1609_transform_private_key);
EXPORT_SYMBOL( virgil_ieee1609_parse_cert);
EXPORT_SYMBOL( virgil_ieee1609_verify_cert);
