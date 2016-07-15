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
 * @file verify.c
 * @brief Function for signature verification.
 */

#include <linux/module.h>

#include <virgil/kernel/private/usermode-communicator.h>
#include <virgil/kernel/private/data-waiter.h>

#include <virgil/kernel/crypto.h>

/******************************************************************************/
static __u32 verify_request(bool use_pubkey, data_t cert_or_pubkey, data_t data, data_t signature) {
	fields_t fields;
	struct package_field_t fields_ar[3];
	__u32 res;

	fields.count = 3;
	fields.ar = fields_ar;

	FILL_FIELD(fields_ar[0], use_pubkey ? VIRGIL_FIELD_PUBLIC_KEY : VIRGIL_FIELD_CERT, cert_or_pubkey);
	FILL_FIELD(fields_ar[1], VIRGIL_FIELD_DATA, data);
	FILL_FIELD(fields_ar[2], VIRGIL_FIELD_SIGNATURE, signature);

	SEND_WITH_CHECK(VIRGIL_CMD_CRYPTO_VERIFY,
			fields,
			res,
			"ERROR: Signature verification can't be processed");

	return res;
}

/******************************************************************************/
static int verify(bool use_pubkey, data_t cert_or_pubkey, data_t data, data_t signature, bool * is_verified) {
	__u32 id;
	fields_t fields;
	int res;
	__s16 res_field;

	// Check input parameters
	NOT_ZERO(is_verified);

	// Send request and wait for response
	REQUEST_CHECK(id, verify_request(use_pubkey, cert_or_pubkey, data, signature));
	CHECK(data_waiter_execute(id, &fields, VIRGIL_OPERATION_TIMEOUT_MS));

	res = fields_result(fields, &res_field);

	*is_verified = VIRGIL_OPERATION_OK == res_field;

	fields_free(&fields);

	return res;
}

/******************************************************************************/
int virgil_verify_with_pubkey(data_t public_key, data_t data, data_t signature, bool * is_verified) {
	const bool use_pubkey = true;
	return verify(use_pubkey, public_key, data, signature, is_verified);
}

/******************************************************************************/
int virgil_verify_with_cert(data_t cert, data_t data, data_t signature, bool * is_verified) {
	const bool use_pubkey = false;
	return verify(use_pubkey, cert, data, signature, is_verified);
}

EXPORT_SYMBOL( virgil_verify_with_pubkey);
EXPORT_SYMBOL( virgil_verify_with_cert);
