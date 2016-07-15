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
 * @file keypair.c
 * @brief Key-pair creation function.
 */

#include <linux/module.h>

#include <virgil/kernel/private/usermode-communicator.h>
#include <virgil/kernel/private/data-waiter.h>
#include <virgil/kernel/private/fields.h>

#include <virgil/kernel/crypto.h>

/******************************************************************************/
static __u32 create_keypair_request(void) {
	fields_t fields;
	__u32 res;

	fields_reset(&fields);

	SEND_WITH_CHECK(VIRGIL_CMD_CRYPTO_KEYGEN,
			fields,
			res,
			"ERROR: Keypair creation can't be processed");

	return res;
}

/******************************************************************************/
int virgil_create_keypair(data_t * private_key, data_t * public_key) {
	__u32 id;
	fields_t fields;
	__s16 err_res;
	int res = 0;

	// Check input parameters
	NOT_ZERO(private_key);
	NOT_ZERO(public_key);

	// Send request and wait for response
	REQUEST_CHECK(id, create_keypair_request());
	CHECK(data_waiter_execute(id, &fields, VIRGIL_OPERATION_TIMEOUT_MS));

	// Parse response
	CHECK_ERROR(fields, err_res);
	CHECK(fields_dup_first(VIRGIL_FIELD_PRIVATE_KEY, fields, private_key));
	CHECK(fields_dup_first(VIRGIL_FIELD_PUBLIC_KEY, fields, public_key));

	fields_free(&fields);

	return res;
}

EXPORT_SYMBOL( virgil_create_keypair);
