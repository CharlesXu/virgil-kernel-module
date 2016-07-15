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

#include <virgil/kernel/crypto.h>
#include <virgil/kernel/foundation/data.h>

#include "macro.h"

static const char * text = "In 1971, ALOHAnet connected the Hawaiian Islands with a UHF wireless packet network.";

/******************************************************************************/
static void password_based_encrypt_decrypt_test(void) {
	const char * password = "test_password";

	data_t data;
	data_t encrypted_data;
	data_t decrypted_data;

	data.data = (void *)text;
	data.sz = strlen(text) + 1;

	virgil_data_reset(&encrypted_data);
	virgil_data_reset(&decrypted_data);

	START_TEST("PASSWORD ENCRYPTION");

	LOG("Data to be encrypted : <%s>", text);

	TEST_CASE_OK("Encrypt data with password",
			virgil_encrypt_with_password(password, data, &encrypted_data));

	TEST_CASE_OK("Decrypt data with password",
			virgil_decrypt_with_password(password, encrypted_data, &decrypted_data));

	LOG("Decrypted data       : <%s>", (char *)decrypted_data.data);

	terminate:
	virgil_data_free(&encrypted_data);
	virgil_data_free(&decrypted_data);
}

/******************************************************************************/
static void encrypt_decrypt_test(void) {
	const char * identity_bob = "bob-identifier";
	const char * identity_carl = "carl-identifier";

	data_t bob_private_key;
	data_t carl_private_key;

	data_t data;
	data_t encrypted_data;
	data_t decrypted_data;

	data_t pubkey_ar[2];
	const char * identity_ar[2];

	virgil_data_reset(&bob_private_key);
	virgil_data_reset(&carl_private_key);
	virgil_data_reset(&pubkey_ar[0]);
	virgil_data_reset(&pubkey_ar[1]);
	virgil_data_reset(&data);
	virgil_data_reset(&encrypted_data);
	virgil_data_reset(&decrypted_data);

	data.data = (void *)text;
	data.sz = strlen(text) + 1;

	START_TEST("SIMPLE CRYPTO");

	LOG("Data to be encrypted : <%s>", text);

	TEST_CASE_OK("Create keys for BOB",
			virgil_create_keypair(&bob_private_key, &pubkey_ar[0]));

	TEST_CASE_OK("Create keys for CARL",
				virgil_create_keypair(&carl_private_key, &pubkey_ar[1]));

	identity_ar[0] = identity_bob;
	identity_ar[1] = identity_carl;

	TEST_CASE_OK("Encrypt data (By ALICE to BOB and CARL)",
			virgil_encrypt_with_pubkey(2, pubkey_ar, identity_ar, data, &encrypted_data));

	TEST_CASE_OK("Decrypt data (By BOB)",
			virgil_decrypt_with_key(bob_private_key, encrypted_data, identity_bob, &decrypted_data));

	virgil_data_free(&decrypted_data);

	TEST_CASE_OK("Decrypt data (By CARL)",
				virgil_decrypt_with_key(carl_private_key, encrypted_data, identity_carl, &decrypted_data));

	LOG("Decrypted data       : <%s>", (char *)decrypted_data.data);

	terminate:
	virgil_data_free(&bob_private_key);
	virgil_data_free(&carl_private_key);
	virgil_data_free(&pubkey_ar[0]);
	virgil_data_free(&pubkey_ar[1]);
	virgil_data_free(&encrypted_data);
	virgil_data_free(&decrypted_data);
}

/******************************************************************************/
static void sign_verify_test(void) {
	data_t data;
	data_t signature;
	data_t private_key;
	data_t public_key;
	bool is_verified;

	data.data = (void *)text;
	data.sz = strlen(text) + 1;

	START_TEST("SIGN VERIFY");

	virgil_data_reset(&signature);
	virgil_data_reset(&private_key);
	virgil_data_reset(&public_key);

	TEST_CASE_OK("Create key pair",
			virgil_create_keypair(&private_key, &public_key));

	TEST_CASE_OK("Sign data with private key",
			virgil_sign(private_key, data, &signature));

	TEST_CASE("Verify data with public key",
			VIRGIL_OPERATION_OK == virgil_verify_with_pubkey(public_key, data, signature, &is_verified) &&
			is_verified);

	terminate:;
	virgil_data_free(&signature);
	virgil_data_free(&private_key);
	virgil_data_free(&public_key);
}

/******************************************************************************/
void crypto_test(void) {
	START_TEST("CRYPTO");

	password_based_encrypt_decrypt_test();
	encrypt_decrypt_test();
	sign_verify_test();
}
