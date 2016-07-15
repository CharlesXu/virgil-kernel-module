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
#include <virgil/kernel/certificates.h>
#include <virgil/kernel/foundation/data.h>

#include <virgil/kernel/foundation/data.h>
#include <virgil/kernel/foundation/key-value.h>

#include "macro.h"

data_t root_certificate;

void print_time(time_t time);

static const char * text = "In 1971, ALOHAnet connected the Hawaiian Islands with a UHF wireless packet network.";

/******************************************************************************/
static void get_root_certificate_test(void) {
	TEST_CASE_OK("Get ROOT certificate (from Virgil Service)",
			virgil_certificate_get(ROOT_CERTIFICATE_IDENTITY, &root_certificate));
	terminate:;
}
/******************************************************************************/
static void certificate_life_cycl_test(void) {
	const char * identity = "test-identity";
	kv_container_t addition_data;
	data_t private_key;
	data_t created_certificate;
	data_t getted_certificate;
	bool is_ok;

	START_TEST("Certificate life-cycl");

	virgil_kv_reset(&addition_data);
	virgil_data_reset(&private_key);
	virgil_data_reset(&created_certificate);
	virgil_data_reset(&getted_certificate);

	TEST_CASE_OK("Create certificate",
			virgil_certificate_create(identity, addition_data, &private_key, &created_certificate));

	TEST_CASE_OK("Get certificate (from Virgil Service)",
			virgil_certificate_get(identity, &getted_certificate));

	TEST_CASE("Verify received certificate",
			VIRGIL_OPERATION_OK == virgil_certificate_verify(getted_certificate, root_certificate, &is_ok) &&
			is_ok);

	TEST_CASE("Revoke certificate",
			VIRGIL_OPERATION_OK == virgil_certificate_revoke(identity, private_key, &is_ok) &&
			is_ok);

	terminate:
	virgil_kv_free(&addition_data);
	virgil_data_free(&private_key);
	virgil_data_free(&created_certificate);
	virgil_data_free(&getted_certificate);
}

/******************************************************************************/
static void certificate_based_crypto_test(void) {
	const char * alice_identity = "alice-identity";
	data_t alice_private_key;
	data_t alice_certificate;
	const char * bob_identity = "bob-identity";
	data_t bob_private_key;
	data_t bob_certificate;
	kv_container_t addition_data;
	data_t data;
	data_t encrypted_data;
	data_t decrypted_data;
	data_t signature;
	bool is_verified;

	virgil_kv_reset(&addition_data);
	virgil_data_reset(&alice_private_key);
	virgil_data_reset(&alice_certificate);
	virgil_data_reset(&bob_private_key);
	virgil_data_reset(&bob_certificate);
	virgil_data_reset(&encrypted_data);
	virgil_data_reset(&decrypted_data);
	virgil_data_reset(&signature);

	data.data = (void *)text;
	data.sz = strlen(text) + 1;

	TEST_CASE_OK("Create certificate for ALICE",
			virgil_certificate_create(alice_identity, addition_data, &alice_private_key, &alice_certificate));

	TEST_CASE_OK("Create certificate for BOB",
			virgil_certificate_create(bob_identity, addition_data, &bob_private_key, &bob_certificate));

	TEST_CASE_OK("ALICE encrypts data to BOB",
			virgil_encrypt_with_cert(1, &bob_certificate, data, &encrypted_data));

	TEST_CASE_OK("Sign encrypted data by ALICE",
			virgil_sign(alice_private_key, encrypted_data, &signature));

	TEST_CASE("BOB verifies signature from ALICE.",
				VIRGIL_OPERATION_OK == virgil_verify_with_cert(alice_certificate, encrypted_data, signature, &is_verified) &&
				is_verified);

	TEST_CASE_OK("BOB decrypts data from ALICE",
			virgil_decrypt_with_key(bob_private_key, encrypted_data, bob_identity, &decrypted_data));

	terminate:
	virgil_kv_free(&addition_data);
	virgil_data_free(&alice_private_key);
	virgil_data_free(&alice_certificate);
	virgil_data_free(&bob_private_key);
	virgil_data_free(&bob_certificate);
	virgil_data_free(&encrypted_data);
	virgil_data_free(&decrypted_data);
	virgil_data_free(&signature);
}

/******************************************************************************/
static void certificate_revocation_list_test(void) {
	time_t last_crl_time;
	time_t next_crl_time;

	TEST_CASE_OK("Get CRL info",
			virgil_certificate_crl_info(&last_crl_time, &next_crl_time));

	print_time(last_crl_time);
	print_time(next_crl_time);

	terminate:;
}

#if 0
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
#endif
/******************************************************************************/
void print_time(time_t time) {
	struct tm tm;
	time_to_tm(time, 0, &tm);
	LOG(" @ (%04d-%02d-%02d %02d:%02d:%02d)\n",
			(int)tm.tm_year + 1900,
			(int)tm.tm_mon + 1,
			(int)tm.tm_mday,
			(int)tm.tm_hour,
			(int)tm.tm_min,
			(int)tm.tm_sec);
}
/******************************************************************************/
void certificates_test(void) {
	START_TEST("CERTIFICATES");

	virgil_data_reset(&root_certificate);

	get_root_certificate_test();
	certificate_life_cycl_test();
	certificate_based_crypto_test();
	certificate_revocation_list_test();

	virgil_data_free(&root_certificate);
}
