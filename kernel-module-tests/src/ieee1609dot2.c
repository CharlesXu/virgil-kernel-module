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

#include <virgil/kernel/key-storage.h>
#include <virgil/kernel/crypto.h>
#include <virgil/kernel/certificates.h>
#include <virgil/kernel/ieee1609dot2/ieee1609dot2-helper.h>

#include <virgil/kernel/foundation/data.h>
#include <virgil/kernel/foundation/key-value.h>

#include "macro.h"

static const char * text = "In 1971, ALOHAnet connected the Hawaiian Islands with a UHF wireless packet network.";

extern void print_time(time_t time);
/******************************************************************************/
static void main_actions_test(void) {
	// Let's test communication between two devices with names ALICE and BOB.

	// Data for Alice
	cmh_t alice_cmh = 0;                                    			// Crypto material handle
	data_t alice_certificate;                                           // Certificate (will be created once in virgil_ieee1609_create_material)
	data_t alice_private_key;                                           // Private key (will be created once in virgil_ieee1609_create_material)
	kv_container_t alice_cert_data;                                     // Key/value addition data such as permissions and etc (will be inserted to a certificate)

	// Data for Bob
	cmh_t bob_cmh = 0;
	data_t bob_certificate;
	data_t bob_private_key;
	kv_container_t bob_cert_data;

	data_t root_certificate;                                             // Root public key for all certificates verification.

	// Temporary data
	data_t alice_cert_tmp;
	data_t bob_cert_tmp;
	bool is_ok;

	data_t data;
	data_t encrypted_data;
	data_t decrypted_data;

	data_t signature;
	bool is_verified = 0;

	kv_container_t read_kv;

	// Clear data
	virgil_data_reset(&alice_certificate);
	virgil_data_reset(&alice_private_key);
	virgil_kv_reset(&alice_cert_data);

	virgil_data_reset(&bob_certificate);
	virgil_data_reset(&bob_private_key);
	virgil_kv_reset(&bob_cert_data);

	virgil_data_reset(&root_certificate);

	// Clear temp data
	virgil_data_reset(&alice_cert_tmp);
	virgil_data_reset(&bob_cert_tmp);
	virgil_data_reset(&data);
	virgil_data_reset(&encrypted_data);
	virgil_data_reset(&decrypted_data);
	virgil_data_reset(&signature);

	virgil_kv_reset(&read_kv);

	// Start test
	START_TEST("VIRGIL IEEE1609 Main actions");

	TEST_CASE_OK("Get the Virgil Root certificate",
			virgil_ieee1609_request_cert(
					ROOT_CERTIFICATE_CMH,
					&root_certificate));

	TEST_CASE_OK("Save Root certificate",
			virgil_ieee1609_add_cert(root_certificate, true));

	TEST_CASE_OK("Create crypto material handle for ALICE",
			virgil_ieee1609_cmh_create(&alice_cmh));

	TEST_CASE_OK("Create certificate and private key for ALICE",
			virgil_ieee1609_create_material(
					alice_cmh,                     	// In
					ALGORITHM_ECDSA_BP256R1_SHA256,
					alice_cert_data,                // In
					&alice_private_key,             // Out
					&alice_certificate));           // Out

	TEST_CASE_OK("Save crypto material for ALICE (Operation produced in ALICE device)",
			virgil_ieee1609_cmh_store_cert_and_key(
					alice_cmh,
					alice_certificate,
					alice_private_key));

	TEST_CASE_OK("Create crypto material handle for BOB",
			virgil_ieee1609_cmh_create(&bob_cmh));

	TEST_CASE_OK("Create crypto material for BOB (Operation produced in CA device or PC)",
			virgil_ieee1609_create_material(
					bob_cmh,
					ALGORITHM_ECDSA_NIST256_SHA256,
					bob_cert_data,
					&bob_private_key,
					&bob_certificate));

	TEST_CASE_OK("Save crypto material for BOB (Operation produced in ALICE device)",
			virgil_ieee1609_cmh_store_cert_and_key(
					bob_cmh,
					bob_certificate,
					bob_private_key));


	// Free all data which were used for devices initialization.
	virgil_data_free(&alice_certificate);
	virgil_data_free(&alice_private_key);
	virgil_kv_free(&alice_cert_data);

	virgil_data_free(&bob_certificate);
	virgil_data_free(&bob_private_key);
	virgil_kv_free(&bob_cert_data);

	virgil_data_free(&root_certificate);

	LOG("Ok, now we have two devices (ALICE and BOB) and all preparations were done for them.");

	LOG("Bootload ALICE");

	TEST_CASE_OK("Load ALICE private key",
			virgil_ieee1609_load_key(
					alice_cmh,
					KEY_TYPE_PRIVATE,
					&alice_private_key));

	TEST_CASE_OK("Load ALICE certificate",
			virgil_ieee1609_load_key(
					alice_cmh,
					KEY_TYPE_CERTIFICATE,
					&alice_certificate));

	LOG("Bootload BOB.");

	TEST_CASE_OK("Load BOB private key",
			virgil_ieee1609_load_key(
					bob_cmh,
					KEY_TYPE_PRIVATE,
					&bob_private_key));

	TEST_CASE_OK("Load BOB certificate",
			virgil_ieee1609_load_key(
					bob_cmh,
					KEY_TYPE_CERTIFICATE,
					&bob_certificate));

	TEST_CASE_OK("ALICE requests BOB's certificate from Virgil Keys Service",
			virgil_ieee1609_request_cert(bob_cmh, &bob_cert_tmp));

	LOG("Remark : BOB hasn't connection to internet. It can tries to load certificate from local cache. But if there is no cert, then need to use P2PCD");

	TEST_CASE_OK("BOB requests ALICE's certificate by P2PCD (here used simple copy))",
			virgil_data_dup(&alice_cert_tmp, alice_certificate));

	is_ok = 0;

	TEST_CASE("BOB doesn't trust to P2PCD. That's why BOB wants to verify the received certificate (Look at the previouse action).)",
			VIRGIL_OPERATION_OK == virgil_ieee1609_verify_cert(alice_cert_tmp, &is_ok) &&
			is_ok);

	TEST_CASE_OK("The certificate is valid, so BOB can save it in the local cache.",
			virgil_ieee1609_add_cert(alice_cert_tmp, false));

	LOG("Now both devices have own crypto material and opponent's certificates. So, we have all need for secure communication.");


	LOG("ALICE encrypts and signs data for sent to BOB.");

	data.data = (void *)text;
	data.sz = strlen(text) + 1;

	LOG("Data to be encrypted : <%s>", text);

	TEST_CASE_OK("Encrypt data (By ALICE to BOB)",
			virgil_encrypt_with_cert(1, &bob_cert_tmp, data, &encrypted_data));

	LOG("Encrypted data size  : %lu", (unsigned long)encrypted_data.sz);

	TEST_CASE_OK("Sign data by ALICE",
			virgil_ieee1609_cmh_sign(alice_cmh, encrypted_data, &signature));

	LOG("Here the encrypted data and the signature should be sent from ALICE to BOB.");

	TEST_CASE("At first BOB verifies signature from ALICE.",
			VIRGIL_OPERATION_OK == virgil_verify_with_cert(alice_cert_tmp, encrypted_data, signature, &is_verified) &&
			is_verified);

	TEST_CASE_OK("BOB decrypts data from ALICE",
			virgil_ieee1609_decrypt_with_cmh(bob_cmh, encrypted_data, &decrypted_data));

	LOG("Decrypted data       : <%s>", (char *)decrypted_data.data);

	LOG("Good, we have done successful secure data pass from ALICE to BOB.");

	TEST_CASE("Let's try to revoke cert of ALICE",
			VIRGIL_OPERATION_OK == virgil_ieee1609_revoke_cert(alice_cmh, alice_private_key, &is_ok) &&
			is_ok);

	TEST_CASE("Let's try to revoke cert of BOB",
			VIRGIL_OPERATION_OK == virgil_ieee1609_revoke_cert(bob_cmh, bob_private_key, &is_ok) &&
			is_ok);

	TEST_CASE_OK("Check certificate deletion",
			virgil_ieee1609_delete_cert(alice_cert_tmp));

	TEST_CASE_OK("Remove CMH for ALICE",
			virgil_ieee1609_cmh_delete(alice_cmh));

	TEST_CASE_OK("Remove CMH for BOB",
			virgil_ieee1609_cmh_delete(bob_cmh));

	terminate:

	virgil_data_free(&alice_certificate);
	virgil_data_free(&alice_private_key);
	virgil_kv_free(&alice_cert_data);

	virgil_data_free(&bob_certificate);
	virgil_data_free(&bob_private_key);
	virgil_kv_free(&bob_cert_data);

	virgil_data_free(&root_certificate);

	virgil_data_free(&alice_cert_tmp);
	virgil_data_free(&bob_cert_tmp);
	virgil_data_free(&signature);

	virgil_kv_free(&read_kv);
}

/******************************************************************************/
static void addition_actions_test(void) {
	cmh_t cmh = 0;
	data_t certificate;
	data_t public_key;
	data_t private_key;
	data_t private_key_transformed;
	data_t hash_id8;
	kv_container_t cert_data;

	char * geo_scope = 0;
	time_t last_crl_time;
	time_t next_crl_time;
	bool is_root_cert;
	bool is_revoked;

	// Clear data
	virgil_data_reset(&certificate);
	virgil_data_reset(&public_key);
	virgil_data_reset(&private_key);
	virgil_data_reset(&private_key_transformed);
	virgil_data_reset(&hash_id8);
	virgil_kv_reset(&cert_data);

	// Start test
	START_TEST("VIRGIL IEEE1609 Addition actions");

	TEST_CASE_OK("Create test crypto material handle",
			virgil_ieee1609_cmh_create(&cmh));

	TEST_CASE_OK("Create key pair",
			virgil_ieee1609_cmh_gen_keypair(
					cmh,
					ALGORITHM_ECIES_NIST256,
					&public_key,
					&private_key));

	TEST_CASE_OK("Save key pair",
			virgil_ieee1609_cmh_store_keypair(
					cmh,
					ALGORITHM_ECIES_NIST256,
					public_key,
					private_key));

	TEST_CASE_OK("Remove crypto material handle)",
			virgil_ieee1609_cmh_delete(cmh));

	virgil_data_free(&certificate);
	virgil_data_free(&public_key);
	virgil_data_free(&private_key);

	TEST_CASE_OK("Create certificate and private key",
			virgil_ieee1609_create_material(
					cmh,
					EC_NIST256,
					cert_data,
					&private_key,
					&certificate));

	TEST_CASE_OK("Create Hashed ID8",
			virgil_ieee1609_hashed_id8(private_key, &hash_id8));

	TEST_CASE_OK("Private key transformation",
			virgil_ieee1609_transform_private_key(
					private_key,
					&private_key_transformed));

	TEST_CASE_OK("Save own certificate",
			virgil_ieee1609_cmh_store_cert(
					cmh,
					certificate,
					private_key_transformed));

	TEST_CASE_OK("Parse certificate",
			virgil_ieee1609_parse_cert(
					certificate,
					&cert_data,
					&geo_scope,
					&last_crl_time,
					&next_crl_time,
					&is_root_cert));

	TEST_CASE_OK("Check is certificate revoked",
			virgil_ieee1609_check_revocation(
						certificate,
						&is_revoked));

#if 0
	LOG("Certificate is : %s", is_revoked ? "REVOKED" : "NOT REVOKED");
#endif

	TEST_CASE_OK("Remove crypto material handle)",
			virgil_ieee1609_cmh_delete(cmh));

	TEST_CASE_OK("Get CRL info",
			virgil_ieee1609_get_crl_info(&last_crl_time, &next_crl_time));

	print_time(last_crl_time);
	print_time(next_crl_time);

	terminate:
	virgil_data_free(&certificate);
	virgil_data_free(&public_key);
	virgil_data_free(&private_key);
	virgil_data_free(&private_key_transformed);
	virgil_data_free(&hash_id8);
}

/******************************************************************************/
void ieee1609dot2_helpers_test(void) {
	main_actions_test();
	addition_actions_test();
}
