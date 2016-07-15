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
 * @file crypto.h
 * @brief API to crypto functions.
 * Encryption/decryption, data sign and verification.
 * Synchronous calls.
 */

#ifndef VIRGIL_CRYPTO_H
#define VIRGIL_CRYPTO_H

#include <virgil/kernel/types.h>
#include <virgil/kernel/foundation/data.h>

/**
 * @brief Create key pair.
 *
 * @param[out] private_key    	- generated private key.
 * @param[out] public_key		- generated public key.
 *
 * @return [VIRGIL_OPERATION_OK or VIRGIL_OPERATION_ERROR].
 */
extern int virgil_create_keypair(
		data_t * private_key,
		data_t * public_key);

/**
 * @brief Encrypt data with password.
 *
 * @param[in] password      - password string.
 * @param[in] data          - data for encryption.
 * @param[out] enc_data     - encrypted data.
 *
 * @return [VIRGIL_OPERATION_OK or VIRGIL_OPERATION_ERROR].
 */
extern int virgil_encrypt_with_password(const char * password, data_t data, data_t * enc_data);

/**
 * @brief Encrypt data for given recipients with public keys and identities.
 *
 * @param[in] recipients_count  - count of recipients of the encrypted message.
 * @param[in] public_keys      	- array with public keys.
 * @param[in] identities      	- array with identities.
 * @param[in] data              - data for encryption.
 * @param[out] enc_data         - encrypted data.
 *
 * @return [VIRGIL_OPERATION_OK or VIRGIL_OPERATION_ERROR].
 */
extern int virgil_encrypt_with_pubkey(__u32 recipients_count,
        const data_t * public_keys, const char ** identities,
        data_t data, data_t * enc_data);

/**
 * @brief Encrypt data for given recipients with certificate.
 *
 * @param[in] recipients_count  - count of recipients of the encrypted message.
 * @param[in] certificates      - array with certificates.
 * @param[in] data              - data for encryption.
 * @param[out] enc_data         - encrypted data.
 *
 * @return [VIRGIL_OPERATION_OK or VIRGIL_OPERATION_ERROR].
 */
extern int virgil_encrypt_with_cert(__u32 recipients_count,
        const data_t * certificates,
        data_t data, data_t * enc_data);

/**
 * @brief Decrypt data with given password.
 *
 * @param[in] password          - password string.
 * @param[in] data              - data for decryption.
 * @param[out] decrypted_data   - decrypted data.
 *
 * @return [VIRGIL_OPERATION_OK or VIRGIL_OPERATION_ERROR].
 */
extern int virgil_decrypt_with_password(const char * password, data_t data, data_t * decrypted_data);

/**
 * @brief Decrypt data with given Private Key.
 *
 * @param[in] private_key       - private key data.
 * @param[in] data              - data for decryption.
 * @param[out] decrypted_data   - decrypted data.
 *
 * @return [VIRGIL_OPERATION_OK or VIRGIL_OPERATION_ERROR].
 */
extern int virgil_decrypt_with_key(data_t private_key, data_t data, const char * identity, data_t * decrypted_data);

/**
 * @brief Sign data.
 *
 * @param[in] private_key       - private key data.
 * @param[in] data              - data to be signed.
 * @param[out] signature        - created signature.
 *
 * @return [VIRGIL_OPERATION_OK or VIRGIL_OPERATION_ERROR].
 */
extern int virgil_sign(data_t private_key, data_t data, data_t * signature);

/**
 * @brief Verify signature using public key.
 *
 * @param[in] public_key        - public key data.
 * @param[in] data              - signed data.
 * @param[in] signature         - signature data.
 * @param[out] is_verified      - 1 - verification has been done successfully.
 *
 * @return [VIRGIL_OPERATION_OK or VIRGIL_OPERATION_ERROR].
 */
extern int virgil_verify_with_pubkey(data_t public_key, data_t data, data_t signature, bool * is_verified);

/**
 * @brief Verify signature using certificate.
 *
 * @param[in] cert              - certificate data.
 * @param[in] data              - signed data.
 * @param[in] signature         - signature data.
 * @param[out] is_verified      - 1 - verification has been done successfully.
 *
 * @return [VIRGIL_OPERATION_OK or VIRGIL_OPERATION_ERROR].
 */
extern int virgil_verify_with_cert(data_t cert, data_t data, data_t signature, bool * is_verified);

/**
 * @brief Create SHA-256.
 *
 * @param[in] hash_type		- identifier of hash function (look at defines like HASH_xxx)
 * @param[in] data          - data.
 * @param[out] hash_data    - hash data.
 *
 * @return [VIRGIL_OPERATION_OK or VIRGIL_OPERATION_ERROR].
 */
extern int virgil_hash(__u8 hash_type, data_t data, data_t * hash_data);

#endif /* VIRGIL_CRYPTO_H */
