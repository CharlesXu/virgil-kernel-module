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
 * @file ieee1609dot2-helper.h
 * @brief IEEE1609.2 helper functions.
 */

#ifndef VIRGIL_IEEE1609DOT2_HELPER_H
#define VIRGIL_IEEE1609DOT2_HELPER_H

#include <virgil/kernel/types.h>
#include <virgil/kernel/key-storage.h>

#define ALGORITHM_ECDSA_BP256R1_SHA256	0 		/**< Analog for ecdsaBrainpoolP256r1WithSha256 in IEEE1609.2 */
#define ALGORITHM_ECDSA_NIST256_SHA256	1 		/**< Analog for ecdsaNistP256WithSha256  in IEEE1609.2 */
#define ALGORITHM_ECIES_NIST256			2 		/**< Analog for eciesNistP256  in IEEE1609.2 */
#define ALGORITHM_ECIES_BP256R1			3 		/**< Analog for eciesBrainpoolP256r1 in IEEE1609.2 */

#define ALGORITHM_SYMMETRIC_AES256_CCM	100 	/**< Analog for aes256-ccm  in IEEE1609.2 */
#define HASH_SHA256						0		/**< Hash is SHA-256 */

#define KEY_TYPE_PRIVATE				0		/**< Private key. Helper description of key to be stored or loaded */
#define KEY_TYPE_PUBLIC					1		/**< Public key. Helper description of key to be stored or loaded */
#define KEY_TYPE_CERTIFICATE			2		/**< Certificate. Helper description of key to be stored or loaded */
#define KEY_TYPE_SYMMETRIC				3		/**< Symmetric key. Helper description of key to be stored or loaded */

#define ROOT_CERTIFICATE_CMH			0 		/**< Crypto material handle for Root certificate */

/** Type definition for Crypto Material Handle */
typedef __u64 cmh_t;

// Create aliases
#define virgil_ieee1609_get_crl_info		virgil_certificate_crl_info
#define virgil_ieee1609_check_revocation	virgil_certificate_is_revoked

/**
 * @brief Create crypto material (private key and certificate).
 *
 * @param[in] cmh                  		- crypto material handle.
 * @param[in] addition_data             - key/value array with addition data.
 * @param[out] private_key       - private key.
 * @param[out] certificate       - certificate.
 *
 * @return [VIRGIL_OPERATION_OK or VIRGIL_OPERATION_ERROR].
 */
extern int virgil_ieee1609_create_material(cmh_t cmh,
        kv_container_t addition_data,
        data_t * private_key,
        data_t * certificate);

/**
 * @brief Request certificate by Identity from Virgil Service.
 *
 * @param[in] cmh          		- crypto material handle.
 * @param[out] certificate      - certificate.
 *
 * @return [VIRGIL_OPERATION_OK or VIRGIL_OPERATION_ERROR].
 */
extern int virgil_ieee1609_request_cert(cmh_t cmh, data_t * certificate);

/**
 * @brief Verify certificate's signature.
 *
 * @param[in] certificate      - certificate.
 * @param[out] is_ok           - true - if has been done successfully.
 *
 * @return [VIRGIL_OPERATION_OK or VIRGIL_OPERATION_ERROR].
 */
extern int virgil_ieee1609_verify_cert(data_t certificate, bool * is_ok);

/**
 * @brief Revoke a Virgil Certificate.
 *
 * @param[in] cmh          		- crypto material handle.
 * @param[in] private_key       - private key data.
 * @param[out] is_ok            - true - if has been done successfully.
 *
 * @return [VIRGIL_OPERATION_OK or VIRGIL_OPERATION_ERROR].
 */
extern int virgil_ieee1609_revoke_cert(cmh_t cmh, data_t private_key, bool * is_ok);

/**
 * @brief Add certificate to cache.
 *
 * @param[in] certificate		- certificate data.
 * @param[in] is_root			- is root certificate.
 *
 * @return [VIRGIL_OPERATION_OK or VIRGIL_OPERATION_ERROR].
 */
extern int virgil_ieee1609_add_cert(data_t certificate, bool is_root);

/**
 * @brief Delete certificate from cache.
 *
 * @param[in] certificate		- certificate data.
 *
 * @return [VIRGIL_OPERATION_OK or VIRGIL_OPERATION_ERROR].
 */
extern int virgil_ieee1609_delete_cert(data_t certificate);

/**
 * @brief Load key data by crypto material handler.
 *
 * @param[in] cmh            - crypto material handler.
 * @param[in] key_type       - type of key for load.
 * @param[out] loaded_key    - loaded key data.
 *
 * @return [VIRGIL_OPERATION_OK or VIRGIL_OPERATION_ERROR].
 */
extern int virgil_ieee1609_load_key(cmh_t cmh, int key_type, data_t * loaded_key);

/**
 * @brief Decrypt data with crypto material handler.
 *
 * @param[in] cmh		       	- crypto material handler.
 * @param[in] data              - data for decryption.
 * @param[out] decrypted_data   - decrypted data.
 *
 * @return [VIRGIL_OPERATION_OK or VIRGIL_OPERATION_ERROR].
 */
extern int virgil_ieee1609_decrypt_with_cmh(cmh_t cmh, data_t data, data_t * decrypted_data);

/**
 * @brief Get certificate info.
 *
 * @param[in] certificate               - certificate.
 * @param[out] kv_data                	- key/value in certificate.
 * @param[out] geo_scope                - Geographic Scope.
 * @param[out] last_crl_time            - Last Received CRL Time.
 * @param[out] next_crl_time            - Next Expected CRL Time.
 * @param[out] is_root_cert             - is root certificate.
 *
 * @return [VIRGIL_OPERATION_OK or VIRGIL_OPERATION_ERROR].
 */
extern int virgil_ieee1609_parse_cert(data_t certificate, kv_container_t * kv_data, char ** geo_scope,
	time_t * last_crl_time, time_t * next_crl_time, bool * is_root_cert);

/**
 * @brief Create crypto material handler (CMH).
 *
 * @param[out] cmh            - crypto material handler.
 *
 * @return [VIRGIL_OPERATION_OK or VIRGIL_OPERATION_ERROR].
 */
extern int virgil_ieee1609_cmh_create(cmh_t * cmh);

/**
 * @brief Create key pair for given CMH.
 *
 * @param[in] cmh            - crypto material handler.
 * @param[in] algorithm      - algorithm for new key-pair.
 * @param[out] public_key    - public key data.
 * @param[out] private_key   - private key data.
 *
 * @return [VIRGIL_OPERATION_OK or VIRGIL_OPERATION_ERROR].
 */
extern int virgil_ieee1609_cmh_gen_keypair(cmh_t cmh, int algorithm, data_t * public_key, data_t * private_key);

/**
 * @brief Store key pair.
 *
 * @param[in] cmh            - crypto material handler.
 * @param[in] algorithm      - algorithm for new key-pair.
 * @param[in] public_key     - public key data.
 * @param[in] private_key    - private key data.
 *
 * @return [VIRGIL_OPERATION_OK or VIRGIL_OPERATION_ERROR].
 */
extern int virgil_ieee1609_cmh_store_keypair(cmh_t cmh, int algorithm, data_t public_key, data_t private_key);

/**
 * @brief Store certificate for CMH.
 *
 * @param[in] cmh                   - crypto material handler.
 * @param[in] certificate           - certificate data.
 * @param[in] priv_key_transform    - private key transformation.
 *
 * @return [VIRGIL_OPERATION_OK or VIRGIL_OPERATION_ERROR].
 */
extern int virgil_ieee1609_cmh_store_cert(cmh_t cmh, data_t certificate, data_t priv_key_transform);

/**
 * @brief Store certificate and private key for CMH.
 *
 * @param[in] cmh                   - crypto material handler.
 * @param[in] certificate           - certificate data.
 * @param[in] private_key           - private key.
 *
 * @return [VIRGIL_OPERATION_OK or VIRGIL_OPERATION_ERROR].
 */
extern int virgil_ieee1609_cmh_store_cert_and_key(cmh_t cmh, data_t certificate, data_t private_key);

/**
 * @brief Delete crypto material handler with data.
 *
 * @param[in] cmh                   - crypto material handler.
 * @return [VIRGIL_OPERATION_OK or VIRGIL_OPERATION_ERROR].
 */
extern int virgil_ieee1609_cmh_delete(cmh_t cmh);

/**
 * @brief Sign data using crypto material handler.
 *
 * @param[in] cmh       		- crypto material handler.
 * @param[in] data              - data to be signed.
 * @param[out] signature        - created signature.
 *
 * @return [VIRGIL_OPERATION_OK or VIRGIL_OPERATION_ERROR].
 */
extern int virgil_ieee1609_cmh_sign(cmh_t cmh, data_t data, data_t * signature);

/**
 * @brief Create HashedId8 for data.
 *
 * @param[in] data            - data for hash creation.
 * @param[out] hashed_id8     - HashedId8.
 *
 * @return [VIRGIL_OPERATION_OK or VIRGIL_OPERATION_ERROR].
 */
extern int virgil_ieee1609_hashed_id8(data_t data, data_t * hashed_id8);

/**
 * @brief Make transformation of a private key.
 *
 * @param[in] private_key     		- A private key for the transformation.
 * @param[out] priv_key_transform   - Transformed private key.
 *
 * @return [VIRGIL_OPERATION_OK or VIRGIL_OPERATION_ERROR].
 */
extern int virgil_ieee1609_transform_private_key(data_t private_key, data_t * priv_key_transform);


#endif /* VIRGIL_IEEE1609DOT2_HELPER_H */
