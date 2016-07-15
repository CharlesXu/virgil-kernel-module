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
 * @file certificates.h
 * @brief API certificates specific functions.
 */

#ifndef VIRGIL_CERTIFICATES_H
#define VIRGIL_CERTIFICATES_H

#include <virgil/kernel/types.h>
#include <virgil/kernel/foundation/key-value.h>
#include <linux/capability.h>
#include <linux/errno.h>

#include <asm/uaccess.h>
#include <asm/unistd.h>

#define ROOT_CERTIFICATE_IDENTITY			"0"		/**< Identity of the Root certificate */

/**
 * @brief Create certificate and private key.
 *
 * @param[in] identity         		- identity.
 * @param[in] addition_data      	- key/value array with addition data.
 * @param[out] private_key      	- generated private key.
 * @param[out] certificate       	- created certificate.
 *
 * @return [VIRGIL_OPERATION_OK or VIRGIL_OPERATION_ERROR].
 */
extern int virgil_certificate_create(
		const char * identity,
		kv_container_t addition_data,
		data_t * private_key,
		data_t * certificate);

/**
 * @brief Request certificate by Identity from Virgil Service.
 *
 * @param[in] identity        	- identity.
 * @param[out] certificate      - certificate.
 *
 * @return [VIRGIL_OPERATION_OK or VIRGIL_OPERATION_ERROR].
 */
extern int virgil_certificate_get(const char * identity, data_t * certificate);

/**
 * @brief Verify certificate's signature using root certificate.
 *
 * @param[in] certificate      - certificate.
 * @param[in] root_certificate - root_certificate.
 * @param[out] is_ok           - 1 - if has been done successfully.
 *
 * @return [VIRGIL_OPERATION_OK or VIRGIL_OPERATION_ERROR].
 */
extern int virgil_certificate_verify(data_t certificate, data_t root_certificate, bool * is_ok);

/**
 * @brief Parse certificate data.
 *
 * @param[in] certificate               - certificate.
 * @param[out] cert_data                - data in certificate.
 *
 * @return [VIRGIL_OPERATION_OK or VIRGIL_OPERATION_ERROR].
 */
extern int virgil_certificate_parse(data_t certificate, kv_container_t * cert_data);

/**
 * @brief Revoke a Virgil Certificate.
 *
 * @param[in] identity        	- identity.
 * @param[in] private_key       - private key data.
 * @param[out] is_ok            - 1 - if has been done successfully.
 *
 * @return [VIRGIL_OPERATION_OK or VIRGIL_OPERATION_ERROR].
 */
extern int virgil_certificate_revoke(const char * identity, data_t private_key, bool * is_ok);

/**
 * @brief Get CRL info.
 *
 * @param[out] last		- Time of last CRL request.
 * @param[out] next		- Time of next CRL request.
 *
 * @return [VIRGIL_OPERATION_OK or VIRGIL_OPERATION_ERROR].
 */
extern int virgil_certificate_crl_info(time_t * last, time_t * next);

/**
 * @brief Check a certificate for revocation.
 *
 * @param[in] certificate     		- certificate data.
 * @param[out] is_revoked   		- Boolean value of revocation state.
 *
 * @return [VIRGIL_OPERATION_OK or VIRGIL_OPERATION_ERROR].
 */
extern int virgil_certificate_is_revoked(data_t certificate, bool * is_revoked);

/**
 * @brief Get identity from certificate.
 *
 * @param[in] certificate     		- certificate data.
 * @param[out] identity   			- identity.
 *
 * @return [VIRGIL_OPERATION_OK or VIRGIL_OPERATION_ERROR].
 */
extern int virgil_certificate_get_identity(data_t certificate, char ** identity);

#endif /* VIRGIL_CERTIFICATES_H */
