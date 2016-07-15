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

#ifndef VIRGIL_TYPES_H
#define VIRGIL_TYPES_H

/**
 * @file types.h
 * @brief Declare global definitions and common structures.
 */

#define VIRGIL_INVALID_ID 0                     /**< ID of invalid communication operation */

#define VIRGIL_OPERATION_OK     0               /**< Operation result is OK*/
#define VIRGIL_OPERATION_ERROR  1               /**< Operation result is GENERAL ERROR*/

#define VIRGIL_OPERATION_TIMEOUT_MS     15000    /**< Timeout of each operation in milliseconds */

#define VIRGIL_CMD_UNKNOWN      		0               /**< Code for unknown command */
#define VIRGIL_CMD_PING        			1               /**< Ping command. */

#define VIRGIL_CMD_CRYPTO_KEYGEN       	2               /**< Request to virgil-service for key pair generation */
#define VIRGIL_CMD_CRYPTO_ENCRYPT_PASS 	3               /**< Encrypt data with password */
#define VIRGIL_CMD_CRYPTO_DECRYPT_PASS 	4               /**< Decrypt data with password */
#define VIRGIL_CMD_CRYPTO_ENCRYPT      	5               /**< Encrypt data with public keys list or certificates list */
#define VIRGIL_CMD_CRYPTO_DECRYPT      	6               /**< Decrypt data with private key */
#define VIRGIL_CMD_CRYPTO_SIGN         	7               /**< Create data signature with private key */
#define VIRGIL_CMD_CRYPTO_VERIFY       	8               /**< Verify data signature with public key */
#define VIRGIL_CMD_CRYPTO_HASH       	9               /**< Verify data signature with public key */

#define VIRGIL_CMD_STORAGE_STORE     	10         		/**< Save any key to local storage. Can be passed password for key encryption. */
#define VIRGIL_CMD_STORAGE_LOAD     	11         		/**< Load any key from local storage. Can be passed password for key decryption. */
#define VIRGIL_CMD_STORAGE_REMOVE   	12         		/**< Revoke key. */

#define VIRGIL_CMD_CERTIFICATE_CREATE 			13  	/**< Create certificate and private key */
#define VIRGIL_CMD_CERTIFICATE_GET        		14  	/**< Load certificate from Virgil Service */
#define VIRGIL_CMD_CERTIFICATE_VERIFY     		15  	/**< Verify certificate's signature */
#define VIRGIL_CMD_CERTIFICATE_PARSE      		16  	/**< Parse certificate */
#define VIRGIL_CMD_CERTIFICATE_REVOKE     		17  	/**< Revoke certificate */
#define VIRGIL_CMD_CERTIFICATE_CRL_INFO     	18  	/**< Get CRL info */
#define VIRGIL_CMD_CERTIFICATE_CHECK_IS_REVOKED 19  	/**< Check is certificate revoked */

#define VIRGIL_CMD_MAX          				20

#define VIRGIL_RECIPIENTS_COUNT_MAX		50

#define VIRGIL_KV_KEY_MAX_SZ    50              /**< Maximum size of key in key-value pair */

#pragma pack(push,1)
typedef union {
        void * p;           /**< pointer to data */
        __u8 pad[8];        /**< padding */
} ptr_with_pad_t;
#pragma pack(pop)

#endif /* VIRGIL_TYPES_H */
