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
 * @file fields.h
 * @brief Data wrapper for communication with user-space.
 */

#ifndef FIELDS_H
#define FIELDS_H

#include <linux/module.h>

#include <virgil/kernel/types.h>
#include <virgil/kernel/private/log.h>
#include <virgil/kernel/foundation/data.h>

#pragma pack(push,1)

/**
 * @struct package_field_t
 * Used for netlink communication
 */
struct package_field_t {
    __u16 type;             /**< Type of data field */
    __u32 data_sz;          /**< Size of data field in bytes */
    ptr_with_pad_t data;    /**< Pointer to data */
};
#pragma pack(pop)

/**
 * @struct fields_t
 * Array of data fields for communication
 */
typedef struct {
    __u16 count;
    struct package_field_t * ar;
} fields_t;

#define VIRGIL_FIELD_UNKNOWN            0		/**< Unknown data field */
#define VIRGIL_FIELD_TOKEN              1		/**< Data field with Token */
#define VIRGIL_FIELD_CURVE_TYPE         2		/**< Data field with EC Curve Type */
#define VIRGIL_FIELD_PASSWORD           3		/**< Data field with Password*/
#define VIRGIL_FIELD_PRIVATE_KEY        4		/**< Data field with Private Key */
#define VIRGIL_FIELD_PUBLIC_KEY         5		/**< Data field with Public Key */
#define VIRGIL_FIELD_KEY_TYPE           6		/**< Data field with Key Type (Private, Public, Symmetric, Certificate)*/
#define VIRGIL_FIELD_IDENTITY           7		/**< Data field with Identity */
#define VIRGIL_FIELD_DATA               8		/**< Data field with Data */
#define VIRGIL_FIELD_SIGNATURE          9		/**< Data field with Signature */
#define VIRGIL_FIELD_RES                10		/**< Data field with Operation Result or Error Code */
#define VIRGIL_FIELD_CERT               11		/**< Data field with Certificate */
#define VIRGIL_FIELD_ROOT_CERT          12		/**< Data field with Root Certificate */
#define VIRGIL_FIELD_CRL_LAST           13		/**< Data field with Time of last getting of Certificate Revocation Time */
#define VIRGIL_FIELD_CRL_NEXT           14		/**< Data field with Time of next getting of Certificate Revocation Time */
#define VIRGIL_FIELD_HASH_FUNC          15		/**< Data field with Hash type */
#define VIRGIL_FIELD_OPTIONAL_1         16		/**< Data field with Optional field */

#define VIRGIL_FIELD_MAX                17		/**< Maximun number of field */

/** Helper macros to fill data field using data_t structure */
#define FILL_FIELD(FIELD, TYPE, DATA) do { \
        FIELD.type = (TYPE);               \
        FIELD.data_sz = (DATA.sz);         \
        FIELD.data.p = (DATA.data);        \
        } while(0);

/** Helper macros to fill data using raw data */
#define FILL_FIELD_AR(FIELD, TYPE, DATA, DATA_SZ) do {  \
        FIELD.type = (TYPE);                            \
        FIELD.data_sz = (DATA_SZ);                      \
        FIELD.data.p = (void*)(DATA);                   \
        } while(0);

/** Helper macros to fill data using string */
#define FILL_FIELD_STR(FIELD, TYPE, STR) do {           \
        FIELD.type = (TYPE);                            \
        FIELD.data_sz = (strlen(STR) + 1);              \
        FIELD.data.p = (void*)(STR);                    \
        } while(0);

/** Helper macros to check errors in request */
#define CHECK_ERROR(FIELDS, ERR_VAR) do {                               \
        if (VIRGIL_OPERATION_OK == fields_result(FIELDS, &ERR_VAR)) {   \
            if (VIRGIL_OPERATION_OK != ERR_VAR)                         \
            	fields_free(&FIELDS);									\
                return ERR_VAR;                                         \
        } } while(0);

/** Helper macros to check operation processing */
#define CHECK(OPERATION) do {                                   \
        if (VIRGIL_OPERATION_ERROR == (OPERATION)) {            \
            return VIRGIL_OPERATION_ERROR;  } } while(0);

/**
 * @brief Free fields_t structure with all data.
 *
 * @param[in]  fields           -pointer to  fields structure
 *
 * @return [VIRGIL_OPERATION_OK or VIRGIL_OPERATION_ERROR].
 */
extern void fields_free(fields_t * fields);

/**
 * @brief Get fields by type.
 *
 * @param[in]  field_type           - need type of field
 * @param[in]  fields_cnt           - all fields count
 * @param[in]  fields               - all  fields
 * @param[in]  res_limit            - maximum count of result elements
 * @param[out] res_cnt              - result array size (allocated by a caller)
 * @param[out] res                  - pointer to result array (allocated by a caller)
 *
 * @return [VIRGIL_OPERATION_OK or VIRGIL_OPERATION_ERROR].
 */
extern int fields_by_type(__u16 field_type,
        fields_t fields,
        __u16 res_limit,
        __u16 * res_cnt, struct package_field_t ** res);

/**
 * @brief Get result code from received data (if present).
 *
 * @param[in] fields                - data fields
 * @param[out] result               - result code
 *
 * @return [VIRGIL_OPERATION_OK or VIRGIL_OPERATION_ERROR].
 */
extern int fields_result(fields_t fields, __s16 * result);

/**
 * @brief Duplicate fields data.
 *
 * @param[out] dst                	- destination data fields
 * @param[in] src               	- source data fields
 *
 * @return VIRGIL_OPERATION_OK - if error code has been read.
 */
extern int fields_dup(fields_t * dst, fields_t src);

/**
 * @brief Reset data fields.
 *
 * @param[in] fields           -pointer to  fields structure
 *
 * @return [VIRGIL_OPERATION_OK or VIRGIL_OPERATION_ERROR].
 */
extern int fields_reset(fields_t * fields);

/**
 * @brief Duplicate first data field with selected type.
 *
 * @param[in] field_type       - field type to be searched
 * @param[in] fields           - data fields
 * @param[out] dst             - pointer to destination data
 *
 * @return [VIRGIL_OPERATION_OK or VIRGIL_OPERATION_ERROR].
 */
extern int fields_dup_first(int field_type, fields_t fields, data_t * dst);

#endif // FIELDS_H
