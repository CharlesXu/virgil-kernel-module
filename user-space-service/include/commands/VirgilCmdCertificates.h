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

#ifndef VIRGIL_CMD_CERTIFICATES_H
#define VIRGIL_CMD_CERTIFICATES_H

#include "VirgilCommand.h"
#include <map>

class VirgilCmdCertificates {
#pragma pack(push,1)

typedef struct {
        char key[50]; /**< Key in key-value pair */
        uint16_t value_sz; /**< Size of data field in bytes */
        uint64_t pad; /**< Pad */
    } kv_pair_t;
#pragma pack(pop)

public:
    VirgilCmdCertificates() = default;
    virtual ~VirgilCmdCertificates();
    VirgilCmdCertificates(const VirgilCmdCertificates&) = delete;
    VirgilCmdCertificates & operator=(const VirgilCmdCertificates&) = delete;

    static VirgilByteArray process(const VirgilCommand & cmd);

private:
    static std::map <std::string, VirgilByteArray> parseCustomData(const VirgilByteArray & rawData);
    static VirgilByteArray packKeyValueData(const std::map <std::string, std::string> & data);

    static const std::string kIdentityType;
    static const std::string kRootCertificateId;
    static const size_t kKVKeySize;
    static const size_t kKVMaxCount;

    static VirgilByteArray create(const VirgilCommand & cmd);
    static VirgilByteArray get(const VirgilCommand & cmd);
    static VirgilByteArray verify(const VirgilCommand & cmd);
    static VirgilByteArray parse(const VirgilCommand & cmd);
    static VirgilByteArray revoke(const VirgilCommand & cmd);
    static VirgilByteArray crlInfo(const VirgilCommand & cmd);
    static VirgilByteArray isRevoked(const VirgilCommand & cmd);

    template<typename T>
    static T readNum(size_t pos, const VirgilByteArray & data) {
        T res(0);
        const uint8_t * pBytes(reinterpret_cast<const uint8_t *> (data.data() + pos));
        memcpy(&res, pBytes, sizeof (T));
        return res;
    }
    static VirgilByteArray readByteArray(size_t pos, size_t sz, const VirgilByteArray & data);
};

#endif /* VIRGIL_CMD_CERTIFICATES_H */

