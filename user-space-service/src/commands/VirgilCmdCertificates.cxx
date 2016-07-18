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

#include "VirgilCmdCertificates.h"
#include "VirgilCertificates.h"
#include "VirgilParams.h"
#include "VirgilCRLProcessor.h"

#include "helpers/VirgilLog.h"
#include "helpers/VirgilFilesHelper.h"
#include <iostream>

#include <virgil/crypto/VirgilKeyPair.h>
#include <virgil/crypto/foundation/VirgilBase64.h>
#include <virgil/crypto/VirgilCipher.h>

#include "VirgilStorage.h"
#include "VirgilCmdCrypto.h"

using namespace virgil::crypto;

const std::string VirgilCmdCertificates::kIdentityType = "virgil-kernel";
const std::string VirgilCmdCertificates::kRootCertificateId = "0";
const size_t VirgilCmdCertificates::kKVKeySize = 50;
const size_t VirgilCmdCertificates::kKVMaxCount = 50;

VirgilCmdCertificates::~VirgilCmdCertificates() {

}

template<typename T>
static VirgilByteArray & operator<<(VirgilByteArray & data, T number) {
    uint8_t * pBytes(reinterpret_cast<uint8_t *> (& number));
    for (int i = 0; i < sizeof (number); ++i) {
        data.push_back(pBytes[i]);
    }
    return data;
}

static VirgilByteArray & operator<<(VirgilByteArray & data, const VirgilByteArray & additionData) {
    data.insert(data.end(), additionData.begin(), additionData.end());
    return data;
}

VirgilByteArray VirgilCmdCertificates::readByteArray(size_t pos, size_t sz, const VirgilByteArray & data) {
    VirgilByteArray res;
    if (data.size() >= (pos + sz)) {
        res.insert(res.end(), data.begin() + pos, data.begin() + pos + sz);
    }
    return res;
}

std::map <std::string, VirgilByteArray> VirgilCmdCertificates::parseCustomData(const VirgilByteArray & rawData) {
    LOG("Parse custom data ...");
    size_t pos(0);
    std::map <std::string, VirgilByteArray> res;

    const size_t _cnt(readNum <uint16_t> (pos, rawData));

    if (_cnt > kKVMaxCount) return res;

    pos += sizeof (uint16_t);
    pos += 8;

    const kv_pair_t * pairs = reinterpret_cast<const kv_pair_t *> (rawData.data() + pos);
    size_t dataPos = pos + sizeof (kv_pair_t) * _cnt;

    for (int i = 0; i < _cnt; ++i) {
        const std::string _key(pairs[i].key);
        const VirgilByteArray _data(readByteArray(dataPos, pairs[i].value_sz, rawData));
        dataPos += pairs[i].value_sz;
        res[_key] = _data;
    }

    return res;
}

VirgilByteArray VirgilCmdCertificates::packKeyValueData(const std::map <std::string, std::string> & data) {
    VirgilByteArray res;
    VirgilByteArray payload;
    VirgilByteArray keyName(VirgilCmdCertificates::kKVKeySize);

    res << static_cast<uint16_t> (data.size())
            << uint32_t(0)
            << uint32_t(0);
    for (const auto & kv : data) {
        memset(keyName.data(), 0, VirgilCmdCertificates::kKVKeySize);
        memcpy(keyName.data(), kv.first.c_str(), kv.first.length());

        res << keyName
                << static_cast<uint16_t> (kv.second.length() + 1)
                << uint32_t(0)
                << uint32_t(0);
        VirgilByteArray ba(str2bytes(kv.second));
        ba.push_back(0);
        payload << ba;
    }

    res << payload;
    return res;
}

VirgilByteArray VirgilCmdCertificates::create(const VirgilCommand & cmd) {
    LOG("Create certificate and private key for a new device");

    const std::list<VirgilByteArray> _identities(cmd.dataByField(fldIdentity));
    const std::list<VirgilByteArray> _additionData(cmd.dataByField(fldData));
    const std::list<VirgilByteArray> _curveTypes(cmd.dataByField(fldCurveType));

    if (_identities.size() != 1 || _additionData.size() > 1 || _curveTypes.size() != 1 || _curveTypes.front().size() < 1) {
        return VirgilByteArray();
    }

    // Create a full set of crypto material
    std::map <std::string, VirgilByteArray> customData;

    if (_additionData.size()) {
        customData = parseCustomData(_additionData.front());
    }

    for (const auto & kv : customData) {
        LOG("[custom data] : %s : %s", kv.first.c_str(), foundation::VirgilBase64::encode(kv.second).c_str());
    }

    const std::string _id(bytes2str(_identities.front()));
    CertificateAndKey certificateAndKey(
            VirgilCertificates().createCertificate(
            static_cast <virgil::kernel::ecType> (_curveTypes.front()[0]),
            _id,
            kIdentityType,
            customData
            ));

    if (certificateAndKey.first.empty()) {
        return VirgilByteArray();
    }

    return VirgilCommand(cmd.command(), cmd.id())
            .appendData(fldPrivateKey, certificateAndKey.second)
            .appendData(fldCertificate, str2bytes(certificateAndKey.first))
            .data();
}

VirgilByteArray VirgilCmdCertificates::get(const VirgilCommand & cmd) {
    LOG("Get certificate from Virgil Service");

    const std::list<VirgilByteArray> _identities(cmd.dataByField(fldIdentity));

    if (_identities.size() != 1) {
        return VirgilByteArray();
    }

    const std::string _id(reinterpret_cast<const char*> (_identities.front().data()));
    std::string certificate;

    if (kRootCertificateId == _id) {
        certificate = VirgilCertificates().getRootCertificate();
    } else {
        certificate = VirgilCertificates().getCertificate(_id, kIdentityType);
    }

    if (certificate.empty()) {
        return VirgilByteArray();
    }
    return VirgilCommand(cmd.command(), cmd.id())
            .appendData(fldCertificate, str2bytes(certificate))
            .data();
}

VirgilByteArray VirgilCmdCertificates::verify(const VirgilCommand & cmd) {
    LOG("Verify certificates signature");

    const std::list<VirgilByteArray> _certificates(cmd.dataByField(fldCertificate));
    const std::list<VirgilByteArray> _rootCertificates(cmd.dataByField(fldRootCertificate));

    if (_certificates.size() != 1 || _rootCertificates.size() != 1) {
        return VirgilByteArray();
    }

    const bool _isVerified(VirgilCertificates().verifyCertificateWithRoot(
            bytes2str(_certificates.front()),
            bytes2str(_rootCertificates.front())));

    return VirgilCommand::resultCmd(cmd.command(), cmd.id(), _isVerified ? resOk : resGeneralError);
}

VirgilByteArray VirgilCmdCertificates::parse(const VirgilCommand & cmd) {
    LOG("IEEE1609 parse certificate");

    const std::list<VirgilByteArray> _certificates(cmd.dataByField(fldCertificate));

    if (_certificates.size() != 1) {
        return VirgilByteArray();
    }

    const auto _certData(VirgilCertificates().certificateData(bytes2str(_certificates.front())));
    const VirgilByteArray _data(packKeyValueData(_certData));

    if (_data.empty()) {
        return VirgilByteArray();
    }

    return VirgilCommand(cmd.command(), cmd.id())
            .appendData(fldData, _data)
            .data();
}

VirgilByteArray VirgilCmdCertificates::revoke(const VirgilCommand & cmd) {
    LOG("Revoke certificate");

    const std::list<VirgilByteArray> _identities(cmd.dataByField(fldIdentity));
    const std::list<VirgilByteArray> _privateKeys(cmd.dataByField(fldPrivateKey));

    if (_identities.size() != 1 || _privateKeys.size() != 1) {
        return VirgilByteArray();
    }

    const std::string _id(reinterpret_cast<const char*> (_identities.front().data()));
    const bool _res(VirgilCertificates().revokeCertificate(_id,
            kIdentityType,
            _privateKeys.front()));

    return VirgilCommand::resultCmd(cmd.command(), cmd.id(), _res ? resOk : resGeneralError);
}

VirgilByteArray VirgilCmdCertificates::crlInfo(const VirgilCommand & cmd) {
    LOG("Get CRL info");

    return VirgilCommand(cmd.command(), cmd.id())
            .appendTimeData(fldCRLTimeLast, VirgilCRLProcessor::instance().lastCRLTime())
            .appendTimeData(fldCRLTimeNext, VirgilCRLProcessor::instance().nextCRLTime())
            .data();
}

VirgilByteArray VirgilCmdCertificates::isRevoked(const VirgilCommand & cmd) {
    LOG("Check is certificate revoked");

    const std::list<VirgilByteArray> _certificates(cmd.dataByField(fldCertificate));

    if (_certificates.size() != 1) {
        return VirgilByteArray();
    }

    const CertificateModel _parsedCert(Marshaller<CertificateModel>::fromJson(bytes2str(_certificates.front())));
    const uint8_t isRevoked(VirgilCRLProcessor::instance().isCertificateRevoked(_parsedCert.getCard().getId()) ? 1 : 0);
    VirgilByteArray res;
    res << isRevoked;

    return VirgilCommand(cmd.command(), cmd.id())
            .appendData(fldOptional_1, res)
            .data();
}

VirgilByteArray VirgilCmdCertificates::process(const VirgilCommand & cmd) {
    try {
        switch (cmd.command()) {

            case cmdCertificateCreate:
                return create(cmd);

            case cmdCertificateGet:
                return get(cmd);

            case cmdCertificateVerify:
                return verify(cmd);

            case cmdCertificateParse:
                return parse(cmd);

            case cmdCertificateRevoke:
                return revoke(cmd);

            case cmdCertificateCRLInfo:
                return crlInfo(cmd);

            case cmdCertificateCheckIsRevoked:
                return isRevoked(cmd);

            default:
            {
                LOG("Unknown");
            }
        }
    } catch (std::exception& exception) {
        LOG("%s", exception.what());
    }

    return VirgilByteArray();
}
