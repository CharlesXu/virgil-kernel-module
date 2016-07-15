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

#include "VirgilCmdCrypto.h"
#include "VirgilCertificates.h"
#include "helpers/VirgilLog.h"

#include <virgil/crypto/VirgilKeyPair.h>
#include <virgil/crypto/VirgilCipher.h>
#include <virgil/crypto/VirgilSigner.h>
#include <virgil/crypto/foundation/VirgilHash.h>
#include <virgil/sdk/models/CardModel.h>

#include <iostream>

using namespace virgil::crypto;
using namespace virgil::crypto::foundation;
using namespace virgil::sdk;
using namespace virgil::sdk::models;

using namespace virgil::crypto;

VirgilByteArray VirgilCmdCrypto::keygen(const VirgilCommand & cmd) {
    LOG("Keygen");
    VirgilKeyPair keypair(VirgilKeyPair::ecNist256());
    return VirgilCommand(cmdCryptoKeygen, cmd.id())
            .appendData(fldPrivateKey, keypair.privateKey())
            .appendData(fldPublicKey, keypair.publicKey())
            .data();
}

VirgilByteArray VirgilCmdCrypto::encryptWithPassword(const VirgilCommand & cmd) {
    LOG("Encrypt with password");
    const std::list<VirgilByteArray> _passwords(cmd.dataByField(fldPassword));
    const std::list<VirgilByteArray> _dataList(cmd.dataByField(fldData));
    if (_passwords.size() != 1 || _dataList.size() != 1) {
        return VirgilByteArray();
    }

    VirgilCipher cipher;
    cipher.addPasswordRecipient(_passwords.front());
    return VirgilCommand(cmdCryptoEncryptPassword, cmd.id())
            .appendData(fldData, cipher.encrypt(_dataList.front(), true))
            .data();
}

VirgilByteArray VirgilCmdCrypto::decryptWithPassword(const VirgilCommand & cmd) {
    LOG("Decrypt with password");
    const std::list<VirgilByteArray> _passwords(cmd.dataByField(fldPassword));
    const std::list<VirgilByteArray> _dataList(cmd.dataByField(fldData));
    if (_passwords.size() != 1 || _dataList.size() != 1) {
        return VirgilByteArray();
    }

    const VirgilByteArray _decryptedData(VirgilCipher().decryptWithPassword(_dataList.front(), _passwords.front()));

    return VirgilCommand(cmdCryptoDecryptPassword, cmd.id())
            .appendData(fldData, _decryptedData)
            .data();
}

VirgilByteArray VirgilCmdCrypto::encrypt(const VirgilCommand & cmd) {
    LOG("Encrypt");
    const std::list<VirgilByteArray> _publicKeys(cmd.dataByField(fldPublicKey));
    const std::list<VirgilByteArray> _identities(cmd.dataByField(fldIdentity));
    const std::list<VirgilByteArray> _certificates(cmd.dataByField(fldCertificate));
    const std::list<VirgilByteArray> _dataList(cmd.dataByField(fldData));

    if (_dataList.size() != 1) {
        return VirgilByteArray();
    }

    const bool _isCertificatesBasedEncryption(!_certificates.empty());
    const bool _isPubKeyBasedEncryption(!_publicKeys.empty() && _publicKeys.size() == _identities.size());

    if (!_isCertificatesBasedEncryption && !_isPubKeyBasedEncryption) {
        return VirgilByteArray();
    }

    VirgilCipher cipher;
    if (_isCertificatesBasedEncryption) {
        for (const auto & cert : _certificates) {
            try {
                const CertificateModel _parsedCert(Marshaller<CertificateModel>::fromJson(bytes2str(cert)));

                const std::string _identity(_parsedCert.getCard().getCardIdentity().getValue());
                VirgilByteArray baIdentity(str2bytes(_identity));
                baIdentity.push_back(0);
                cipher.addKeyRecipient(
                        baIdentity,
                        _parsedCert.getCard().getPublicKey().getKey());
            } catch (...) {
            }
        }
    } else {
        std::list<VirgilByteArray>::const_iterator _itPubKey(_publicKeys.begin());
        std::list<VirgilByteArray>::const_iterator _itPubKeyEnd(_publicKeys.end());
        std::list<VirgilByteArray>::const_iterator _itIdentity(_identities.begin());
        
        for (; _itPubKey != _itPubKeyEnd; _itPubKey++, _itIdentity++) {
            try {
                cipher.addKeyRecipient(*_itIdentity, *_itPubKey);
            } catch (...) {}
        }
    }

    return VirgilCommand(cmdCryptoEncrypt, cmd.id())
            .appendData(fldData, cipher.encrypt(_dataList.front(), true))
            .data();
}

VirgilByteArray VirgilCmdCrypto::decrypt(const VirgilCommand & cmd) {
    LOG("Decrypt");
    const std::list<VirgilByteArray> _privateKeys(cmd.dataByField(fldPrivateKey));
    const std::list<VirgilByteArray> _dataList(cmd.dataByField(fldData));
    const std::list<VirgilByteArray> _identities(cmd.dataByField(fldIdentity));

    if (_privateKeys.size() != 1 || _dataList.size() != 1 || _identities.size() != 1) {
        return VirgilByteArray();
    }

    const VirgilByteArray _decryptedData(
            VirgilCipher().decryptWithKey(_dataList.front(),
            _identities.front(),
            _privateKeys.front()));

    return VirgilCommand(cmdCryptoDecrypt, cmd.id())
            .appendData(fldData, _decryptedData)
            .data();
}

VirgilByteArray VirgilCmdCrypto::sign(const VirgilCommand & cmd) {
    LOG("Sign data");
    const std::list<VirgilByteArray> _privateKeys(cmd.dataByField(fldPrivateKey));
    const std::list<VirgilByteArray> _dataList(cmd.dataByField(fldData));

    if (_privateKeys.size() != 1 || _dataList.size() != 1) {
        return VirgilByteArray();
    }

    return VirgilCommand(cmdCryptoSign, cmd.id())
            .appendData(fldSignature, VirgilSigner().sign(_dataList.front(), _privateKeys.front()))
            .data();
}

VirgilByteArray VirgilCmdCrypto::verify(const VirgilCommand & cmd) {
    LOG("Verify data");
    const std::list<VirgilByteArray> _publicKeys(cmd.dataByField(fldPublicKey));
    const std::list<VirgilByteArray> _certificates(cmd.dataByField(fldCertificate));
    const std::list<VirgilByteArray> _dataList(cmd.dataByField(fldData));
    const std::list<VirgilByteArray> _signatureList(cmd.dataByField(fldSignature));

    if (_dataList.size() != 1 || _signatureList.size() != 1) {
        return VirgilByteArray();
    }
    
    const bool _isCertificateBasedVerify(_certificates.size() == 1);
    const bool _isPubkeyBasedVerify(_publicKeys.size() == 1);
    
    if (!_isCertificateBasedVerify && !_isPubkeyBasedVerify) {
        return VirgilByteArray();
    }

    VirgilByteArray res;
    bool _res(false);
    if (_isCertificateBasedVerify) {        
        CertificateModel _certificate(Marshaller<CertificateModel>::fromJson(bytes2str(_certificates.front())));
        _res = VirgilSigner().verify(_dataList.front(),
                _signatureList.front(),
                _certificate.getCard().getPublicKey().getKey());
    } else {
        _res = VirgilSigner().verify(_dataList.front(),
                _signatureList.front(),
                _publicKeys.front());
    }

    return VirgilCommand::resultCmd(cmd.command(), cmd.id(), _res ? resOk : resGeneralError);
}

VirgilByteArray VirgilCmdCrypto::hash(const VirgilCommand & cmd) {
    LOG("Create hash");
    const std::list<VirgilByteArray> _hashFunc(cmd.dataByField(fldHashFunc));
    const std::list<VirgilByteArray> _dataList(cmd.dataByField(fldData));

    if (_hashFunc.size() != 1 || _dataList.size() != 1) {
        return VirgilByteArray();
    }

    const uint8_t _hashFuncCode(static_cast<uint8_t> (_hashFunc.front().front()));

    VirgilHash hash;
    if (static_cast<uint8_t> (virgil::kernel::md5) == _hashFuncCode) {
        hash = VirgilHash::md5();
    } else if (static_cast<uint8_t> (virgil::kernel::sha384) == _hashFuncCode) {
        hash = VirgilHash::sha384();
    } else if (static_cast<uint8_t> (virgil::kernel::sha512) == _hashFuncCode) {
        hash = VirgilHash::sha512();
    } else {
        hash = VirgilHash::sha256();
    }

    return VirgilCommand(cmdCryptoSign, cmd.id())
            .appendData(fldData, hash.hash(_dataList.front()))
            .data();
}

VirgilByteArray VirgilCmdCrypto::process(const VirgilCommand & cmd) {
    try {
        switch (cmd.command()) {

            case cmdCryptoKeygen:
                return keygen(cmd);

            case cmdCryptoEncryptPassword:
                return encryptWithPassword(cmd);

            case cmdCryptoDecryptPassword:
                return decryptWithPassword(cmd);

            case cmdCryptoEncrypt:
                return encrypt(cmd);

            case cmdCryptoDecrypt:
                return decrypt(cmd);

            case cmdCryptoSign:
                return sign(cmd);

            case cmdCryptoVerify:
                return verify(cmd);

            case cmdCryptoHash:
                return hash(cmd);

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
