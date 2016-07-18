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

#include "VirgilCertificates.h"
#include "VirgilParams.h"
#include "helpers/VirgilLog.h"
#include "VirgilCmdCrypto.h"

#include <virgil/crypto/foundation/VirgilBase64.h>
#include <virgil/sdk/models/IdentityModel.h>
#include <virgil/sdk/models/CardModel.h>
#include <virgil/sdk/models/CertificateModel.h>
#include <virgil/sdk/util/obfuscator.h>
#include <virgil/sdk/util/token.h>

#include <iostream>

const std::string VirgilCertificates::kIdentityKey = "v__IdentityKey";
const std::string VirgilCertificates::kPublicKeyKey = "v__PublicKeyKey";
    
VirgilCertificates::~VirgilCertificates() {

}

CertificateAndKey VirgilCertificates::createCertificate(
        virgil::kernel::ecType ecType,
        const std::string & identityValue,
        const std::string & identityType,
        const std::map<std::string, VirgilByteArray> & customData) {
    
    try {
       Credentials appCredentials(VirgilParams::instance().appPrivateKey(), str2bytes(VirgilParams::instance().appPrivateKeyPassword()));
        const std::string validationToken(util::generate_validation_token(
                identityValue, identityType, appCredentials));

        // Create key pair
        VirgilKeyPair keyPair(VirgilKeyPair::ecNist256());
        
        if (ecType == virgil::kernel::bp256) {
            keyPair = VirgilKeyPair::ecBrainpool256();
        }

        Credentials userCredentials(keyPair.privateKey());

        ValidatedIdentity validatedIdentity(Identity(identityValue, identityType), validationToken);

        ServicesHub servicesHub(_createServicesHub());
        
        std::map <std::string, std::string> preparedCustomData;
        
        for (const auto & kv: customData) {
            preparedCustomData[kv.first] = foundation::VirgilBase64::encode(kv.second);
        }

        const VirgilByteArray _publicKey(keyPair.publicKey());
        auto certificate(servicesHub.certificate().create(validatedIdentity, 
                                                          keyPair.publicKey(), 
                                                          userCredentials,
                                                          preparedCustomData));

        const std::string jsonCertificate(Marshaller<CertificateModel>::toJson<-1>(certificate));
        std::cout << jsonCertificate << std::endl;

        return CertificateAndKey(jsonCertificate, keyPair.privateKey());
    } catch (std::exception& exception) {
        std::cerr << exception.what() << std::endl;
    }
    return CertificateAndKey("", VirgilByteArray());
}

std::string VirgilCertificates::getCertificate(
        const std::string & identity,
        const std::string & identityType) {
    try {
        ServicesHub servicesHub(_createServicesHub());

        const auto _certificate(servicesHub.certificate().pull(Identity(identity, identityType)));

        const std::string jsonCertificate(Marshaller<CertificateModel>::toJson<-1>(_certificate));
        std::cout << jsonCertificate << std::endl;

        return jsonCertificate;
    } catch (std::exception& exception) {
        std::cerr << exception.what() << std::endl;
    }

    return "";
}

std::string VirgilCertificates::getRootCertificate() {
    try {
        ServicesHub servicesHub(_createServicesHub());
        const auto _certificate(servicesHub.certificate().pullRootCertificate());
        const std::string jsonCertificate(Marshaller<CertificateModel>::toJson<-1>(_certificate));
        std::cout << jsonCertificate << std::endl;
        return jsonCertificate;
    } catch (std::exception& exception) {
        std::cerr << exception.what() << std::endl;
    }
    return "";
}

bool VirgilCertificates::verifyCertificateWithRoot(
            const std::string & cert,
            const std::string & rootCert
            ) {
    bool res(false);
    try {
        const auto _parsedCert(Marshaller<CertificateModel>::fromJson(cert));
        const auto _parsedRootCert(Marshaller<CertificateModel>::fromJson(rootCert));
        res = _parsedCert.verifyWith(_parsedRootCert);
    } catch (std::exception& exception) {
        std::cerr << exception.what() << std::endl;
        res = false;
    }
    return res;
}

bool VirgilCertificates::revokeCertificate(
        const std::string & identity,
        const std::string & identityType,
        const VirgilByteArray & privateKey) {
    try {
        Credentials appCredentials(VirgilParams::instance().appPrivateKey(), str2bytes(VirgilParams::instance().appPrivateKeyPassword()));
        const std::string validationToken(util::generate_validation_token(
                identity, identityType, appCredentials));

        Credentials userCredentials(privateKey);

        ValidatedIdentity validatedIdentity(Identity(identity, identityType), validationToken);

        ServicesHub servicesHub(_createServicesHub());
        const auto _certificate(servicesHub.certificate().pull(Identity(identity, identityType)));

        servicesHub.certificate().revoke(_certificate.getCard().getId(), validatedIdentity, userCredentials);

        return true;
    } catch (std::exception& exception) {
        std::cerr << exception.what() << std::endl;
    }
    return false;
}

CRLModel VirgilCertificates::crl() {
    try {
        return _createServicesHub().certificate().getCRL();
    } catch (std::exception& exception) {
        std::cerr << exception.what() << std::endl;
    }
    return CRLModel();
}

KeyValueData VirgilCertificates::certificateData(const std::string & cert) {
    KeyValueData res;
    try {
        const CertificateModel _parsedCert(Marshaller<CertificateModel>::fromJson(cert));
        res = _parsedCert.getCard().getData();
        res.insert(std::make_pair(kIdentityKey, _parsedCert.getCard().getCardIdentity().getValue()));
        res.insert(std::make_pair(kPublicKeyKey, bytes2str(_parsedCert.getCard().getPublicKey().getKey())));
    } catch (std::exception& exception) {
        std::cerr << exception.what() << std::endl;
        res.clear();
    }
    return res;
}

ServicesHub VirgilCertificates::_createServicesHub() {
    return ServicesHub(VirgilParams::instance().accessToken(), 
            ServiceUri("", VirgilParams::instance().keysURL(), "", VirgilParams::instance().caURL()));
}
