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
 * @file VirgilCertificates.h
 * @brief Work with Virgil Certificates (access to CA, certificates processing).
 */

#ifndef VIRGIL_CERTIFICATES_H
#define	VIRGIL_CERTIFICATES_H

#include <virgil/sdk/ServicesHub.h>
#include <virgil/sdk/dto/Identity.h>
#include <virgil/sdk/models/IdentityModel.h>
#include <virgil/sdk/models/CRLModel.h>
#include <virgil/sdk/io/Marshaller.h>
#include <virgil/crypto/VirgilKeyPair.h>
#include <virgil/crypto/VirgilByteArray.h>

#include <map>

using namespace virgil::crypto;
using namespace virgil::sdk;
using namespace virgil::sdk::io;
using namespace virgil::sdk::dto;
using namespace virgil::sdk::models;

typedef std::pair<std::string, VirgilByteArray> CertificateAndKey;
typedef std::map<std::string, std::string> KeyValueData;

class VirgilCertificates {
public:
    VirgilCertificates() = default;
    virtual ~VirgilCertificates();

    VirgilCertificates(const VirgilCertificates&) = delete;
    VirgilCertificates& operator=(const VirgilCertificates&) = delete;

    CertificateAndKey createCertificate(
            const std::string & identityValue,
            const std::string & identityType,
            const std::map<std::string, VirgilByteArray> & customData
            );
    
    std::string getCertificate(
            const std::string & identity,
            const std::string & identityType
            );
    
    std::string getRootCertificate();
    
    bool verifyCertificateWithRoot(
            const std::string & cert,
            const std::string & rootCert
            );
    
    bool revokeCertificate(
            const std::string & identity,
            const std::string & identityType,
            const VirgilByteArray & privateKey
            );
    
    KeyValueData certificateData(const std::string & cert);
    
    CRLModel crl();
    
public:
    static const std::string kIdentityKey;
    static const std::string kPublicKeyKey;
    
private:
    ServicesHub _createServicesHub();

};

#endif	/* VIRGIL_CERTIFICATES_H */

