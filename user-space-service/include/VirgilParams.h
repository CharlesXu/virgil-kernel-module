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
 * @file VirgilParams.h
 * @brief Parameters loader.
 */

#ifndef VIRGIL_PARAMS_H
#define	VIRGIL_PARAMS_H

#include <virgil/crypto/VirgilByteArray.h>

using namespace virgil::crypto;

/**
 * @brief Class for parameters loader.
 */
class VirgilParams {
public:
    // delete copy and move constructors and assign operators
    VirgilParams(VirgilParams const&) = delete;
    VirgilParams(VirgilParams&&) = delete;
    VirgilParams& operator=(VirgilParams const&) = delete;
    VirgilParams& operator=(VirgilParams &&) = delete;

    /**
     * @brief Singleton instance.
     */
    static VirgilParams & instance();

    VirgilByteArray appPrivateKey() const;
    std::string appPrivateKeyPassword() const;
    std::string accessToken() const;
    std::string caURL() const;
    std::string keysURL() const;
    
private:
     VirgilParams();
    ~VirgilParams();
  
    bool load();
    std::string path(const std::string & fileName);
    void readConfig();

    static const std::string kPrivateKeyFile;
    static const std::string kPasswordFile;
    static const std::string kTokenFile;
    static const std::string kConfigFile;
    static const std::string kDefaultCA;
    static const std::string kDefaultKeys;
    
    std::string m_appPrivateKey;
    std::string m_appPassword;
    std::string m_accessToken;
    std::string m_caURL;
    std::string m_keysURL;
};

#endif	/* VIRGIL_KEY_STORAGE_H */

