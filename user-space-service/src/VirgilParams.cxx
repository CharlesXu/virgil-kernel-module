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

#include "VirgilParams.h"
#include "helpers/VirgilLog.h"
#include "helpers/VirgilFilesHelper.h"

#include "ini.hpp"

#if !defined(VIRGIL_DEBUG_PARAMS_LOADER)
#define VIRGIL_DEBUG_PARAMS_LOADER
#endif

const std::string VirgilParams::kPrivateKeyFile = ".vprivkey";
const std::string VirgilParams::kPasswordFile = ".vpasswd";
const std::string VirgilParams::kTokenFile = ".vtoken";
const std::string VirgilParams::kConfigFile = ".virgil-conf.ini";

const std::string VirgilParams::kDefaultCA = "https://ca.virgilsecurity.com";
const std::string VirgilParams::kDefaultKeys = "https://keys.virgilsecurity.com";

VirgilParams & VirgilParams::instance() {
    static VirgilParams myInstance;
    return myInstance;
}

VirgilParams::VirgilParams() {
    load();
}

VirgilParams::~VirgilParams() {

}

std::string VirgilParams::path(const std::string & fileName) {
    return VirgilFilesHelper::homeDir() + VirgilFilesHelper::separator() + fileName;
}

bool VirgilParams::load() {
    bool res(false);

    // Load password for private key
    const auto _passwordData(VirgilFilesHelper::loadFile(path(kPasswordFile)));
    if (_passwordData.empty()) {
        LOG_ERROR("Application password not loaded : %s", path(kPasswordFile).c_str());
        return false;
    }
    m_appPassword = bytes2str(_passwordData);
    m_appPassword.erase(remove(m_appPassword.begin(), m_appPassword.end(), '\n'), m_appPassword.end());
    if (m_appPassword.empty()) return false;

    // Load private key
    auto _keyData(VirgilFilesHelper::loadFile(path(kPrivateKeyFile)));
    if (_keyData.empty()) {
        LOG_ERROR("Application private key not loaded : %s", path(kPrivateKeyFile).c_str());
        return false;
    }
    m_appPrivateKey = bytes2str(_keyData);

    // Load access token
    auto _tokenData(VirgilFilesHelper::loadFile(path(kTokenFile)));
    if (_tokenData.empty()) {
        LOG_ERROR("Application token not loaded : %s", path(kTokenFile).c_str());
        return false;
    }
    m_accessToken = bytes2str(_tokenData);
    m_accessToken.erase(remove(m_accessToken.begin(), m_accessToken.end(), '\n'), m_accessToken.end());
    
    readConfig();

#if defined(VIRGIL_DEBUG_PARAMS_LOADER)
    LOG("Application private key : %s", m_appPrivateKey.c_str());
    LOG("Application password : \"%s\"", m_appPassword.c_str());
    LOG("Application token : \"%s\"", m_accessToken.c_str());
    LOG("CA URL : \"%s\"", m_caURL.c_str());
    LOG("KEYS URL : \"%s\"", m_keysURL.c_str());
#endif

    return res;
}

std::string VirgilParams::appPrivateKeyPassword() const {
    return m_appPassword;
}

VirgilByteArray VirgilParams::appPrivateKey() const {
    return str2bytes(m_appPrivateKey);
}

std::string VirgilParams::accessToken() const {
    return m_accessToken;
}

std::string VirgilParams::caURL() const {
    return m_caURL;
}

std::string VirgilParams::keysURL() const {
    return m_keysURL;
}

void VirgilParams::readConfig() {
    try {
        auto _configData(VirgilFilesHelper::loadFile(path(kConfigFile)));
        if (!_configData.empty()) {
            std::stringstream ssConfig(bytes2str(_configData));
            INI::Parser iniParser(ssConfig);
            m_caURL = iniParser.top()("URLs")["CA"];
            m_keysURL = iniParser.top()("URLs")["KEYS"];
        }

    } catch (std::runtime_error& exception) {
        LOG("Can't parse config file: %s", path(kConfigFile).c_str());
    }
    
    if (m_caURL.empty()) {
        m_caURL = kDefaultCA;
    }
    
    if (m_keysURL.empty()) {
        m_keysURL = kDefaultKeys;
    }
}
