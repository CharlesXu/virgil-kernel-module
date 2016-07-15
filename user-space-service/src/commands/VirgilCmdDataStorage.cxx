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

#include "VirgilCmdStorage.h"
#include "helpers/VirgilLog.h"

#include <virgil/crypto/VirgilKeyPair.h>
#include <virgil/crypto/VirgilCipher.h>
#include <virgil/crypto/VirgilSigner.h>

#include <iostream>

using namespace virgil::crypto;

VirgilByteArray VirgilCmdDataStorage::store(const VirgilCommand & cmd) {
    LOG("Save key");
    const std::list<VirgilByteArray> _identity(cmd.dataByField(fldIdentity));
    const std::list<VirgilByteArray> _dataList(cmd.dataByField(fldData));
    const std::list<VirgilByteArray> _keyType(cmd.dataByField(fldKeyType));
    const std::list<VirgilByteArray> _password(cmd.dataByField(fldPassword));

    if (_identity.size() != 1
            || _dataList.size() != 1
            || _keyType.size() != 1) {
        return VirgilByteArray();
    }

    VirgilByteArray key(_dataList.front());
    if (_password.size()) {
        VirgilCipher cipher;
        cipher.addPasswordRecipient(_password.front());
        key = cipher.encrypt(_dataList.front(), true);
    }

    const uint16_t _keyTypeData(VirgilCommand::readNum <uint16_t> (0, _keyType.front()));
    const std::string _id(reinterpret_cast<const char*> (_identity.front().data()));
    const bool _res(VirgilDataStorage::instance().save(_id,
            key,
            static_cast<virgil::dataStorage::VirgilStoreType> (_keyTypeData)));

    return VirgilCommand::resultCmd(cmd.command(), cmd.id(), _res ? resOk : resGeneralError);
}

VirgilByteArray VirgilCmdDataStorage::load(const VirgilCommand & cmd) {
    LOG("Load key");
    const std::list<VirgilByteArray> _identity(cmd.dataByField(fldIdentity));
    const std::list<VirgilByteArray> _password(cmd.dataByField(fldPassword));

    if (_identity.size() != 1) {
        return VirgilByteArray();
    }

    const std::string _id(reinterpret_cast<const char*> (_identity.front().data()));
    VirgilByteArray key(VirgilDataStorage::instance().load(_id));

    if (key.size() && _password.size()) {
        key = VirgilCipher().decryptWithPassword(key, _password.front());
    }

    if (key.size()) {
        return VirgilCommand(cmd.command(), cmd.id())
                .appendData(fldData, key)
                .data();
    }
    return VirgilByteArray();
}

VirgilByteArray VirgilCmdDataStorage::remove(const VirgilCommand & cmd) {
    LOG("Revoke key");
    const std::list<VirgilByteArray> _identity(cmd.dataByField(fldIdentity));

    if (_identity.size() != 1) {
        return VirgilByteArray();
    }

    const std::string _id(reinterpret_cast<const char*> (_identity.front().data()));
    const bool _res(VirgilDataStorage::instance().remove(_id));
    return VirgilCommand::resultCmd(cmd.command(), cmd.id(), _res ? resOk : resGeneralError);
}

VirgilByteArray VirgilCmdDataStorage::process(const VirgilCommand & cmd) {
    try {
        switch (cmd.command()) {
            case cmdStorageStore:
                return store(cmd);

            case cmdStorageLoad:
                return load(cmd);

            case cmdStorageRemove:
                return remove(cmd);

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
