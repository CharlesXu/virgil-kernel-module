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

#include "VirgilStorage.h"
#include "helpers/VirgilFilesHelper.h"
#include "helpers/VirgilLog.h"

#include <unistd.h>
#include <sys/types.h>
#include <iostream>
#include <fstream>
#include <algorithm>
#include <map>

using namespace virgil::dataStorage;

VirgilDataStorage & VirgilDataStorage::instance() {
    static VirgilDataStorage myInstance;
    return myInstance;
}

VirgilDataStorage::VirgilDataStorage() :
_fileSize(sizeof (VirgilStorageElementInFile) * restrStorageElemensCount) {
    _fileName = VirgilFilesHelper::homeDir() + "/.virgil-keys-cache.dat";
    m_permanentDataBuf.resize(_fileSize);
    loadPermanentData();
    _printContent();
}

VirgilDataStorage::~VirgilDataStorage() {

}

bool VirgilDataStorage::createClearFile() {
    VirgilByteArray data;
    data.resize(_fileSize, 0);
    return VirgilFilesHelper::saveFile(_fileName, data);
}

void VirgilDataStorage::_updatePermanentDataPointer() {
    m_permanentData = (reinterpret_cast<VirgilStorageElementInFile *> (m_permanentDataBuf.data()));
}

bool VirgilDataStorage::loadPermanentData() {
    VirgilByteArray _keyData(VirgilFilesHelper::loadFile(_fileName));
    memset(m_permanentDataBuf.data(), 0, m_permanentDataBuf.size());

    if (_keyData.empty()) {
        createClearFile();
    } else {
        m_permanentDataBuf = _keyData;
    }

    _updatePermanentDataPointer();

    return false;
}

bool VirgilDataStorage::storePermanentData() {
    return VirgilFilesHelper::saveFile(_fileName, m_permanentDataBuf);
}

int VirgilDataStorage::posById(const std::string & id) const {
    for (int i = 0; i < restrStorageElemensCount; ++i) {
        const std::string _elId(reinterpret_cast<char *> (m_permanentData[i].id));
        if (_elId == id) {
            return i;
        }
    }
    return -1;
}

int VirgilDataStorage::writePos() const {
    uint32_t val = 0xFFull;
    int res = 0;
    for (int i = 0; i < restrStorageElemensCount; ++i) {
        if (0 == m_permanentData[i].id[0]) {
            return i;
        }
        if (m_permanentData[i].num <= val) {
            val = m_permanentData[i].num;
            res = i;
        }
    }
    return res;
}

uint32_t VirgilDataStorage::maxNum() const {
    uint32_t res = 0;
    for (int i = 0; i < restrStorageElemensCount; ++i) {
        if (m_permanentData[i].num > m_permanentData[res].num) {
            res = i;
        }
    }
    return m_permanentData[res].num;
}

void VirgilDataStorage::_printContent() const {
    for (int i = 0; i < restrStorageElemensCount; ++i) {
        const std::string _elId(reinterpret_cast<char *> (m_permanentData[i].id));
        if (!_elId.empty()) {
            LOG("[%d] num = %3d size = %5d id = %s",
                    i,
                    static_cast<int> (m_permanentData[i].num),
                    static_cast<int> (m_permanentData[i].dataSize),
                    _elId.c_str() ? _elId.c_str() : "NULL");
        }
    }
}

bool VirgilDataStorage::save(const std::string & id, const VirgilByteArray & data, virgil::dataStorage::VirgilStoreType storeType) {
    if (virgil::dataStorage::stTemporary == storeType) {
        if (m_temporaryData.size() > kTemporaryDataMaxCount) {
            m_temporaryData.erase(m_temporaryData.begin());
        }

        auto it = std::find_if(m_temporaryData.begin(), m_temporaryData.end(),
                [&](const virgil::dataStorage::tempData v) {
                    return v.id == id;
                });

        if (m_temporaryData.end() != it) {
            m_temporaryData.erase(it);
        }

        m_temporaryData.push_back(virgil::dataStorage::tempData(id, data));
        return true;

    } else if (virgil::dataStorage::stPermanent == storeType) {
        if (data.size() > restrDataSizeMax) return false;

        int _pos(posById(id));
        if (_pos < 0) {
            _pos = writePos();
        }

        m_permanentData[_pos].num = maxNum() + 1;
        memset(m_permanentData[_pos].id, 0, restrIdSize);
        strncpy(reinterpret_cast<char *> (m_permanentData[_pos].id), id.c_str(), restrIdSize);
        m_permanentData[_pos].dataSize = data.size();
        memcpy(m_permanentData[_pos].data, data.data(), data.size());

        storePermanentData();

        _printContent();

        return true;
    }

    return false;
}

VirgilByteArray VirgilDataStorage::load(const std::string & id) {
    VirgilByteArray res;

    auto it = std::find_if(m_temporaryData.begin(), m_temporaryData.end(),
            [&](const virgil::dataStorage::tempData v) {
                return v.id == id;
            });

    if (m_temporaryData.end() != it) {
        res = it->data;
    } else {
        const int _pos(posById(id));
        LOG("LOAD : id : %s\n   pos :%d", id.c_str(), _pos);
        if (_pos >= 0) {
            res.assign(reinterpret_cast<unsigned char *> (m_permanentData[_pos].data),
                    reinterpret_cast<unsigned char *> (m_permanentData[_pos].data) +
                    std::min(m_permanentData[_pos].dataSize, static_cast<uint16_t> (restrDataSizeMax)));
        }
    }
    return res;
}

bool VirgilDataStorage::remove(const std::string & id) {
    auto it = std::find_if(m_temporaryData.begin(), m_temporaryData.end(),
            [&](const virgil::dataStorage::tempData v) {
                return v.id == id;
            });

    if (m_temporaryData.end() != it) {
        m_temporaryData.erase(it);;
    }

    const int _pos(posById(id));
    if (_pos >= 0) {
        m_permanentData[_pos].num = 0;
        m_permanentData[_pos].id[0] = 0;
    }
    _printContent();
    storePermanentData();

    return true;
}
