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
 * @file VirgilStorage.h
 * @brief Data storage.
 */

#ifndef VIRGIL_STORAGE_H
#define	VIRGIL_STORAGE_H

#include <virgil/crypto/VirgilByteArray.h>
#include <list>

using namespace virgil::crypto;

namespace virgil {
    namespace dataStorage {

        enum VirgilStoreType : uint16_t {
            stUnknown = 0,
            stPermanent,
            stTemporary,

            stMax
        };

        enum VirgilStorageRestrictions : uint16_t {
            restrStorageElemensCount = 30,
            restrIdSize = 100,
            restrDataSizeMax = 2048
        };

#pragma pack(push,1)
        struct VirgilStorageElementInFile {
            uint32_t num;
            uint8_t id[restrIdSize];
            uint16_t dataSize;
            uint8_t data[restrDataSizeMax];
        };
#pragma pack(pop)
        
        struct tempData {
            tempData(const std::string & _id, const VirgilByteArray & _data) : id(_id), data(_data) {
            }
            std::string id;
            VirgilByteArray data;
        };
        
    }
}

/**
 * @brief Class for data storage.
 */
class VirgilDataStorage {
public:
    // delete copy and move constructors and assign operators
    VirgilDataStorage(VirgilDataStorage const&) = delete;
    VirgilDataStorage(VirgilDataStorage&&) = delete;
    VirgilDataStorage& operator=(VirgilDataStorage const&) = delete;
    VirgilDataStorage& operator=(VirgilDataStorage &&) = delete;

    /**
     * @brief Singleton instance.
     */
    static VirgilDataStorage & instance();

    /**
     * @brief Save data to storage.
     * @param id - identifier of data
     * @param data - data
     * @param dataType - data type
     * @return true if was done successfully
     */
    bool save(const std::string & id, const VirgilByteArray & data, virgil::dataStorage::VirgilStoreType storeType);
    
    /**
     * @brief Load data from storage.
     * @param id - identifier of data
     * @return data or empty array in case of error
     */
    VirgilByteArray load(const std::string & id);
    
    /**
     * @brief Revoke data from storage.
     * @param id - identifier of data
     * @return true if was done successfully
     */
    bool remove(const std::string & id);

private:
     VirgilDataStorage();
    ~VirgilDataStorage();
    
    std::string _fileName;
    const size_t _fileSize;
    
    static const size_t kTemporaryDataMaxCount = 200;

    std::list <virgil::dataStorage::tempData> m_temporaryData;
    VirgilByteArray m_permanentDataBuf;
    virgil::dataStorage::VirgilStorageElementInFile * m_permanentData;

    bool createClearFile();
    bool writeToFile(const VirgilByteArray & data);
    VirgilByteArray readFromFile();

    int posById(const std::string & id) const;
    int writePos() const;
    uint32_t maxNum() const;

    bool loadPermanentData();
    bool storePermanentData();

    void _updatePermanentDataPointer();
    void _printContent() const;
};

#endif	/* VIRGIL_STORAGE_H */

