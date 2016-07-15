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
 * @file VirgilFilesHelper.h
 * @brief Helper class for work with file system.
 */

#ifndef VIRGIL_FILES_HELPER_H
#define VIRGIL_FILES_HELPER_H

#include <virgil/crypto/VirgilByteArray.h>

using namespace virgil::crypto;

class VirgilFilesHelper {
public:
    VirgilFilesHelper() = delete;
    virtual ~VirgilFilesHelper() = delete;
    VirgilFilesHelper(const VirgilFilesHelper&) = delete;
    VirgilFilesHelper & operator=(const VirgilFilesHelper&) = delete;

    /**
     * @brief Loads file data to byte array.
     */
    static VirgilByteArray loadFile(const std::string & fileName);
    
    /**
     * @brief Save byte array to file.
     */
    static bool saveFile(const std::string & fileName, const VirgilByteArray & data);
    
    /**
     * @brief Returns home directory for current user.
     */
    static std::string homeDir();
    
    /**
     * @brief Returns file path separator for current OS.
     */
    static std::string separator();
};

#endif /*VIRGIL_FILES_HELPER_H */
