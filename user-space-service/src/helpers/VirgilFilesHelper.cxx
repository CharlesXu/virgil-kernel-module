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

#include "helpers/VirgilFilesHelper.h"
#include "helpers/VirgilLog.h"

#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>
#include <iostream>
#include <fstream>
#include <algorithm>

VirgilByteArray VirgilFilesHelper::loadFile(const std::string & fileName) {
    VirgilByteArray res;
    try {
        std::ifstream file(fileName, std::ifstream::ate | std::ifstream::binary);
        size_t _sz(file.tellg());

        if (_sz > 1024 * 1024) {
            return res;
        }

        file.seekg(0, file.beg);
        res.resize(_sz);
        file.read(reinterpret_cast<char *> (res.data()), res.size());
        file.close();
    } catch (...) {
        res.clear();
    }
    return res;
}

bool VirgilFilesHelper::saveFile(const std::string & fileName, const VirgilByteArray & data) {
    try {
        std::ofstream file(fileName, std::ios::binary);
        file.write(reinterpret_cast<const char *> (data.data()), data.size());
        file.close();
    } catch (...) {
        return false;
    }
    return true;
}

std::string VirgilFilesHelper::homeDir() {
    struct passwd *pw = getpwuid(getuid());
    return std::string(pw->pw_dir);
}

std::string VirgilFilesHelper::separator() {
#ifdef _WIN32
    return "\\";
#else
    return "/";
#endif
}
