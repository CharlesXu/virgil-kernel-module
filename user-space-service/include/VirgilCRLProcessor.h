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
 * @file VirgilCRLProcessor.h
 * @brief Work with Virgil Certificates Revocation List.
 */

#ifndef VIRGIL_CRL_PROCESSOR_H
#define VIRGIL_CRL_PROCESSOR_H

#include <mutex>
#include <thread>

#include <virgil/sdk/models/CRLModel.h>
#include <virgil/crypto/VirgilByteArray.h>

#include <list>

using namespace virgil::crypto;
using namespace virgil::sdk::models;

class VirgilCRLProcessor {
public:
    // delete copy and move constructors and assign operators
    VirgilCRLProcessor(VirgilCRLProcessor const&) = delete;
    VirgilCRLProcessor(VirgilCRLProcessor&&) = delete;
    VirgilCRLProcessor& operator=(VirgilCRLProcessor const&) = delete;
    VirgilCRLProcessor& operator=(VirgilCRLProcessor &&) = delete;

    /**
     * @brief Singleton instance.
     */
    static VirgilCRLProcessor & instance();

    time_t lastCRLTime() const;
    time_t nextCRLTime() const;

    bool isCertificateRevoked(const std::string & certificateId);

private:
    VirgilCRLProcessor();
    virtual ~VirgilCRLProcessor();

    static const int kAskPeriodSec;

    std::list <std::string> m_crlIds;
    std::mutex m_crlMutex;

    std::thread m_requestThread;
    time_t m_nextActionTime;
    time_t m_lastActionTime;

    bool m_stop;

    void requestThread();
};

#endif /* VIRGIL_CRL_PROCESSOR_H */

