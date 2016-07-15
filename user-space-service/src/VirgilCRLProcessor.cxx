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

#include "VirgilCRLProcessor.h"
#include "VirgilParams.h"
#include "VirgilCertificates.h"

#include "helpers/VirgilLog.h"

#include <ctime>

const int VirgilCRLProcessor::kAskPeriodSec = 10 * 60;

using namespace virgil::sdk::models;

VirgilCRLProcessor & VirgilCRLProcessor::instance() {
    static VirgilCRLProcessor myInstance;
    return myInstance;
}

VirgilCRLProcessor::VirgilCRLProcessor() :
m_requestThread(&VirgilCRLProcessor::requestThread, this),
m_nextActionTime(0),
m_lastActionTime(0),
m_stop(false) {

}

VirgilCRLProcessor::~VirgilCRLProcessor() {
    m_stop = true;
    m_requestThread.join();
}

time_t VirgilCRLProcessor::lastCRLTime() const {
    return m_lastActionTime;
}

time_t VirgilCRLProcessor::nextCRLTime() const {
    return m_nextActionTime;
}

bool VirgilCRLProcessor::isCertificateRevoked(const std::string & certificateId) {
    const std::lock_guard <std::mutex> _lock(m_crlMutex);
    return std::find(m_crlIds.begin(), m_crlIds.end(), certificateId) != m_crlIds.end();
}

void VirgilCRLProcessor::requestThread() {
    while (!m_stop) {
        if ((std::time(nullptr) - m_nextActionTime) > kAskPeriodSec) {
            m_nextActionTime = std::time(nullptr) + kAskPeriodSec;
            const CRLModel _crl(VirgilCertificates().crl());
            {
                const std::lock_guard <std::mutex> _lock(m_crlMutex);
                m_crlIds.clear();
                for (const auto crlEl : _crl.getElements()) {
                    m_crlIds.push_back(crlEl.getId());
                }
                m_lastActionTime = std::time(nullptr);
                LOG("CRL has been asked. It contains %d elements.\n", m_crlIds.size());
            }
        }

        if (m_nextActionTime > std::time(nullptr)) {
            std::this_thread::sleep_until(
                    std::chrono::system_clock::now() + std::chrono::seconds(kAskPeriodSec)
                    );
        }
    }
}
