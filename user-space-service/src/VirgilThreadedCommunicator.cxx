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

#include "VirgilThreadedCommunicator.h"
#include "helpers/VirgilLog.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <iostream>
#include <cstdlib>
#include <cstring>
#include <unistd.h>

#if !defined(VIRGIL_THREADED_PROCESSING)
#define VIRGIL_THREADED_PROCESSING
#endif

VirgilThreadedCommunicator::VirgilThreadedCommunicator() :
m_sendThread(&VirgilThreadedCommunicator::sendThread, this),
m_receiveThread(&VirgilThreadedCommunicator::receiveThread, this),
m_stop(false) {
}

VirgilThreadedCommunicator::~VirgilThreadedCommunicator() {
    m_stop = true;
    m_sendCondVar.notify_all();
    m_sendThread.join();
}

bool VirgilThreadedCommunicator::reset() {
    const std::lock_guard <std::mutex> _lock(m_sendQueueMutex);
    std::queue <VirgilByteArray> empty;
    std::swap(m_sendQueue, empty);
}

bool VirgilThreadedCommunicator::send(const VirgilByteArray & cmd, int to) {
    if (!isReady() && !start()) return false;

    {
        const std::lock_guard <std::mutex> _lock(m_sendQueueMutex);
        m_sendQueue.push(cmd);
    }
    m_sendCondVar.notify_all();

    return true;
}

bool VirgilThreadedCommunicator::start() {
    const bool res(_start());
    if (res) {
        m_rcvCondVar.notify_all();
        fireReady();
    } else {
        fireNotReady();
    }
    return res;
}

void VirgilThreadedCommunicator::stop() {
    _stop();
    reset();
    fireNotReady();
}

void VirgilThreadedCommunicator::sendThread() {
    while (!m_stop) {
        std::unique_lock<std::mutex> _lock(m_condVarMutex);
        m_sendCondVar.wait_for(_lock, std::chrono::milliseconds(500), [this]() {
            const std::lock_guard <std::mutex> _lock(m_sendQueueMutex);
            return !m_sendQueue.empty();
        });

        VirgilByteArray data;
        {
            const std::lock_guard <std::mutex> _lock(m_sendQueueMutex);
            if (!m_sendQueue.empty()) {
                data = m_sendQueue.front();
                m_sendQueue.pop();
            }
        }

        if (data.empty()) continue;

        _send(-1, data);
    }
}

void VirgilThreadedCommunicator::receiveThread() {
    VirgilByteArray data;

    while (!m_stop) {
        data.clear();

        std::unique_lock<std::mutex> _lock(m_rcvCondVarMutex);
        m_rcvCondVar.wait_for(_lock, std::chrono::milliseconds(500), [this]() {
            return m_stop || isReady();
        });

        if (m_stop) break;
        if (!isReady()) continue;

        int from(-1);
        _receive(&from, data);

        if (data.empty()) {
            start();
            continue;
        }

#if 0      
        LOG("Received data (%d bytes)", data.size());
#endif
        
        // Normal receive
#if defined(VIRGIL_THREADED_PROCESSING)
        std::thread t([this, from, data]() {
            fireDataReceived(from, data);
        });
        t.detach();
#else
        fireDataReceived(from, data);
#endif
    }
}
