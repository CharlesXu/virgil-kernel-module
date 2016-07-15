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

#ifndef VIRGIL_THREADED_COMMUNICATOR_H
#define	VIRGIL_THREADED_COMMUNICATOR_H

#include <stdint.h>
#include "signals/Signal.h"

#include <queue>
#include <mutex>
#include <thread>
#include <condition_variable>

#include <virgil/crypto/VirgilByteArray.h>

using namespace virgil::crypto;

class VirgilThreadedCommunicator {
public:
    VirgilThreadedCommunicator();
    virtual ~VirgilThreadedCommunicator();
    
    VirgilThreadedCommunicator(const VirgilThreadedCommunicator&) = delete;
    VirgilThreadedCommunicator& operator=(const VirgilThreadedCommunicator&) = delete;
    
    virtual bool reset();
    virtual bool send(const VirgilByteArray & data, int to = -1);
    
    virtual bool isReady() const = 0;
    void stop();
    
    Gallant::Signal0 <> fireReady;
    Gallant::Signal0 <> fireNotReady;
    Gallant::Signal2 <int, const VirgilByteArray &> fireDataReceived;
    
protected:
    virtual bool _start() = 0;
    virtual void _stop() = 0;
    virtual bool _send(int to, const VirgilByteArray & data) = 0;
    virtual bool _receive(int * from, VirgilByteArray & data) = 0;
    
    virtual void sendThread();
    virtual void receiveThread();

    bool start();
private:
    std::queue <VirgilByteArray> m_sendQueue;
    std::mutex m_sendQueueMutex;
    
    std::condition_variable m_sendCondVar;
    std::mutex m_condVarMutex;
    std::thread m_sendThread;
    std::thread m_receiveThread;
    
    std::condition_variable m_rcvCondVar;
    std::mutex m_rcvCondVarMutex;
    
    bool m_stop;
};

#endif	/* VIRGIL_THREADED_COMMUNICATOR_H */

