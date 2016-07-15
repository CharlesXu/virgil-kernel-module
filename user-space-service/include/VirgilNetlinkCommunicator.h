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
 * @file VirgilNetlinkCommunicator.h
 * @brief Communication of current service and kernel module.
 */

#ifndef VIRGIL_NETLINK_COMMUNICATOR_H
#define	VIRGIL_NETLINK_COMMUNICATOR_H

#include <stdint.h>
#include "VirgilCommand.h"
#include "VirgilThreadedCommunicator.h"

/**
 * @brief Class for communication of current service and kernel module.
 */
class VirgilNetlinkCommunicator : public VirgilThreadedCommunicator {
public:
    VirgilNetlinkCommunicator();
    virtual ~VirgilNetlinkCommunicator();

    VirgilNetlinkCommunicator(const VirgilNetlinkCommunicator&) = delete;
    VirgilNetlinkCommunicator& operator=(const VirgilNetlinkCommunicator&) = delete;

    /**
     * @brief Check is communicator ready.
     */
    virtual bool isReady() const final;

private:
    /**
     * @brief Start communication.
     */
    virtual bool _start() final;
    
    /**
     * @brief Stop communication.
     */
    virtual void _stop() final;
    
    /**
     * @brief Send prepared data.
     * @param to - ignored here
     * @param data - data array for send
     * @return true if data has been sent successfully
     */
    virtual bool _send(int to, const VirgilByteArray & data) final;
    
    /**
     * @brief Receive data.
     * @param from - ignored here
     * @param data - data array for receive
     */
    virtual bool _receive(int * from, VirgilByteArray & data) final;

    static const int kVirgilNetlink = 27; /**< Netlink protocol */

    std::mutex m_socketMutex;
    int m_socket;
};

#endif	/* VIRGIL_NETLINK_COMMUNICATOR_H */