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

#include "VirgilNetlinkCommunicator.h"
#include "helpers/VirgilLog.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <iostream>
#include <cstdlib>
#include <cstring>
#include <unistd.h>

VirgilNetlinkCommunicator::VirgilNetlinkCommunicator() : m_socket(-1) {
}

VirgilNetlinkCommunicator::~VirgilNetlinkCommunicator() {
    
}

bool VirgilNetlinkCommunicator::_start() {
    const std::lock_guard <std::mutex> _lock(m_socketMutex);

    if (m_socket > 0) {
        close(m_socket);
    }
    reset();

    m_socket = socket(AF_NETLINK, SOCK_RAW, VirgilNetlinkCommunicator::kVirgilNetlink);

    /* source address */
    struct sockaddr_nl s_nladdr;
    memset(&s_nladdr, 0, sizeof (s_nladdr));
    s_nladdr.nl_family = AF_NETLINK;
    s_nladdr.nl_pad = 0;
    s_nladdr.nl_pid = getpid();

    const bool res(0 == bind(m_socket, (struct sockaddr*) &s_nladdr, sizeof (s_nladdr)));

    return res;
}

void VirgilNetlinkCommunicator::_stop() {
    const std::lock_guard <std::mutex> _lock(m_socketMutex);
    if (m_socket > 0) {
        close(m_socket);
    }
    m_socket = -1;
}

bool VirgilNetlinkCommunicator::isReady() const {
    return m_socket >= 0;
}

bool VirgilNetlinkCommunicator::_receive(int * from, VirgilByteArray & data) {
    #define MAX_PAYLOAD (1024 * 1024)

    static char buffer[MAX_PAYLOAD];

    static struct nlmsghdr * nlh = reinterpret_cast<struct nlmsghdr *> (buffer);
    static struct sockaddr_nl nladdr;
    static struct msghdr msg;
    static struct iovec iov;

    memset(buffer, 0, MAX_PAYLOAD);
    memset(&nladdr, 0, sizeof (struct sockaddr_nl));
    memset(&msg, 0, sizeof (struct msghdr));
    memset(&iov, 0, sizeof (struct iovec));

    iov.iov_base = (void *) nlh;
    iov.iov_len = MAX_PAYLOAD;
    msg.msg_name = (void *) &(nladdr);
    msg.msg_namelen = sizeof (nladdr);

    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    
    data.clear();

    if (0 >= recvmsg(m_socket, &msg, 0)) {
        return false;
    }

    data.assign(reinterpret_cast<char *> (NLMSG_DATA(nlh)), reinterpret_cast<char *> (NLMSG_DATA(nlh) + NLMSG_PAYLOAD(nlh, 0)));

    return true;
}

bool VirgilNetlinkCommunicator::_send(int to, const VirgilByteArray & data) {
    /* destination address */
    struct sockaddr_nl s_nladdr, d_nladdr;
    memset(&d_nladdr, 0, sizeof (d_nladdr));
    d_nladdr.nl_family = AF_NETLINK;
    d_nladdr.nl_pad = 0;
    d_nladdr.nl_pid = 0; /* destined to kernel */

    /* Fill the netlink message header */
    const size_t _sz(sizeof (struct nlmsghdr) + data.size());
    struct nlmsghdr * nlh = (struct nlmsghdr *) malloc(_sz);
    memset(nlh, 0, _sz);
    memcpy(NLMSG_DATA(nlh), data.data(), data.size());
    nlh->nlmsg_len = _sz;
    nlh->nlmsg_pid = getpid();
    nlh->nlmsg_flags = 1;
    nlh->nlmsg_type = 0;

    /*iov structure */
    struct iovec iov;
    iov.iov_base = (void *) nlh;
    iov.iov_len = nlh->nlmsg_len;

    /* msg */
    struct msghdr msg;
    memset(&msg, 0, sizeof (msg));
    msg.msg_name = (void *) &d_nladdr;
    msg.msg_namelen = sizeof (d_nladdr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    sendmsg(m_socket, &msg, 0);

    return true;
}
