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
 * @file netlink.c
 * @brief Communication through NetLink.
 */

#if defined(__PC__)
#define __TASKSTATS_CMD_MAX 3
#define XFRM_POLICY_MAX 3
#endif

#include <linux/module.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>
#include <net/sock.h>

#include <virgil/kernel/private/log.h>
#include <virgil/kernel/private/netlink.h>

#define VIRGIL_NETLINK 27

static struct sock *netlink_sock = 0;
static netlink_processor_cb data_processor = 0;
static int user_space_pid = -1;

#if !defined(VIRGIL_NETLINK_DEBUG)
//#define VIRGIL_NETLINK_DEBUG
#endif

/******************************************************************************/
bool netlink_is_valid(void) {
    return (0 < user_space_pid);
}

/******************************************************************************/
static void netlink_data_ready(struct sk_buff * buffer) {
    struct nlmsghdr *nlh = NULL;
    int data_sz = -1;

    if (!buffer) {
        return;
    }

    nlh = (struct nlmsghdr *) buffer->data;

    data_sz = NLMSG_PAYLOAD(nlh, 0);

#if defined(VIRGIL_NETLINK_DEBUG)
    LOG("received netlink message payload (%d bytes) from %d", data_sz, user_space_pid);
#endif

    if (data_sz <= 0 || data_sz > (7 * 1024)) {
        //LOG("ERROR: Wrong package size. Package has been dropped.  Type : 0x%x \n", (int)nlh->nlmsg_type);
        return;
    }

    user_space_pid = nlh->nlmsg_pid;

    if (data_processor) {
        (*data_processor)(NLMSG_DATA(nlh), data_sz);
    }
}

/******************************************************************************/
void netlink_start(void) {
#if 0
    netlink_sock = netlink_kernel_create(&init_net, VIRGIL_NETLINK, 0, netlink_data_ready, NULL, THIS_MODULE);
#else
    struct netlink_kernel_cfg cfg = { .input = netlink_data_ready, };

    netlink_sock = netlink_kernel_create(&init_net, VIRGIL_NETLINK, &cfg);
#endif

    LOG("netlink start");

    if (!netlink_sock) {
        LOG("ERROR: can't create socket.");
    }
}

/******************************************************************************/
void netlink_stop(void) {
    LOG("netlink stop");
    if (netlink_sock && netlink_sock->sk_socket) {
        sock_release(netlink_sock->sk_socket);
    }
}

/******************************************************************************/
void netlink_set_processor(netlink_processor_cb processor) {
    data_processor = processor;
}

/******************************************************************************/
bool netlink_send(const void * data, __u32 data_sz) {
	struct nlmsghdr *nlh;
    struct sk_buff * skb_out;

    if (!data || !data_sz || !netlink_is_valid()) return false;

#if defined(VIRGIL_NETLINK_DEBUG)
    LOG("netlink send : %lu", (long unsigned int) data_sz);
#endif

    skb_out = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
    if (!skb_out) {
        LOG("ERROR: Can't send data (no memory)");
        return false;
    }

    nlh = nlmsg_put(skb_out, 0, 0, NLM_F_REQUEST, data_sz, 0);
    NETLINK_CB(skb_out).dst_group = 0;
    memcpy(NLMSG_DATA(nlh), data, data_sz);
    if (0 != nlmsg_unicast(netlink_sock, skb_out, user_space_pid)) {
    	LOG("Netlink Error (send)");
    	user_space_pid = -1;
    	return false;
    }
    return true;
}
