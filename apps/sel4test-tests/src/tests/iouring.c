/*
 * Copyright 2017, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <sel4/sel4.h>
#include <vka/object.h>
#include <sel4rpc/client.h>
#include <rpc.pb.h>

#include "../helpers.h"

struct io_uring_sqe {
	uint8_t	opcode;		/* type of operation for this sqe */
	uint8_t	flags;		/* IOSQE_ flags */
	union {
		uint64_t	addr;	/* pointer to buffer or iovecs */
		uint64_t	splice_off_in;
	};
	uint32_t	len;		/* buffer size or number of iovecs */
	uint16_t	user_cookie;	/* data to be passed back at completion time */
};

struct io_uring_state {
	uint64_t*	sqes;		/* type of operation for this sqe */
	uint64_t	sqes_len;		/* IOSQE_ flags */
};

static int user_thread(int32_t fd, uint64_t addr1, uint64_t addr2, uint64_t addr3)
{
    
    return SUCCESS;
}

static int
test_iouring(env_t env)
{
    cspacepath_t path;
    int error;
    error = vka_cspace_alloc_path(&env->vka, &path);
    RpcMessage rpcMsg = {
        .which_msg = RpcMessage_net_tag,
        .msg.net = {
            .op = 0,
            .result = 1,
            .group = 99,
            .cookie = 1,
        },
    };
    int ret = sel4rpc_call(&env->rpc_client, &rpcMsg, path.root, path.capPtr, path.capDepth);
    printf("first coo: %i, result: %i\n", (int)rpcMsg.msg.net.cookie, (int)rpcMsg.msg.net.result);

    RpcMessage rpcMsg1 = {
        .which_msg = RpcMessage_net_tag,
        .msg.net = {
            .op = 1,
            .result = 1,
            .group = 99,
            .cookie = 1,
        },
    };
    ret = sel4rpc_call(&env->rpc_client, &rpcMsg1, path.root, path.capPtr, path.capDepth);


    helper_thread_t sq;
    return SUCCESS;
}
DEFINE_TEST(IOURING0001, "Test basic io uring", test_iouring, true)
