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

static int
test_iouring(env_t env)
{
    cspacepath_t path;
    int error;
    error = vka_cspace_alloc_path(&env->vka, &path);
    printf("========1, error: %i\n", (int)error);
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
    printf("coo: %i, result: %i\n", (int)rpcMsg.msg.net.cookie, (int)rpcMsg.msg.net.result);
    return SUCCESS;
}
DEFINE_TEST(IOURING0001, "Test basic io uring", test_iouring, true)
