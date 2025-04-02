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
	uint8_t	opcode;
	uint8_t	flags;
	union {
		uint64_t    addr;
		uint64_t	splice_off_in;
	};
	uint32_t	len;
	uint64_t	user_cookie;
    uint16_t    result;
};
typedef struct io_uring_sqe io_uring_sqe_t;

struct io_uring_state {
	uint64_t 	sqes_sqt;
    uint64_t 	sqes_user;
	uint64_t	sqes_len;

    uint64_t	sq_sqt;
    uint64_t	sq_user;
    uint64_t	sq_len;
    uint64_t	cq_sqt;
    uint64_t	cq_user;
    uint64_t	cq_len;

    uint64_t	sq_sqt_head;
    uint64_t	sq_user_tail;

    uint64_t	cq_sqt_tail;
    uint64_t	cq_user_head;
};
typedef struct io_uring_state io_uring_state_t;

bool create_iouring_sharedpage(env_t env, uint64_t *paddr, uint64_t *vaddr, seL4_CPtr *page_frame)
{
    seL4_CPtr frame = vka_alloc_frame_leaky(&env->vka, 12);
    seL4_ARCH_Page_GetAddress_t paddr_t = seL4_X86_Page_GetAddress(frame);
    void *vaddr_t;
    uintptr_t cookie = 0;
    reservation_t reserve = vspace_reserve_range_aligned(&env->vspace, 2 * BIT(12), 12, seL4_AllRights, 1, &vaddr_t);
    if (vspace_map_pages_at_vaddr(&env->vspace, &frame, &cookie, (void *)vaddr_t, 1, 12, reserve))
        return false;
    *paddr = paddr_t.paddr;
    *vaddr = (uint64_t)vaddr;
    *page_frame = frame;
    return true;
}

bool map_frame(env_t env, seL4_CPtr frame, uint64_t *vaddr, helper_thread_t *thread)
{
    seL4_CPtr frame_2 = get_free_slot(env);
    cnode_copy(env, frame, frame_2, seL4_AllRights);
    void *vaddr_2;
    uintptr_t cookie = 0;
    reservation_t reserve = vspace_reserve_range_aligned(&thread->process.vspace, 2 * BIT(12), 12, seL4_AllRights, 1, &vaddr_2);
    if (vspace_map_pages_at_vaddr(&thread->process.vspace, &frame_2, &cookie, (void *)vaddr_2, 1, 12, reserve))
        return false;
    *vaddr = (uint64_t)vaddr_2;
    return true;
}

static int user_thread(int32_t fd, uint64_t addr1, uint64_t addr2, uint64_t addr3)
{
    
    return SUCCESS;
}

static int
test_iouring(env_t env)
{
    /*
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
    */

    helper_thread_t user_thread;
    create_helper_process(env, &user_thread);

    // We will use
    uint64_t paddr;
    io_uring_state_t* state;
    uint64_t state_user;

    // Create io_uring_state_t and map
    uint64_t io_state_vaddr;
    seL4_CPtr io_state_frame;
    if (!create_iouring_sharedpage(env, &paddr, &io_state_vaddr, &io_state_frame)) {
        return FAILURE;
    }
    state = (io_uring_state_t*)io_state_vaddr;
    if (!map_frame(env, io_state_frame, &state_user, &user_thread)) {
        return FAILURE;
    }

    // Create cq and map
    seL4_CPtr cq_frame;
    if (!create_iouring_sharedpage(env, &paddr, &(state->cq_sqt), &cq_frame)) {
        return FAILURE;
    }
    if (!map_frame(env, cq_frame, &(state->cq_user), &user_thread)) {
        return FAILURE;
    }
    state->cq_len = 4096 / sizeof(io_uring_sqe_t*);

    // Create sq and map
    seL4_CPtr sq_frame;
    if (!create_iouring_sharedpage(env, &paddr, &(state->sq_sqt), &sq_frame)) {
        return FAILURE;
    }
    if (!map_frame(env, sq_frame, &(state->sq_user), &user_thread)) {
        return FAILURE;
    }
    state->sq_len = 4096 / sizeof(io_uring_sqe_t*);

    // Create sqs and map
    seL4_CPtr sqs_frame;
    if (!create_iouring_sharedpage(env, &paddr, &(state->sqes_sqt), &sqs_frame)) {
        return FAILURE;
    }
    if (!map_frame(env, sqs_frame, &(state->sqes_user), &user_thread)) {
        return FAILURE;
    }
    state->sqes_len = 4096 / sizeof(io_uring_sqe_t);

    return SUCCESS;
}
DEFINE_TEST(IOURING0001, "Test basic io uring", test_iouring, true)
