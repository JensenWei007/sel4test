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
};
typedef struct io_uring_sqe io_uring_sqe_t;

struct io_uring_cqe {
	uint8_t	flags;
    uint64_t	user_cookie;
    uint16_t    result;
	union {
		uint64_t    addr;
		uint64_t	splice_off_in;
	};
	uint32_t	len;
};
typedef struct io_uring_cqe io_uring_cqe_t;


struct io_uring_state {
	uint64_t 	sqes_sqt;
    uint64_t 	sqes_user;
	uint64_t	sqes_len;

    uint64_t 	cqes_sqt;
    uint64_t 	cqes_user;
	uint64_t	cqes_len;

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

static uint64_t get_cookie()
{
    static uint64_t ret = 0;
    return ret++;
}

static int user_add_sq(io_uring_state_t* state)
{
    uint64_t sqes_len = state->sqes_len;
    uint64_t tail = state->sq_user_tail;
    if (tail + 1 == sqes_len) {
        state->sq_user_tail = 0;
    } else {
        state->sq_user_tail += 1;
    }
    io_uring_sqe_t* sqes = (io_uring_sqe_t*)state->sqes_user;
    io_uring_sqe_t* sqe = &sqes[tail];
    sqe->opcode = 1;
    sqe->user_cookie = get_cookie();
    sqe->flags |= 0x1;
    return 1;
}

static int sqt_add_sq(uint64_t cookie)
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
            .cookie = cookie,
        },
    };
    int ret = sel4rpc_call(&env->rpc_client, &rpcMsg, path.root, path.capPtr, path.capDepth);
    printf("first coo: %i, result: %i\n", (int)rpcMsg.msg.net.cookie, (int)rpcMsg.msg.net.result);
}

static uint64_t sqt_get_cq(uint64_t* cookies, uint64_t cookies_len)
{
    cspacepath_t path;
    int error;
    error = vka_cspace_alloc_path(&env->vka, &path);
    RpcMessage rpcMsg = {
        .which_msg = RpcMessage_net_tag,
        .msg.net = {
            .op = 1,
            .result = 1,
            .group = 99,
            .cookie = cookie,
        },
    };
    int ret = sel4rpc_call(&env->rpc_client, &rpcMsg, path.root, path.capPtr, path.capDepth);
    for(int i = 0; i < cookies_len; i++) {
        if(cookies[i] == 0)
            break;
        uint64_t temp = cookies[i];
        cookies[i] = 0;
        return temp;
    }
    return 0;
}

static int sqt_add_cq(io_uring_state_t* state, uint64_t cookie)
{
    uint64_t cqes_len = state->cqes_len;
    uint64_t tail = state->cq_sqt_tail;
    if (tail + 1 == cqes_len) {
        state->cq_sqt_tail = 0;
    } else {
        state->cq_sqt_tail += 1;
    }
    io_uring_cqe_t* cqes = (io_uring_cqe_t*)state->cqes_sqt;
    io_uring_cqe_t* cqe = &cqes[tail];
    cqe->user_cookie = cookie;
    cqe->flags |= 0x1;
    cqe->result = 1;
    return 1;
}

static int user_thread(uint64_t state_addr)
{
    io_uring_state_t* state = (io_uring_state_t*)state_addr;
    if (!user_add_sq(state))
        return FAILURE;
    // do multiple

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
    uint64_t* cookies;
    uint64_t cookies_len = 4096 / 8;

    // Create io_uring_state_t and map
    uint64_t io_state_vaddr;
    seL4_CPtr io_state_frame;
    if (!create_iouring_sharedpage(env, &paddr, &io_state_vaddr, &io_state_frame)) {
        return FAILURE;
    }
    state = (io_uring_state_t*)io_state_vaddr;
    memset(state, 0, 4096);
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
    state->cq_len = 4096 / sizeof(io_uring_cqe_t*);

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

    // Create cqs and map
    seL4_CPtr cqs_frame;
    if (!create_iouring_sharedpage(env, &paddr, &(state->cqes_sqt), &cqs_frame)) {
        return FAILURE;
    }
    if (!map_frame(env, cqs_frame, &(state->cqes_user), &user_thread)) {
        return FAILURE;
    }
    state->cqes_len = 4096 / sizeof(io_uring_cqe_t);

    // Map cookies
    void *cookies_t;
    uintptr_t cookie = 0;
    reservation_t reserve = vspace_reserve_range_aligned(&env->vspace, 2 * BIT(12), 12, seL4_AllRights, 1, &cookies_t);
    if (vspace_map_pages_at_vaddr(&env->vspace, &env->cookies_v, &cookie, (void *)cookies_t, 1, 12, reserve))
        return false;
    cookies = (uint64_t*)cookies_t;

    // Start user_thread
    printf("================cores : %i\n", (int)env->cores);
    if (env->cores > 1)
        set_helper_affinity(env, &user_thread, 1);
    start_helper(env, &user_thread, user_thread, state_user, 0, 0, 0);

    // do cq
    io_uring_sqe_t* sqes = (io_uring_sqe_t*)state->sqes_sqt;
    while(1) {
        uint64_t sqes_len = state->sqes_len;
        uint64_t head = state->sq_sqt_head;
        io_uring_sqe_t* sqe = &sqes[head];
        if(sqe->flags & 0x1) {
            if (head + 1 == sqes_len) {
                state->sq_sqt_head = 0;
            } else {
                state->sq_sqt_head += 1;
            }
            if (!sqt_add_sq(sqe->user_cookie))
                return FAILURE;
            memset(sqe, 0, sizeof(io_uring_sqe_t));
        }
        uint64_t cookie = sqt_get_cq();
        if(cookie != 0) {
            
            break;
        }
    }

    return SUCCESS;
}
DEFINE_TEST(IOURING0001, "Test basic io uring", test_iouring, true)
