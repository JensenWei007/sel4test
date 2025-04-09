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

#include </usr/include/clang/14/include/x86gprintrin.h>

#define COMP 7*100000
#define COMP_SIZE 100

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

struct io_uring_sqes {
    io_uring_sqe_t sqes[100];
};
typedef struct io_uring_sqes io_uring_sqes_t;

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

struct io_uring_cqes {
    io_uring_cqe_t cqes[100];
};
typedef struct io_uring_cqes io_uring_cqes_t;

struct io_uring_state {
    uint64_t    state_user;

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

    uint64_t    uintr_upid_paddr;
    uint64_t    uintr_upid_vaddr;

    uint64_t    uintr_fd[10];
    uint64_t    uintr_fd_valid[10];
};
typedef struct io_uring_state io_uring_state_t;

uint64_t state_addr_uintr;
uint64_t io_isdown;

#define FASTFN inline __attribute__((always_inline))

static FASTFN void private_lfence()
{
    asm volatile("lfence");
}

static FASTFN uint64_t private_rdtsc()
{
    uint32_t lo, hi;
    asm volatile(
        "rdtsc"
        : "=a"(lo), "=d"(hi));
    return (((uint64_t)hi << 32ull) | (uint64_t)lo);
}

static FASTFN uint64_t get_cycle_count()
{
    private_lfence(); /* Serialise all preceding instructions */
    uint64_t time = private_rdtsc();
    private_lfence(); /* Serialise all following instructions */
    return time;
}

bool compute(uint64_t size){
    uint64_t x = 2;
    for(unsigned long i = 1; i < COMP * size; i++) {
        x *= i;
    }
    return 1;
}

bool create_iouring_sharedpage(env_t env, uint64_t *paddr, uint64_t *vaddr, seL4_CPtr *page_frame)
{
    seL4_CPtr frame = vka_alloc_frame_leaky(&env->vka, 12);
    seL4_ARCH_Page_GetAddress_t paddr_t = seL4_X86_Page_GetAddress(frame);
    void *vaddr_t1;
    uintptr_t cookie = 0;
    reservation_t reserve = vspace_reserve_range_aligned(&env->vspace, 2 * BIT(12), 12, seL4_AllRights, 1, &vaddr_t1);
    if (vspace_map_pages_at_vaddr(&env->vspace, &frame, &cookie, (void *)vaddr_t1, 1, 12, reserve))
        return false;
    *paddr = paddr_t.paddr;
    *vaddr = (uint64_t)vaddr_t1;
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
    io_uring_sqes_t* sqes = (io_uring_sqes_t*)state->sqes_user;
    sqes->sqes[tail].opcode = 1;
    sqes->sqes[tail].user_cookie = get_cookie();
    sqes->sqes[tail].flags |= 0x1;
    return 1;
}

static int sqt_add_sq(env_t env, uint64_t cookie)
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
    return 1;
}

static uint64_t sqt_get_cq(env_t env, uint64_t* cookies, uint64_t cookies_len)
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
            .cookie = 0,
        },
    };
    int ret = sel4rpc_call(&env->rpc_client, &rpcMsg, path.root, path.capPtr, path.capDepth);
    for(int i = 0; i < cookies_len; i++) {
        if(cookies[i] != 0) {
            uint64_t temp = cookies[i];
            cookies[i] = 0;
            return temp;
        }
    }
    return 0;
}

static int user_get_cq(io_uring_state_t* state, uint64_t* cookie)
{
    io_uring_cqe_t* cqes = (io_uring_cqe_t*)state->cqes_user;
    uint64_t cqes_len = state->cqes_len;
    uint64_t head = state->cq_user_head;
    io_uring_cqe_t* cqe = &cqes[head];
    if(cqe->flags & 0x1) {
        if (head + 1 == cqes_len) {
            state->cq_user_head = 0;
        } else {
            state->cq_user_head += 1;
        }
        *cookie = cqe->user_cookie;
        memset(cqe, 0, sizeof(io_uring_cqe_t));
        return 1;
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

static int user_thread_func(uint64_t state_addr)
{
    io_uring_state_t* state = (io_uring_state_t*)state_addr;

    if (!user_add_sq(state))
        return FAILURE;
    
    // do multiple
    uint64_t cookie = 0;
    while(!user_get_cq(state, &cookie)) {
        compute(COMP_SIZE);
    };

    return SUCCESS;
}

static void __attribute__((interrupt)) uintr_handler(struct __uintr_frame *ui_frame, unsigned long long vector)
{
    printf("========== UINTR HANDLER START ==========\n");
    io_uring_state_t* state = (io_uring_state_t*)state_addr_uintr;
    uint64_t cookie = 0;
    if(!user_get_cq(state, &cookie))
        printf("== Error, uintr hasnot cq ==\n");
    io_isdown = 1;
    printf("=========== UINTR HANDLER END ===========\n");
}

static int user_thread_func_uintr(uint64_t state_addr)
{
    state_addr_uintr = state_addr;
    io_isdown = 0;
    io_uring_state_t* state = (io_uring_state_t*)state_addr;

    uint64_t addr[2] = {state->uintr_upid_paddr, state->uintr_upid_vaddr};
    seL4_uintr_register_handler((uint64_t)uintr_handler, 0, addr);

    state->uintr_fd[0] = seL4_uintr_vector_fd(0, 0);
    state->uintr_fd_valid[0] = 1;

	_stui();

    if (!user_add_sq(state))
        return FAILURE;

    // do multiple
    while(!io_isdown) {
        compute(COMP_SIZE);
    };

    seL4_uintr_unregister_handler(0);
    _clui();

    return SUCCESS;
}

static int
test_io(env_t env)
{
    uint64_t cookie = 0;

    // Map cookies
    void *cookies_vaddr;
    uint64_t* cookies;
    uintptr_t cookie1 = 0;
    reservation_t reserve = vspace_reserve_range_aligned(&env->vspace, 2 * BIT(12), 12, seL4_AllRights, 1, &cookies_vaddr);
    if (vspace_map_pages_at_vaddr(&env->vspace, &env->cookies_v, &cookie1, (void *)cookies_vaddr, 1, 12, reserve))
        return false;
    cookies = (uint64_t*)cookies_vaddr;

    uint64_t compute_start = get_cycle_count();
    compute(COMP_SIZE);
    uint64_t compute_end = get_cycle_count();
    printf("== Compute cycles: %lu ==\n", (unsigned long)(compute_end - compute_start));
    
    uint64_t io_start = get_cycle_count();
    sqt_add_sq(env, &cookie);
    while(!sqt_get_cq(env, cookies_vaddr, 4096 / 8)) {};
    uint64_t io_end = get_cycle_count();
    printf("== IO cycles: %lu ==\n", (unsigned long)(io_end - io_start));

    uint64_t all_start = get_cycle_count();
    sqt_add_sq(env, &cookie);
    while(!sqt_get_cq(env, cookies_vaddr, 4096 / 8)) {};
    compute(COMP_SIZE);
    uint64_t all_end = get_cycle_count();
    printf("== ALL cycles: %lu ==\n", (unsigned long)(all_end - all_start));

    return SUCCESS;
}
DEFINE_TEST(IOURING0001, "Test basic io", test_io, true)

static int
test_iouring(env_t env)
{
    helper_thread_t user_thread;
    create_helper_process(env, &user_thread);

    // We will use
    uint64_t paddr;
    io_uring_state_t* state;
    uint64_t* cookies;
    uint64_t cookies_len = 4096 / 8;

    // Create io_uring_state_t and map
    uint64_t io_state_vaddr;
    seL4_CPtr io_state_frame;
    if (!create_iouring_sharedpage(env, &paddr, &io_state_vaddr, &io_state_frame)) {
        return FAILURE;
    }
    state = (io_uring_state_t*)io_state_vaddr;
    //memset(state, 0, 4096);
    if (!map_frame(env, io_state_frame, &(state->state_user), &user_thread)) {
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
    void *cookies_vaddr;
    uintptr_t cookie = 0;
    reservation_t reserve = vspace_reserve_range_aligned(&env->vspace, 2 * BIT(12), 12, seL4_AllRights, 1, &cookies_vaddr);
    if (vspace_map_pages_at_vaddr(&env->vspace, &env->cookies_v, &cookie, (void *)cookies_vaddr, 1, 12, reserve))
        return false;
    cookies = (uint64_t*)cookies_vaddr;

    // Start user_thread
    //printf("================cores : %i, user: %lx\n", (int)env->cores, (unsigned long)state->state_user);
    if (env->cores > 1)
        set_helper_affinity(env, &user_thread, 1);
    start_helper(env, &user_thread, user_thread_func, state->state_user, 0, 0, 0);

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
            if (!sqt_add_sq(env, sqe->user_cookie))
                return FAILURE;
            memset(sqe, 0, sizeof(io_uring_sqe_t));
        }
        uint64_t cookie = sqt_get_cq(env, cookies_vaddr, 4096 / 8);
        if(cookie != 0) {
            sqt_add_cq(state, cookie);
            break;
        }
    }
    
    wait_for_helper(&user_thread);
    return SUCCESS;
}
DEFINE_TEST(IOURING0002, "Test basic io uring", test_iouring, true)

static int
test_iouring_uintr(env_t env)
{
    helper_thread_t user_thread;
    create_helper_process(env, &user_thread);

    // We will use
    uint64_t paddr;
    io_uring_state_t* state;
    uint64_t* cookies;
    uint64_t cookies_len = 4096 / 8;

    // Create io_uring_state_t and map
    uint64_t io_state_vaddr;
    seL4_CPtr io_state_frame;
    if (!create_iouring_sharedpage(env, &paddr, &io_state_vaddr, &io_state_frame)) {
        return FAILURE;
    }
    state = (io_uring_state_t*)io_state_vaddr;
    //memset(state, 0, 4096);
    if (!map_frame(env, io_state_frame, &(state->state_user), &user_thread)) {
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
    void *cookies_vaddr;
    uintptr_t cookie = 0;
    reservation_t reserve = vspace_reserve_range_aligned(&env->vspace, 2 * BIT(12), 12, seL4_AllRights, 1, &cookies_vaddr);
    if (vspace_map_pages_at_vaddr(&env->vspace, &env->cookies_v, &cookie, (void *)cookies_vaddr, 1, 12, reserve))
        return false;
    cookies = (uint64_t*)cookies_vaddr;

    // Create UITT
    seL4_CPtr frame_uitt;
    uint64_t uitt_sender_paddr;
    uint64_t uitt_sender_vaddr;
    if (!create_iouring_sharedpage(env, &uitt_sender_paddr, &uitt_sender_vaddr, &frame_uitt)) {
        return FAILURE;
    }

    // Create and map UPID
    seL4_CPtr frame_upid;
    uint64_t upid_sender_vaddr;
    if (!create_iouring_sharedpage(env, &(state->uintr_upid_paddr), &upid_sender_vaddr, &frame_upid)) {
        return FAILURE;
    }
    if (!map_frame(env, frame_upid, &(state->uintr_upid_vaddr), &user_thread)) {
        return FAILURE;
    }

    // Start user_thread
    //printf("================cores : %i, user: %lx\n", (int)env->cores, (unsigned long)state->state_user);
    if (env->cores > 1)
        set_helper_affinity(env, &user_thread, 1);
    start_helper(env, &user_thread, user_thread_func_uintr, state->state_user, 0, 0, 0);

    // Wait for uintr_fd and register
    while(!state->uintr_fd_valid[0]) {};
    uint64_t addr[3] = {upid_sender_vaddr, uitt_sender_paddr, uitt_sender_vaddr};
    int index = seL4_uintr_register_sender(state->uintr_fd[0], 0, addr);

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
            if (!sqt_add_sq(env, sqe->user_cookie))
                return FAILURE;
            memset(sqe, 0, sizeof(io_uring_sqe_t));
        }
        uint64_t cookie = sqt_get_cq(env, cookies_vaddr, 4096 / 8);
        if(cookie != 0) {
            sqt_add_cq(state, cookie);
            _senduipi(index);
            break;
        }
    }
    
    wait_for_helper(&user_thread);

    seL4_uintr_unregister_sender(index, 0);
    return SUCCESS;
}
DEFINE_TEST(IOURING0003, "Test basic io uring with uintr", test_iouring_uintr, true)
