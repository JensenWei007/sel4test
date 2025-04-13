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

#include "../helpers.h"

#define FASTFN inline __attribute__((always_inline))

#ifdef CONFIG_X86_64_UINTR
#include </usr/include/clang/14/include/x86gprintrin.h>
uint64_t uintr_end;
static void __attribute__((interrupt)) uintr_handler(struct __uintr_frame *ui_frame, unsigned long long vector)
{
    uint32_t lo, hi;
    asm volatile("lfence");
    asm volatile(
        "rdtsc"
        : "=a"(lo), "=d"(hi));
    asm volatile("lfence");
    uintr_end = ((uint64_t)hi << 32ull) | (uint64_t)lo;
}
#endif

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

struct ThreadSpace
{
    int wait_for_pingpong;
    int is_done;
    uint64_t timestamp;
    seL4_CPtr ep;
#ifdef CONFIG_X86_64_UINTR
    int uintr_received;
    int fd;
    uint64_t recv_addr1;
    uint64_t recv_addr2;
    uint64_t send_addr1;
    uint64_t send_addr2;
    uint64_t send_addr3;
#endif
};
typedef struct ThreadSpace ThreadSpace_t;

typedef int (*test_func_t)(seL4_Word /* endpoint */, seL4_Word /* seed */, seL4_Word /* reply */,
                           seL4_CPtr /* extra */);

static void ThreadSpaceReset(ThreadSpace_t* t, seL4_CPtr ep)
{
    t->wait_for_pingpong = 2;
    t->is_done = 0;
    t->timestamp = 0;
    t->ep = ep;
#ifdef CONFIG_X86_64_UINTR
    t->uintr_received = 0;
    t->fd = 0;
    t->recv_addr1 = 0;
    t->recv_addr2 = 0;
    t->send_addr1 = 0;
    t->send_addr2 = 0;
    t->send_addr3 = 0;
#endif
}

static int slow_pong_fn(uint64_t space_addr)
{
    ThreadSpace_t* space = (ThreadSpace_t*)space_addr;
    seL4_MessageInfo_t info = seL4_MessageInfo_new(0, 0, 0, 0);
    seL4_CPtr ep = space->ep;

    // Wait sync
    space->wait_for_pingpong -=1;
    while (space->wait_for_pingpong) {};

    seL4_Recv(ep, NULL);
    space->timestamp = get_cycle_count();

    space->is_done = 1;
    return SUCCESS;
}

static int
test_pingpong_smp_slowpath(env_t env)
{
    // Create process
    helper_thread_t pong;
    create_helper_process(env, &pong);
    set_helper_affinity(env, &pong, 1);

    // Create and map SpacePing
    seL4_CPtr space_ping = vka_alloc_frame_leaky(&env->vka, 12);
    void *vaddr_space_ping;
    uintptr_t cookie1 = 0;
    reservation_t reserve1 = vspace_reserve_range_aligned(&env->vspace, 2 * BIT(12), 12, seL4_AllRights, 1, &vaddr_space_ping);
    int err1 = vspace_map_pages_at_vaddr(&env->vspace, &space_ping, &cookie1, (void *)vaddr_space_ping, 1, 12, reserve1);

    // Create and map SpacePong
    seL4_CPtr space_pong = vka_alloc_frame_leaky(&env->vka, 12);
    void *vaddr_space_pong;
    uintptr_t cookie3 = 0;
    reservation_t reserve3 = vspace_reserve_range_aligned(&env->vspace, 2 * BIT(12), 12, seL4_AllRights, 1, &vaddr_space_pong);
    int err3 = vspace_map_pages_at_vaddr(&env->vspace, &space_pong, &cookie3, (void *)vaddr_space_pong, 1, 12, reserve3);
    seL4_CPtr space_pong_2 = get_free_slot(env);
    cnode_copy(env, space_pong, space_pong_2, seL4_AllRights);
    void *vaddr_space_pong2;
    uintptr_t cookie4 = 0;
    reservation_t reserve4 = vspace_reserve_range_aligned(&pong.process.vspace, 2 * BIT(12), 12, seL4_AllRights, 1, &vaddr_space_pong2);
    int err4 = vspace_map_pages_at_vaddr(&pong.process.vspace, &space_pong_2, &cookie4, (void *)vaddr_space_pong2, 1, 12, reserve4);

    // Create ep to ipc
    seL4_CPtr ep = vka_alloc_endpoint_leaky(&env->vka);
    cspacepath_t path;
    vka_cspace_make_path(&env->vka, ep, &path);
    seL4_CPtr pong_ep = sel4utils_copy_path_to_process(&pong.process, path);

    // Reset ThreadSpace
    ThreadSpace_t* t1 = (ThreadSpace_t*)vaddr_space_ping;
    ThreadSpace_t* t2 = (ThreadSpace_t*)vaddr_space_pong;
    ThreadSpaceReset(t1, ep);
    ThreadSpaceReset(t2, pong_ep);

    // Start ping-pong
    start_helper(env, &pong, slow_pong_fn, (uint64_t)vaddr_space_pong2, 0, 0, 0);

    seL4_MessageInfo_t info = seL4_MessageInfo_new(0, 0, 0, 0);

    // Wait ping-pong is sync
    while (t2->wait_for_pingpong == 2) {};

    t1->timestamp = get_cycle_count();
    t2->wait_for_pingpong -= 1;

    seL4_Send(ep, info);

    // Wait ping-pong is done
    while(!t2->is_done) {};

    printf("Slowpath cycles is %lu\n", (unsigned long)t2->timestamp - t1->timestamp);

    wait_for_helper(&pong);
    cleanup_helper(env, &pong);

    return SUCCESS;
}
DEFINE_TEST(PINGPONG0001, "Test basic pingpong for slowpath", test_pingpong_smp_slowpath, CONFIG_MAX_NUM_NODES >= 3)

static int fast_ping_fn(uint64_t space_addr)
{
    ThreadSpace_t* space = (ThreadSpace_t*)space_addr;
    seL4_MessageInfo_t info = seL4_MessageInfo_new(0, 0, 0, 1);
    seL4_CPtr ep = space->ep;

    // Wait sync
    space->wait_for_pingpong -=1;
    while (space->wait_for_pingpong) {};

    space->timestamp = get_cycle_count();
    seL4_Call(ep, info);

    space->is_done = 1;
    return SUCCESS;
}

static int fast_pong_fn(uint64_t space_addr)
{
    ThreadSpace_t* space = (ThreadSpace_t*)space_addr;
    seL4_MessageInfo_t info = seL4_MessageInfo_new(0, 0, 0, 0);
    seL4_MessageInfo_t tag;
    seL4_CPtr ep = space->ep;

    // Wait sync
    space->wait_for_pingpong -=1;
    while (space->wait_for_pingpong) {};

    tag = seL4_ReplyRecv(ep, info, NULL);
    space->timestamp = get_cycle_count();

    seL4_Reply(tag);

    space->is_done = 1;
    return SUCCESS;
}

static int
test_pingpong_smp_fastpath(env_t env)
{
    // Create process
    helper_thread_t pong;
    create_helper_process(env, &pong);
    set_helper_affinity(env, &pong, 1);

    // Create and map SpacePing
    seL4_CPtr space_ping = vka_alloc_frame_leaky(&env->vka, 12);
    void *vaddr_space_ping;
    uintptr_t cookie1 = 0;
    reservation_t reserve1 = vspace_reserve_range_aligned(&env->vspace, 2 * BIT(12), 12, seL4_AllRights, 1, &vaddr_space_ping);
    int err1 = vspace_map_pages_at_vaddr(&env->vspace, &space_ping, &cookie1, (void *)vaddr_space_ping, 1, 12, reserve1);

    // Create and map SpacePong
    seL4_CPtr space_pong = vka_alloc_frame_leaky(&env->vka, 12);
    void *vaddr_space_pong;
    uintptr_t cookie3 = 0;
    reservation_t reserve3 = vspace_reserve_range_aligned(&env->vspace, 2 * BIT(12), 12, seL4_AllRights, 1, &vaddr_space_pong);
    int err3 = vspace_map_pages_at_vaddr(&env->vspace, &space_pong, &cookie3, (void *)vaddr_space_pong, 1, 12, reserve3);
    seL4_CPtr space_pong_2 = get_free_slot(env);
    cnode_copy(env, space_pong, space_pong_2, seL4_AllRights);
    void *vaddr_space_pong2;
    uintptr_t cookie4 = 0;
    reservation_t reserve4 = vspace_reserve_range_aligned(&pong.process.vspace, 2 * BIT(12), 12, seL4_AllRights, 1, &vaddr_space_pong2);
    int err4 = vspace_map_pages_at_vaddr(&pong.process.vspace, &space_pong_2, &cookie4, (void *)vaddr_space_pong2, 1, 12, reserve4);

    // Create ep to ipc
    seL4_CPtr ep = vka_alloc_endpoint_leaky(&env->vka);
    cspacepath_t path;
    vka_cspace_make_path(&env->vka, ep, &path);
    seL4_CPtr pong_ep = sel4utils_copy_path_to_process(&pong.process, path);

    // Reset ThreadSpace
    ThreadSpace_t* t1 = (ThreadSpace_t*)vaddr_space_ping;
    ThreadSpace_t* t2 = (ThreadSpace_t*)vaddr_space_pong;
    ThreadSpaceReset(t1, ep);
    ThreadSpaceReset(t2, pong_ep);

    // Start ping-pong
    start_helper(env, &pong, fast_pong_fn, (uint64_t)vaddr_space_pong2, 0, 0, 0);

    seL4_MessageInfo_t info = seL4_MessageInfo_new(0, 0, 0, 1);

    // Wait ping-pong is sync
    while (t2->wait_for_pingpong == 2) {};

    t1->timestamp = get_cycle_count();
    t2->wait_for_pingpong -= 1;

    seL4_Call(ep, info);

    // Wait ping-pong is done
    while(!t2->is_done) {};

    printf("Fastpath cycles is %lu\n", (unsigned long)t2->timestamp - t1->timestamp);

    wait_for_helper(&pong);
    cleanup_helper(env, &pong);

    return SUCCESS;
}
DEFINE_TEST(PINGPONG0002, "Test basic pingpong for fastpath", test_pingpong_smp_fastpath, CONFIG_MAX_NUM_NODES >= 3)

#ifdef CONFIG_X86_64_UINTR
static int uintr_pong_fn(uint64_t space_addr)
{
    ThreadSpace_t* space = (ThreadSpace_t*)space_addr;

    uint64_t addr1[2] = {space->recv_addr1, space->recv_addr2};
    seL4_uintr_register_handler((uint64_t)uintr_handler, 0, addr1);
    space->fd = seL4_uintr_vector_fd(0, 0);
    space->wait_for_pingpong -= 1;

	_stui();

    uintr_end = 0;

    // Wait sync
    while (space->wait_for_pingpong) {};

    while (uintr_end == 0) {};
    space->timestamp = uintr_end;
    seL4_uintr_unregister_handler(0);
    _clui();
    space->is_done = 1;
    return SUCCESS;
}

static int
test_pingpong_smp_uintr(env_t env)
{
    // Create process
    helper_thread_t pong;
    create_helper_process(env, &pong);
    set_helper_affinity(env, &pong, 1);
    //set_helper_priority(env, &pong, 255);

    // Create and map SpacePing
    seL4_CPtr space_ping = vka_alloc_frame_leaky(&env->vka, 12);
    void *vaddr_space_ping;
    uintptr_t cookie1 = 0;
    reservation_t reserve1 = vspace_reserve_range_aligned(&env->vspace, 2 * BIT(12), 12, seL4_AllRights, 1, &vaddr_space_ping);
    int err1 = vspace_map_pages_at_vaddr(&env->vspace, &space_ping, &cookie1, (void *)vaddr_space_ping, 1, 12, reserve1);

    // Create and map SpacePong
    seL4_CPtr space_pong = vka_alloc_frame_leaky(&env->vka, 12);
    void *vaddr_space_pong;
    uintptr_t cookie3 = 0;
    reservation_t reserve3 = vspace_reserve_range_aligned(&env->vspace, 2 * BIT(12), 12, seL4_AllRights, 1, &vaddr_space_pong);
    int err3 = vspace_map_pages_at_vaddr(&env->vspace, &space_pong, &cookie3, (void *)vaddr_space_pong, 1, 12, reserve3);
    seL4_CPtr space_pong_2 = get_free_slot(env);
    cnode_copy(env, space_pong, space_pong_2, seL4_AllRights);
    void *vaddr_space_pong2;
    uintptr_t cookie4 = 0;
    reservation_t reserve4 = vspace_reserve_range_aligned(&pong.process.vspace, 2 * BIT(12), 12, seL4_AllRights, 1, &vaddr_space_pong2);
    int err4 = vspace_map_pages_at_vaddr(&pong.process.vspace, &space_pong_2, &cookie4, (void *)vaddr_space_pong2, 1, 12, reserve4);

    // Create ep to ipc
    seL4_CPtr ep = vka_alloc_endpoint_leaky(&env->vka);
    cspacepath_t path;
    vka_cspace_make_path(&env->vka, ep, &path);
    seL4_CPtr pong_ep = sel4utils_copy_path_to_process(&pong.process, path);

    // Reset ThreadSpace
    ThreadSpace_t* t1 = (ThreadSpace_t*)vaddr_space_ping;
    ThreadSpace_t* t2 = (ThreadSpace_t*)vaddr_space_pong;
    ThreadSpaceReset(t1, ep);
    ThreadSpaceReset(t2, pong_ep);

    // Create and map UPID
    seL4_CPtr frame_upid = vka_alloc_frame_leaky(&env->vka, 12);
    seL4_ARCH_Page_GetAddress_t r1 = seL4_X86_Page_GetAddress(frame_upid);
    void *vaddr_upid;
    uintptr_t cookie11 = 0;
    reservation_t reserve11 = vspace_reserve_range_aligned(&pong.process.vspace, 2 * BIT(12), 12, seL4_AllRights, 1, &vaddr_upid);
    int err11 = vspace_map_pages_at_vaddr(&pong.process.vspace, &frame_upid, &cookie11, (void *)vaddr_upid, 1, 12, reserve11);
    t2->recv_addr1 = r1.paddr;
    t2->recv_addr2 = (uint64_t)vaddr_upid;

    // Create and map UITT
    seL4_CPtr frame_uitt = vka_alloc_frame_leaky(&env->vka, 12);
    seL4_ARCH_Page_GetAddress_t r2 = seL4_X86_Page_GetAddress(frame_uitt);
    void *vaddr_uitt;
    uintptr_t cookie12 = 0;
    reservation_t reserve12 = vspace_reserve_range_aligned(&env->vspace, 2 * BIT(12), 12, seL4_AllRights, 1, &vaddr_uitt);
    int err12 = vspace_map_pages_at_vaddr(&env->vspace, &frame_uitt, &cookie12, (void *)vaddr_uitt, 1, 12, reserve12);

    // map UPID
    seL4_CPtr frame_upid_2 = get_free_slot(env);
    cnode_copy(env, frame_upid, frame_upid_2, seL4_AllRights);
    void *vaddr_upid2;
    uintptr_t cookie13 = 0;
    reservation_t reserve13 = vspace_reserve_range_aligned(&env->vspace, 2 * BIT(12), 12, seL4_AllRights, 1, &vaddr_upid2);
    int err13 = vspace_map_pages_at_vaddr(&env->vspace, &frame_upid_2, &cookie13, (void *)vaddr_upid2, 1, 12, reserve13);
    t1->send_addr1 = (uint64_t)vaddr_upid2;
    t1->send_addr2 = r2.paddr;
    t1->send_addr3 = (uint64_t)vaddr_uitt;

    // Start ping-pong
    start_helper(env, &pong, uintr_pong_fn, (uint64_t)vaddr_space_pong2, 0, 0, 0);

    // Wait for fd
    while (t2->wait_for_pingpong == 2) {};
    t1->fd = t2->fd;

    uint64_t addr[3] = {t1->send_addr1, t1->send_addr2, t1->send_addr3};
    int index = seL4_uintr_register_sender(t1->fd, 0, addr);

    // Wait ping-pong is sync
    t2->wait_for_pingpong -= 1;
    t1->timestamp = get_cycle_count();
    
    _senduipi(index);
    
    // Wait ping-pong is done
    while(!t2->is_done) {};
    
    seL4_uintr_unregister_sender(index, 0);

    printf("Uintr cycles is %lu\n", (unsigned long)t2->timestamp - t1->timestamp);

    wait_for_helper(&pong);
    cleanup_helper(env, &pong);

    return SUCCESS;
}
DEFINE_TEST(PINGPONG0003, "Test basic pingpong for uintr", test_pingpong_smp_uintr, config_set(CONFIG_X86_64_UINTR) && CONFIG_MAX_NUM_NODES > 2)
#endif