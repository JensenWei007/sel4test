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

#ifdef CONFIG_X86_64_UINTR
#include </usr/include/clang/14/include/x86gprintrin.h>

typedef int (*test_func_t)(seL4_Word /* endpoint */, seL4_Word /* seed */, seL4_Word /* reply */,
                           seL4_CPtr /* extra */);

unsigned int uintr_received;
int32_t uintr_test_fd;

static void __attribute__((interrupt)) uintr_handler(struct __uintr_frame *ui_frame, unsigned long long vector)
{
    printf("handel\n");
    uintr_received = 1;
}

static int uintr_send(int32_t fd, uint64_t addr1, uint64_t addr2, uint64_t addr3)
{
    printf("send: %i\n",fd);

    uint64_t addr[3] = {addr1, addr2, addr3};
    printf("send, addr : %lx\n",addr[3]);
    int index = seL4_uintr_register_sender(fd, 0, addr);
    printf("send 2\n");

    _senduipi(index);
    printf("send 3\n");

    //seL4_uintr_unregister_sender(uipi_index, 0);
    printf("send 4\n");
    while(1){};
    return SUCCESS;
}

static int test_ipc_pair_uintr(env_t env, test_func_t fa, bool inter_as, seL4_Word nr_cores)
{
    int error;
    helper_thread_t thread1;

    int32_t fd = 0;

    // Create and map UPID
    seL4_CPtr frame_upid = vka_alloc_frame_leaky(&env->vka, 12);
    seL4_ARCH_Page_GetAddress_t r1 = seL4_X86_Page_GetAddress(frame_upid);
    void *vaddr_upid;
    uintptr_t cookie1 = 0;
    reservation_t reserve1 = vspace_reserve_range_aligned(&env->vspace, 2 * BIT(12), 12, seL4_AllRights, 1, &vaddr_upid);
    int err1 = vspace_map_pages_at_vaddr(&env->vspace, &frame_upid, &cookie1, (void *)vaddr_upid, 1, 12, reserve1);

    uint64_t addr1[2] = {r1.paddr, (uint64_t)vaddr_upid};
    seL4_uintr_register_handler((uint64_t)uintr_handler, 0, addr1);

    fd = seL4_uintr_vector_fd(0, 0);

    /* Enable interrupts */
	_stui();

    uintr_test_fd = fd;

    /* Create some threads that need mutual exclusion */
    create_helper_process(env, &thread1);
    set_helper_affinity(env, &thread1, 1);

    printf("map 111\n");
    // Create and map UITT
    seL4_CPtr frame_uitt = vka_alloc_frame_leaky(&env->vka, 12);
    seL4_ARCH_Page_GetAddress_t r2 = seL4_X86_Page_GetAddress(frame_uitt);
    void *vaddr_uitt;
    uintptr_t cookie2 = 0;
    reservation_t reserve2 = vspace_reserve_range_aligned(&thread1.process.vspace, 2 * BIT(12), 12, seL4_AllRights, 1, &vaddr_uitt);
    int err2 = vspace_map_pages_at_vaddr(&thread1.process.vspace, &frame_uitt, &cookie2, (void *)vaddr_uitt, 1, 12, reserve2);

    printf("map 222, p1 : %lx, v1: %lx, p2: %lx, v2: %lx\n", r1.paddr, (uint64_t)vaddr_upid, r2.paddr, (uint64_t)vaddr_uitt);
    // map UPID
    // 只要下面的map上就行了
    void *vaddr_upid2;
    uintptr_t cookie3 = 0;
    reservation_t reserve3 = vspace_reserve_range_aligned(&thread1.process.vspace, 2 * BIT(12), 12, seL4_AllRights, 1, &vaddr_upid2);
    int err3 = vspace_map_pages_at_vaddr(&thread1.process.vspace, &frame_upid, &cookie3, (void *)vaddr_upid2, 1, 12, reserve3);

    //printf("============ frame pyh addr : %lx vaddr : %lx, err :%i\n", r1.paddr, (unsigned long)vaddr,err);
    start_helper(env, &thread1, fa, fd, (uint64_t)vaddr_upid, r2.paddr, (uint64_t)vaddr_uitt);

    printf("recv 3, fd: %i, uinfd: %i\n", fd, uintr_test_fd);

    while (uintr_received == 0) {};

    printf("recv 4\n");
    //seL4_uintr_unregister_handler(0);
    printf("recv 5\n");

    /* Wait for them to do their thing */
    wait_for_helper(&thread1);
    cleanup_helper(env, &thread1);

    return SUCCESS;
}

static int
test_uintr_base(env_t env)
{
    uintr_received = 0;
    uintr_test_fd = -1;
    printf("===========WJX_uintr  start\n");
    return test_ipc_pair_uintr(env, uintr_send, false, env->cores);
}
DEFINE_TEST(UINTR0001, "Test uintr for basic send&recv", test_uintr_base, true)
#endif
