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

static int uintr_send(int32_t fd)
{
    printf("send: %i\n",fd);

    uint64_t ret[5] = {0, 0, 0, 0, 0};
    seL4_uintr_register_sender(fd, 0, ret);
    printf("send 2\n");
    printf("send, addr : %lx  ,  %lx  ,  %lx  ,  %lx \n", ret[1], ret[2], ret[3], ret[4]);

    _senduipi(ret[0]);
    printf("send 3\n");

    //seL4_uintr_unregister_sender(uipi_index, 0);
    printf("send 4\n");
    while(1){};
    return SUCCESS;
}

static int test_ipc_pair_uintr(env_t env, test_func_t fa, bool inter_as, seL4_Word nr_cores)
{
    int error;
    helper_thread_t thread1, thread2;

    int32_t fd = 0;
    uint64_t ret[2] = {0, 0};
    seL4_uintr_register_handler((uint64_t)uintr_handler, 0, ret);
    printf("recv, addr : %lx  ,  %lx  \n", ret[0], ret[1]);

    fd = seL4_uintr_vector_fd(0, 0);

    /* Enable interrupts */
	_stui();

    uintr_test_fd = fd;

    /* Create some threads that need mutual exclusion */
    create_helper_process(env, &thread1);
    //create_helper_thread(env, &thread2);
    set_helper_affinity(env, &thread1, 1);
    start_helper(env, &thread1, fa, fd, 0, 0, 0);

    printf("recv 3, fd: %i, uinfd: %i\n", fd, uintr_test_fd);

    while (uintr_received == 0) {};

    printf("recv 4\n");
    //seL4_uintr_unregister_handler(0);
    printf("recv 5\n");

    /* Wait for them to do their thing */
    wait_for_helper(&thread1);
    //wait_for_helper(&thread2);
    cleanup_helper(env, &thread1);
    //cleanup_helper(env, &thread2);

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
