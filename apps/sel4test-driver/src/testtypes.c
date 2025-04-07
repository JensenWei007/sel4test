/*
 * Copyright 2017, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

/* Include Kconfig variables. */
#include <autoconf.h>
#include <sel4test-driver/gen_config.h>

#include <sel4debug/register_dump.h>
#include <vka/capops.h>

#include "test.h"
#include "timer.h"
#include <sel4rpc/server.h>
#include <sel4nanopb/sel4nanopb.h>
#include <rpc.pb.h>
#include <pb_encode.h>
#include <pb_decode.h>
#include <ethdrivers/raw.h>
#include <ethdrivers/intel.h>
#include <sel4testsupport/testreporter.h>

uint8_t arp_packet[4096] = {
    // 以太网帧头部
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,  // 目标 MAC（广播）
    0x02, 0x00, 0x00, 0x00, 0x00, 0x01,  // 源 MAC (02:00:00:00:00:01)
    0x08, 0x06,                          // 以太网类型: ARP (0x0806)

    // ARP 头部
    0x00, 0x01,                          // 硬件类型: 以太网 (0x0001)
    0x08, 0x00,                          // 协议类型: IPv4 (0x0800)
    0x06,                                // 硬件地址长度: 6
    0x04,                                // 协议地址长度: 4
    0x00, 0x01,                          // 操作码: 请求 (0x0001)

    // 发送方地址
    0x02, 0x00, 0x00, 0x00, 0x00, 0x01,  // 发送方 MAC (02:00:00:00:00:01)
    0xC0, 0xA8, 0x01, 0x64,              // 发送方 IP (192.168.1.100)

    // 目标地址
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // 目标 MAC (未知)
    0xC0, 0xA8, 0x01, 0x01,              // 目标 IP (192.168.1.1)

    // 填充 4054 字节 (保证总长度为 4096)
};

/* Bootstrap test type. */
static inline void bootstrap_set_up_test_type(uintptr_t e)
{
    ZF_LOGD("setting up bootstrap test type");
}
static inline void bootstrap_tear_down_test_type(uintptr_t e)
{
    ZF_LOGD("tearing down bootstrap test type");
}
static inline void bootstrap_set_up(uintptr_t e)
{
    ZF_LOGD("set up bootstrap test");
}
static inline void bootstrap_tear_down(uintptr_t e)
{
    ZF_LOGD("tear down bootstrap test");
}
static inline test_result_t bootstrap_run_test(struct testcase *test, uintptr_t e)
{
    return test->function(e);
}

static DEFINE_TEST_TYPE(BOOTSTRAP, BOOTSTRAP,
                        bootstrap_set_up_test_type, bootstrap_tear_down_test_type,
                        bootstrap_set_up, bootstrap_tear_down, bootstrap_run_test);

/* Basic test type. Each test is launched as its own process. */
/* copy untyped caps into a processes cspace, return the cap range they can be found in */
static seL4_SlotRegion copy_untypeds_to_process(sel4utils_process_t *process, vka_object_t *untypeds, int num_untypeds,
                                                driver_env_t env)
{
    seL4_SlotRegion range = {0};

    for (int i = 0; i < num_untypeds; i++) {
        seL4_CPtr slot = sel4utils_copy_cap_to_process(process, &env->vka, untypeds[i].cptr);

        /* set up the cap range */
        if (i == 0) {
            range.start = slot;
        }
        range.end = slot;
    }
    assert((range.end - range.start) + 1 == num_untypeds);
    return range;
}

static void handle_timer_requests(driver_env_t env, sel4test_output_t test_output)
{

    seL4_MessageInfo_t info;
    uint64_t timeServer_ns;
    seL4_Word timeServer_timeoutType;

    switch (test_output) {

    case SEL4TEST_TIME_TIMEOUT:

        timeServer_timeoutType = seL4_GetMR(1);
        timeServer_ns = sel4utils_64_get_mr(2);

        timeout(env, timeServer_ns, timeServer_timeoutType);

        info = seL4_MessageInfo_new(seL4_Fault_NullFault, 0, 0, 1);

        seL4_SetMR(0, 0);
        api_reply(env->reply.cptr, info);
        break;

    case SEL4TEST_TIME_TIMESTAMP:
        timeServer_ns = timestamp(env);
        sel4utils_64_set_mr(1, timeServer_ns);
        info = seL4_MessageInfo_new(seL4_Fault_NullFault, 0, 0, SEL4UTILS_64_WORDS + 1);
        seL4_SetMR(0, 0);
        api_reply(env->reply.cptr, info);
        break;

    case SEL4TEST_TIME_RESET:
        timer_reset(env);
        info = seL4_MessageInfo_new(seL4_Fault_NullFault, 0, 0, 1);
        seL4_SetMR(0, 0);
        api_reply(env->reply.cptr, info);
        break;

    default:
        ZF_LOGF("Invalid time request");
        break;
    }

}

/* This function waits on:
 * Timer interrupts (from hardware)
 * Requests from tests (sel4driver acts as a server)
 * Results from sel4test/tests
 */
static int sel4test_driver_wait(driver_env_t env, struct testcase *test)
{
    seL4_MessageInfo_t info;
    sel4test_output_t test_output;
    int result = SUCCESS;
    seL4_Word badge = 0;
    sel4rpc_server_env_t rpc_server;

    sel4rpc_server_init(&rpc_server, &env->vka, sel4rpc_default_handler, env,
                        &env->reply, &env->simple);

    while (1) {
        /* wait for tests to finish or fault, receive test request or report result */
        info = api_recv(env->test_process.fault_endpoint.cptr, &badge, env->reply.cptr);
        test_output = seL4_GetMR(0);

        /* FIXME: Assumptions made at the time of writing this code:
         * 1) fault sync EP cap has a badge of 0
         * 2) notification_cap bound to sel4test-driver TCB, and has a non zero badge.
         * 3) sel4test-driver only sets up and expects timer interrupts. If, in the
         * future, other types of interrupts are to be handled, the following code would
         * be wrong, and would need refactoring.
         *
         * For now, assume it is a timer interrupt, handle it and signal any test processes
         * that might be waiting on it.
         */
        if (badge != 0) {
            assert(config_set(CONFIG_HAVE_TIMER));
        }

        if (config_set(CONFIG_HAVE_TIMER) && badge != 0) {
            /* handle timer interrupts in hardware */
            handle_timer_interrupts(env, badge);
            /* Driver does extra work to check whether timeout succeeded and signals
             * clients/tests
             */
            int error = tm_update(&env->tm);
            ZF_LOGF_IF(error, "Failed to update time manager");
            continue;
        }

        if (sel4test_isTimerRPC(test_output)) {

            if (config_set(CONFIG_HAVE_TIMER)) {
                handle_timer_requests(env, test_output);
                continue;
            } else {
                ZF_LOGF("Requesting a timer service from sel4test-driver while there is no"
                        "supported HW timer.");
            }
        } else if (test_output == SEL4TEST_PROTOBUF_RPC) {
            RpcMessage rpcMsg;
            pb_istream_t stream = pb_istream_from_IPC(1);
            bool ret = pb_decode_delimited(&stream, &RpcMessage_msg, &rpcMsg);
            if (rpcMsg.which_msg != RpcMessage_net_tag)
                sel4rpc_server_recv(&rpc_server);
            
            memset(arp_packet + 42, 0, 4054);
            uintptr_t phys[2] = {0, 0};
            uint8_t* send1 = (uint8_t*)ps_dma_alloc(&env->init->net_ops.dma_manager, 4096, 4096, 1, PS_MEM_NORMAL);
            phys[0] = ps_dma_pin(&env->init->net_ops.dma_manager, send1, 4096);
            uint8_t* send2 = (uint8_t*)ps_dma_alloc(&env->init->net_ops.dma_manager, 4096, 4096, 1, PS_MEM_NORMAL);
            phys[1] = ps_dma_pin(&env->init->net_ops.dma_manager, send2, 4096);
            unsigned int si[2] = {4096, 4096};
            int coo = 2002;
            printf("virt: %lx, phys0 : %lx, phys1: %lx\n", (unsigned long)send1 ,(unsigned long)phys[0], (unsigned long)phys[1]);
            //memset(send, 0, 4096);
            memcpy(send1, arp_packet, 4096);
            memcpy(send2, arp_packet, 4096);
            if (rpcMsg.msg.net.op == 0) {
                env->init->eth_driver->i_fn.raw_tx(env->init->eth_driver, 2, phys, si, (void *)(&coo));
            } else if (rpcMsg.msg.net.op == 1) {
                env->init->eth_driver->i_fn.raw_poll(env->init->eth_driver);
            }
            sel4rpc_net_reply(&rpc_server, 0, 9, 11);
            continue;
        }

        result = test_output;
        if (seL4_MessageInfo_get_label(info) != seL4_Fault_NullFault) {
            sel4utils_print_fault_message(info, test->name);
            printf("Register of root thread in test (may not be the thread that faulted)\n");
            sel4debug_dump_registers(env->test_process.thread.tcb.cptr);
            result = FAILURE;
        }

        if (config_set(CONFIG_HAVE_TIMER)) {
            timer_cleanup(env);
        }

        return result;
    }
}

void basic_set_up(uintptr_t e)
{
    int error;
    driver_env_t env = (driver_env_t)e;

    sel4utils_process_config_t config = process_config_default_simple(&env->simple, TESTS_APP, env->init->priority);
    config = process_config_mcp(config, seL4_MaxPrio);
    config = process_config_auth(config, simple_get_tcb(&env->simple));
    config = process_config_create_cnode(config, TEST_PROCESS_CSPACE_SIZE_BITS);
    error = sel4utils_configure_process_custom(&(env->test_process), &env->vka, &env->vspace, config);
    assert(error == 0);

    /* set up caps about the process */
    env->init->stack_pages = CONFIG_SEL4UTILS_STACK_SIZE / PAGE_SIZE_4K;
    env->init->stack = env->test_process.thread.stack_top - CONFIG_SEL4UTILS_STACK_SIZE;
    env->init->page_directory = sel4utils_copy_cap_to_process(&(env->test_process), &env->vka, env->test_process.pd.cptr);
    env->init->root_cnode = SEL4UTILS_CNODE_SLOT;
    env->init->tcb = sel4utils_copy_cap_to_process(&(env->test_process), &env->vka, env->test_process.thread.tcb.cptr);
    if (config_set(CONFIG_HAVE_TIMER)) {
        env->init->timer_ntfn = sel4utils_copy_cap_to_process(&(env->test_process), &env->vka, env->timer_notify_test.cptr);
    }

    env->init->domain = sel4utils_copy_cap_to_process(&(env->test_process), &env->vka, simple_get_init_cap(&env->simple,
                                                                                                           seL4_CapDomain));
    env->init->asid_pool = sel4utils_copy_cap_to_process(&(env->test_process), &env->vka, simple_get_init_cap(&env->simple,
                                                                                                              seL4_CapInitThreadASIDPool));
    env->init->asid_ctrl = sel4utils_copy_cap_to_process(&(env->test_process), &env->vka, simple_get_init_cap(&env->simple,
                                                                                                              seL4_CapASIDControl));
#ifdef CONFIG_IOMMU
    env->init->io_space = sel4utils_copy_cap_to_process(&(env->test_process), &env->vka, simple_get_init_cap(&env->simple,
                                                                                                             seL4_CapIOSpace));
#endif /* CONFIG_IOMMU */
#ifdef CONFIG_TK1_SMMU
    env->init->io_space_caps = arch_copy_iospace_caps_to_process(&(env->test_process), &env);
#endif
    env->init->cores = simple_get_core_count(&env->simple);
    /* copy the sched ctrl caps to the remote process */
    if (config_set(CONFIG_KERNEL_MCS)) {
        seL4_CPtr sched_ctrl = simple_get_sched_ctrl(&env->simple, 0);
        env->init->sched_ctrl = sel4utils_copy_cap_to_process(&(env->test_process), &env->vka, sched_ctrl);
        for (int i = 1; i < env->init->cores; i++) {
            sched_ctrl = simple_get_sched_ctrl(&env->simple, i);
            sel4utils_copy_cap_to_process(&(env->test_process), &env->vka, sched_ctrl);
        }
    }
#ifdef CONFIG_ALLOW_SMC_CALLS
    env->init->smc = sel4utils_copy_cap_to_process(&(env->test_process), &env->vka, simple_get_init_cap(&env->simple,
                                                                                                        seL4_CapSMC));
#endif /* CONFIG_ALLOW_SMC_CALLS */

    /* setup data about untypeds */
    env->init->untypeds = copy_untypeds_to_process(&(env->test_process), env->untypeds, env->num_untypeds, env);
    /* copy the fault endpoint - we wait on the endpoint for a message
     * or a fault to see when the test finishes */
    env->endpoint = sel4utils_copy_cap_to_process(&(env->test_process), &env->vka, env->test_process.fault_endpoint.cptr);

    /* copy the device frame, if any */
    if (env->init->device_frame_cap) {
        env->init->device_frame_cap = sel4utils_copy_cap_to_process(&(env->test_process), &env->vka, env->device_obj.cptr);
    }

    if (env->init->sq_frame_cap) {
        env->init->sq_frame_cap = sel4utils_copy_cap_to_process(&(env->test_process), &env->vka, env->init->sq_frame_cap);
    }

    /* map the cap into remote vspace */
    env->remote_vaddr = vspace_share_mem(&env->vspace, &(env->test_process).vspace, env->init, 1, PAGE_BITS_4K,
                                         seL4_AllRights, 1);
    assert(env->remote_vaddr != 0);

    /* WARNING: DO NOT COPY MORE CAPS TO THE PROCESS BEYOND THIS POINT,
     * AS THE SLOTS WILL BE CONSIDERED FREE AND OVERRIDDEN BY THE TEST PROCESS. */
    /* set up free slot range */
    env->init->cspace_size_bits = TEST_PROCESS_CSPACE_SIZE_BITS;
    if (env->init->device_frame_cap) {
        env->init->free_slots.start = env->init->device_frame_cap + 1;
    } else {
        env->init->free_slots.start = env->endpoint + 1;
    }

    for (int i = 0; i < 32; i++)
    {
        seL4_CPtr cap = env->init->net_cap[i];
        env->init->net_cap[i] = sel4utils_copy_cap_to_process(&(env->test_process), &env->vka, cap);
        //printf("before : %i, after: %i\n", (int)cap, (int)env->init->net_cap[i]);
    }
    env->init->free_slots.start = env->init->net_cap[31] + 1;

    env->init->free_slots.end = (1u << TEST_PROCESS_CSPACE_SIZE_BITS);
    assert(env->init->free_slots.start < env->init->free_slots.end);
}

test_result_t basic_run_test(struct testcase *test, uintptr_t e)
{
    int error;
    driver_env_t env = (driver_env_t)e;

    /* copy test name */
    strncpy(env->init->name, test->name, TEST_NAME_MAX);
    /* ensure string is null terminated */
    env->init->name[TEST_NAME_MAX - 1] = '\0';
#ifdef CONFIG_DEBUG_BUILD
    seL4_DebugNameThread(env->test_process.thread.tcb.cptr, env->init->name);
#endif

    /* set up args for the test process */
    seL4_Word argc = 2;
    char string_args[argc][WORD_STRING_SIZE];
    char *argv[argc];
    sel4utils_create_word_args(string_args, argv, argc, env->endpoint, env->remote_vaddr);

    /* spawn the process */
    error = sel4utils_spawn_process_v(&(env->test_process), &env->vka, &env->vspace,
                                      argc, argv, 1);
    ZF_LOGF_IF(error != 0, "Failed to start test process!");

    if (config_set(CONFIG_HAVE_TIMER)) {
        error = tm_alloc_id_at(&env->tm, TIMER_ID);
        ZF_LOGF_IF(error != 0, "Failed to alloc time id %d", TIMER_ID);
    }

    /* wait on it to finish or fault, report result */
    int result = sel4test_driver_wait(env, test);

    test_assert(result == SUCCESS);

    return result;
}

void basic_tear_down(uintptr_t e)
{
    driver_env_t env = (driver_env_t)e;
    /* unmap the env->init data frame */
    vspace_unmap_pages(&(env->test_process).vspace, env->remote_vaddr, 1, PAGE_BITS_4K, NULL);

    /* reset all the untypeds for the next test */
    for (int i = 0; i < env->num_untypeds; i++) {
        cspacepath_t path;
        vka_cspace_make_path(&env->vka, env->untypeds[i].cptr, &path);
        vka_cnode_revoke(&path);
    }

    /* destroy the process */
    sel4utils_destroy_process(&(env->test_process), &env->vka);
}

DEFINE_TEST_TYPE(BASIC, BASIC, NULL, NULL, basic_set_up, basic_tear_down, basic_run_test);

