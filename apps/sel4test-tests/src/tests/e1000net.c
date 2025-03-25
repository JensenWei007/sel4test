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
#include <pci/pci.h>

#include "../helpers.h"


static int
test_e1000(env_t env)
{
    // Scan pci to get device
    int error = sel4platsupport_new_io_ops(&env->vspace, &env->vka, &env->simple, &env->pci_inops);
    error = sel4platsupport_new_arch_ops(&env->pci_inops, &env->simple, &env->vka);
    error = sel4platsupport_new_io_ops(&env->vspace, &env->vka, &env->simple, &env->pci_outops);
    error = sel4platsupport_new_arch_ops(&env->pci_outops, &env->simple, &env->vka);
    libpci_scan(env->pci_inops.io_port_ops, env->pci_outops.io_port_ops);

    // Check the device
    libpci_device_t* net = libpci_find_device(0x8086, 0x10d3);
    if (!net)
        return FAILURE;
    
    // Map device
    uint64_t paddr = libpci_device_iocfg_get_baseaddr(&net->cfg, 0);
    uint64_t size = net->cfg.base_addr_size[0];
    uint64_t page_num = size / 4096;
    void *vaddr_net;
    uintptr_t cookie = 0;
    reservation_t reserve = vspace_reserve_range_aligned(&env->vspace, page_num * BIT(12), 12, seL4_AllRights, 1, &vaddr_net);
    seL4_CPtr frames[page_num];
    for (int i = 0; i < page_num; i++)
    {
        vka_object_t frame;
        int er = vka_alloc_frame_at(&env->vka, seL4_PageBits, paddr + i * 4096, &frame);
        printf("----i : %i, er: %i\n", i, er);
        frames[i] = frame.cptr;
    }
    int errpr = vspace_map_pages_at_vaddr(&env->vspace, frames, &cookie, (void *)vaddr_net, 32, 12, reserve);
    printf("map, er: %i\n", errpr);

    printf("=================================,paddr : %lx, size: %lx\n", (unsigned long)paddr, (unsigned long)size);
    libpci_device_iocfg_debug_print(&libpci_find_device(0x8086, 0x10d3)->cfg, true);
    printf("=================================\n");
    libpci_device_iocfg_debug_print(&libpci_find_device(0x8086, 0x10d3)->cfg, false);
    printf("=================================\n");
    //error = vka_alloc_frame_at(&env.vka, seL4_PageBits, ut_paddr, &env.device_obj);
    return SUCCESS;
}
DEFINE_TEST(E1000NET0001, "Test e1000", test_e1000, true)
