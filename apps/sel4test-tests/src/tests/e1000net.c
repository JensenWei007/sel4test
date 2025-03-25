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
    // First we scan pci to get device
    int error = sel4platsupport_new_io_ops(&env->vspace, &env->vka, &env->simple, &env->pci_inops);
    error = sel4platsupport_new_arch_ops(&env->pci_inops, &env->simple, &env->vka);
    error = sel4platsupport_new_io_ops(&env->vspace, &env->vka, &env->simple, &env->pci_outops);
    error = sel4platsupport_new_arch_ops(&env->pci_outops, &env->simple, &env->vka);
    libpci_scan(env->pci_inops.io_port_ops, env->pci_outops.io_port_ops);
    // Then we will get 82574, vendor id = 8086, device id = 10d3
    return SUCCESS;
}
DEFINE_TEST(E1000NET0001, "Test e1000", test_e1000, true)
