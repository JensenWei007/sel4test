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
    int error = sel4platsupport_new_io_ops(&env->vspace, &env->vka, &env->simple, &env->ops);
    printf("create new io, error: %i\n", error);
    error = sel4platsupport_new_arch_ops(&env->ops, &env->simple, &env->vka);
    printf("create new io ops, error: %i\n", error);
    printf("=========111111, : %i\n", (int)env->ops.io_port_ops.io_port_out_fn);
    libpci_scan(env->ops.io_port_ops);
    return SUCCESS;
}
DEFINE_TEST(E1000NET0001, "Test e1000", test_e1000, true)
