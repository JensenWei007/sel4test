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


static int
test_e1000(env_t env)
{
    env->vka;
    return SUCCESS;
}
DEFINE_TEST(E1000NET0001, "Test e1000", test_e1000, true)
