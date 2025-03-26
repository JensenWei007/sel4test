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

#include <ethdrivers/raw.h>
#include <ethdrivers/intel.h>

#include "../helpers.h"

/*
static int init_device(ps_io_ops_t *io_ops, void *vaddr, struct eth_driver *eth_driver)
{
    // We do not use interrupt and prom mode
    printf("============1\n");
    int error = malloc(&io_ops->malloc_ops, sizeof(*eth_driver), (void **)&eth_driver);
    printf("============1\n");
    memset(eth_driver, 0, sizeof(*eth_driver));
    if (error) {
        printf("Failed to allocate struct for ethdriver\n");
        return error;
    }

    printf("============1\n");

    ethif_intel_config_t *eth_config = calloc(1, sizeof(ethif_intel_config_t) + sizeof(ps_irq_t));
    *eth_config = (ethif_intel_config_t) {
        .bar0 = vaddr,
        .prom_mode = 0,
        .num_irqs = 0
    };

    printf("============2\n");

    error = ethif_e82574_init(eth_driver, *io_ops, eth_config);
    if (error) {
        printf("ERROR init ethernet\n");
        return error;
    }

    return 0;
}
*/

static int
test_e1000(env_t env)
{
    /*
    // Get device frame and map
    seL4_CPtr cap[32];
    for (int i = 0; i < 32; i++)
        cap[i] = env->net_cap[i];
    void *vaddr_net;
    uintptr_t cookie = 0;
    reservation_t reserve = vspace_reserve_range_aligned(&env->vspace, 32 * BIT(12), 12, seL4_AllRights, 1, &vaddr_net);
    int errpr = vspace_map_pages_at_vaddr(&env->vspace, cap, &cookie, (void *)vaddr_net, 32, 12, reserve);
    printf("map, er: %i, vaddr: %lx\n", errpr, (unsigned long)vaddr_net);

    // Init and create device
    struct eth_driver *eth_driver = malloc(sizeof(struct eth_driver));
    memset(eth_driver, 0, sizeof(*eth_driver));
    printf("============1\n");
    ethif_intel_config_t *eth_config = calloc(1, sizeof(ethif_intel_config_t) + sizeof(ps_irq_t));
    *eth_config = (ethif_intel_config_t) {
        .bar0 = vaddr_net,
        .prom_mode = 0,
        .num_irqs = 0
    };
    printf("============1, addr: %lx\n", (unsigned long)env->net_ops.dma_manager.dma_alloc_fn);
    errpr = ethif_e82574_init(eth_driver, env->net_ops, eth_config);
    printf("init device, er: %i, vaddr: %lx\n", errpr, (unsigned long)vaddr_net);
    */
    struct eth_driver *eth_driver = env->eth_driver;
    printf("driver: %lx\n", (unsigned long)env->eth_driver);
    //printf("driver fn : %lx\n", (unsigned long)eth_driver->i_fn.get_mac);
    return SUCCESS;
}
DEFINE_TEST(E1000NET0001, "Test e1000", test_e1000, true)
