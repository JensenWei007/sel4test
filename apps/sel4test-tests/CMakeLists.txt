#
# Copyright 2017, Data61, CSIRO (ABN 41 687 119 230)
#
# SPDX-License-Identifier: BSD-2-Clause
#

cmake_minimum_required(VERSION 3.7.2)

project(sel4test-tests C CXX)

# Use arm arch source files on RISCV
set(arch ${KernelArch})
if(KernelArchRiscV)
    set(arch arm)
endif()

set_source_files_properties(src/tests/ipc.c PROPERTIES COMPILE_FLAGS "-muintr -mgeneral-regs-only -minline-all-stringops")

file(
    GLOB
        deps
        src/*.c
        src/tests/ipc.c
        src/arch/${arch}/*.c
        src/*.cxx
)

add_executable(sel4test-tests EXCLUDE_FROM_ALL ${deps})
# special handling for "arm_hyp", it's really "aarch32"
set(_inc_folder_KernelSel4Arch "${KernelSel4Arch}")
if("${KernelSel4Arch}" STREQUAL "arm_hyp")
    set(_inc_folder_KernelSel4Arch "aarch32")
endif()

target_include_directories(
    sel4test-tests
    PRIVATE include arch/${KernelArch} sel4_arch/${_inc_folder_KernelSel4Arch}
)

target_link_libraries(
    sel4test-tests
    PUBLIC
        sel4_autoconf
        muslc
        sel4
        sel4runtime
        sel4allocman
        sel4vka
        sel4utils
        sel4rpc
        sel4test
        sel4sync
        sel4muslcsys
        sel4testsupport
        sel4serialserver_tests
    PRIVATE sel4test-driver_Config
)
