//
//  kernel_utils.h
//  sefebreak
//
//  Created by Xavier Perarnau on 02/03/2019.
//  Copyright © 2019 Xavier Perarnau All rights reserved.
//

#ifndef kernel_utils_h
#define kernel_utils_h

#include <stdio.h>
#include <stdbool.h>

#include <mach/mach.h>

/*
 * kernel_base
 *
 * Description:
 *     The static kernel base.
 */
uint64_t kernel_base = 0xFFFFFFF007004000;

/*
 * static_kernel
 *
 * Description:
 *     If kernel analyzed by patchfinder is static or not.
 */
extern bool static_kernel;

/*
 * kernel_slide
 *
 * Description:
 *     The kASLR slide.
 */
extern uint64_t kernel_slide;

/*
 * kernel_load_base
 *
 * Description:
 *     The slided kernel address.
 */
uint64_t kernel_load_base;

/*
 * task_self_addr
 *
 * Description:
 *     Get addr of task.
 */
uint64_t task_self_addr(void);

/*
 * ipc_space_kernel
 *
 * Description:
 *     Get an ipc space kernel.
 */
uint64_t ipc_space_kernel(void);

/*
 * patch_host_priv
 *
 * Description:
 *     Patch host priv.
 */
bool patch_host_priv(mach_port_t host);

/*
 * find_port_address
 *
 * Description:
 *     Find port address.
 */
uint64_t find_port_address(mach_port_name_t port);

/*
 * fake_host_priv
 *
 * Description:
 *     Fake host priv.
 */
mach_port_t fake_host_priv(void);

/*
 * kernel_alloc_wired
 *
 * Description:
 *     Allocate kernel wired memory.
 */
uint64_t kernel_alloc_wired(uint64_t size);

/*
 * kernel_memcpy
 *
 * Description:
 *     Make a memcpy into a kernel.
 */
void kernel_memcpy(uint64_t dest, uint64_t src, uint32_t length);

/*
 * task_struct_of_pid
 *
 * Description:
 *     Get tasks struc for pid.
 */
uint64_t task_struct_of_pid(pid_t pid);

/*
 * convert_port_to_task_port
 *
 * Description:
 *     Convert a port to task port.
 */
void convert_port_to_task_port(mach_port_t port, uint64_t space, uint64_t task_kaddr);

/*
 * make_port_fake_task_port
 *
 * Description:
 *     Convert a port into a fake task port.
 */
void make_port_fake_task_port(mach_port_t port, uint64_t task_kaddr);

/*
 * proc_of_pid
 *
 * Description:
 *     Get proc struct for pid.
 */
uint64_t proc_of_pid(pid_t pid);

/*
 * slide_addr
 *
 * Description:
 *     Slides the address if we are analyzing a static kernel.
 */
uint64_t slide_addr(uint64_t src_addr);

/*
 * verify_tfp0
 *
 * Description:
 *     Verifies if we have a valid tfp0.
 */
bool verify_tfp0(void);

/*
 * find_kernel_base
 *
 * Description:
 *     Finds the kernel base.
 */
uint64_t find_kernel_base();

/*
 * get_address_of_port
 *
 * Description:
 *     Gets address of port.
 */
uint64_t get_address_of_port(pid_t pid, mach_port_t port);

#endif /* kernel_utils_h */
