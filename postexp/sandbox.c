//
//  sandbox.c
//  sefebreak
//
//  Created by Xavier Perarnau on 04/02/2019.
//  Copyright © 2019 Xavier Perarnau. All rights reserved.
//

#include "sandbox.h"
#include "post-common.h"
#include "kmem.h"
#include "kernel_utils.h"
#include "offsetof.h"

uint64_t old_sandbox_slot = 0;

void save_proc_sandbox_struct(uint64_t task) {
    uint64_t cr_label = kernel_get_cr_label_for_task(task);
    old_sandbox_slot = kernel_read64_internal(cr_label + off_sandbox_slot);
}

bool unsandbox(uint64_t task) {
    uint64_t cr_label = kernel_get_cr_label_for_task(task);
    kernel_write64_internal(cr_label + off_sandbox_slot, 0);
    return (kernel_read32_internal(cr_label + off_sandbox_slot) == 0) ? true : false;
}

bool sandbox(uint64_t task) {
    uint64_t cr_label = kernel_get_cr_label_for_task(task);
    kernel_write64_internal(cr_label + off_sandbox_slot, old_sandbox_slot);
    return (kernel_read32_internal(cr_label + off_sandbox_slot) == old_sandbox_slot) ? true : false;
}

bool setcsflags(uint64_t task) {
    uint64_t proc = kernel_get_proc_for_task(task);
    uint32_t old_csflags = kernel_read32_internal(proc + off_p_csflags);
    uint32_t newflags = (old_csflags | CS_PLATFORM_BINARY | CS_INSTALLER | CS_GET_TASK_ALLOW | CS_DEBUGGED) & ~(CS_RESTRICT | CS_HARD | CS_KILL);
    kernel_write32_internal(proc + off_p_csflags, newflags);
    return (kernel_read32_internal(proc + off_p_csflags) == newflags) ? true : false;
}

void restore_csflags(uint64_t task) {
    uint64_t proc = kernel_get_proc_for_task(task);
    unplatformize(task);
    uint32_t old_csflags = kernel_read32_internal(proc + off_p_csflags);
    old_csflags = (old_csflags & ~(CS_PLATFORM_BINARY | CS_INSTALLER | CS_GET_TASK_ALLOW | CS_DEBUGGED)) & (CS_RESTRICT | CS_HARD | CS_KILL);
    kernel_write32_internal(proc + off_p_csflags, old_csflags); //patch csflags
}

void platformize(uint64_t task) {
    uint64_t proc = kernel_get_proc_for_task(task);
    uint32_t t_flags = kernel_read32_internal(task + off_t_flags);
    // add TF_PLATFORM flag, = 0x400
    t_flags |= TF_PLATFORM;
    kernel_write32_internal(task + off_t_flags, t_flags);
    uint32_t csflags = kernel_read32_internal(proc + off_p_csflags);
    //patch csflags
    csflags |= TF_PLATFORM_CS_PATCH;
    kernel_write32_internal(proc + off_p_csflags, csflags);
}

void unplatformize(uint64_t task) {
    uint64_t proc = kernel_get_proc_for_task(task);
    uint32_t t_flags = kernel_read32_internal(task + off_t_flags);
    // remove TF_PLATFORM flag, = 0x400
    t_flags &= ~(TF_PLATFORM);
    kernel_write32_internal(task + off_t_flags, t_flags);
    uint32_t csflags = kernel_read32_internal(proc + off_p_csflags);
    // unpatch csflags
    csflags &= ~(TF_PLATFORM_CS_PATCH);
    kernel_write32_internal(proc + off_p_csflags, csflags);
}

bool unsandbox_given_pid(pid_t pid) {
    uint64_t task = kernel_get_task_for_pid(pid);
    return unsandbox(task);
}

bool sandbox_given_pid(pid_t pid) {
    uint64_t task = kernel_get_task_for_pid(pid);
    return sandbox(task);
}

void platformize_given_pid(pid_t pid) {
    uint64_t task = kernel_get_task_for_pid(pid);
    platformize(task);
}

void unplatformize_given_pid(pid_t pid) {
    uint64_t task = kernel_get_task_for_pid(pid);
    unplatformize(task);
}
