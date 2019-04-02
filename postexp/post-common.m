//
//  post-common.c
//  sefebreak
//
//  Created by Xavier Perarnau on 04/02/2019.
//  Copyright © 2019 Xavier Perarnau All rights reserved.
//

#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonDigest.h>
#import <UIKit/UIKit.h>

#include "post-common.h"
#include "kmem.h"
#include "offsets.h"
#include "offsetof.h"
#include "mach_vm.h"
#include "log.h"
#include "amfi_utils.h"
#include "kernel_utils.h"

uint64_t kernel_get_task_for_pid(pid_t pid) {
    uint64_t proc = proc_of_pid(pid);
    return kernel_read64(proc + off_task);
}

uint64_t kernel_get_proc_for_task(uint64_t task) {
    return kernel_read64(task + _koffset(KSTRUCT_OFFSET_TASK_BSD_INFO));
}

uint64_t kernel_get_ucred_for_task(uint64_t task) {
    uint64_t proc_self = kernel_get_proc_for_task(task);
    return kernel_read64(proc_self + off_p_ucred);
}

uint64_t kernel_get_cr_label_for_task(uint64_t task) {
    uint64_t ucred = kernel_get_ucred_for_task(task);
    return kernel_read64(ucred + off_ucred_cr_label);
}

bool entitle_pid(uint64_t task, const char *ent, bool val) {
    if (!task) return false;
    
    uint64_t proc = kernel_get_proc_for_task(task);
    uint64_t ucred = kernel_read64(proc + off_p_ucred);
    uint64_t cr_label = kernel_read64(ucred + off_ucred_cr_label);
    uint64_t entitlements = kernel_read64(cr_label + off_amfi_slot);
    
    //    TODO: Generate osobject from XNU SOurce
//    if (OSDictionary_GetItem(entitlements, ent) == 0) {
//        INFO("setting Entitlements...\n");
//        uint64_t entval = OSDictionary_GetItem(entitlements, ent);
//
//        INFO("before: %s is 0x%llx\n", ent, entval);
//        OSDictionary_SetItem(entitlements, ent, (val) ? Find_OSBoolean_True() : Find_OSBoolean_False());
//
//        entval = OSDictionary_GetItem(entitlements, ent);
//        INFO("after: %s is 0x%llx\n", ent, entval);
//
//        return (entval) ? YES : NO;
//    }
    return true;
}
