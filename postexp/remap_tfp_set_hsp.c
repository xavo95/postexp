//
//  remap_tfp_set_hsp.c
//  electra
//
//  Created by Viktor Oreshkin on 16.01.18.
//  Copyright © 2018 Electra Team. All rights reserved.
//

#import "remap_tfp_set_hsp.h"

#import <stdlib.h>
#import "offsets_dump.h"
#include "kernel_utils.h"
#include "offsets.h"
#include "kmem.h"
#include "log.h"

kern_return_t mach_vm_remap(vm_map_t dst, mach_vm_address_t *dst_addr, mach_vm_size_t size, mach_vm_offset_t mask, int flags, vm_map_t src, mach_vm_address_t src_addr, boolean_t copy, vm_prot_t *cur_prot, vm_prot_t *max_prot, vm_inherit_t inherit);

uint64_t make_fake_task(uint64_t vm_map) {
    uint64_t fake_task_kaddr = kernel_alloc_wired(0x1000);
    
    void* fake_task = malloc(0x1000);
    memset(fake_task, 0, 0x1000);
    *(uint32_t*)(fake_task + _koffset(KSTRUCT_OFFSET_TASK_REF_COUNT)) = 0xd00d; // leak references
    *(uint32_t*)(fake_task + _koffset(KSTRUCT_OFFSET_TASK_ACTIVE)) = 1;
    *(uint64_t*)(fake_task + _koffset(KSTRUCT_OFFSET_TASK_VM_MAP)) = vm_map;
    *(uint8_t*)(fake_task + _koffset(KSTRUCT_OFFSET_TASK_LCK_MTX_TYPE)) = 0x22;
    kernel_memcpy(fake_task_kaddr, (uint64_t) fake_task, 0x1000);
    free(fake_task);
    
    return fake_task_kaddr;
}

#ifdef CLASSIC_FILE_STYLE

void set_all_image_info_addr(uint64_t kernel_task_kaddr, uint64_t all_image_info_addr) {
    struct task_dyld_info dyld_info = { 0 };
    mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;
    if(task_info(kernel_task_port, TASK_DYLD_INFO, (task_info_t)&dyld_info, &count) == KERN_SUCCESS) {
        INFO("Will set all_image_info_addr to: %llu", all_image_info_addr);
        if (dyld_info.all_image_info_addr != all_image_info_addr) {
            INFO("Setting all_image_info_addr...");
            kernel_write64(kernel_task_kaddr + _koffset(KSTRUCT_OFFSET_TASK_ALL_IMAGE_INFO_ADDR), all_image_info_addr);
            //        TODO: add this assertions
            //        task_info(tfp0, TASK_DYLD_INFO, (task_info_t)&dyld_info, &count) == KERN_SUCCESS,;
            //        dyld_info.all_image_info_addr == all_image_info_addr;
        } else {
            INFO("All_image_info_addr already set.");
        }
    }
}

#else

void set_all_image_info_addr(uint64_t kernel_task_kaddr) {
    struct task_dyld_info dyld_info = { 0 };
    mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;
    if(task_info(kernel_task_port, TASK_DYLD_INFO, (task_info_t)&dyld_info, &count) == KERN_SUCCESS) {
        INFO("Will save offsets to all_image_info_addr");
        if (dyld_info.all_image_info_addr && dyld_info.all_image_info_addr != kernel_load_base && dyld_info.all_image_info_addr > kernel_load_base) {
            size_t blob_size = kernel_read64_internal(dyld_info.all_image_info_addr);
            struct cache_blob *blob = create_cache_blob(blob_size);
            kernel_read_internal(dyld_info.all_image_info_addr, blob, blob_size);
            // Adds any entries that are in kernel but we don't have
            merge_cache_blob(blob);
            free(blob);
            // Free old offset cache - didn't bother comparing because it's faster to just replace it if it's the same
            kfree_internal(dyld_info.all_image_info_addr, blob_size);
        }
        struct cache_blob *cache;
        size_t cache_size = export_cache_blob(&cache);
        INFO("Setting all_image_info_addr...");
        SETOFFSET(kernel_base, kernel_load_base);
        SETOFFSET(kernel_slide, kernel_slide);
        uint64_t kernel_cache_blob = kernel_alloc_wired(cache_size);
        blob_rebase(cache, (uint64_t)cache, kernel_cache_blob);
        kernel_write_internal(kernel_cache_blob, cache, cache_size);
        free(cache);
        kernel_write64_internal(kernel_task_kaddr + _koffset(KSTRUCT_OFFSET_TASK_ALL_IMAGE_INFO_ADDR), kernel_cache_blob);
        //        TODO: add this assertions
        //        _assert(task_info(tfp0, TASK_DYLD_INFO, (task_info_t)&dyld_info, &count) == KERN_SUCCESS, message, true);
        //        _assert(dyld_info.all_image_info_addr == kernel_cache_blob, message, true);
    }
}

#endif

void set_all_image_info_size(uint64_t kernel_task_kaddr, uint64_t all_image_info_size) {
    struct task_dyld_info dyld_info = { 0 };
    mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;
    if(task_info(kernel_task_port, TASK_DYLD_INFO, (task_info_t)&dyld_info, &count) == KERN_SUCCESS) {
        INFO("Will set all_image_info_size to: %llu", all_image_info_size);
        if (dyld_info.all_image_info_size != all_image_info_size) {
            INFO("Setting all_image_info_size...");
            kernel_write64_internal(kernel_task_kaddr + _koffset(KSTRUCT_OFFSET_TASK_ALL_IMAGE_INFO_SIZE), all_image_info_size);
//          TODO: add this assertions
//          task_info(tfp0, TASK_DYLD_INFO, (task_info_t)&dyld_info, &count) == KERN_SUCCESS
//          dyld_info.all_image_info_size == all_image_info_size
        } else {
            INFO("All_image_info_size already set.");
        }
    }
}

int set_hsp4() {
    // huge thanks to Siguza for hsp4 & v0rtex
    // for explainations and being a good rubber duck :p
    
    // see https://github.com/siguza/hsp4 for some background and explaination
    // tl;dr: there's a pointer comparison in convert_port_to_task_with_exec_token
    //   which makes it return TASK_NULL when kernel_task is passed
    //   "simple" vm_remap is enough to overcome this.
    
    // However, vm_remap has weird issues with submaps -- it either doesn't remap
    // or using remapped addresses leads to panics and kittens crying.
    
    // tasks fall into zalloc, so src_map is going to be zone_map
    // zone_map works perfectly fine as out zone -- you can
    // do remap with src/dst being same and get new address
    
    // however, using kernel_map makes more sense
    // we don't want zalloc to mess with our fake task
    // and neither
    
    // proper way to use vm_* APIs from userland is via mach_vm_*
    // but those accept task ports, so we're gonna set up
    // fake task, which has zone_map as its vm_map
    // then we'll build fake task port from that
    // and finally pass that port both as src and dst
    
    // last step -- wire new kernel task -- always a good idea to wire critical
    // kernel structures like tasks (or vtables :P )
    
    // and we can write our port to realhost.special[4]
    
    // we can use mach_host_self() if we're root
    
    mach_port_t mapped_tfp0 = MACH_PORT_NULL;
    mach_port_t *port = &mapped_tfp0;
    mach_port_t host_priv = fake_host_priv();
    
    int ret;
    uint64_t remapped_task_addr = 0;
    // task is smaller than this but it works so meh
    uint64_t sizeof_task = 0x1000;
    
    uint64_t kernel_task_kaddr;
    
    {
        // find kernel task first
        kernel_task_kaddr = task_struct_of_pid_internal(0);
        
        if (kernel_task_kaddr == 0) {
            ERROR("[remap_kernel_task] failed to find kernel task");
            return 1;
        }
        
        INFO("[remap_kernel_task] kernel task at 0x%llx", kernel_task_kaddr);
    }
    
    mach_port_t zm_fake_task_port = MACH_PORT_NULL;
    mach_port_t km_fake_task_port = MACH_PORT_NULL;
    ret = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &zm_fake_task_port);
    ret = ret || mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &km_fake_task_port);
    
    if (ret == KERN_SUCCESS && *port == MACH_PORT_NULL) {
        ret = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, port);
    }
    
    if (ret != KERN_SUCCESS) {
        ERROR("[remap_kernel_task] unable to allocate ports: 0x%x (%s)", ret, mach_error_string(ret));
        return 1;
    }
    
    // strref \"Nothing being freed to the zone_map. start = end = %p\\n\"
    // or traditional \"zone_init: kmem_suballoc failed\"
    uint64_t zone_map_kptr = GETOFFSET(zone_map_ref);
    uint64_t zone_map = kernel_read64_internal(zone_map_kptr);
    
    // kernel_task->vm_map == kernel_map
    uint64_t kernel_map = kernel_read64_internal(kernel_task_kaddr + _koffset(KSTRUCT_OFFSET_TASK_VM_MAP));
    
    uint64_t zm_fake_task_kptr = make_fake_task(zone_map);
    uint64_t km_fake_task_kptr = make_fake_task(kernel_map);
    
    make_port_fake_task_port(zm_fake_task_port, zm_fake_task_kptr);
    make_port_fake_task_port(km_fake_task_port, km_fake_task_kptr);
    
    km_fake_task_port = zm_fake_task_port;
    
    vm_prot_t cur, max;
    ret = mach_vm_remap(km_fake_task_port,
                        &remapped_task_addr,
                        sizeof_task,
                        0,
                        VM_FLAGS_ANYWHERE | VM_FLAGS_RETURN_DATA_ADDR,
                        zm_fake_task_port,
                        kernel_task_kaddr,
                        0,
                        &cur, &max,
                        VM_INHERIT_NONE);
    
    
    if (ret != KERN_SUCCESS) {
        ERROR("[remap_kernel_task] remap failed: 0x%x (%s)", ret, mach_error_string(ret));
        return 1;
    }
    
    if (kernel_task_kaddr == remapped_task_addr) {
        ERROR("[remap_kernel_task] remap failure: addr is the same after remap");
        return 1;
    }
    
    INFO("[remap_kernel_task] remapped successfully to 0x%llx", remapped_task_addr);
    
    ret = mach_vm_wire(host_priv, km_fake_task_port, remapped_task_addr, sizeof_task, VM_PROT_READ | VM_PROT_WRITE);
    
    if (ret != KERN_SUCCESS) {
        ERROR("[remap_kernel_task] wire failed: 0x%x (%s)", ret, mach_error_string(ret));
        return 1;
    }
    
    uint64_t port_kaddr = find_port_address(*port);
    INFO("[remap_kernel_task] port kaddr: 0x%llx", port_kaddr);
    
    make_port_fake_task_port(*port, remapped_task_addr);
    
    if (kernel_read64_internal(port_kaddr + _koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT)) != remapped_task_addr) {
        ERROR("[remap_kernel_task] read back tfpzero kobject didnt match!");
        return 1;
    }
    
    // lck_mtx -- arm: 8  arm64: 16
    const int off_host_special = 0x10;
    uint64_t host_priv_kaddr = find_port_address(mach_host_self());
    uint64_t realhost_kaddr = kernel_read64_internal(host_priv_kaddr + _koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT));
    kernel_write64_internal(realhost_kaddr + off_host_special + 4 * sizeof(void*), port_kaddr);
#ifdef CLASSIC_FILE_STYLE
    set_all_image_info_addr(kernel_task_kaddr, kernel_base);
#else
    set_all_image_info_addr(kernel_task_kaddr);
#endif
    set_all_image_info_size(kernel_task_kaddr, kernel_slide);
    
    return 0;
}

