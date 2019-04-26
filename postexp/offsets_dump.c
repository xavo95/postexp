//
//  offsets_dump.c
//  sefebreak
//
//  Created by Jake James on 8/29/18.
//  Copyright © 2018 Jake James. All rights reserved.
//

#include "offsets_dump.h"
#include <sys/fcntl.h>
#include <unistd.h>
#include <stdbool.h>
#include "kernel_utils.h"
#include "kmem.h"
typedef bool BOOL;

#include <mach/mach.h>
#include "patchfinder64.h"

#ifdef CLASSIC_FILE_STYLE

void set_cached_offsets(double kCFCoreFoundationVersionNumber) {
    cached_offsets.allproc = slide_addr(find_allproc());
    if (!auth_ptrs) {
        cached_offsets.add_x0_x0_0x40_ret = slide_addr(find_add_x0_x0_0x40_ret());
    }
    cached_offsets.OSBooleanTrue = slide_addr(find_OSBoolean_True());
    cached_offsets.OSBooleanFalse = cached_offsets.OSBooleanTrue + sizeof(void *);
    cached_offsets.OSUnserializeXML = slide_addr(find_osunserializexml());
    cached_offsets.smalloc = slide_addr(find_smalloc());
    cached_offsets.zone_map_ref = slide_addr(find_zone_map_ref());
    
    ///////////////////// TODO: SLIDE OR NOT ?? /////////////////////
    cached_offsets.vfs_context = slide_addr(find_symbol("_vfs_context_current"));
    if (!cached_offsets.vfs_context) cached_offsets.vfs_context = find_vfs_context_current();
    
    cached_offsets.vnode_lookup = slide_addr(find_symbol("_vnode_lookup"));
    if (!cached_offsets.vnode_lookup) cached_offsets.vnode_lookup = find_vnode_lookup();
    
    cached_offsets.vnode_put = find_symbol("_vnode_put");
    if (!cached_offsets.vnode_put) cached_offsets.vnode_put = find_vnode_put();
    ///////////////////// TODO: SLIDE OR NOT ?? /////////////////////
    
    cached_offsets.kernel_task = slide_addr(find_kernel_task());
    cached_offsets.shenanigans = slide_addr(find_shenanigans());
    cached_offsets.lck_mtx_lock = slide_addr(find_lck_mtx_lock());
    cached_offsets.lck_mtx_unlock = slide_addr(find_lck_mtx_unlock());
    if (kCFCoreFoundationVersionNumber >= 1535.12) {
        cached_offsets.vnode_get_snapshot = slide_addr(find_vnode_get_snapshot());
        cached_offsets.fs_lookup_snapshot_metadata_by_name_and_return_name = slide_addr(find_fs_lookup_snapshot_metadata_by_name_and_return_name());
        cached_offsets.apfs_jhash_getvnode = slide_addr(find_apfs_jhash_getvnode());
    }
    
    cached_offsets.trustcache = slide_addr(find_trustcache());
    if (auth_ptrs) {
        cached_offsets.f_load_trust_cache = slide_addr(find_pmap_load_trust_cache());
        cached_offsets.paciza_pointer__l2tp_domain_module_start = slide_addr(find_paciza_pointer__l2tp_domain_module_start());
        cached_offsets.paciza_pointer__l2tp_domain_module_stop = slide_addr(find_paciza_pointer__l2tp_domain_module_stop());
        cached_offsets.l2tp_domain_inited = slide_addr(find_l2tp_domain_inited());
        cached_offsets.sysctl__net_ppp_l2tp = slide_addr(find_sysctl__net_ppp_l2tp());
        cached_offsets.sysctl_unregister_oid = slide_addr(find_sysctl_unregister_oid());
        cached_offsets.mov_x0_x4__br_x5 = slide_addr(find_mov_x0_x4__br_x5());
        cached_offsets.mov_x9_x0__br_x1 = slide_addr(find_mov_x9_x0__br_x1());
        cached_offsets.mov_x10_x3__br_x6 = slide_addr(find_mov_x10_x3__br_x6());
        cached_offsets.kernel_forge_pacia_gadget = slide_addr(find_kernel_forge_pacia_gadget());
        cached_offsets.kernel_forge_pacda_gadget = slide_addr(find_kernel_forge_pacda_gadget());
        cached_offsets.IOUserClient__vtable = slide_addr(find_IOUserClient__vtable());
        cached_offsets.IORegistryEntry__getRegistryEntryID = slide_addr(find_IORegistryEntry__getRegistryEntryID());
    }
}

int dump_offsets_to_file(char *file) {
    int fd = open(file, O_RDONLY);
    if (fd >= 0) {
        unlink(file);
        close(fd);
    }
    
    FILE *f = fopen(file, "wb");
    fwrite(&cached_offsets, sizeof(struct patchfinder_offsets), 1, f);
    fclose(f);
    
    fd = open(file, O_RDONLY);
    
    return (fd < 0);
}

#else

void set_cached_offsets(double kCFCoreFoundationVersionNumber) {
    SETOFFSET(kernel_slide, kernel_slide);
    SETOFFSET(kernel_load_base, kernel_slide);
    SETOFFSET(allproc, slide_addr(find_allproc()));
    SETOFFSET(kernproc, slide_addr(find_kernproc()));
    if (!auth_ptrs) {
        SETOFFSET(add_x0_x0_0x40_ret, slide_addr(find_add_x0_x0_0x40_ret()));
    }
    SETOFFSET(OSBooleanTrue, slide_addr(find_OSBoolean_True()));
    SETOFFSET(OSBooleanFalse, slide_addr(find_OSBoolean_True() + sizeof(void *)));
    SETOFFSET(OSUnserializeXML, slide_addr(find_osunserializexml()));
    SETOFFSET(smalloc, slide_addr(find_smalloc()));
    SETOFFSET(zone_map_ref, slide_addr(find_zone_map_ref()));
    
    uint64_t vfscontext = slide_addr(find_symbol("_vfs_context_current"));
    if(!vfscontext || vfscontext == kernel_slide) {
        SETOFFSET(vfs_context, slide_addr(find_vfs_context_current()));
    } else {
        SETOFFSET(vfs_context, vfscontext);
    }
    
    uint64_t vfslookup = slide_addr(find_symbol("_vnode_lookup"));
    if(!vfslookup || vfslookup == kernel_slide) {
        SETOFFSET(vnode_lookup, slide_addr(find_vnode_lookup()));
    } else {
        SETOFFSET(vnode_lookup, vfslookup);
    }
    
    uint64_t vnodeput = slide_addr(find_symbol("_vnode_put"));
    if(!vnodeput || vnodeput == kernel_slide) {
        SETOFFSET(vnode_put, slide_addr(find_vfs_context_current()));
    } else {
        SETOFFSET(vnode_put, vnodeput);
    }
    SETOFFSET(kernel_task, slide_addr(find_kernel_task()));
    SETOFFSET(shenanigans, slide_addr(find_shenanigans()));
    SETOFFSET(lck_mtx_lock, slide_addr(find_lck_mtx_lock()));
    SETOFFSET(lck_mtx_unlock, slide_addr(find_lck_mtx_unlock()));

    if (kCFCoreFoundationVersionNumber >= 1535.12) {
        SETOFFSET(vnode_get_snapshot, slide_addr(find_vnode_get_snapshot()));
        SETOFFSET(fs_lookup_snapshot_metadata_by_name_and_return_name, slide_addr(find_fs_lookup_snapshot_metadata_by_name_and_return_name()));
        SETOFFSET(apfs_jhash_getvnode, slide_addr(find_apfs_jhash_getvnode()));
    }
    
    SETOFFSET(trustcache, slide_addr(find_trustcache()));
    if (auth_ptrs) {
        SETOFFSET(auth_ptrs, true);
        SETOFFSET(f_load_trust_cache, slide_addr(find_pmap_load_trust_cache()));
        SETOFFSET(paciza_pointer__l2tp_domain_module_start, slide_addr(find_paciza_pointer__l2tp_domain_module_start()));
        SETOFFSET(paciza_pointer__l2tp_domain_module_stop, slide_addr(find_paciza_pointer__l2tp_domain_module_stop()));
        SETOFFSET(l2tp_domain_inited, slide_addr(find_l2tp_domain_inited()));
        SETOFFSET(sysctl__net_ppp_l2tp, slide_addr(find_sysctl__net_ppp_l2tp()));
        SETOFFSET(sysctl_unregister_oid, slide_addr(find_sysctl_unregister_oid()));
        SETOFFSET(mov_x0_x4__br_x5, slide_addr(find_mov_x0_x4__br_x5()));
        SETOFFSET(mov_x9_x0__br_x1, slide_addr(find_mov_x9_x0__br_x1()));
        SETOFFSET(mov_x10_x3__br_x6, slide_addr(find_mov_x10_x3__br_x6()));
        SETOFFSET(kernel_forge_pacia_gadget, slide_addr(find_kernel_forge_pacia_gadget()));
        SETOFFSET(kernel_forge_pacda_gadget, slide_addr(find_kernel_forge_pacda_gadget()));
        SETOFFSET(IOUserClient__vtable, slide_addr(find_IOUserClient__vtable()));
        SETOFFSET(IORegistryEntry__getRegistryEntryID, slide_addr(find_IORegistryEntry__getRegistryEntryID()));
    }

    SETOFFSET(cs_blob_generation_count, slide_addr(find_cs_blob_generation_count()));
    SETOFFSET(cs_find_md, slide_addr(find_cs_find_md()));
    SETOFFSET(cs_validate_csblob, slide_addr(find_cs_validate_csblob()));
    SETOFFSET(kalloc_canblock, slide_addr(find_kalloc_canblock()));
    SETOFFSET(ubc_cs_blob_allocate_site, slide_addr(find_ubc_cs_blob_allocate_site()));
    SETOFFSET(kfree, slide_addr(find_kfree()));
    
    SETOFFSET(hook_cred_label_update_execve, slide_addr(find_hook_cred_label_update_execve()));
    SETOFFSET(flow_divert_connect_out, slide_addr(find_flow_divert_connect_out()));
    SETOFFSET(unix_syscall, slide_addr(find_unix_syscall()));
    SETOFFSET(pthread_kext_register, slide_addr(find_pthread_kext_register()));
    SETOFFSET(pthread_callbacks, slide_addr(find_pthread_callbacks()));
    SETOFFSET(unix_syscall_return, slide_addr(find_unix_syscall_return()));
    SETOFFSET(sysent, slide_addr(find_sysent()));
    //    uint64_t find_syscall(int n);
    SETOFFSET(proc_find, slide_addr(find_proc_find()));
    //  EX: find_mpo(cred_label_update_execve)
    //    #define find_mpo(name) find_mpo_entry(offsetof(struct mac_policy_ops, mpo_ ##name))
    //    uint64_t find_mpo_entry(uint64_t offset);
    //    uint64_t find_hook_policy_syscall(int n);
    SETOFFSET(syscall_set_profile, slide_addr(find_syscall_set_profile()));
    SETOFFSET(sandbox_set_container_copyin, slide_addr(find_sandbox_set_container_copyin()));
    SETOFFSET(platform_set_container, slide_addr(find_platform_set_container()));
    SETOFFSET(extension_create_file, slide_addr(find_extension_create_file()));
    SETOFFSET(extension_add, slide_addr(find_extension_add()));
    SETOFFSET(extension_release, slide_addr(find_extension_release()));
    SETOFFSET(sfree, slide_addr(find_sfree()));

    if(monolithic_kernel) {
        SETOFFSET(monolithic_kernel, true);
    }
}

#endif
