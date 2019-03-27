//
//  offsets_dump.h
//  sefebreak
//
//  Created by Jake James on 8/29/18.
//  Copyright © 2018 Jake James. All rights reserved.
//

#ifndef offsets_dump_h
#define offsets_dump_h

#include <stdio.h>

struct patchfinder_offsets {
    uint64_t allproc;
    uint64_t OSBooleanTrue;
    uint64_t OSBooleanFalse;
    uint64_t add_x0_x0_0x40_ret;
    uint64_t zone_map_ref;
    uint64_t OSUnserializeXML;
    uint64_t smalloc;
    uint64_t vnode_lookup;
    uint64_t vfs_context;
    uint64_t vnode_put;
    uint64_t trustcache;
    uint64_t f_load_trust_cache;
    uint64_t kernel_task;
    uint64_t shenanigans;
    uint64_t lck_mtx_lock;
    uint64_t lck_mtx_unlock;
    uint64_t vnode_get_snapshot;
    uint64_t fs_lookup_snapshot_metadata_by_name_and_return_name;
    uint64_t apfs_jhash_getvnode;
    uint64_t paciza_pointer__l2tp_domain_module_start;
    uint64_t paciza_pointer__l2tp_domain_module_stop;
    uint64_t l2tp_domain_inited;
    uint64_t sysctl__net_ppp_l2tp;
    uint64_t sysctl_unregister_oid;
    uint64_t mov_x0_x4__br_x5;
    uint64_t mov_x9_x0__br_x1;
    uint64_t mov_x10_x3__br_x6;
    uint64_t kernel_forge_pacia_gadget;
    uint64_t kernel_forge_pacda_gadget;
    uint64_t IOUserClient__vtable;
    uint64_t IORegistryEntry__getRegistryEntryID;
};

struct patchfinder_offsets cached_offsets;

/*
 * set_cached_offsets
 *
 * Description:
 *     Caches the offsets so we can shutdown patchfinder
 */
void set_cached_offsets(double kCFCoreFoundationVersionNumber);

/*
 * dump_offsets_to_file
 *
 * Description:
 *     Dump relevant offsets to file.
 */
int dump_offsets_to_file(char *file);

#endif /* offsetsDump_h */
