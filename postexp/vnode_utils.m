//
//  vnode_utils.c
//  postexp
//
//  Created by Xavier Perarnau on 25/04/2019.
//  Copyright © 2019 xavo95. All rights reserved.
//

#include "vnode_utils.h"

#import <stdlib.h>
#import <string.h>
#include "kmem.h"
#include "offsets_dump.h"
#include "kernel_call.h"
#include "kernel_utils.h"
#include "postexp.h"

static uint64_t _vnode_lookup = 0;
static uint64_t _vnode_put = 0;
static uint64_t _vfs_context_current = 0;

int vnode_lookup(const char *path, int flags, uint64_t *vnode, uint64_t vfs_context) {
    
    size_t len = strlen(path) + 1;
    uint64_t ptr = kalloc_internal(8);
    uint64_t ptr2 = kalloc_internal(len);
    kernel_write_internal(ptr2, path, len);
    
    if (_vnode_lookup == 0) {
        _vnode_lookup = GETOFFSET(vnode_lookup);
    }
    
    if (kernel_call_7_internal(_vnode_lookup, 4, ptr2, flags, ptr, vfs_context)) {
        return -1;
    }
    *vnode = kernel_read64_internal(ptr);
    kfree_internal(ptr2, len);
    kfree_internal(ptr, 8);
    return 0;
}

uint64_t get_vfs_context() {
    if (_vfs_context_current == 0) {
        _vfs_context_current = kernel_call_7_internal(GETOFFSET(vfs_context), 1, 1);
        _vfs_context_current = zm_fix_addr(_vfs_context_current);
    }
    return _vfs_context_current;
}

int vnode_put(uint64_t vnode) {
    if (_vnode_put == 0) {
        _vnode_put = GETOFFSET(vnode_put);
    }
    return (int)kernel_call_7_internal(_vnode_put, 1, vnode);
}

void copy_file_in_memory(char *original, char *replacement, uint64_t *vnode1, uint64_t *vnode2) {
    uint64_t orig = get_vnode_at_path(original);
    uint64_t fake = get_vnode_at_path(replacement);
    
    if (vnode1) *vnode1 = orig;
    if (vnode2) *vnode2 = fake;
    
    struct vnode rvp, fvp;
    kernel_read_internal(orig, &rvp, sizeof(struct vnode));
    kernel_read_internal(fake, &fvp, sizeof(struct vnode));
    
    fvp.v_usecount = rvp.v_usecount;
    fvp.v_kusecount = rvp.v_kusecount;
    fvp.v_parent = rvp.v_parent;
    fvp.v_freelist = rvp.v_freelist;
    fvp.v_mntvnodes = rvp.v_mntvnodes;
    fvp.v_ncchildren = rvp.v_ncchildren;
    fvp.v_nclinks = rvp.v_nclinks;
    
    kernel_write_internal(orig, &fvp, sizeof(struct vnode));
}
