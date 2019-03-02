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
#import <sys/utsname.h>
typedef bool BOOL;

#include <mach/mach.h>
#include "patchfinder64.h"
#include "parameters.h"
#include "kernel_slide.h"

int dump_offsets_to_file(char *file) {
    
    int fd = open(file, O_RDONLY);
    if (fd >= 0) {
        unlink(file);
        close(fd);
    }
    
    struct offsets off;
    
    off.allproc = find_allproc();
    off.gadget = find_add_x0_x0_0x40_ret();
    off.OSBooleanFalse = 0; //Find_OSBoolean_False();
    off.OSBooleanTrue = find_OSBoolean_True();
    off.OSUnserializeXML = find_osunserializexml();
    off.smalloc = find_smalloc();
    off.zone_map_ref = find_zone_map_ref();
    
    off.vfs_context = find_symbol("_vfs_context_current");
    if (!off.vfs_context) off.vfs_context = find_vfs_context_current() - kernel_slide;
    
    off.vnode_lookup = find_symbol("_vnode_lookup");
    if (!off.vnode_lookup) off.vnode_lookup = find_vnode_lookup() - kernel_slide;
    
    off.vnode_put = find_symbol("_vnode_put");
    if (!off.vnode_put) off.vnode_put = find_vnode_put() - kernel_slide;
    
    off.kernelbase = kernel_load_base;
    
    off.trustcache = find_trustcache();
    off.f_load_trust_cache = find_pmap_load_trust_cache();
    struct utsname ut;
    uname(&ut);
    if(off.trustcache == 0) {
        if(strcmp("iPhone11,8", ut.machine) == 0) {
            off.trustcache = kernel_slide + 0xFFFFFFF008ED42C8;
        } else {
            off.trustcache = kernel_slide + 0xFFFFFFF008F702C8;
        }
    }
    if(off.f_load_trust_cache == 0) {
        if(strcmp("iPhone11,8", ut.machine) == 0) {
            off.f_load_trust_cache = kernel_slide + 0xFFFFFFF007B50504;
        } else {
            off.f_load_trust_cache = kernel_slide + 0xFFFFFFF007B80504;
        }
    }
    
    FILE *f = fopen(file, "wb");
    fwrite(&off, sizeof(struct offsets), 1, f);
    fclose(f);
    
    fd = open(file, O_RDONLY);
    
    return (fd < 0);
}
