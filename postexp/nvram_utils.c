//
//  nvram_utils.c
//  postexp
//
//  Created by Xavier Perarnau on 25/04/2019.
//  Copyright © 2019 xavo95. All rights reserved.
//

#include "nvram_utils.h"

// iOS 11 moves OFVariables to const
// https://twitter.com/s1guza/status/908790514178301952
// however, if we:
//  1) Can find IODTNVRAM service
//  2) Have tfp0 / kernel read|write|alloc
//  3) Can leak kernel address of mach port
// then we can fake vtable on IODTNVRAM object
// async_wake satisfies those requirements
// however, I wasn't able to actually set or get ANY nvram variable
// not even userread/userwrite
// Guess sandboxing won't let to access nvram

#import <stdlib.h>
#import <CoreFoundation/CoreFoundation.h>
#import "kernel_utils.h"
#import "offsetof.h"
#include "kmem.h"
#include "log.h"

// convertPropToObject calls getOFVariableType
// open convertPropToObject, look for first vtable call -- that'd be getOFVariableType
// find xrefs, figure out vtable start from that
// following are offsets of entries in vtable

// it always returns false
const uint64_t searchNVRAMProperty = 0x590;
// 0 corresponds to root only
const uint64_t getOFVariablePerm = 0x558;

typedef mach_port_t io_service_t;
typedef mach_port_t io_connect_t;
extern const mach_port_t kIOMasterPortDefault;
CFMutableDictionaryRef IOServiceMatching(const char *name) CF_RETURNS_RETAINED;
io_service_t IOServiceGetMatchingService(mach_port_t masterPort, CFDictionaryRef matching CF_RELEASES_ARGUMENT);


// get kernel address of IODTNVRAM object
uint64_t get_iodtnvram_obj(void) {
    // get user serv
    io_service_t IODTNVRAMSrv = IOServiceGetMatchingService(kIOMasterPortDefault, IOServiceMatching("IODTNVRAM"));
    
    // leak user serv
    uint64_t nvram_up = find_port_address(IODTNVRAMSrv);
    // get kern obj -- IODTNVRAM*
    uint64_t IODTNVRAMObj = kernel_read64_internal(nvram_up + off_ip_kobject);
    
    return IODTNVRAMObj;
}

uint64_t orig_vtable = -1;

void unlock_nvram_internal(void) {
    
    uint64_t IODTNVRAMObj = get_iodtnvram_obj();
    if (IODTNVRAMObj == 0) {
        ERROR("get_iodtnvram_obj failed!");
        return;
    }
    
    uint64_t vtable_start = kernel_read64_internal(IODTNVRAMObj);
    
    orig_vtable = vtable_start;
    
    uint64_t vtable_end = vtable_start;
    // Is vtable really guaranteed to end with 0 or was it just a coincidence?..
    // should we just use some max value instead?
    while (kernel_read64_internal(vtable_end) != 0) vtable_end += sizeof(uint64_t);
    
    uint32_t vtable_len = (uint32_t) (vtable_end - vtable_start);
    
    // copy vtable to userspace
    uint64_t *buf = calloc(1, vtable_len);
    kernel_read_internal(vtable_start, buf, vtable_len);
    
    // alter it
    buf[getOFVariablePerm/sizeof(uint64_t)] = buf[searchNVRAMProperty/sizeof(uint64_t)];
    
    // allocate buffer in kernel and copy it back
    uint64_t fake_vtable = kernel_alloc_wired(vtable_len);
    kernel_write_internal(fake_vtable, buf, vtable_len);
    
    // replace vtable on IODTNVRAM object
    kernel_write64_internal(IODTNVRAMObj, fake_vtable);
    
    free(buf);
}

int lock_nvram_internal(void) {
    if (orig_vtable == -1) {
        ERROR("trying to lock nvram, but didnt unlock first");
        return -1;
    }
    
    uint64_t obj = get_iodtnvram_obj();
    if (obj == 0) { // would never happen but meh
        ERROR("get_iodtnvram_obj failed!");
        return -1;
    }
    
    kernel_write64_internal(obj, orig_vtable);
    
    INFO("locked nvram");
    return 0;
}
