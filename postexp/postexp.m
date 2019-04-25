//
//  postexp.m
//  sefebreak
//
//  Created by Xavier Perarnau on 04/02/2019.
//  Copyright © 2019 Xavier Perarnau. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonDigest.h>
#import <UIKit/UIKit.h>
#import <unistd.h>
#import <sys/stat.h>

#include "kmem.h"
#include "kernel_utils.h"
#include "kernel_call.h"
#include "postexp.h"
#include "offsets.h"
#include "root.h"
#include "sandbox.h"
#include "log.h"
#include "post-common.h"
#include "launch_utils.h"
#include "offsets_dump.h"
#include "remap_tfp_set_hsp.h"
#include "kernel_call/kc_parameters.h"

#include "patchfinder64.h"
#include "untar.h"
#include "amfi_utils.h"

#import "kerneldec/kerneldec.h"

#define fileExists(file) [[NSFileManager defaultManager] fileExistsAtPath:@(file)]

#define removeFile(file) if (fileExists(file)) {\
[[NSFileManager defaultManager]  removeItemAtPath:@(file) error:&error]; \
if (error) { \
ERROR("error removing file %s (%s)", file, [[error localizedDescription] UTF8String]); \
} else {\
INFO("deleted old copy from %s", file);\
}\
}

#define copyFile(copyFrom, copyTo) [[NSFileManager defaultManager] copyItemAtPath:@(copyFrom) toPath:@(copyTo) error:&error]; \
INFO("copying %s to %s", copyFrom, copyTo);\
if (error) { \
ERROR("error copying item %s to path %s (%s)", copyFrom, copyTo, [[error localizedDescription] UTF8String]); \
}

#define moveFile(copyFrom, moveTo) [[NSFileManager defaultManager] moveItemAtPath:@(copyFrom) toPath:@(moveTo) error:&error]; \
if (error) {\
ERROR("error moving item %s to path %s (%s)", copyFrom, moveTo, [[error localizedDescription] UTF8String]); \
}

const char *kernel_path = "/System/Library/Caches/com.apple.kernelcaches/kernelcache";
bool found_offsets = false;
uint64_t static_kernel_base = 0xFFFFFFF007004000;

enum post_exp_t recover_with_hsp4(mach_port_t *tfp0, uint64_t *ext_kernel_slide, uint64_t *ext_kernel_load_base) {
    struct task_dyld_info dyld_info = { 0 };
    mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;
    mach_port_t tfpzero = 0;
    kern_return_t kr = task_for_pid(mach_task_self(), 0, &tfpzero);
    if(kr != KERN_SUCCESS) {
        kr = host_get_special_port(mach_host_self(), HOST_LOCAL_NODE, 4, &tfpzero);
        pid_t pid = 10;
        if((kr != KERN_SUCCESS) || !MACH_PORT_VALID(tfpzero) || !((pid_for_task(tfpzero, &pid) == KERN_SUCCESS) && (pid == 0))) {
            return ERROR_TFP0_NOT_RECOVERED;
        }
    }
    if(task_info(tfpzero, TASK_DYLD_INFO, (task_info_t)&dyld_info, &count) == KERN_SUCCESS) {
        kernel_task_port = tfpzero;
        kernel_slide = dyld_info.all_image_info_size;
        size_t blob_size = kernel_read64_internal(dyld_info.all_image_info_addr);
        INFO("Restoring persisted offsets cache");
        struct cache_blob *blob = create_cache_blob(blob_size);
        if(kernel_read_internal(dyld_info.all_image_info_addr, blob, blob_size)) {
            import_cache_blob(blob);
            free(blob);
            kernel_slide = GETOFFSET(kernel_slide);
            kernel_load_base = GETOFFSET(kernel_load_base);
            found_offsets = true;
        }
        *ext_kernel_slide = kernel_slide;
        *ext_kernel_load_base = kernel_load_base;
        *tfp0 = tfpzero;
        _offsets_init();
        return NO_ERROR;
    }
    
    return ERROR_TFP0_NOT_RECOVERED;
}

enum post_exp_t init(mach_port_t tfp0, uint64_t *ext_kernel_slide, uint64_t *ext_kernel_load_base) {
    // Initialize offsets
    _offsets_init();
    
    kernel_task_port = tfp0;
    if((*ext_kernel_slide != 0) && (*ext_kernel_load_base != 0)) {
        kernel_load_base = *ext_kernel_load_base;
        kernel_slide = *ext_kernel_slide;
    } else if((*ext_kernel_slide == 0) && (*ext_kernel_load_base != 0)) {
        kernel_load_base = *ext_kernel_load_base;
        kernel_slide = kernel_load_base - static_kernel_base;
        *ext_kernel_slide = kernel_slide;
    } else if((*ext_kernel_slide != 0) && (*ext_kernel_load_base == 0)) {
        kernel_slide = *ext_kernel_slide;
        kernel_load_base = static_kernel_base + kernel_slide;
        *ext_kernel_load_base = kernel_load_base;
    } else {
        kernel_load_base = find_kernel_base();
        kernel_slide = kernel_load_base - static_kernel_base;
        *ext_kernel_slide = kernel_slide;
        *ext_kernel_load_base = kernel_load_base;
    }
    
    if (!verify_tfp0_internal()) {
        ERROR("Failed to verify TFP0.");
        return ERROR_INITIALAZING_LIBRARY;
    }

    return NO_ERROR;
}

enum post_exp_t root_pid(pid_t pid) {
    uint64_t task_struct = task_struct_of_pid_internal(pid);
    // Get r00t
    save_proc_user_struct(task_struct);
    INFO("current UID: %d", getuid());
    root(task_struct);
    uid_t current_uid = getuid();
    if(current_uid != 0) {
        ERROR("couldn't get r00t");
        cleanup();
        return ERROR_GETTING_ROOT;
    } else {
        INFO("current UID: %d", getuid());
    }
    return NO_ERROR;
}

enum post_exp_t unsandbox_pid(pid_t pid) {
    uint64_t task_struct = task_struct_of_pid_internal(pid);
    // Unsandbox
    save_proc_sandbox_struct(task_struct);
    unsandbox(task_struct);
    
    setcsflags(task_struct);
    platformize(task_struct);
    INFO("the application is now a platform binary");
    
    return NO_ERROR;
}

enum post_exp_t get_kernel_file(void) {
    NSString *docs = [[[[NSFileManager defaultManager] URLsForDirectory:NSDocumentDirectory inDomains:NSUserDomainMask] lastObject] path];
    mkdir((char *)[docs UTF8String], 0777);
    
    const char *location = [[docs stringByAppendingPathComponent:[NSString stringWithFormat:@"kernelcache.dump"]] UTF8String];
    NSError *error = NULL;
    
    removeFile(location);
    error = NULL;
    copyFile(kernel_path, location);
    if (error) {
        cleanup();
        return ERROR_ESCAPING_SANDBOX;
    }
    chown(location, 501, 501);
    return NO_ERROR;
}

enum post_exp_t initialize_patchfinder64(bool use_static_kernel) {
    if(!found_offsets) {
        static_kernel = use_static_kernel;
        if(static_kernel) {
            NSString *docs = [[[[NSFileManager defaultManager] URLsForDirectory:NSDocumentDirectory inDomains:NSUserDomainMask] lastObject] path];
            const char *original_kernel_cache_path = [[docs stringByAppendingPathComponent:[NSString stringWithFormat:@"kernelcache.dump"]] UTF8String];
            const char *decompressed_kernel_cache_path = [[docs stringByAppendingPathComponent:[NSString stringWithFormat:@"kernelcache.dec"]] UTF8String];
            
            NSError *error = NULL;
            removeFile(decompressed_kernel_cache_path);
            
            FILE *original_kernel_cache = fopen(original_kernel_cache_path, "rb");
            FILE *decompressed_kernel_cache = fopen(decompressed_kernel_cache_path, "w+b");
            decompress_kernel(original_kernel_cache, decompressed_kernel_cache, NULL, true);
            fclose(decompressed_kernel_cache);
            chown(decompressed_kernel_cache_path, 501, 501);
            
            if (init_kernel(NULL, 0, decompressed_kernel_cache_path) != ERR_SUCCESS) {
                ERROR("failed to initialize patchfinder");
                cleanup();
                return ERROR_SETTING_PATCHFINDER64;
            } else {
                INFO("patchfinder initialized successfully");
#ifdef CLASSIC_FILE_STYLE
                if(dump_offsets_to_file("/var/containers/Bundle/tweaksupport/offsets.data") != 0) {
                    ERROR("failed to save offsets");
                    cleanup();
                    return ERROR_SAVING_OFFSETS;
                }
#else
                set_cached_offsets(kCFCoreFoundationVersionNumber);
#endif
                term_kernel();
                INFO("offsets dumped correctly and patchfinder terminated");
            }
        } else {
            if (init_kernel(kread_pf, kernel_load_base, NULL) != ERR_SUCCESS) {
                ERROR("failed to initialize patchfinder");
                cleanup();
                return ERROR_SETTING_PATCHFINDER64;
            } else {
                INFO("patchfinder initialized successfully");
#ifdef CLASSIC_FILE_STYLE
                if(dump_offsets_to_file("/var/containers/Bundle/tweaksupport/offsets.data") != 0) {
                    ERROR("failed to save offsets");
                    cleanup();
                    return ERROR_SAVING_OFFSETS;
                }
#else
                set_cached_offsets(kCFCoreFoundationVersionNumber);
#endif
                term_kernel();
                INFO("offsets dumped correctly and patchfinder terminated");
            }
        }
    } else {
        auth_ptrs = GETOFFSET(auth_ptrs) == true ? true : false;
        monolithic_kernel = GETOFFSET(monolithic_kernel) == true ? true : false;
    }
    return NO_ERROR;
}

enum post_exp_t set_host_special_port_4_patch(void) {
    //---- host special port 4 ----//
    if(setHSP4()) {
        ERROR("failed to set tfp0 as hsp4!");
        cleanup();
        return ERROR_SETTING_HSP4;
    }
    return NO_ERROR;
}

enum post_exp_t add_to_trustcache(char *trust_path) {
    current_task = task_struct_of_pid_internal(getpid());
#if __arm64e__
    kernel_call_init_internal();
#endif
    int res = trustbin(trust_path);
#if __arm64e__
    kernel_call_deinit_internal();
#endif
    if (res != 0) {
        return ERROR_ADDING_TO_TRUSTCACHE;
    }
    return NO_ERROR;
}

enum post_exp_t dump_apticker(void) {
    NSString *apticket = @"/System/Library/Caches/apticket.der";
    NSString *docs = [[[[NSFileManager defaultManager] URLsForDirectory:NSDocumentDirectory inDomains:NSUserDomainMask] lastObject] path];
    mkdir((char *)[docs UTF8String], 0777);
    
    NSString *location = [docs stringByAppendingPathComponent:[NSString stringWithFormat:@"apticket.der"]];
    NSError *error = NULL;
    
    removeFile([location UTF8String]);
    NSData *fileData = [NSData dataWithContentsOfFile:apticket];
    [fileData writeToFile:location atomically:YES];
    INFO("APTicket dumped");
    
    chown([location UTF8String], 501, 501);
    return NO_ERROR;
}

void cleanup(void) {
    INFO("cleaning up");
    if (verify_tfp0_internal() && GETOFFSET(allproc) && !current_task) {
        current_task = task_struct_of_pid_internal(getpid());
    }
    restore_csflags(current_task);
    sandbox(current_task);
    unroot(current_task);
}

///////////////////////////////////////////// ADVANCED EXPORT METHODS /////////////////////////////////////////////

void untar(FILE *a, const char *path) {
    untar_internal(a, path);
}

int launch(char *binary, char *arg1, char *arg2, char *arg3, char *arg4, char *arg5, char *arg6, char**env) {
    return launch_internal(binary, arg1, arg2, arg3, arg4, arg5, arg6, env);
}

int launch_as_platform(char *binary, char *arg1, char *arg2, char *arg3, char *arg4, char *arg5, char *arg6, char**env) {
    return launch_as_platform_internal(binary, arg1, arg2, arg3, arg4, arg5, arg6, env);
}

bool kernel_call_init(void) {
    current_task = task_struct_of_pid_internal(getpid());
    return kernel_call_init_internal();
}

void kernel_call_deinit(void) {
    return kernel_call_deinit_internal();
}

uint32_t kernel_call_7(uint64_t function, size_t argument_count, ...) {
    assert(argument_count <= 7);
    uint64_t arguments[7];
    va_list ap;
    va_start(ap, argument_count);
    for (size_t i = 0; i < argument_count && i < 7; i++) {
        arguments[i] = va_arg(ap, uint64_t);
    }
    va_end(ap);
    return kernel_call_7v(function, argument_count, arguments);
}

bool kernel_read(uint64_t address, void *data, size_t size) {
    return kernel_read_internal(address, data, size);
}

bool kernel_write(uint64_t address, const void *data, size_t size) {
    return kernel_write_internal(address, data, size);
}

uint8_t kernel_read8(uint64_t address) {
    return kernel_read8_internal(address);
}

uint16_t kernel_read16(uint64_t address) {
    return kernel_read16_internal(address);
}

uint32_t kernel_read32(uint64_t address) {
    return kernel_read32_internal(address);
}

uint64_t kernel_read64(uint64_t address) {
    return kernel_read64_internal(address);
}

bool kernel_write8(uint64_t address, uint8_t value) {
    return kernel_write8_internal(address, value);
}

bool kernel_write16(uint64_t address, uint16_t value) {
    return kernel_write16_internal(address, value);
}

bool kernel_write32(uint64_t address, uint32_t value) {
    return kernel_write32_internal(address, value);
}

bool kernel_write64(uint64_t address, uint64_t value) {
    return kernel_write64_internal(address, value);
}

uint64_t kalloc(vm_size_t size) {
    return kalloc_internal(size);
}

bool kfree(mach_vm_address_t address, vm_size_t size) {
    return kfree_internal(address, size);
}

size_t kread(uint64_t where, void *p, size_t size) {
    return kread_internal(where, p, size);
}

uint64_t task_struct_of_pid(pid_t pid) {
    return task_struct_of_pid_internal(pid);
}

uint64_t proc_of_pid(pid_t pid) {
    return proc_of_pid_internal(pid);
}

bool verify_tfp0(void) {
    return verify_tfp0_internal();
}
