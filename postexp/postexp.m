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

#define in_bundle(obj) strdup([[[[NSBundle mainBundle] bundlePath] stringByAppendingPathComponent:@obj] UTF8String])

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

enum post_exp_t recover_with_hsp4(mach_port_t tfp0, uint64_t *ext_kernel_slide, uint64_t *ext_kernel_load_base) {
    struct task_dyld_info dyld_info = { 0 };
    mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;
    if((host_get_special_port(mach_host_self(), HOST_LOCAL_NODE, 4, &tfp0) == KERN_SUCCESS) && MACH_PORT_VALID(tfp0)) {
        if(task_info(tfp0, TASK_DYLD_INFO, (task_info_t)&dyld_info, &count) == KERN_SUCCESS) {
            kernel_task_port = tfp0;
            kernel_slide = dyld_info.all_image_info_size;
            size_t blob_size = kernel_read64(dyld_info.all_image_info_addr);
            INFO("Restoring persisted offsets cache");
            struct cache_blob *blob = create_cache_blob(blob_size);
            if(kernel_read(dyld_info.all_image_info_addr, blob, blob_size)) {
                import_cache_blob(blob);
                free(blob);
                kernel_slide = GETOFFSET(kernel_slide);
                kernel_load_base = GETOFFSET(kernel_load_base);
                found_offsets = true;
            }
            *ext_kernel_slide = kernel_slide;
            *ext_kernel_load_base = kernel_load_base;
            return NO_ERROR;
        }
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
    
    if (!verify_tfp0()) {
        ERROR("Failed to verify TFP0.");
        return ERROR_INITIALAZING_LIBRARY;
    }

    return NO_ERROR;
}

enum post_exp_t root_pid(pid_t pid) {
    uint64_t task_struct = task_struct_of_pid(pid);
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
    uint64_t task_struct = task_struct_of_pid(pid);
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
    current_task = task_struct_of_pid(getpid());
    kernel_call_init();
    trustbin(trust_path);
    kernel_call_deinit();
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

void extract_tar(FILE *a, const char *path) {
    untar(a, path);
}

int launch_binary(char *binary, char *arg1, char *arg2, char *arg3, char *arg4, char *arg5, char *arg6, char**env) {
    return launch(binary, arg1, arg2, arg3, arg4, arg5, arg6, env);
}

void cleanup(void) {
    INFO("cleaning up");
    if (verify_tfp0() && GETOFFSET(allproc) && !current_task) {
        current_task = task_struct_of_pid(getpid());
    }
    restore_csflags(current_task);
    sandbox(current_task);
    unroot(current_task);
}
