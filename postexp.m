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
#include "payload.h"
#include "offsets_dump.h"

#include "patchfinder64.h"
#include "macho-helper.h"
#include "lzssdec.hpp"
#include "untar.h"
#include "amfi_utils.h"

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

enum post_exp_t clean_up_previous(void) {
    NSError *error = NULL;
    if (!fileExists("/var/containers/Bundle/.installed_rootlessJB3")) {
        
        if (fileExists("/var/containers/Bundle/iosbinpack64")) {
            INFO("uninstalling previous build...");
            
            removeFile("/var/LIB");
            removeFile("/var/ulb");
            removeFile("/var/bin");
            removeFile("/var/sbin");
            removeFile("/var/containers/Bundle/tweaksupport/Applications");
            removeFile("/var/Apps");
            removeFile("/var/profile");
            removeFile("/var/motd");
            removeFile("/var/dropbear");
            removeFile("/var/containers/Bundle/tweaksupport");
            removeFile("/var/containers/Bundle/iosbinpack64");
            removeFile("/var/containers/Bundle/dylibs");
            removeFile("/var/log/testbin.log");
            
            if (fileExists("/var/log/jailbreakd-stdout.log")) removeFile("/var/log/jailbreakd-stdout.log");
            if (fileExists("/var/log/jailbreakd-stderr.log")) removeFile("/var/log/jailbreakd-stderr.log");
        }
        
        INFO("installing bootstrap...");
        
        chdir("/var/containers/Bundle/");
        FILE *bootstrap = fopen((char*)in_bundle("iosbinpack.tar"), "r");
        untar(bootstrap, "/var/containers/Bundle/");
        fclose(bootstrap);
        
//        FILE *tweaks = fopen((char*)in_bundle("tweaksupport.tar"), "r");
//        untar(tweaks, "/var/containers/Bundle/");
//        fclose(tweaks);
        
//        if(!fileExists("/var/containers/Bundle/tweaksupport") || !fileExists("/var/containers/Bundle/iosbinpack64")) {
//            ERROR("[-] Failed to install bootstrap");
//        }
        
        mkdir("/var/containers/Bundle/tweaksupport", 0777);
        if(!fileExists("/var/containers/Bundle/iosbinpack64")) {
            ERROR("failed to install bootstrap");
            cleanup();
            return ERROR_INSTALLING_BOOTSTRAP;
        }
        
        INFO("creating symlinks...");
        
//        symlink("/var/containers/Bundle/tweaksupport/Library", "/var/LIB");
//        symlink("/var/containers/Bundle/tweaksupport/usr/lib", "/var/ulb");
//        symlink("/var/containers/Bundle/tweaksupport/Applications", "/var/Apps");
//        symlink("/var/containers/Bundle/tweaksupport/bin", "/var/bin");
//        symlink("/var/containers/Bundle/tweaksupport/sbin", "/var/sbin");
//        symlink("/var/containers/Bundle/tweaksupport/usr/libexec", "/var/libexec");
        
        close(open("/var/containers/Bundle/.installed_rootlessJB3", O_CREAT));
        
        //limneos
        symlink("/var/containers/Bundle/iosbinpack64/etc", "/var/etc");
//        symlink("/var/containers/Bundle/tweaksupport/usr", "/var/usr");
        symlink("/var/containers/Bundle/iosbinpack64/usr/bin/killall", "/var/bin/killall");
        
        INFO("installed bootstrap!");
    }
    return NO_ERROR;
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
        cleanup();
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
        cleanup();
        return ERROR_SETTING_PATCHFINDER64;
    } else {
        INFO("patchfinder initialized successfully");
        return NO_ERROR;
    }
}

enum post_exp_t bootstrap() {
    enum post_exp_t clean_result = clean_up_previous();
    if(clean_result != NO_ERROR) {
        cleanup();
        return clean_result;
    }
    
    if(dump_offsets_to_file("/var/containers/Bundle/tweaksupport/offsets.data") != 0) {
        ERROR("failed to save offsets");
        cleanup();
        return ERROR_SAVING_OFFSETS;
    }
    
    prepare_payload();
    
    NSError *error = NULL;
    removeFile("/var/containers/Bundle/iosbinpack64/usr/local/bin/dropbear");
    removeFile("/var/containers/Bundle/iosbinpack64/usr/bin/scp");
    
    chdir("/var/containers/Bundle/");
    FILE *fixed_dropbear = fopen(in_bundle("dropbear.v2018.76.tar"), "r");
    untar(fixed_dropbear, "/var/containers/Bundle/");
    fclose(fixed_dropbear);
    INFO("installed Dropbear SSH!");
    
    removeFile("/var/containers/Bundle/iosbinpack64/bin/jailbreakd");
    if (!fileExists(in_bundle("jailbreakd"))) {
        chdir(in_bundle(""));
        
        FILE *jbd = fopen(in_bundle("jailbreakd.tar"), "r");
        untar(jbd, in_bundle("jailbreakd"));
        fclose(jbd);
        
        removeFile(in_bundle("jailbreakd.tar"));
    }
    copyFile(in_bundle("jailbreakd"), "/var/containers/Bundle/iosbinpack64/bin/jailbreakd");

    kernel_call_init();
    trustbin("/var/containers/Bundle/iosbinpack64");
    kernel_call_deinit();
    
    mkdir("/var/dropbear", 0777);
    removeFile("/var/profile");
    removeFile("/var/motd");
    chmod("/var/profile", 0777);
    chmod("/var/motd", 0777);
    
    copyFile("/var/containers/Bundle/iosbinpack64/etc/profile", "/var/profile");
    copyFile("/var/containers/Bundle/iosbinpack64/etc/motd", "/var/motd");
    FILE *motd = fopen("/var/motd", "w");
    struct utsname ut;
    uname(&ut);
    fprintf(motd, "A12 dropbear exec by @xavo95\n");
    fprintf(motd, "%s %s %s %s %s\n", ut.sysname, ut.nodename, ut.release, ut.version, ut.machine);
    fclose(motd);
    chmod("/var/motd", 0777);
    
    launch("/var/containers/Bundle/iosbinpack64/usr/bin/killall", "-SEGV", "dropbear", NULL, NULL, NULL, NULL, NULL);
//    launch_as_platform("/var/containers/Bundle/iosbinpack64/usr/local/bin/dropbear", "-R", "-E", "-p", "22", "-p", "2222", NULL);
    
    if(fileExists(in_bundle("dropbear.plist"))) {
        removeFile("/var/containers/Bundle/iosbinpack64/LaunchDaemons/dropbear.plist");
        copyFile(in_bundle("dropbear.plist"), "/var/containers/Bundle/iosbinpack64/LaunchDaemons/dropbear.plist");
    }
    if(fileExists(in_bundle("jailbreakd.plist"))) {
        removeFile("/var/containers/Bundle/iosbinpack64/LaunchDaemons/jailbreakd.plist");
        copyFile(in_bundle("jailbreakd.plist"), "/var/containers/Bundle/iosbinpack64/LaunchDaemons/jailbreakd.plist");
    }
    //------------- launch daeamons -------------//
    //-- you can drop any daemon plist in iosbinpack64/LaunchDaemons and it will be loaded automatically --//
    NSArray *plists = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:@"/var/containers/Bundle/iosbinpack64/LaunchDaemons" error:nil];
    
    for (__strong NSString *file in plists) {
        INFO("adding permissions to plist %s", [file UTF8String]);
        
        file = [@"/var/containers/Bundle/iosbinpack64/LaunchDaemons" stringByAppendingPathComponent:file];
        
        if (strstr([file UTF8String], "jailbreakd")) {
            INFO("found jailbreakd plist, special handling");
            
            NSMutableDictionary *job = [NSPropertyListSerialization propertyListWithData:[NSData dataWithContentsOfFile:file] options:NSPropertyListMutableContainers format:nil error:nil];
            
            job[@"EnvironmentVariables"][@"KernelBase"] = [NSString stringWithFormat:@"0x%16llx", kernel_load_base];
            [job writeToFile:file atomically:YES];
        }
        
        chmod([file UTF8String], 0644);
        chown([file UTF8String], 0, 0);
    }
    
    // clean up
    removeFile("/var/log/testbin.log");
    removeFile("/var/log/jailbreakd-stderr.log");
    removeFile("/var/log/jailbreakd-stdout.log");
    
    launch("/var/containers/Bundle/iosbinpack64/bin/launchctl", "unload", "/var/containers/Bundle/iosbinpack64/LaunchDaemons", NULL, NULL, NULL, NULL, NULL);
    launch("/var/containers/Bundle/iosbinpack64/bin/launchctl", "load", "/var/containers/Bundle/iosbinpack64/LaunchDaemons", NULL, NULL, NULL, NULL, NULL);
    
    sleep(1);
    
    if(!fileExists("/var/log/testbin.log")) {
        ERROR("failed to load launch daemons");
        cleanup();
        return ERROR_LOADING_LAUNCHDAEMONS;
    }
    if(!fileExists("/var/log/jailbreakd-stdout.log")) {
        ERROR("failed to load jailbreakd");
        cleanup();
        return ERROR_LOADING_JAILBREAKD;
    }
    return NO_ERROR;
}

void cleanup(void) {
    INFO("cleaning up");
    term_kernel();
    restore_csflags(current_task);
    sandbox(current_task);
    unroot(current_task);
}
