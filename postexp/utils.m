//
//  utils.c
//  postexp
//
//  Created by Xavier Perarnau on 13/03/2019.
//  Copyright © 2019 xavo95. All rights reserved.
//

#include "utils.h"

#import <Foundation/Foundation.h>
#import <sys/stat.h>
#import "log.h"
#include "untar.h"

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

bool clean_up_previous(void) {
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
            return false;
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
    return true;
}
