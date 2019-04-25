//
//  launch_utils.c
//  sefebreak
//
//  Created by Xavier Perarnau on 02/03/2019.
//  Copyright © 2019 Xavier Perarnau. All rights reserved.
//

#include "launch_utils.h"

#include "log.h"
#include <spawn.h>
#include <string.h>
#include <sys/wait.h>
#include <signal.h>
#include <mach/mach.h>
#include "sandbox.h"
#include "kernel_utils.h"

int launch_internal(char *binary, char *arg1, char *arg2, char *arg3, char *arg4, char *arg5, char *arg6, char**env) {
    pid_t pd;
    const char* args[] = {binary, arg1, arg2, arg3, arg4, arg5, arg6,  NULL};
    
    int rv = posix_spawn(&pd, binary, NULL, NULL, (char **)&args, env);
    if (rv) {
        ERROR("error spawing process %s", strerror(rv));
        return rv;
    }
    
    int a = 0;
    waitpid(pd, &a, 0);
    
    return WEXITSTATUS(a);
}

int launch_as_platform_internal(char *binary, char *arg1, char *arg2, char *arg3, char *arg4, char *arg5, char *arg6, char**env) {
    pid_t pd;
    const char* args[] = {binary, arg1, arg2, arg3, arg4, arg5, arg6,  NULL};
    
    posix_spawnattr_t attr;
    posix_spawnattr_init(&attr);
    posix_spawnattr_setflags(&attr, POSIX_SPAWN_START_SUSPENDED); //this flag will make the created process stay frozen until we send the CONT signal. This so we can platformize it before it launches.
    
    int rv = posix_spawn(&pd, binary, NULL, &attr, (char **)&args, env);
    if (rv) {
        ERROR("error spawing process %s", strerror(rv));
        return rv;
    }
    
    platformize_given_pid(pd);
    kill(pd, SIGCONT); //continue
    
    int a = 0;
    waitpid(pd, &a, 0);
    
    return WEXITSTATUS(a);
}
