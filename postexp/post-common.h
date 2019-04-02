//
//  post-common.h
//  sefebreak
//
//  Created by Xavier Perarnau on 04/02/2019.
//  Copyright © 2019 Xavier Perarnau. All rights reserved.
//

#ifndef post_common_h
#define post_common_h

#include <stdio.h>
#include <stdbool.h>
#include <mach/mach.h>

/*
 * kernel_get_task_for_pid
 *
 * Description:
 *     Get the task struct for a pid.
 */
uint64_t kernel_get_task_for_pid(pid_t pid);

/*
 * kernel_get_proc_for_task
 *
 * Description:
 *     Get the proc struct for a task.
 */
uint64_t kernel_get_proc_for_task(uint64_t task);

/*
 * kernel_get_ucred_for_task
 *
 * Description:
 *     Get the ucred struct for a task.
 */
uint64_t kernel_get_ucred_for_task(uint64_t task);

/*
 * kernel_get_cr_label_for_task
 *
 * Description:
 *     Get the cr_label struct for a task.
 */
uint64_t kernel_get_cr_label_for_task(uint64_t task);

/*
 * entitle_pid
 *
 * Description:
 *     Injects to trustcache.
 */
bool entitle_pid(uint64_t task, const char *ent, bool val);

#endif /* post_common_h */
