//
//  launch_utils.h
//  sefebreak
//
//  Created by Xavier Perarnau on 02/03/2019.
//  Copyright © 2019 Xavier Perarnau. All rights reserved.
//

#ifndef launch_utils_h
#define launch_utils_h

#include <stdio.h>

/*
 * launch
 *
 * Description:
 *     Launch a binary.
 */
int launch(char *binary, char *arg1, char *arg2, char *arg3, char *arg4, char *arg5, char *arg6, char**env);

/*
 * launchAsPlatform
 *
 * Description:
 *     Launch a binary as platform binary.
 */
int launch_as_platform(char *binary, char *arg1, char *arg2, char *arg3, char *arg4, char *arg5, char *arg6, char**env);

#endif /* launch_utils_h */
