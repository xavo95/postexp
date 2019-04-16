//
//  tar.h
//  sefebreak
//
//  Created by Xavier Perarnau on 27/02/2019.
//  Copyright © 2019 Xavier Perarnau. All rights reserved.
//

#ifndef tar_h
#define tar_h

#include <stdio.h>

/*
 * untar_internal
 *
 * Description:
 *     Untar a file to a specific task.
 */
void untar_internal(FILE *a, const char *path);

#endif /* tar_h */
