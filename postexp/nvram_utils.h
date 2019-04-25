//
//  nvram_utils.h
//  postexp
//
//  Created by Xavier Perarnau on 25/04/2019.
//  Copyright © 2019 xavo95. All rights reserved.
//

#ifndef nvram_utils_h
#define nvram_utils_h

#include <stdio.h>

/*
 * unlock_nvram
 *
 * Description:
 *     Unlocks NVRAM for setting boot nonce.
 */
void unlock_nvram_internal(void);

/*
 * lock_nvram
 *
 * Description:
 *     Locks NVRAM after setting boot nonce.
 */
int lock_nvram_internal(void);

#endif /* nvram_utils_h */
