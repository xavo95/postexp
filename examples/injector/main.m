/*
 *  main.m
 *  
 *  Created by Xavier Perarnau on 17/07/019
 *  Copyright 2019 Xavier Perarnau. All Rights Reserved.
 *
 */

#include <Foundation/Foundation.h>
#include <CoreFoundation/CoreFoundation.h>
#include "postexp.h"

int main(int argc, char* argv[]) {
    if (argc < 2) {
        fprintf(stderr,"Usage: inject /full/path/to/executable\n");
        fprintf(stderr,"Inject executables to trust cache\n");
        return -1;
    }
    mach_port_t tfpzero;
    uint64_t ext_kernel_slide;
    uint64_t ext_kernel_load_base;

    enum post_exp_t res = recover_with_hsp4(&tfpzero, &ext_kernel_slide, &ext_kernel_load_base);
    if((res == ERROR_TFP0_NOT_RECOVERED) || !verify_tfp0()) {
        fprintf(stderr, "Unable to obtain tfp0\n");
        return -2;
    }
    printf("Got working TFP0.\n");
    printf("Kernel_slide: %llu\n", ext_kernel_slide);
    printf("Lernel_load_base: %llu\n", ext_kernel_load_base);
  @autoreleasepool {
    printf("Injecting to trust cache...\n");
    enum post_exp_t ret = NO_ERROR;
    for (int i=1; i<argc; i++) {
        ret = add_to_trustcache(argv[i]);
        if (ret != 0) {
            printf("Error %d injecting to trust cache.\n", ret);
            break;
        } else {
            printf("Successfully injected [%d/%d] paths to trust cache.\n", i, argc - 1);
        }
    }
    return ret;
  }
}