#include <sys/param.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>

#include <mach/mach.h>
#include <mach/error.h>

#include "postexp.h"

int main(int argc, char* argv[]) {
    printf("the fun and games shall begin! (applying lube...)\n");

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

    #define MEMORYSTATUS_CMD_SET_JETSAM_TASK_LIMIT 6
    extern int memorystatus_control(uint32_t command, int32_t pid, uint32_t flags, void *buffer, size_t buffersize);

    if (kernel_call_init() && memorystatus_control(MEMORYSTATUS_CMD_SET_JETSAM_TASK_LIMIT, getpid(), 0, NULL, 0) == 0) {
        printf("Initialized successfully!\n");
        printf("Terminating kexecute\n");
        kernel_call_deinit();
        return 0;
    } else {
        printf("Failed to initialize kexecute :(");
        return -1;
    }   
}