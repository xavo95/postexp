/*
 * kernel_call.c
 * Brandon Azad
 */
#include "kernel_call.h"

#include <assert.h>

#include "pac.h"
#include "user_client.h"
#include "log.h"

static bool kernel_call_inited = false;

// ---- Public API --------------------------------------------------------------------------------

bool
kernel_call_init_internal() {
    if(!kernel_call_inited) {
        bool ok = stage1_kernel_call_init()
        && stage2_kernel_call_init()
        && stage3_kernel_call_init();
        kernel_call_inited = true;
        if (!ok) {
            kernel_call_deinit_internal();
        }
        return ok;
    }
    return true;
}

void
kernel_call_deinit_internal() {
    if(kernel_call_inited) {
        stage3_kernel_call_deinit();
        stage2_kernel_call_deinit();
        stage1_kernel_call_deinit();
        kernel_call_inited = false;
    }
}

uint32_t
kernel_call_7_internal(uint64_t function, size_t argument_count, ...) {
	assert(argument_count <= 7);
	uint64_t arguments[7];
	va_list ap;
	va_start(ap, argument_count);
	for (size_t i = 0; i < argument_count && i < 7; i++) {
		arguments[i] = va_arg(ap, uint64_t);
	}
	va_end(ap);
	return kernel_call_7v(function, argument_count, arguments);
}
