/*
 * kernel_memory.c
 * Brandon Azad
 */
#define KERNEL_MEMORY_EXTERN
#include "kmem.h"

#include "log.h"
#include "mach_vm.h"
#include "offsets.h"

// ---- Kernel memory functions -------------------------------------------------------------------

bool
kernel_read(uint64_t address, void *data, size_t size) {
	mach_vm_size_t size_out;
	kern_return_t kr = mach_vm_read_overwrite(kernel_task_port, address,
			size, (mach_vm_address_t) data, &size_out);
	if (kr != KERN_SUCCESS) {
		ERROR("%s returned %d: %s", "mach_vm_read_overwrite", kr, mach_error_string(kr));
		ERROR("could not %s address 0x%016llx", "read", address);
		return false;
	}
	if (size_out != size) {
		ERROR("partial read of address 0x%016llx: %llu of %zu bytes",
				address, size_out, size);
		return false;
	}
	return true;
}

bool
kernel_write(uint64_t address, const void *data, size_t size) {
	kern_return_t kr = mach_vm_write(kernel_task_port, address,
			(mach_vm_address_t) data, (mach_msg_size_t) size);
	if (kr != KERN_SUCCESS) {
		ERROR("%s returned %d: %s", "mach_vm_write", kr, mach_error_string(kr));
		ERROR("could not %s address 0x%016llx", "write", address);
		return false;
	}
	return true;
}

uint8_t
kernel_read8(uint64_t address) {
	uint8_t value;
	bool ok = kernel_read(address, &value, sizeof(value));
	if (!ok) {
		return -1;
	}
	return value;
}

uint16_t
kernel_read16(uint64_t address) {
	uint16_t value;
	bool ok = kernel_read(address, &value, sizeof(value));
	if (!ok) {
		return -1;
	}
	return value;
}

uint32_t
kernel_read32(uint64_t address) {
	uint32_t value;
	bool ok = kernel_read(address, &value, sizeof(value));
	if (!ok) {
		return -1;
	}
	return value;
}

uint64_t
kernel_read64(uint64_t address) {
	uint64_t value;
	bool ok = kernel_read(address, &value, sizeof(value));
	if (!ok) {
		return -1;
	}
	return value;
}

bool
kernel_write8(uint64_t address, uint8_t value) {
	return kernel_write(address, &value, sizeof(value));
}

bool
kernel_write16(uint64_t address, uint16_t value) {
	return kernel_write(address, &value, sizeof(value));
}

bool
kernel_write32(uint64_t address, uint32_t value) {
	return kernel_write(address, &value, sizeof(value));
}

bool
kernel_write64(uint64_t address, uint64_t value) {
	return kernel_write(address, &value, sizeof(value));
}

uint64_t kalloc(vm_size_t size) {
    mach_vm_address_t address = 0;
    mach_vm_allocate(kernel_task_port, (mach_vm_address_t *)&address, size, VM_FLAGS_ANYWHERE);
    return address;
}

bool kfree(mach_vm_address_t address, vm_size_t size) {
    kern_return_t kr = mach_vm_deallocate(kernel_task_port, address, size);
    if (kr != KERN_SUCCESS) {
        return false;
    }
    return true;
}

size_t kread(uint64_t address, void *data, size_t size) {
    mach_vm_size_t size_out;
    kern_return_t kr = mach_vm_read_overwrite(kernel_task_port, address,
                                              size, (mach_vm_address_t) data, &size_out);
    if (kr != KERN_SUCCESS) {
        ERROR("%s returned %d: %s", "mach_vm_read_overwrite", kr, mach_error_string(kr));
        ERROR("could not %s address 0x%016llx", "read", address);
        return -1;
    }
    return size_out;
}

size_t kread_pf(uint64_t where, void *p, size_t size) {
    int rv;
    size_t offset = 0;
    while (offset < size) {
        mach_vm_size_t sz, chunk = 0xFFF;
        if (chunk > size - offset) {
            chunk = size - offset;
        }
        rv = mach_vm_read_overwrite(kernel_task_port, where + offset, chunk, (mach_vm_address_t)p + offset, &sz);
        if (rv || sz == 0) {
            ERROR(" error reading kernel @%p\n", (void *)(offset + where));
            break;
        }
        offset += sz;
    }
    return offset;
}
