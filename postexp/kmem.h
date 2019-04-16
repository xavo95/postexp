/*
 * kernel_memory.h
 * Brandon Azad
 */
#ifndef VOUCHER_SWAP__KERNEL_MEMORY_H_
#define VOUCHER_SWAP__KERNEL_MEMORY_H_

#include <mach/mach.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef KERNEL_MEMORY_EXTERN
#define extern KERNEL_MEMORY_EXTERN
#endif

/*
 * kernel_base
 *
 * Description:
 *     The static kernel base.
 */
uint64_t static_kernel_base = 0xFFFFFFF007004000;

/*
 * static_kernel
 *
 * Description:
 *     If kernel analyzed by patchfinder is static or not.
 */
bool static_kernel;

/*
 * kernel_slide
 *
 * Description:
 *     The kASLR slide.
 */
extern uint64_t kernel_slide;

/*
 * kernel_load_base
 *
 * Description:
 *     The slided kernel address.
 */
uint64_t kernel_load_base;

/*
 * kernel_task_port
 *
 * Description:
 * 	The kernel task port.
 */
extern mach_port_t kernel_task_port;

/*
 * current_task
 *
 * Description:
 * 	The address of the current task in kernel memory.
 */
extern uint64_t current_task;

/*
 * kernel_read_internal
 *
 * Description:
 * 	Read data from kernel memory.
 */
bool kernel_read_internal(uint64_t address, void *data, size_t size);

/*
 * kernel_write_internal
 *
 * Description:
 * 	Write data to kernel memory.
 */
bool kernel_write_internal(uint64_t address, const void *data, size_t size);

/*
 * kernel_read8_internal
 *
 * Description:
 * 	Read a single byte from kernel memory. If the read fails, -1 is returned.
 */
uint8_t kernel_read8_internal(uint64_t address);

/*
 * kernel_read16_internal
 *
 * Description:
 * 	Read a 16-bit value from kernel memory. If the read fails, -1 is returned.
 */
uint16_t kernel_read16_internal(uint64_t address);

/*
 * kernel_read32_internal
 *
 * Description:
 * 	Read a 32-bit value from kernel memory. If the read fails, -1 is returned.
 */
uint32_t kernel_read32_internal(uint64_t address);

/*
 * kernel_read64_internal
 *
 * Description:
 * 	Read a 64-bit value from kernel memory. If the read fails, -1 is returned.
 */
uint64_t kernel_read64_internal(uint64_t address);

/*
 * kernel_write8_internal
 *
 * Description:
 * 	Write a single byte to kernel memory.
 */
bool kernel_write8_internal(uint64_t address, uint8_t value);

/*
 * kernel_write16_internal
 *
 * Description:
 * 	Write a 16-bit value to kernel memory.
 */
bool kernel_write16_internal(uint64_t address, uint16_t value);

/*
 * kernel_write32_internal
 *
 * Description:
 * 	Write a 32-bit value to kernel memory.
 */
bool kernel_write32_internal(uint64_t address, uint32_t value);

/*
 * kernel_write64_internal
 *
 * Description:
 * 	Write a 64-bit value to kernel memory.
 */
bool kernel_write64_internal(uint64_t address, uint64_t value);

/*
 * kalloc_internal
 *
 * Description:
 *     Allocate data to kernel memory.
 */
uint64_t kalloc_internal(vm_size_t size);

/*
 * kfree_internal
 *
 * Description:
 *     Free data from kernel memory.
 */
bool kfree_internal(mach_vm_address_t address, vm_size_t size);

/*
 * kread_internal
 *
 * Description:
 *     Reads data from kernel memory.
 */
size_t kread_internal(uint64_t where, void *p, size_t size);

/*
 * kread_pf
 *
 * Description:
 *     Reads data from kernel memory in chuck(for huge amount of memory).
 */
size_t kread_pf(uint64_t where, void *p, size_t size);

#undef extern

#endif
