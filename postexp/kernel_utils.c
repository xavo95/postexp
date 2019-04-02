//
//  kernel_utils.c
//  sefebreak
//
//  Created by Xavier Perarnau on 02/03/2019.
//  Copyright © 2019 Xavier Perarnau. All rights reserved.
//

#include "kernel_utils.h"

#include <mach-o/loader.h>

#include "kmem.h"
#include "mach_vm.h"
#include "offsetof.h"
#include "offsets.h"
#include <mach/mach.h>
#include <unistd.h>
#include "log.h"
#include "post-common.h"
#include "offsets_dump.h"

mach_port_t fake_host_priv_port = MACH_PORT_NULL;

uint64_t task_self_addr(void) {
    uint64_t selfproc = proc_of_pid(getpid());
    if (selfproc == 0) {
        ERROR("failed to find our task addr\n");
        return -1;
    }
    uint64_t addr = kernel_read64(selfproc + off_task);
    
    uint64_t task_addr = addr;
    uint64_t itk_space = kernel_read64(task_addr + off_itk_space);
    
    uint64_t is_table = kernel_read64(itk_space + off_ipc_space_is_table);
    
    uint32_t port_index = mach_task_self() >> 8;
    const int sizeof_ipc_entry_t = 0x18;
    
    uint64_t port_addr = kernel_read64(is_table + (port_index * sizeof_ipc_entry_t));
    
    return port_addr;
}

uint64_t ipc_space_kernel(void) {
    return kernel_read64(task_self_addr() + 0x60);
}

bool patch_host_priv(mach_port_t host) {
#define IO_ACTIVE 0x80000000
#define IKOT_HOST_PRIV 4
    // locate port in kernel
    uint64_t host_kaddr = find_port_address(host);
    
    // change port host type
    uint32_t old = kernel_read32(host_kaddr + 0x0);
    INFO("old host type: 0x%x", old);
    
    kernel_write32(host_kaddr + 0x0, IO_ACTIVE | IKOT_HOST_PRIV);
    
    uint32_t new = kernel_read32(host_kaddr);
    INFO("new host type: 0x%x", new);
    
    return ((IO_ACTIVE | IKOT_HOST_PRIV) == new) ? true : false;
}

uint64_t find_port_address(mach_port_name_t port) {
    uint64_t task_port_addr = task_self_addr();
    //uint64_t task_addr = TaskSelfAddr();
    uint64_t task_addr = kernel_read64(task_port_addr + off_ip_kobject);
    uint64_t itk_space = kernel_read64(task_addr + off_itk_space);
    
    uint64_t is_table = kernel_read64(itk_space + off_ipc_space_is_table);
    
    uint32_t port_index = port >> 8;
    const int sizeof_ipc_entry_t = 0x18;
    
    uint64_t port_addr = kernel_read64(is_table + (port_index * sizeof_ipc_entry_t));
    
    return port_addr;
}

// build a fake host priv port
mach_port_t fake_host_priv(void) {
    if (fake_host_priv_port != MACH_PORT_NULL) {
        return fake_host_priv_port;
    }
    // get the address of realhost:
    uint64_t hostport_addr = find_port_address(mach_host_self());
    uint64_t realhost = kernel_read64(hostport_addr + off_ip_kobject);
    
    // allocate a port
    mach_port_t port = MACH_PORT_NULL;
    kern_return_t err;
    err = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port);
    if (err != KERN_SUCCESS) {
        printf("[-] failed to allocate port\n");
        return MACH_PORT_NULL;
    }
    // get a send right
    mach_port_insert_right(mach_task_self(), port, port, MACH_MSG_TYPE_MAKE_SEND);
    
    // make sure port type has IKOT_HOST_PRIV
    patch_host_priv(port);
    
    // locate the port
    uint64_t port_addr = find_port_address(port);
    
    // change the space of the port
    kernel_write64(port_addr + _koffset(KSTRUCT_OFFSET_IPC_PORT_IP_RECEIVER), ipc_space_kernel());
    
    // set the kobject
    kernel_write64(port_addr + off_ip_kobject, realhost);
    
    fake_host_priv_port = port;
    
    return port;
}

uint64_t kernel_alloc_wired(uint64_t size) {
    if (kernel_task_port == MACH_PORT_NULL) {
        printf("[-] attempt to allocate kernel memory before any kernel memory write primitives available\n");
        sleep(3);
        return 0;
    }
    
    kern_return_t err;
    mach_vm_address_t addr = 0;
    mach_vm_size_t ksize = round_page_kernel(size);
    
    printf("[*] vm_kernel_page_size: %lx\n", vm_kernel_page_size);
    
    err = mach_vm_allocate(kernel_task_port, &addr, ksize+0x4000, VM_FLAGS_ANYWHERE);
    if (err != KERN_SUCCESS) {
        printf("[-] unable to allocate kernel memory via tfp0: %s %x\n", mach_error_string(err), err);
        sleep(3);
        return 0;
    }
    
    printf("[+] allocated address: %llx\n", addr);
    
    addr += 0x3fff;
    addr &= ~0x3fffull;
    
    printf("[*] address to wire: %llx\n", addr);
    
    err = mach_vm_wire(fake_host_priv(), kernel_task_port, addr, ksize, VM_PROT_READ|VM_PROT_WRITE);
    if (err != KERN_SUCCESS) {
        printf("[-] unable to wire kernel memory via tfp0: %s %x\n", mach_error_string(err), err);
        sleep(3);
        return 0;
    }
    return addr;
}

const uint64_t kernel_address_space_base = 0xffff000000000000;
void kernel_memcpy(uint64_t dest, uint64_t src, uint32_t length) {
    if (dest >= kernel_address_space_base) {
        // copy to kernel:
        kernel_write(dest, (void*) src, length);
    } else {
        // copy from kernel
        kernel_read(src, (void*)dest, length);
    }
}

uint64_t task_struct_of_pid(pid_t pid) {
    uint64_t task_kaddr = kernel_read64(task_self_addr() + _koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT));
    while (task_kaddr) {
        uint64_t proc = kernel_read64(task_kaddr + _koffset(KSTRUCT_OFFSET_TASK_BSD_INFO));
        uint32_t pd = kernel_read32(proc + off_p_pid);
        if (pd == pid) return task_kaddr;
        task_kaddr = kernel_read64(task_kaddr + _koffset(KSTRUCT_OFFSET_TASK_PREV));
    }
    return 0;
}

void convert_port_to_task_port(mach_port_t port, uint64_t space, uint64_t task_kaddr) {
    // now make the changes to the port object to make it a task port:
    uint64_t port_kaddr = find_port_address(port);
    
    kernel_write32(port_kaddr + _koffset(KSTRUCT_OFFSET_IPC_PORT_IO_BITS), 0x80000000 | 2);
    kernel_write32(port_kaddr + _koffset(KSTRUCT_OFFSET_IPC_PORT_IO_REFERENCES), 0xf00d);
    kernel_write32(port_kaddr + _koffset(KSTRUCT_OFFSET_IPC_PORT_IP_SRIGHTS), 0xf00d);
    kernel_write64(port_kaddr + _koffset(KSTRUCT_OFFSET_IPC_PORT_IP_RECEIVER), space);
    kernel_write64(port_kaddr + _koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT),  task_kaddr);
    
    // swap our receive right for a send right:
    uint64_t task_port_addr = task_self_addr();
    uint64_t task_addr = kernel_read64(task_port_addr + _koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT));
    uint64_t itk_space = kernel_read64(task_addr + _koffset(KSTRUCT_OFFSET_TASK_ITK_SPACE));
    uint64_t is_table = kernel_read64(itk_space + _koffset(KSTRUCT_OFFSET_IPC_SPACE_IS_TABLE));
    
    uint32_t port_index = port >> 8;
    const int sizeof_ipc_entry_t = 0x18;
    uint32_t bits = kernel_read32(is_table + (port_index * sizeof_ipc_entry_t) + 8); // 8 = offset of ie_bits in struct ipc_entry
    
#define IE_BITS_SEND (1<<16)
#define IE_BITS_RECEIVE (1<<17)
    
    bits &= (~IE_BITS_RECEIVE);
    bits |= IE_BITS_SEND;
    
    kernel_write32(is_table + (port_index * sizeof_ipc_entry_t) + 8, bits);
}

void make_port_fake_task_port(mach_port_t port, uint64_t task_kaddr) {
    convert_port_to_task_port(port, ipc_space_kernel(), task_kaddr);
}

uint64_t proc_of_pid(pid_t pid) {
    uint64_t proc = kernel_read64(kernel_read64(GETOFFSET(kernel_task)) + _koffset(KSTRUCT_OFFSET_TASK_BSD_INFO));
    while (proc) {
        if (kernel_read32(proc + _koffset(KSTRUCT_OFFSET_PROC_PID)) == pid)
            return proc;
        proc = kernel_read64(proc + _koffset(KSTRUCT_OFFSET_PROC_P_LIST));
    }
    return 0;

}

uint64_t slide_addr(uint64_t src_addr) {
    if (static_kernel) {
        return src_addr + kernel_slide;
    }
    return src_addr;
}

bool verify_tfp0() {
    size_t test_size = sizeof(uint64_t);
    uint64_t test_kptr = kalloc(test_size);
    if (test_kptr == 0) {
        ERROR("failed to allocate kernel memory!");
        return false;
    }
    uint64_t test_write_data = 0x4141414141414141;
    if (!kernel_write(test_kptr, (void *)&test_write_data, test_size)) {
        ERROR("failed to write to kernel memory!");
        return false;
    }
    uint64_t test_read_data = 0;
    if (!kernel_read(test_kptr, (void *)&test_read_data, test_size)) {
        ERROR("failed to read kernel memory!");
        return false;
    }
    if (test_write_data != test_read_data) {
        ERROR("failed to verify kernel memory read data!");
        return false;
    }
    if (!kfree(test_kptr, test_size)) {
        ERROR("failed to deallocate kernel memory!");
        return false;
    }
    return true;
}

uint64_t find_kernel_base(void) {
    host_t host = mach_host_self();
    uint64_t hostport_addr = get_address_of_port(getpid(), host);
    mach_port_deallocate(mach_task_self(), host);
    uint64_t realhost = kernel_read64(hostport_addr + _koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT));
    
    uint64_t base = realhost & ~0xfffULL;
    // walk down to find the magic:
    for (int i = 0; i < 0x10000; i++) {
        if (kernel_read32(base) == MH_MAGIC_64) {
            return base;
        }
        base -= 0x1000;
    }
    return 0;
}

uint64_t get_address_of_port(pid_t pid, mach_port_t port) {
    static uint64_t proc_struct_addr = 0;
    static uint64_t task_addr = 0;
    static uint64_t itk_space = 0;
    static uint64_t is_table = 0;
    if (proc_struct_addr == 0) {
        proc_struct_addr = proc_of_pid(pid);
        INFO("proc_struct_addr = %llu", proc_struct_addr);
        if (proc_struct_addr == 0) {
            ERROR("failed to get proc_struct_addr!");
            return 0;
        }
    }
    if (task_addr == 0) {
        task_addr = kernel_read64(proc_struct_addr + off_task);
        INFO("task_addr = %llu", task_addr);
        if (task_addr == 0) {
            ERROR("failed to get task_addr!");
            return 0;
        }
    }
    if (itk_space == 0) {
        itk_space = kernel_read64(task_addr + _koffset(KSTRUCT_OFFSET_TASK_ITK_SPACE));
        INFO("itk_space = %llu", itk_space);
        if (itk_space == 0) {
            ERROR("failed to get itk_space!");
            return 0;
        }
    }
    if (is_table == 0) {
        is_table = kernel_read64(itk_space + _koffset(KSTRUCT_OFFSET_IPC_SPACE_IS_TABLE));
        INFO("is_table = %llu", is_table);
        if (is_table == 0) {
            ERROR("failed to get is_table!");
            return 0;
        }
    }
    uint32_t port_index = port >> 8;
    const int sizeof_ipc_entry_t = 0x18;
    uint64_t port_addr = kernel_read64(is_table + (port_index * sizeof_ipc_entry_t));
    INFO("port_addr = %llu", port_addr);
    if (port_addr == 0) {
        ERROR("failed to get port_addr!");
        return 0;
    }
    return port_addr;
}
