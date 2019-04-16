//  Comes from Electra, adapted for FAT binary support by me
//
//  amfi_utils.c
//  electra
//
//  Created by Jamie on 27/01/2018.
//  Copyright © 2018 Electra Team. All rights reserved.
//

#include "amfi_utils.h"
#include "offsets_dump.h"
#include "macho-helper.h"
#include "kmem.h"
#include "kernel_call.h"
#include "kernel_utils.h"
#include "post-common.h"
#include <stdlib.h>
#include <string.h>
#include <mach-o/loader.h>
#include <mach-o/fat.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <CommonCrypto/CommonDigest.h>
#include <Foundation/Foundation.h>
#include "log.h"

uint32_t swap_uint32( uint32_t val ) {
    val = ((val << 8) & 0xFF00FF00 ) | ((val >> 8) & 0xFF00FF );
    return (val << 16) | (val >> 16);
}

uint32_t read_magic(FILE* file, off_t offset) {
    uint32_t magic;
    fseek(file, offset, SEEK_SET);
    fread(&magic, sizeof(uint32_t), 1, file);
    return magic;
}

void getSHA256inplace(const uint8_t* code_dir, uint8_t *out) {
    if (code_dir == NULL) {
        INFO("NULL passed to getSHA256inplace!");
        return;
    }
    uint32_t* code_dir_int = (uint32_t*)code_dir;
    
    uint32_t realsize = 0;
    for (int j = 0; j < 10; j++) {
        if (swap_uint32(code_dir_int[j]) == 0xfade0c02) {
            realsize = swap_uint32(code_dir_int[j+1]);
            code_dir += 4*j;
        }
    }
    
    CC_SHA256(code_dir, realsize, out);
}

uint8_t *getSHA256(const uint8_t* code_dir) {
    uint8_t *out = malloc(CC_SHA256_DIGEST_LENGTH);
    getSHA256inplace(code_dir, out);
    return out;
}

uint8_t *getCodeDirectory(const char* name) {
    
    FILE* fd = fopen(name, "r");
    
    uint32_t magic;
    fread(&magic, sizeof(magic), 1, fd);
    fseek(fd, 0, SEEK_SET);
    
    long off = 0, file_off = 0;
    int ncmds = 0;
    BOOL foundarm64 = false;
    
    if (magic == MH_MAGIC_64) { // 0xFEEDFACF
        struct mach_header_64 mh64;
        fread(&mh64, sizeof(mh64), 1, fd);
        off = sizeof(mh64);
        ncmds = mh64.ncmds;
    }
    else if (magic == MH_MAGIC) {
        ERROR("%s is 32bit. What are you doing here?", name);
        fclose(fd);
        return NULL;
    }
    else if (magic == 0xBEBAFECA) { //FAT binary magic
        
        size_t header_size = sizeof(struct fat_header);
        size_t arch_size = sizeof(struct fat_arch);
        size_t arch_off = header_size;
        
        struct fat_header *fat = (struct fat_header*)load_bytes(fd, 0, header_size);
        struct fat_arch *arch = (struct fat_arch *)load_bytes(fd, arch_off, arch_size);
        
        int n = swap_uint32(fat->nfat_arch);
        INFO("binary is FAT with %d architectures", n);
        
        while (n-- > 0) {
            magic = read_magic(fd, swap_uint32(arch->offset));
            
            if (magic == 0xFEEDFACF) {
                INFO("found arm64");
                foundarm64 = true;
                struct mach_header_64* mh64 = (struct mach_header_64*)load_bytes(fd, swap_uint32(arch->offset), sizeof(struct mach_header_64));
                file_off = swap_uint32(arch->offset);
                off = swap_uint32(arch->offset) + sizeof(struct mach_header_64);
                ncmds = mh64->ncmds;
                break;
            }
            
            arch_off += arch_size;
            arch = load_bytes(fd, arch_off, arch_size);
        }
        
        if (!foundarm64) { // by the end of the day there's no arm64 found
            ERROR("No arm64? RIP");
            fclose(fd);
            return NULL;
        }
    }
    else {
        ERROR("%s is not a macho! (or has foreign endianness?) (magic: %x)", name, magic);
        fclose(fd);
        return NULL;
    }
    
    for (int i = 0; i < ncmds; i++) {
        struct load_command cmd;
        fseek(fd, off, SEEK_SET);
        fread(&cmd, sizeof(struct load_command), 1, fd);
        if (cmd.cmd == LC_CODE_SIGNATURE) {
            uint32_t off_cs;
            fread(&off_cs, sizeof(uint32_t), 1, fd);
            uint32_t size_cs;
            fread(&size_cs, sizeof(uint32_t), 1, fd);
            
            uint8_t *cd = malloc(size_cs);
            fseek(fd, off_cs + file_off, SEEK_SET);
            fread(cd, size_cs, 1, fd);
            fclose(fd);
            return cd;
        } else {
            off += cmd.cmdsize;
        }
    }
    fclose(fd);
    return NULL;
}

//from xerub
int strtail(const char *str, const char *tail)
{
    size_t lstr = strlen(str);
    size_t ltail = strlen(tail);
    if (ltail > lstr) {
        return -1;
    }
    str += lstr - ltail;
    return memcmp(str, tail, ltail);
}

/*
 * inject_trusts
 *
 * Description:
 *     Injects to trustcache.
 */
void inject_trusts(int pathc, NSMutableArray *paths) {
    INFO("injecting into trust cache...");
    
    static uint64_t tc = 0;
    if (tc == 0) {
        tc = GETOFFSET(trustcache);
    }
    
    INFO("trust cache: 0x%llx", tc);
    
    struct trust_chain fake_chain;
    fake_chain.next = kernel_read64_internal(tc);
#if __arm64e__
    arc4random_buf(&fake_chain.uuid, 16);
#else
    *(uint64_t *)&fake_chain.uuid[0] = 0xabadbabeabadbabe;
    *(uint64_t *)&fake_chain.uuid[8] = 0xabadbabeabadbabe;
#endif
    
    int cnt = 0;
    uint8_t hash[CC_SHA256_DIGEST_LENGTH];
    hash_t *allhash = malloc(sizeof(hash_t) * pathc);
    for (int i = 0; i != pathc; ++i) {
        uint8_t *cd = getCodeDirectory((char*)[[paths objectAtIndex:i] UTF8String]);
        if (cd != NULL) {
            getSHA256inplace(cd, hash);
            memmove(allhash[cnt], hash, sizeof(hash_t));
            ++cnt;
        }
    }
    
    fake_chain.count = cnt;
    
    size_t length = (sizeof(fake_chain) + cnt * sizeof(hash_t) + 0x3FFF) & ~0x3FFF;
    uint64_t kernel_trust = kalloc_internal(length);
    INFO("kalloc: 0x%llx", kernel_trust);
    
    INFO("writing fake_chain");
    kernel_write_internal(kernel_trust, &fake_chain, sizeof(fake_chain));
    INFO("writing allhash");
    kernel_write_internal(kernel_trust + sizeof(fake_chain), allhash, cnt * sizeof(hash_t));
    INFO("writing trust cache");
    
#if __arm64e__
    uint64_t f_load_trust_cache = 0;
    f_load_trust_cache = GETOFFSET(f_load_trust_cache);
    uint32_t ret = kernel_call_7_internal(f_load_trust_cache, 3,
                                 kernel_trust,
                                 length,
                                 0);
    INFO("load_trust_cache: 0x%x", ret);
#else
    kernel_write64_internal(tc, kernel_trust);
#endif
    
    INFO("injected trust cache");
}

/*
 * trustbin
 *
 * Description:
 *     Injects to trustcache.
 */
int trustbin(const char *path) {
    NSMutableArray *paths = [NSMutableArray array];
    NSFileManager *fileManager = [NSFileManager defaultManager];
    
    BOOL isDir = NO;
    if (![fileManager fileExistsAtPath:@(path) isDirectory:&isDir]) {
        ERROR("path does not exist!");
        return -1;
    }
    
    NSURL *directoryURL = [NSURL URLWithString:@(path)];
    NSArray *keys = [NSArray arrayWithObject:NSURLIsDirectoryKey];
    
    if (isDir) {
        NSDirectoryEnumerator *enumerator = [fileManager
                                             enumeratorAtURL:directoryURL
                                             includingPropertiesForKeys:keys
                                             options:0
                                             errorHandler:^(NSURL *url, NSError *error) {
                                             if (error) ERROR("%s", [[error localizedDescription] UTF8String]);
                                             return YES;
                                             }];
        
        for (NSURL *url in enumerator) {
            NSError *error;
            NSNumber *isDirectory = nil;
            if (![url getResourceValue:&isDirectory forKey:NSURLIsDirectoryKey error:&error]) {
                if (error) continue;
            }
            else if (![isDirectory boolValue]) {
                
                int rv;
                int fd;
                uint8_t *p;
                off_t sz;
                struct stat st;
                uint8_t buf[16];
                
                char *fpath = strdup([[url path] UTF8String]);
                
                if (strtail(fpath, ".plist") == 0 || strtail(fpath, ".nib") == 0 || strtail(fpath, ".strings") == 0 || strtail(fpath, ".png") == 0) {
                    continue;
                }
                
                rv = lstat(fpath, &st);
                if (rv || !S_ISREG(st.st_mode) || st.st_size < 0x4000) {
                    continue;
                }
                
                fd = open(fpath, O_RDONLY);
                if (fd < 0) {
                    continue;
                }
                
                sz = read(fd, buf, sizeof(buf));
                if (sz != sizeof(buf)) {
                    close(fd);
                    continue;
                }
                if (*(uint32_t *)buf != 0xBEBAFECA && !MACHO(buf)) {
                    close(fd);
                    continue;
                }
                
                p = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
                if (p == MAP_FAILED) {
                    close(fd);
                    continue;
                }
                
                [paths addObject:@(fpath)];
                INFO("will trust %s", fpath);
                free(fpath);
            }
        }
        if ([paths count] == 0) {
            ERROR("no files in %s passed the integrity checks!", path);
            return -2;
        }
    }
    else {
        INFO("will trust %s", path);
        [paths addObject:@(path)];
        
        int rv;
        int fd;
        uint8_t *p;
        off_t sz;
        struct stat st;
        uint8_t buf[16];
        
        if (strtail(path, ".plist") == 0 || strtail(path, ".nib") == 0 || strtail(path, ".strings") == 0 || strtail(path, ".png") == 0) {
            ERROR("binary not an executable! Kernel doesn't like trusting data, geez");
            return 2;
        }
        
        rv = lstat(path, &st);
        if (rv || !S_ISREG(st.st_mode) || st.st_size < 0x4000) {
            ERROR("binary too big");
            return 3;
        }
        
        fd = open(path, O_RDONLY);
        if (fd < 0) {
            ERROR("don't have permission to open file");
            return 4;
        }
        
        sz = read(fd, buf, sizeof(buf));
        if (sz != sizeof(buf)) {
            close(fd);
            ERROR("failed to read from binary");
            return 5;
        }
        if (*(uint32_t *)buf != 0xBEBAFECA && !MACHO(buf)) {
            close(fd);
            ERROR("binary not a macho!");
            return 6;
        }
        
        p = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
        if (p == MAP_FAILED) {
            close(fd);
            ERROR("failed to mmap file");
            return 7;
        }
    }
    
    inject_trusts([paths count], paths);
    return 0;
}
