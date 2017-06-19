//===------------------------------------------------------------*- C++ -*-===//
//
//                     Created by F8LEFT on 2017/6/13.
//                   Copyright (c) 2017. All rights reserved.
//===--------------------------------------------------------------------------
//
//===----------------------------------------------------------------------===//

#include "FAGotHook.h"
#include "MinAndroidDef.h"
#include <dlfcn.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>

FAGotHook::FAGotHook(const char *libName, Config* config)
    : name(libName)
{
    if(config != nullptr) {
        check_ehdr = config->check_ehdr;
        unprotect_got_memory = config->unprotect_got_memory;
        with_local_func = config->with_local_func;
    }

    // load from map
    load_bias_ = loadFromMap(libName);

    // Parse elf file
    is_valid_ = Load();
}


bool FAGotHook::Load() {
    return ReadElfHeader() &&
           (check_ehdr ? VerifyElfHeader(): true) &&
           FindPhdr() &&
           ReadSoInfo() &&
           ReadGotInfo();
}

bool FAGotHook::ReadElfHeader() {
    if(load_bias_ == 0) {
        FLOGE(Unable to find so file %s in map, name.c_str());
        return false;
    }
    header_ = (Elf_Ehdr*)load_bias_;
    return true;
}

bool FAGotHook::VerifyElfHeader() {
    if (header_->e_ident[EI_MAG0] != ELFMAG0 ||
        header_->e_ident[EI_MAG1] != ELFMAG1 ||
        header_->e_ident[EI_MAG2] != ELFMAG2 ||
        header_->e_ident[EI_MAG3] != ELFMAG3) {
        FLOGE(link so %s has bad ELF magic, name.c_str());
        return false;
    }
#ifndef S64
    if (header_->e_ident[EI_CLASS] != ELFCLASS32) {
        FLOGE(not 32-bit so file %s %d, name.c_str(), header_->e_ident[EI_CLASS]);
        return false;
    }
#else
    if (header_->e_ident[EI_CLASS] != ELFCLASS64) {
        FLOGE(not 64-bit so file %s %d, name.c_str(), header_->e_ident[EI_CLASS]);
        return false;
    }
#endif

    if (header_->e_ident[EI_DATA] != ELFDATA2LSB) {
        FLOGE(not little-endian %s %d, name.c_str(), header_->e_ident[EI_DATA]);
        return false;
    }

    if (header_->e_type != ET_DYN) {
        FLOGE(has unexpected e_type %s %d, name.c_str(), header_->e_type);
        return false;
    }

    if (header_->e_version != EV_CURRENT) {
        FLOGE(has unexpected e_version %s %d, name.c_str(), header_->e_version);
        return false;
    }

    return true;
}

/* Return the address and size of the ELF file's .dynamic section in memory,
 * or NULL if missing.
 *
 * Input:
 *   phdr_table  -> program header table
 *   phdr_count  -> number of entries in tables
 *   load_bias   -> load bias
 * Output:
 *   dynamic       -> address of table in memory (NULL on failure).
 *   dynamic_count -> number of items in table (0 on failure).
 *   dynamic_flags -> protection flags for section (unset on failure)
 * Return:
 *   void
 */
void FAGotHook::phdr_table_get_dynamic_section(const Elf_Phdr* phdr_table,
                               int               phdr_count,
                               Elf_Addr        load_bias,
                               Elf_Dyn**       dynamic,
                               size_t*           dynamic_count,
                               Elf_Word*       dynamic_flags)
{
    const Elf_Phdr* phdr = phdr_table;
    const Elf_Phdr* phdr_limit = phdr + phdr_count;

    for (phdr = phdr_table; phdr < phdr_limit; phdr++) {
        if (phdr->p_type != PT_DYNAMIC) {
            continue;
        }

        *dynamic = reinterpret_cast<Elf_Dyn*>(load_bias + phdr->p_vaddr);
        if (dynamic_count) {
            *dynamic_count = (unsigned)(phdr->p_memsz / sizeof(Elf_Dyn));
        }
        if (dynamic_flags) {
            *dynamic_flags = phdr->p_flags;
        }
        return;
    }
    *dynamic = NULL;
    if (dynamic_count) {
        *dynamic_count = 0;
    }
}

// Returns the address of the program header table as it appears in the loaded
// segments in memory. This is in contrast with 'phdr_table_' which
// is temporary and will be released before the library is relocated.
bool FAGotHook::FindPhdr() {
    phdr_table_ = (Elf_Phdr *) (header_->e_phoff + load_bias_);
    phdr_num_ = header_->e_phnum;

    const Elf_Phdr* phdr_limit = phdr_table_ + phdr_num_;

    // If there is a PT_PHDR, use it directly.
    for (const Elf_Phdr* phdr = phdr_table_; phdr < phdr_limit; ++phdr) {
        if (phdr->p_type == PT_PHDR) {
            return CheckPhdr(load_bias_ + phdr->p_vaddr);
        }
    }

    // Otherwise, check the first loadable segment. If its file offset
    // is 0, it starts with the ELF header, and we can trivially find the
    // loaded program header from it.
    for (const Elf_Phdr* phdr = phdr_table_; phdr < phdr_limit; ++phdr) {
        if (phdr->p_type == PT_LOAD) {
            if (phdr->p_offset == 0) {
                Elf_Addr  elf_addr = load_bias_ + phdr->p_vaddr;
                const Elf_Ehdr* ehdr = (const Elf_Ehdr*)(void*)elf_addr;
                Elf_Addr  offset = ehdr->e_phoff;
                return CheckPhdr((Elf_Addr)ehdr + offset);
            }
            break;
        }
    }

    FLOGE(%s cant find loaded phdr, name.c_str());
    return false;
}

// Ensures that our program header is actually within a loadable
// segment. This should help catch badly-formed ELF files that
// would cause the linker to crash later when trying to access it.
bool FAGotHook::CheckPhdr(Elf_Addr loaded) {
    const Elf_Phdr* phdr_limit = phdr_table_ + phdr_num_;
    Elf_Addr loaded_end = loaded + (phdr_num_ * sizeof(Elf_Phdr));
    for (Elf_Phdr* phdr = phdr_table_; phdr < phdr_limit; ++phdr) {
        if (phdr->p_type != PT_LOAD) {
            continue;
        }
        Elf_Addr seg_start = phdr->p_vaddr + load_bias_;
        Elf_Addr seg_end = phdr->p_filesz + seg_start;
        if (seg_start <= loaded && loaded_end <= seg_end) {
            loaded_phdr_ = reinterpret_cast<const Elf_Phdr*>(loaded);
            return true;
        }
    }
    FLOGE(%s loaded phdr %x not in loadable segment, name.c_str(), loaded);
    return false;
}

bool FAGotHook::ReadSoInfo() {

    Elf_Word dynamic_flags;


    /* Extract dynamic section */
    phdr_table_get_dynamic_section(loaded_phdr_, phdr_num_, load_bias_, &dynamic_start,
                                   &dynamic_count, &dynamic_flags);
    if(dynamic_start == nullptr) {
        FLOGE(%s has No valid dynamic phdr data, name.c_str());
        return false;
    }

    // Extract useful information from dynamic section.
    for (Elf_Dyn* d = dynamic_start; d->d_tag != DT_NULL; ++d) {
        switch(d->d_tag){
            case DT_PLTRELSZ:
                plt_rel_count = d->d_un.d_val / sizeof(Elf_Rel);
                break;
            case DT_PLTGOT:
                plt_got = (Elf_Addr *)(load_bias_ + d->d_un.d_ptr);
                break;
            default:
                break;
        }
    }
    return true;
}

bool FAGotHook::ReadGotInfo() {
    if(plt_got == nullptr) {
        return false;
    }

    got_start = plt_got;
    // skip empty padding
    for(auto i = 0; i < 4; i++, got_start++) {
        if(*got_start != 0) {
            break;
        }
    }
    got_end = got_start + plt_rel_count;
    if(with_local_func) {
        got_start = (Elf_Addr *) (dynamic_start + dynamic_count);
    }


    if(unprotect_got_memory) {
        unProtectMemory(got_start, got_end - got_start);
    }
    return true;
}

bool FAGotHook::rebindFunc(Elf_Addr originalFunc, Elf_Addr newFunc) {
    if(!is_valid_) {
        FLOGE(%s has no valid got information, name.c_str());
        return false;
    }

    for(auto func = got_start; func <= got_end; func++) {
        if(*func == originalFunc) {
            if(unprotect_got_memory) {
                *func = newFunc;
            } else {
                unProtectMemory(func, sizeof(Elf_Addr));
                *func = newFunc;
                protectMemory(func, sizeof(Elf_Addr));
            }

            return true;
        }
    }
    FLOGE(Unable to hook function %s %p into %p, name.c_str(), originalFunc, newFunc);
    return false;
}

Elf_Addr FAGotHook::loadFromMap(const char *name) {
    auto fd = fopen("/proc/self/maps", "r");
    if(fd == nullptr) {
        return 0;
    }
    char buf[256];
    while(fgets(buf, 256, fd) != nullptr) {
        if(strstr(buf, name)) {
            fclose(fd);
#ifndef S64
            auto start = strtoul(buf, 0, 16);
            return start;
#else
            auto start = strtoull(buf, 0, 16);
            return start;
#endif
        }
    }
    fclose(fd);
    return 0;
}

bool FAGotHook::unProtectMemory(void *addr, uint32_t size) {
    auto page_size = sysconf(_SC_PAGESIZE);
    auto align = ((size_t)addr) % page_size;
    return mprotect((uint8_t*)addr - align, size + align, PROT_READ|PROT_WRITE) != -1;
}

bool FAGotHook::protectMemory(void *addr, uint32_t size) {
    auto page_size = sysconf(_SC_PAGESIZE);
    auto align = ((size_t)addr) % page_size;
    return mprotect((uint8_t*)addr - align, size + align, PROT_READ) != -1;
}