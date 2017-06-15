//===------------------------------------------------------------*- C++ -*-===//
//
//                     Created by F8LEFT on 2017/6/13.
//                   Copyright (c) 2017. All rights reserved.
//===--------------------------------------------------------------------------
// hook so got table.
//===----------------------------------------------------------------------===//

#ifndef FAGOTHOOK_FAGOTHOOK_H
#define FAGOTHOOK_FAGOTHOOK_H

#include <cwchar>
#include <string>
#include "elf.h"


#if defined(__arm__)
#define S32
#elif defined(__aarch64__)
#define S64
#elif defined(__i386__)
#define S32
#elif defined(__x86_64__)
#define S64
#elif defined(__mips64)  /* mips64el-* toolchain defines __mips__ too */
#define S64
#elif defined(__mips__)
#define S32
#endif

#ifndef S64
typedef Elf32_Ehdr Elf_Ehdr;
typedef Elf32_Phdr Elf_Phdr;
typedef Elf32_Shdr Elf_Shdr;
typedef Elf32_Sym Elf_Sym;
typedef Elf32_Rel Elf_Rel;
typedef Elf32_Rela Elf_Rela;
typedef Elf32_Addr Elf_Addr;
typedef Elf32_Dyn Elf_Dyn;
typedef Elf32_Word Elf_Word;
#else
typedef Elf64_Ehdr Elf_Ehdr;
typedef Elf64_Phdr Elf_Phdr;
typedef Elf64_Shdr Elf_Shdr;
typedef Elf64_Sym Elf_Sym;
typedef Elf64_Rel Elf_Rel;
typedef Elf64_Rela Elf_Rela;
typedef Elf64_Addr Elf_Addr;
typedef Elf64_Dyn Elf_Dyn;
typedef Elf64_Word Elf_Word;
#endif


class FAGotHook {
public:
    struct Config {
        bool check_ehdr;            // do verify so file elf header
        bool unprotect_got_memory;  // unprotect got table memory when parse data
        bool with_local_func;       // collect local func in the same time
    };

    // FAGotHook will read memory data from map with mapName.
    FAGotHook(const char *mapName, Config* config = nullptr);

    bool is_valid() { return is_valid_; }

    /*rebind func address in got table.*/
    bool rebindFunc(Elf_Addr originalFunc, Elf_Addr newFunc);
private:
    Elf_Addr loadFromMap(const char* name);

    bool Load();

    bool ReadElfHeader();
    bool VerifyElfHeader();
    bool FindPhdr();
    bool CheckPhdr(Elf_Addr);

    bool ReadSoInfo();
    bool ReadGotInfo();

    /* remove write protect*/
    static bool unProtectMemory(void* addr, uint32_t size);
    /* add write protect*/
    static bool protectMemory(void* addr, uint32_t size);

    // extra function
    void phdr_table_get_dynamic_section(const Elf_Phdr* phdr_table,
                                        int               phdr_count,
                                        Elf_Addr        load_bias,
                                        Elf_Dyn**       dynamic,
                                        size_t*           dynamic_count,
                                        Elf_Word*       dynamic_flags);


    // variables
    std::string name;

    Elf_Addr load_bias_ = 0;
    // elf info
    Elf_Ehdr* header_ = nullptr;
    Elf_Phdr *phdr_table_ = nullptr;
    size_t phdr_num_ = 0;

    // Loaded phdr.
    const Elf_Phdr *loaded_phdr_ = nullptr;

    bool is_valid_ = false;

    size_t plt_rel_count = 0;

    Elf_Addr * plt_got = nullptr;
    Elf_Addr * got_start = nullptr;
    Elf_Addr * got_end = nullptr;

    Elf_Dyn* dynamic_start = nullptr;
    size_t dynamic_count = 0;
    // feature
private:
    bool check_ehdr = true;
    bool unprotect_got_memory = false;
    bool with_local_func = false;
};




#endif //FAGOTHOOK_FAGOTHOOK_H
