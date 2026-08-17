//===------------------------------------------------------------*- C++ -*-===//
//
//                     Created by F8LEFT on 2017/6/4.
//                   Copyright (c) 2017. All rights reserved.
//===----------------------------------------------------------------------===//
// Rebuild ELF files dumped from process memory.
//===----------------------------------------------------------------------===//

#ifndef SOFIXER_ELFREBUILDER_H
#define SOFIXER_ELFREBUILDER_H

#include <cstdint>
#include <string>
#include <vector>

#include "ObElfReader.h"

#define SOINFO_NAME_LEN 128

struct soinfo {
public:
    const char* name = "name";
    const Elf_Phdr* phdr = nullptr;
    size_t phnum = 0;
    Elf_Addr entry = 0;
    uint8_t* base = nullptr;
    unsigned size = 0;

    Elf_Addr min_load = 0;
    Elf_Addr max_load = 0;

    Elf_Dyn* dynamic = nullptr;
    size_t dynamic_count = 0;
    Elf_Word dynamic_flags = 0;

    const char* strtab = nullptr;
    size_t strtabsize = 0;
    Elf_Sym* symtab = nullptr;
    size_t symtab_count = 0;

    uint8_t* hash = nullptr;
    size_t nbucket = 0;
    size_t nchain = 0;
    unsigned* bucket = nullptr;
    unsigned* chain = nullptr;

    uint8_t* gnu_hash = nullptr;

    Elf_Addr* plt_got = nullptr;

    uint32_t plt_type = DT_REL;
    void* plt_rel = nullptr;
    size_t plt_rel_size = 0;
    size_t plt_rel_count = 0;

    Elf_Rel* rel = nullptr;
    size_t rel_count = 0;
    Elf_Rela* rela = nullptr;
    size_t rela_count = 0;

    void* preinit_array = nullptr;
    size_t preinit_array_count = 0;
    void** init_array = nullptr;
    size_t init_array_count = 0;
    void** fini_array = nullptr;
    size_t fini_array_count = 0;

    void* init_func = nullptr;
    void* fini_func = nullptr;

    Elf_Addr* ARM_exidx = nullptr;
    size_t ARM_exidx_count = 0;

    unsigned mips_symtabno = 0;
    unsigned mips_local_gotno = 0;
    unsigned mips_gotsym = 0;

    uint8_t* load_bias = nullptr;

    bool has_text_relocations = false;
    bool has_DT_SYMBOLIC = false;
};

class ElfRebuilder {
public:
    explicit ElfRebuilder(ObElfReader* elf_reader);
    ~ElfRebuilder() {
        if (rebuild_data != nullptr) delete[] rebuild_data;
    }

    bool Rebuild();

    void* getRebuildData() { return rebuild_data; }
    size_t getRebuildSize() { return rebuild_size; }

    void setPatchInit(bool b) { isPatchInit = b; }

private:
    bool RebuildPhdr();
    bool RebuildShdr();
    bool ReadSoInfo();
    bool RebuildRelocs();
    bool RebuildFin();

    template <bool isRela>
    void relocate(uint8_t* base, Elf_Rel* rel, Elf_Addr dump_base);

    Elf_Word AddSection(const char* name, Elf_Word type, Elf_Xword flags,
                        Elf_Addr addr, Elf_Xword size, Elf_Xword align,
                        Elf_Xword entsize = 0);
    void SortSectionsAndFixLinks();

    ObElfReader* elf_reader_;
    soinfo si;

    size_t rebuild_size = 0;
    uint8_t* rebuild_data = nullptr;

    Elf_Word sDYNSYM = 0;
    Elf_Word sDYNSTR = 0;
    Elf_Word sHASH = 0;
    Elf_Word sGNUHASH = 0;
    Elf_Word sRELDYN = 0;
    Elf_Word sRELADYN = 0;
    Elf_Word sRELPLT = 0;
    Elf_Word sTEXTTAB = 0;
    Elf_Word sARMEXIDX = 0;
    Elf_Word sFINIARRAY = 0;
    Elf_Word sINITARRAY = 0;
    Elf_Word sDYNAMIC = 0;
    Elf_Word sDATA = 0;
    Elf_Word sSHSTRTAB = 0;

    std::vector<Elf_Shdr> shdrs;
    std::string shstrtab;

    unsigned external_pointer = 0;
    bool isPatchInit = false;
};

#endif // SOFIXER_ELFREBUILDER_H
