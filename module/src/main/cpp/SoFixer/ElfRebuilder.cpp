//===------------------------------------------------------------*- C++ -*-===//
//
//                     Created by F8LEFT on 2017/6/4.
//                   Copyright (c) 2017. All rights reserved.
//===----------------------------------------------------------------------===//
// ELF reconstruction for memory-dumped shared objects.
//===----------------------------------------------------------------------===//

#include <algorithm>
#include <cstdio>
#include <cstring>

#include "ElfRebuilder.h"
#include "FDebug.h"
#include "elf.h"
#include "log.h"

#ifdef __LP64__
#define ADDRESS_FORMAT "ll"
#else
#define ADDRESS_FORMAT ""
#endif

ElfRebuilder::ElfRebuilder(ObElfReader* elf_reader) : elf_reader_(elf_reader) {}

bool ElfRebuilder::RebuildPhdr() {
    FLOGD("=======================RebuildPhdr=========================");

    // A memory image is laid out at virtual-address offsets. Adjust offsets so
    // PT_LOAD/PT_DYNAMIC keep pointing at the bytes we write, but preserve the
    // original p_filesz. p_filesz != p_memsz is meaningful (notably for BSS).
    auto* phdr = const_cast<Elf_Phdr*>(elf_reader_->loaded_phdr());
    for (size_t i = 0; i < elf_reader_->phdr_count(); ++i, ++phdr) {
        phdr->p_paddr = phdr->p_vaddr;
        phdr->p_offset = phdr->p_vaddr;
    }

    FLOGD("=====================RebuildPhdr End======================");
    return true;
}

Elf_Word ElfRebuilder::AddSection(const char* name, Elf_Word type, Elf_Xword flags,
                                  Elf_Addr addr, Elf_Xword size, Elf_Xword align,
                                  Elf_Xword entsize) {
    Elf_Shdr shdr = {};
    shdr.sh_name = static_cast<Elf_Word>(shstrtab.size());
    shstrtab.append(name);
    shstrtab.push_back('\0');
    shdr.sh_type = type;
    shdr.sh_flags = flags;
    shdr.sh_addr = addr;
    shdr.sh_offset = addr;
    shdr.sh_size = size;
    shdr.sh_addralign = align;
    shdr.sh_entsize = entsize;
    shdrs.push_back(shdr);
    return static_cast<Elf_Word>(shdrs.size() - 1);
}

void ElfRebuilder::SortSectionsAndFixLinks() {
    for (size_t i = 1; i < shdrs.size(); ++i) {
        for (size_t j = i + 1; j < shdrs.size(); ++j) {
            if (shdrs[i].sh_addr <= shdrs[j].sh_addr) continue;

            std::swap(shdrs[i], shdrs[j]);
            auto swap_index = [i, j](Elf_Word& idx) {
                if (idx == i) idx = static_cast<Elf_Word>(j);
                else if (idx == j) idx = static_cast<Elf_Word>(i);
            };

            swap_index(sDYNSYM);
            swap_index(sDYNSTR);
            swap_index(sHASH);
            swap_index(sGNUHASH);
            swap_index(sRELDYN);
            swap_index(sRELADYN);
            swap_index(sRELPLT);
            swap_index(sTEXTTAB);
            swap_index(sARMEXIDX);
            swap_index(sFINIARRAY);
            swap_index(sINITARRAY);
            swap_index(sDYNAMIC);
            swap_index(sDATA);
            swap_index(sSHSTRTAB);
        }
    }

    if (sDYNSYM) shdrs[sDYNSYM].sh_link = sDYNSTR;
    if (sHASH) shdrs[sHASH].sh_link = sDYNSYM;
    if (sGNUHASH) shdrs[sGNUHASH].sh_link = sDYNSYM;
    if (sRELDYN) shdrs[sRELDYN].sh_link = sDYNSYM;
    if (sRELADYN) shdrs[sRELADYN].sh_link = sDYNSYM;
    if (sRELPLT) shdrs[sRELPLT].sh_link = sDYNSYM;
    if (sDYNAMIC) shdrs[sDYNAMIC].sh_link = sDYNSTR;
    if (sARMEXIDX) shdrs[sARMEXIDX].sh_link = sTEXTTAB;
}

bool ElfRebuilder::RebuildShdr() {
    FLOGD("=======================RebuildShdr=========================");
    const auto base = si.load_bias;

    shdrs.clear();
    shstrtab.clear();
    shstrtab.push_back('\0');
    shdrs.push_back(Elf_Shdr{});

    if (si.symtab != nullptr) {
        // SysV DT_HASH nchain is the exact number of dynamic symbols. Do not
        // infer .dynsym size from the next reconstructed section: version/hash
        // tables can live between DT_SYMTAB and DT_STRTAB.
        const size_t sym_count = si.symtab_count;
        const Elf_Xword sym_size = sym_count ? sym_count * sizeof(Elf_Sym) : 0;
        sDYNSYM = AddSection(".dynsym", SHT_DYNSYM, SHF_ALLOC,
                             reinterpret_cast<uintptr_t>(si.symtab) - reinterpret_cast<uintptr_t>(base),
                             sym_size, sizeof(Elf_Addr), sizeof(Elf_Sym));
    }

    if (si.hash != nullptr) {
        const Elf_Xword hash_size = (2 + si.nbucket + si.nchain) * sizeof(uint32_t);
        sHASH = AddSection(".hash", SHT_HASH, SHF_ALLOC,
                           reinterpret_cast<uintptr_t>(si.hash) - reinterpret_cast<uintptr_t>(base),
                           hash_size, sizeof(uint32_t), sizeof(uint32_t));
    }

    if (si.gnu_hash != nullptr && si.symtab_count != 0) {
        const auto* h = reinterpret_cast<const uint32_t*>(si.gnu_hash);
        const uint32_t nbuckets = h[0];
        const uint32_t symoffset = h[1];
        const uint32_t bloom_size = h[2];
        size_t chain_count = 0;
        if (si.symtab_count > symoffset) chain_count = si.symtab_count - symoffset;
        const Elf_Xword gnu_hash_size = 4 * sizeof(uint32_t) +
                static_cast<Elf_Xword>(bloom_size) * sizeof(Elf_Addr) +
                static_cast<Elf_Xword>(nbuckets) * sizeof(uint32_t) +
                static_cast<Elf_Xword>(chain_count) * sizeof(uint32_t);
        sGNUHASH = AddSection(".gnu.hash", SHT_GNU_HASH, SHF_ALLOC,
                              reinterpret_cast<uintptr_t>(si.gnu_hash) - reinterpret_cast<uintptr_t>(base),
                              gnu_hash_size, sizeof(Elf_Addr), 0);
    }

    if (si.strtab != nullptr) {
        sDYNSTR = AddSection(".dynstr", SHT_STRTAB, SHF_ALLOC,
                             reinterpret_cast<uintptr_t>(si.strtab) - reinterpret_cast<uintptr_t>(base),
                             si.strtabsize, 1, 0);
    }

    if (si.rel != nullptr && si.rel_count != 0) {
        sRELDYN = AddSection(".rel.dyn", SHT_REL, SHF_ALLOC,
                             reinterpret_cast<uintptr_t>(si.rel) - reinterpret_cast<uintptr_t>(base),
                             si.rel_count * sizeof(Elf_Rel), sizeof(Elf_Addr), sizeof(Elf_Rel));
    }

    if (si.rela != nullptr && si.rela_count != 0) {
        sRELADYN = AddSection(".rela.dyn", SHT_RELA, SHF_ALLOC,
                              reinterpret_cast<uintptr_t>(si.rela) - reinterpret_cast<uintptr_t>(base),
                              si.rela_count * sizeof(Elf_Rela), sizeof(Elf_Addr), sizeof(Elf_Rela));
    }

    if (si.plt_rel != nullptr && si.plt_rel_count != 0) {
        const bool is_rela = si.plt_type == DT_RELA;
        sRELPLT = AddSection(is_rela ? ".rela.plt" : ".rel.plt",
                             is_rela ? SHT_RELA : SHT_REL,
                             SHF_ALLOC,
                             reinterpret_cast<uintptr_t>(si.plt_rel) - reinterpret_cast<uintptr_t>(base),
                             si.plt_rel_size,
                             sizeof(Elf_Addr),
                             is_rela ? sizeof(Elf_Rela) : sizeof(Elf_Rel));
    }

    // The old implementation used an ARM32 PLT-size formula on AArch64 and
    // then called everything after it ".text&ARM.extab". Use the executable
    // PT_LOAD boundary instead. This is metadata-backed and architecture-safe.
    for (size_t i = 0; i < si.phnum; ++i) {
        const Elf_Phdr& p = si.phdr[i];
        if (p.p_type == PT_LOAD && (p.p_flags & PF_X) && p.p_filesz != 0) {
            sTEXTTAB = AddSection(".text", SHT_PROGBITS, SHF_ALLOC | SHF_EXECINSTR,
                                  p.p_vaddr, p.p_filesz,
#ifdef __LP64__
                                  16,
#else
                                  4,
#endif
                                  0);
            break;
        }
    }

#ifndef __LP64__
    if (si.ARM_exidx != nullptr && si.ARM_exidx_count != 0) {
        sARMEXIDX = AddSection(".ARM.exidx", SHT_ARMEXIDX,
                               SHF_ALLOC | SHF_LINK_ORDER,
                               reinterpret_cast<uintptr_t>(si.ARM_exidx) - reinterpret_cast<uintptr_t>(base),
                               si.ARM_exidx_count * sizeof(Elf_Addr), 4, 8);
    }
#endif

    if (si.fini_array != nullptr && si.fini_array_count != 0) {
        sFINIARRAY = AddSection(".fini_array", SHT_FINI_ARRAY, SHF_ALLOC | SHF_WRITE,
                                reinterpret_cast<uintptr_t>(si.fini_array) - reinterpret_cast<uintptr_t>(base),
                                si.fini_array_count * sizeof(Elf_Addr), sizeof(Elf_Addr), 0);
    }

    if (si.init_array != nullptr && si.init_array_count != 0) {
        sINITARRAY = AddSection(".init_array", SHT_INIT_ARRAY, SHF_ALLOC | SHF_WRITE,
                                reinterpret_cast<uintptr_t>(si.init_array) - reinterpret_cast<uintptr_t>(base),
                                si.init_array_count * sizeof(Elf_Addr), sizeof(Elf_Addr), 0);
    }

    if (si.dynamic != nullptr && si.dynamic_count != 0) {
        sDYNAMIC = AddSection(".dynamic", SHT_DYNAMIC, SHF_ALLOC | SHF_WRITE,
                              reinterpret_cast<uintptr_t>(si.dynamic) - reinterpret_cast<uintptr_t>(base),
                              si.dynamic_count * sizeof(Elf_Dyn), sizeof(Elf_Addr), sizeof(Elf_Dyn));
    }

    // Represent the writable tail without claiming the entire writable PT_LOAD
    // over .init_array/.fini_array/.dynamic. Program headers still describe the
    // complete mapping, while this gives IDA/Ghidra a useful data section.
    for (size_t i = 0; i < si.phnum; ++i) {
        const Elf_Phdr& p = si.phdr[i];
        if (p.p_type != PT_LOAD || !(p.p_flags & PF_W) || p.p_memsz == 0) continue;

        Elf_Addr start = p.p_vaddr;
        if (si.dynamic != nullptr) {
            const Elf_Addr dyn_end = reinterpret_cast<uintptr_t>(si.dynamic) -
                                     reinterpret_cast<uintptr_t>(base) +
                                     si.dynamic_count * sizeof(Elf_Dyn);
            if (dyn_end > start && dyn_end < p.p_vaddr + p.p_memsz) start = dyn_end;
        }
        const Elf_Addr end = p.p_vaddr + p.p_memsz;
        if (end > start) {
            sDATA = AddSection(".data", SHT_PROGBITS, SHF_ALLOC | SHF_WRITE,
                               start, end - start, sizeof(Elf_Addr), 0);
        }
        break;
    }

    // .shstrtab is appended after the copied memory image.
    sSHSTRTAB = AddSection(".shstrtab", SHT_STRTAB, 0, si.max_load,
                            0, 1, 0);

    SortSectionsAndFixLinks();

    // If no SysV hash is present, use the first later section only as a last
    // resort for .dynsym. With DT_HASH present this path is never used.
    if (sDYNSYM && shdrs[sDYNSYM].sh_size == 0) {
        Elf_Addr next = 0;
        for (const auto& s : shdrs) {
            if (s.sh_addr > shdrs[sDYNSYM].sh_addr &&
                (next == 0 || s.sh_addr < next)) {
                next = s.sh_addr;
            }
        }
        if (next > shdrs[sDYNSYM].sh_addr) {
            shdrs[sDYNSYM].sh_size = next - shdrs[sDYNSYM].sh_addr;
            shdrs[sDYNSYM].sh_size -= shdrs[sDYNSYM].sh_size % sizeof(Elf_Sym);
        }
    }

    shdrs[sSHSTRTAB].sh_size = shstrtab.size();

    FLOGD("=====================RebuildShdr End======================");
    return true;
}

bool ElfRebuilder::Rebuild() {
    return RebuildPhdr() && ReadSoInfo() && RebuildShdr() &&
           RebuildRelocs() && RebuildFin();
}

bool ElfRebuilder::ReadSoInfo() {
    FLOGD("=======================ReadSoInfo=========================");

    si.base = si.load_bias = elf_reader_->load_bias();
    si.phdr = elf_reader_->loaded_phdr();
    si.phnum = elf_reader_->phdr_count();
    auto base = si.load_bias;

    phdr_table_get_load_size(si.phdr, si.phnum, &si.min_load, &si.max_load);
    si.max_load += elf_reader_->pad_size_;

    elf_reader_->GetDynamicSection(&si.dynamic, &si.dynamic_count, &si.dynamic_flags);
    if (si.dynamic == nullptr) {
        FLOGE("No valid dynamic phdr data");
        return false;
    }

#ifndef __LP64__
    phdr_table_get_arm_exidx(si.phdr, si.phnum, si.base,
                             &si.ARM_exidx, reinterpret_cast<unsigned*>(&si.ARM_exidx_count));
#endif

    Elf_Word soname_offset = 0;
    bool have_soname = false;

    for (Elf_Dyn* d = si.dynamic; d->d_tag != DT_NULL; ++d) {
        switch (d->d_tag) {
            case DT_HASH: {
                si.hash = base + d->d_un.d_ptr;
                auto* words = reinterpret_cast<unsigned*>(si.hash);
                si.nbucket = words[0];
                si.nchain = words[1];
                si.symtab_count = si.nchain;
                si.bucket = words + 2;
                si.chain = si.bucket + si.nbucket;
                break;
            }
            case DT_GNU_HASH:
                si.gnu_hash = base + d->d_un.d_ptr;
                break;
            case DT_STRTAB:
                si.strtab = reinterpret_cast<const char*>(base + d->d_un.d_ptr);
                break;
            case DT_STRSZ:
                si.strtabsize = d->d_un.d_val;
                break;
            case DT_SYMTAB:
                si.symtab = reinterpret_cast<Elf_Sym*>(base + d->d_un.d_ptr);
                break;
            case DT_PLTREL:
                si.plt_type = d->d_un.d_val;
                break;
            case DT_JMPREL:
                si.plt_rel = base + d->d_un.d_ptr;
                break;
            case DT_PLTRELSZ:
                // Keep bytes first; the entry size depends on DT_PLTREL and
                // must not be prematurely divided by sizeof(Elf_Rel).
                si.plt_rel_size = d->d_un.d_val;
                break;
            case DT_REL:
                si.rel = reinterpret_cast<Elf_Rel*>(base + d->d_un.d_ptr);
                break;
            case DT_RELSZ:
                si.rel_count = d->d_un.d_val / sizeof(Elf_Rel);
                break;
            case DT_RELA:
                si.rela = reinterpret_cast<Elf_Rela*>(base + d->d_un.d_ptr);
                break;
            case DT_RELASZ:
                si.rela_count = d->d_un.d_val / sizeof(Elf_Rela);
                break;
            case DT_PLTGOT:
                si.plt_got = reinterpret_cast<Elf_Addr*>(base + d->d_un.d_ptr);
                break;
            case DT_INIT:
                si.init_func = reinterpret_cast<void*>(base + d->d_un.d_ptr);
                break;
            case DT_FINI:
                si.fini_func = reinterpret_cast<void*>(base + d->d_un.d_ptr);
                break;
            case DT_INIT_ARRAY:
                si.init_array = reinterpret_cast<void**>(base + d->d_un.d_ptr);
                break;
            case DT_INIT_ARRAYSZ:
                si.init_array_count = d->d_un.d_val / sizeof(Elf_Addr);
                break;
            case DT_FINI_ARRAY:
                si.fini_array = reinterpret_cast<void**>(base + d->d_un.d_ptr);
                break;
            case DT_FINI_ARRAYSZ:
                si.fini_array_count = d->d_un.d_val / sizeof(Elf_Addr);
                break;
            case DT_PREINIT_ARRAY:
                si.preinit_array = reinterpret_cast<void*>(base + d->d_un.d_ptr);
                break;
            case DT_PREINIT_ARRAYSZ:
                si.preinit_array_count = d->d_un.d_val / sizeof(Elf_Addr);
                break;
            case DT_TEXTREL:
                si.has_text_relocations = true;
                break;
            case DT_SYMBOLIC:
                si.has_DT_SYMBOLIC = true;
                break;
            case DT_FLAGS:
                if (d->d_un.d_val & DF_TEXTREL) si.has_text_relocations = true;
                if (d->d_un.d_val & DF_SYMBOLIC) si.has_DT_SYMBOLIC = true;
                break;
            case DT_SONAME:
                soname_offset = d->d_un.d_val;
                have_soname = true;
                break;
            case DT_MIPS_SYMTABNO:
                si.mips_symtabno = d->d_un.d_val;
                break;
            case DT_MIPS_LOCAL_GOTNO:
                si.mips_local_gotno = d->d_un.d_val;
                break;
            case DT_MIPS_GOTSYM:
                si.mips_gotsym = d->d_un.d_val;
                break;
            default:
                break;
        }
    }

    if (have_soname && si.strtab != nullptr && soname_offset < si.strtabsize) {
        si.name = si.strtab + soname_offset;
        FLOGD("soname %s", si.name);
    }

    if (si.plt_rel_size != 0) {
        if (si.plt_type == DT_RELA) {
            si.plt_rel_count = si.plt_rel_size / sizeof(Elf_Rela);
        } else {
            si.plt_rel_count = si.plt_rel_size / sizeof(Elf_Rel);
        }
    }

    FLOGD("dynsym=%zu rel=%zu rela=%zu plt=%zu (%s)",
          si.symtab_count, si.rel_count, si.rela_count, si.plt_rel_count,
          si.plt_type == DT_RELA ? "RELA" : "REL");
    FLOGD("=======================ReadSoInfo End=========================");
    return true;
}

bool ElfRebuilder::RebuildFin() {
    FLOGD("=======================RebuildFin=========================");

    const size_t load_size = si.max_load - si.min_load;
    const size_t shstr_size = shstrtab.size();
    rebuild_size = load_size + shstr_size + shdrs.size() * sizeof(Elf_Shdr);
    rebuild_data = new uint8_t[rebuild_size]();

    memcpy(rebuild_data, reinterpret_cast<void*>(si.load_bias), load_size);
    memcpy(rebuild_data + load_size, shstrtab.data(), shstr_size);

    const size_t shdr_off = load_size + shstr_size;
    memcpy(rebuild_data + shdr_off, shdrs.data(), shdrs.size() * sizeof(Elf_Shdr));

    auto ehdr = *elf_reader_->record_ehdr();
    ehdr.e_type = ET_DYN;
    // Preserve the original e_machine instead of deriving it from the build
    // architecture. The dumper may inspect binaries of a different ABI.
    ehdr.e_shnum = static_cast<Elf_Half>(shdrs.size());
    ehdr.e_shoff = static_cast<Elf_Off>(shdr_off);
    ehdr.e_shstrndx = static_cast<Elf_Half>(sSHSTRTAB);
    memcpy(rebuild_data, &ehdr, sizeof(Elf_Ehdr));

    FLOGD("=======================RebuildFin End=========================");
    return true;
}

template <bool isRela>
void ElfRebuilder::relocate(uint8_t* base, Elf_Rel* rel, Elf_Addr dump_base) {
    if (rel == nullptr) return;

#ifndef __LP64__
    const auto type = ELF32_R_TYPE(rel->r_info);
    const auto sym = ELF32_R_SYM(rel->r_info);
#else
    const auto type = ELF64_R_TYPE(rel->r_info);
    const auto sym = ELF64_R_SYM(rel->r_info);
#endif

    auto* target = reinterpret_cast<Elf_Addr*>(base + rel->r_offset);
    const uintptr_t offset = reinterpret_cast<uintptr_t>(target) -
                             reinterpret_cast<uintptr_t>(base);
    if (offset >= elf_reader_->dump_so_size_) return;

#ifndef __LP64__
    if (type == R_386_RELATIVE || type == R_ARM_RELATIVE) {
        *target -= dump_base;
        return;
    }
#else
    // AArch64 dynamic relocation values from the ELF ABI:
    // 0x401 GLOB_DAT, 0x402 JUMP_SLOT, 0x403 RELATIVE.
    if (type == 0x401 || type == 0x402) {
        if (si.symtab != nullptr && sym < si.symtab_count) {
            const Elf_Sym& syminfo = si.symtab[sym];
            if (syminfo.st_value != 0) {
                *target = syminfo.st_value;
            } else {
                const auto load_size = si.max_load - si.min_load;
                *target = load_size + external_pointer;
                external_pointer += sizeof(*target);
            }
        }
        return;
    }
#endif

    if (isRela) {
        auto* rela = reinterpret_cast<Elf_Rela*>(rel);
#ifdef __LP64__
        if (type == 0x403) {
            *target = rela->r_addend;
            return;
        }
#endif
    }
}

bool ElfRebuilder::RebuildRelocs() {
    if (elf_reader_->dump_so_base_ == 0) return true;

    FLOGD("=======================RebuildRelocs=========================");

    for (size_t i = 0; i < si.rel_count; ++i) {
        relocate<false>(si.load_bias, &si.rel[i], elf_reader_->dump_so_base_);
    }

    for (size_t i = 0; i < si.rela_count; ++i) {
        relocate<true>(si.load_bias,
                       reinterpret_cast<Elf_Rel*>(&si.rela[i]),
                       elf_reader_->dump_so_base_);
    }

    if (si.plt_rel != nullptr) {
        if (si.plt_type == DT_RELA) {
            auto* rela = reinterpret_cast<Elf_Rela*>(si.plt_rel);
            for (size_t i = 0; i < si.plt_rel_count; ++i) {
                relocate<true>(si.load_bias,
                               reinterpret_cast<Elf_Rel*>(&rela[i]),
                               elf_reader_->dump_so_base_);
            }
        } else {
            auto* rel = reinterpret_cast<Elf_Rel*>(si.plt_rel);
            for (size_t i = 0; i < si.plt_rel_count; ++i) {
                relocate<false>(si.load_bias, &rel[i], elf_reader_->dump_so_base_);
            }
        }
    }

    FLOGD("=======================RebuildRelocs End=======================");
    return true;
}
