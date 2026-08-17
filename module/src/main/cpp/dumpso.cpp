#include <unistd.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <cerrno>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include "log.h"
#include "frida-gum.h"
#include "SoFixer/ElfReader.h"
#include "SoFixer/ElfRebuilder.h"
#include "SoFixer/ObElfReader.h"

static std::string output_dir;
static uintptr_t section_addr;

namespace {

constexpr size_t kReadChunk = 64 * 1024;

ssize_t read_self_memory(void* dst, const void* src, size_t size) {
#if defined(__NR_process_vm_readv)
    struct iovec local_iov = {dst, size};
    struct iovec remote_iov = {const_cast<void*>(src), size};
    return syscall(__NR_process_vm_readv, getpid(),
                   &local_iov, 1, &remote_iov, 1, 0);
#else
    errno = ENOSYS;
    return -1;
#endif
}

bool write_memory_range(std::ofstream& out, uintptr_t address, size_t size) {
    std::vector<unsigned char> buffer(kReadChunk);
    std::vector<unsigned char> zeros(kReadChunk, 0);

    size_t done = 0;
    bool complete = true;
    while (done < size) {
        const size_t want = std::min(kReadChunk, size - done);
        const void* remote = reinterpret_cast<const void*>(address + done);
        ssize_t got = read_self_memory(buffer.data(), remote, want);

        if (got > 0) {
            out.write(reinterpret_cast<const char*>(buffer.data()), got);
            if (static_cast<size_t>(got) < want) {
                const size_t missing = want - static_cast<size_t>(got);
                out.write(reinterpret_cast<const char*>(zeros.data()), missing);
                LOGW("partial memory read at %p: %zd/%zu; zero-filled %zu bytes",
                     remote, got, want, missing);
                complete = false;
            }
        } else {
            // Do not crash the target because one page is inaccessible or was
            // remapped between module enumeration and dumping. Preserve file
            // offsets by writing zeros for the unreadable range.
            out.write(reinterpret_cast<const char*>(zeros.data()), want);
            LOGW("memory read failed at %p (%zu bytes, errno=%d); zero-filled",
                 remote, want, errno);
            complete = false;
        }

        if (!out.good()) return false;
        done += want;
    }

    return complete;
}

void save_module_maps(const std::string& path, uintptr_t module_base, size_t module_size) {
    std::ifstream maps("/proc/self/maps");
    std::ofstream sidecar(path + ".maps.txt", std::ofstream::out | std::ofstream::trunc);
    if (!maps.is_open() || !sidecar.is_open()) return;

    const uintptr_t module_end = module_base + module_size;
    std::string line;
    while (std::getline(maps, line)) {
        unsigned long long start = 0;
        unsigned long long end = 0;
        if (sscanf(line.c_str(), "%llx-%llx", &start, &end) != 2) continue;
        if (static_cast<uintptr_t>(end) <= module_base ||
            static_cast<uintptr_t>(start) >= module_end) {
            continue;
        }
        sidecar << line << '\n';
    }
}

} // namespace

gboolean section_found(const GumSectionDetails* details, gpointer user_data) {
    if (strstr(details->name, "il2cpp") != nullptr ||
        strstr(details->name, ".text") != nullptr ||
        strstr(details->name, ".rodata") != nullptr) {
        section_addr = details->address;
        LOGD("found %s section: %p", details->name, reinterpret_cast<void*>(section_addr));
        return false;
    }
    return true;
}

int fix_so(const std::string& sofile_path, uintptr_t module_base, size_t module_size) {
    LOGD("Rebuilding %s", sofile_path.substr(sofile_path.find_last_of('/') + 1).c_str());
    const std::string out_path = sofile_path + ".fix.so";

    ObElfReader elf_reader;
    elf_reader.setDumpSoBaseAddr(module_base);
    elf_reader.setDumpSoSize(module_size);

    if (!elf_reader.setSource(sofile_path.c_str())) {
        LOGD("unable to open source file");
        return -1;
    }
    if (!elf_reader.Load()) {
        LOGD("source so file is invalid");
        return -1;
    }

    ElfRebuilder elf_rebuilder(&elf_reader);
    if (!elf_rebuilder.Rebuild()) {
        LOGD("error occurred while rebuilding ELF file");
        return -1;
    }

    std::ofstream redump(out_path, std::ofstream::out | std::ofstream::binary | std::ofstream::trunc);
    if (!redump.is_open()) {
        LOGD("Can't Output File");
        return -1;
    }
    redump.write(reinterpret_cast<const char*>(elf_rebuilder.getRebuildData()),
                 static_cast<std::streamsize>(elf_rebuilder.getRebuildSize()));
    if (!redump.good()) return -1;
    redump.close();
    return 1;
}

void delay_section_dump_thread(const std::string& dump_so_path,
                               uintptr_t module_base,
                               uintptr_t offset,
                               size_t module_size,
                               uint delay) {
    usleep(delay);

    if (offset > module_size) {
        LOGW("invalid delayed dump offset: 0x%zx > module size 0x%zx",
             static_cast<size_t>(offset), module_size);
        return;
    }

    const size_t remaining_size = module_size - offset;
    LOGD("remaining_size: %zu", remaining_size);

    const std::string module_name_to_dump =
            dump_so_path.substr(dump_so_path.find_last_of('/') + 1);

    std::ofstream dump(dump_so_path,
                       std::ofstream::out | std::ofstream::binary | std::ofstream::app);
    if (!dump.is_open()) {
        LOGD("Failed to open file: %s", dump_so_path.c_str());
        return;
    }

    const bool complete = write_memory_range(dump, module_base + offset, remaining_size);
    dump.close();
    LOGD("mem dump: %p, %zu bytes (%s)",
         reinterpret_cast<const void*>(module_base + offset), remaining_size,
         complete ? "complete" : "with zero-filled gaps");
    LOGD("%s dump done", module_name_to_dump.c_str());
    LOGD("Output: %s", dump_so_path.c_str());

    const int res = fix_so(dump_so_path, module_base, module_size);
    if (res == 1) {
        LOGD("Rebuilding %s Complete", module_name_to_dump.c_str());
        LOGD("Output: %s", (dump_so_path + ".fix.so").c_str());
    } else {
        LOGD("SoFix fail");
    }
}

void dump_so(std::string& package_name,
             const char* so_path,
             uintptr_t module_base,
             size_t module_size,
             uint delay,
             uint delay_section) {
    LOGD("module base: %p, size: %zu", reinterpret_cast<void*>(module_base), module_size);

    output_dir = "/data/data/" + package_name + "/files/";
    std::stringstream module_base_hexstr;
    module_base_hexstr << "0x" << std::hex << module_base;

    const std::string module_name_to_dump =
            std::string(so_path).substr(std::string(so_path).find_last_of('/') + 1);
    const std::string dump_so_path = output_dir + module_name_to_dump +
            ".dump[" + module_base_hexstr.str() + "].so";

    save_module_maps(dump_so_path, module_base, module_size);

    std::ofstream dump(dump_so_path,
                       std::ofstream::out | std::ofstream::binary | std::ofstream::trunc);
    if (!dump.is_open()) {
        LOGD("failed to open file");
        return;
    }

    uintptr_t offset = 0;
    if (delay_section > 0) {
        section_addr = 0; // never reuse an address discovered for an earlier module
        gum_module_enumerate_sections(so_path, section_found, nullptr);

        if (section_addr >= module_base &&
            section_addr < module_base + module_size) {
            offset = section_addr - module_base;
        } else {
#if defined(__LP64__)
            offset = sizeof(Elf64_Ehdr);
#else
            offset = sizeof(Elf32_Ehdr);
#endif
        }

        if (offset > module_size) offset = module_size;
        const bool complete = write_memory_range(dump, module_base, offset);
        dump.close();

        LOGD("initial mem dump: %p, %zu bytes (%s)",
             reinterpret_cast<const void*>(module_base), static_cast<size_t>(offset),
             complete ? "complete" : "with zero-filled gaps");

        std::thread t(delay_section_dump_thread, dump_so_path, module_base,
                      offset, module_size, delay_section);
        t.detach();
        return;
    }

    const bool complete = write_memory_range(dump, module_base, module_size);
    dump.close();

    LOGD("mem dump: %p, %zu bytes (%s)",
         reinterpret_cast<const void*>(module_base), module_size,
         complete ? "complete" : "with zero-filled gaps");
    LOGD("%s dump done", module_name_to_dump.c_str());
    LOGD("Output: %s", dump_so_path.c_str());

    const int res = fix_so(dump_so_path, module_base, module_size);
    if (res == 1) {
        LOGD("Rebuilding %s Complete", module_name_to_dump.c_str());
        LOGD("Output: %s", (dump_so_path + ".fix.so").c_str());
    } else {
        LOGD("SoFix fail");
    }
}
