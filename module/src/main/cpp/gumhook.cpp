#include <atomic>
#include <regex>
#include <string>
#include <thread>
#include <android/dlext.h>
#include <unistd.h>

#include "log.h"
#include "gumhook.h"
#include "dumpso.h"

#define HOOK_DEF(ret, func, ...)         \
    ret (*old_##func)(__VA_ARGS__) = nullptr; \
    ret new_##func(__VA_ARGS__)

struct dumpTargetData {
    std::string package;
    bool watch;
    std::string name;
    std::string regex;
    uint delay;
    uint delay_section;
    bool onload;
};

static dumpTargetData data = {};
static std::string module_name_to_dump;
static GumInterceptor* unlink_interceptor = nullptr;
static std::atomic_bool did_dump{false};

static void delay_dump_thread(std::string package,
                              std::string so_path,
                              uintptr_t module_base,
                              size_t module_size,
                              uint delay,
                              uint delay_section) {
    if (delay > 0) usleep(delay);
    dump_so(package, so_path.c_str(), module_base, module_size, delay, delay_section);
}

static void schedule_dump(const char* so_name, bool onload) {
    if (so_name == nullptr || *so_name == '\0') return;

    if (data.watch) {
        LOGD("%s library: %s", onload ? "onload" : "loaded", so_name);
        return;
    }

    bool should_dump = false;
    std::string matched_name;

    if (!data.name.empty() && strstr(so_name, data.name.c_str()) != nullptr) {
        matched_name = data.name;
        should_dump = true;
    } else if (data.name.empty() && !data.regex.empty()) {
        std::regex pattern(data.regex);
        if (std::regex_match(so_name, pattern)) {
            const std::string path(so_name);
            matched_name = path.substr(path.find_last_of('/') + 1);
            should_dump = true;
        }
    }

    if (!should_dump) return;

    LOGD("%s library: %s", onload ? "onload" : "loaded", so_name);

    const GumAddress base = gum_module_find_base_address(so_name);
    if (base == 0) return;

    GumModuleMap* module_map = gum_module_map_new();
    if (module_map == nullptr) return;

    const GumModuleDetails* m = gum_module_map_find(module_map, base);
    if (m == nullptr || m->path == nullptr || m->range == nullptr || m->range->size == 0) {
        g_object_unref(module_map);
        return;
    }

    // Copy all Gum-owned data before releasing the module map. Passing m->path
    // directly to a detached thread can otherwise become a use-after-lifetime.
    const std::string module_path(m->path);
    const uintptr_t module_base = m->range->base_address;
    const size_t module_size = m->range->size;
    g_object_unref(module_map);

    bool expected = false;
    if (!did_dump.compare_exchange_strong(expected, true)) return;

    module_name_to_dump = matched_name;

    // Always leave the linker hook before doing file I/O, memory reads, or
    // SoFixer work. Even a zero-delay dump is performed on a worker thread to
    // reduce linker-lock re-entrancy, stalls and ANR/crash risk.
    std::thread(delay_dump_thread,
                data.package,
                module_path,
                module_base,
                module_size,
                data.delay,
                data.delay_section).detach();
}

HOOK_DEF(void*, do_dlopen, const char* name, int flags,
         const android_dlextinfo* extinfo, const void* caller_addr) {
    if (data.onload) {
        schedule_dump(name, true);
        return old_do_dlopen(name, flags, extinfo, caller_addr);
    }

    void* handle = old_do_dlopen(name, flags, extinfo, caller_addr);
    if (handle != nullptr) schedule_dump(name, false);
    return handle;
}

HOOK_DEF(int, unlink, const char* pathname) {
    if (pathname == nullptr) return old_unlink(pathname);

    if (!module_name_to_dump.empty() &&
        strstr(pathname, module_name_to_dump.c_str()) != nullptr) {
        std::string fake_pathname = std::string(pathname) + ".hackcatml.so";
        const int ret = old_unlink(fake_pathname.c_str());
        if (ret < 0) {
            LOGD("block unlink: %s", pathname);
            if (unlink_interceptor != nullptr) {
                gum_interceptor_revert(unlink_interceptor, reinterpret_cast<gpointer>(unlink));
            }
        }
        return ret;
    }
    return old_unlink(pathname);
}

static bool doReplace(GumAddress target_addr, const std::string& sym) {
    if (target_addr == 0) {
        LOGE("cannot hook %s: target address is null", sym.c_str());
        return false;
    }

    GumInterceptor* interceptor = gum_interceptor_obtain();
    if (interceptor == nullptr) {
        LOGE("cannot hook %s: interceptor unavailable", sym.c_str());
        return false;
    }

    gum_interceptor_begin_transaction(interceptor);

    auto replace_func = [&](auto new_func, auto& old_func) {
        return gum_interceptor_replace_fast(interceptor,
                                            GSIZE_TO_POINTER(target_addr),
                                            GSIZE_TO_POINTER(new_func),
                                            reinterpret_cast<void**>(&old_func));
    };

    GumReplaceReturn ret = GUM_REPLACE_WRONG_TYPE;
    if (sym == "do_dlopen") {
        ret = replace_func(new_do_dlopen, old_do_dlopen);
    } else if (sym == "unlink") {
        unlink_interceptor = interceptor;
        ret = replace_func(new_unlink, old_unlink);
    }

    gum_interceptor_end_transaction(interceptor);
    const bool ok = ret == GUM_REPLACE_OK;
    LOGD("%s %s", sym.c_str(), ok ? "replaced" : "replace went wrong");
    return ok;
}

void hookAddress(GumAddress addr,
                 std::string& package,
                 bool watch,
                 std::string& target,
                 std::string& regex,
                 uint delay,
                 uint delay_section,
                 bool block_deletion,
                 bool on_load) {
    data.package = package;
    data.watch = watch;
    data.name = target;
    data.regex = regex;
    if (!data.regex.empty()) data.name.clear();

    data.delay = delay;
    data.delay_section = delay_section;
    if (data.delay_section != 0) data.delay = 0;

    if (data.watch) {
        data.name.clear();
        data.regex.clear();
        block_deletion = false;
    }
    data.onload = on_load;
    did_dump.store(false);

    if (!doReplace(addr, "do_dlopen")) return;

    if (block_deletion) {
        doReplace(reinterpret_cast<GumAddress>(unlink), "unlink");
    }
}
