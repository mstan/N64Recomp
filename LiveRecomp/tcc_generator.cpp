// In-process libtcc recompilation backend — see include/recompiler/tcc_recompiler.h.
//
// Drives the existing CGenerator to emit one function's C, prepends the
// embedded recomp.h prelude, then compiles the result in memory with libtcc
// (loaded dynamically so a missing libtcc.dll is non-fatal). Host runtime
// helpers the shard calls are bound by name via tcc_add_symbol before
// tcc_relocate; the resulting recomp_func_t* is owned (with the TCCState that
// backs its executable memory) by the returned TccRecompOutput.

#include "recompiler/tcc_recompiler.h"

#include <sstream>
#include <span>
#include <cstring>
#include <mutex>

#if defined(_WIN32)
#  define WIN32_LEAN_AND_MEAN
#  include <windows.h>
#else
#  include <dlfcn.h>
#endif

// Generated at build time from include/recomp.h (see CMakeLists / embed step).
// The full recomp.h text, so a compiled shard is self-contained apart from the
// C standard headers (resolved from the bundled tcc include/ dir).
extern "C" const char g_tcc_recomp_prelude[];

namespace {

// ---- dynamically-loaded libtcc entry points ----------------------------------
struct TCCState;
typedef TCCState* (*pfn_new)(void);
typedef void      (*pfn_delete)(TCCState*);
typedef void      (*pfn_set_lib_path)(TCCState*, const char*);
typedef void      (*pfn_set_error_func)(TCCState*, void*, void (*)(void*, const char*));
typedef void      (*pfn_set_options)(TCCState*, const char*);
typedef int       (*pfn_add_include_path)(TCCState*, const char*);
typedef int       (*pfn_set_output_type)(TCCState*, int);
typedef int       (*pfn_compile_string)(TCCState*, const char*);
typedef int       (*pfn_add_symbol)(TCCState*, const char*, const void*);
typedef int       (*pfn_relocate)(TCCState*, void*);
typedef void*     (*pfn_get_symbol)(TCCState*, const char*);

constexpr int TCC_OUTPUT_MEMORY = 1;
void* const TCC_RELOCATE_AUTO = reinterpret_cast<void*>(1);

struct LibTcc {
    bool loaded = false;
#if defined(_WIN32)
    HMODULE handle = nullptr;
#else
    void* handle = nullptr;
#endif
    pfn_new              tcc_new = nullptr;
    pfn_delete           tcc_delete = nullptr;
    pfn_set_lib_path     tcc_set_lib_path = nullptr;
    pfn_set_error_func   tcc_set_error_func = nullptr;
    pfn_set_options      tcc_set_options = nullptr;
    pfn_add_include_path tcc_add_include_path = nullptr;
    pfn_set_output_type  tcc_set_output_type = nullptr;
    pfn_compile_string   tcc_compile_string = nullptr;
    pfn_add_symbol       tcc_add_symbol = nullptr;
    pfn_relocate         tcc_relocate = nullptr;
    pfn_get_symbol       tcc_get_symbol = nullptr;
};

void* sym(LibTcc& l, const char* name) {
#if defined(_WIN32)
    return reinterpret_cast<void*>(GetProcAddress(l.handle, name));
#else
    return dlsym(l.handle, name);
#endif
}

// Load libtcc once. `toolchain_dir` (may be empty) is the directory holding
// libtcc.dll; empty falls back to the OS default search path.
LibTcc& load_libtcc(const std::string& toolchain_dir) {
    static std::mutex mtx;
    static LibTcc lib;
    static bool attempted = false;
    std::lock_guard<std::mutex> g(mtx);
    if (attempted) {
        return lib;
    }
    attempted = true;

#if defined(_WIN32)
    std::string dll = toolchain_dir.empty() ? std::string("libtcc.dll")
                                            : toolchain_dir + "\\libtcc.dll";
    lib.handle = LoadLibraryA(dll.c_str());
    if (!lib.handle && !toolchain_dir.empty()) {
        lib.handle = LoadLibraryA("libtcc.dll");  // fall back to PATH
    }
#else
    std::string so = toolchain_dir.empty() ? std::string("libtcc.so")
                                           : toolchain_dir + "/libtcc.so";
    lib.handle = dlopen(so.c_str(), RTLD_NOW | RTLD_LOCAL);
    if (!lib.handle && !toolchain_dir.empty()) {
        lib.handle = dlopen("libtcc.so", RTLD_NOW | RTLD_LOCAL);
    }
#endif
    if (!lib.handle) {
        return lib;
    }

    lib.tcc_new              = (pfn_new)              sym(lib, "tcc_new");
    lib.tcc_delete           = (pfn_delete)           sym(lib, "tcc_delete");
    lib.tcc_set_lib_path     = (pfn_set_lib_path)     sym(lib, "tcc_set_lib_path");
    lib.tcc_set_error_func   = (pfn_set_error_func)   sym(lib, "tcc_set_error_func");
    lib.tcc_set_options      = (pfn_set_options)      sym(lib, "tcc_set_options");
    lib.tcc_add_include_path = (pfn_add_include_path) sym(lib, "tcc_add_include_path");
    lib.tcc_set_output_type  = (pfn_set_output_type)  sym(lib, "tcc_set_output_type");
    lib.tcc_compile_string   = (pfn_compile_string)   sym(lib, "tcc_compile_string");
    lib.tcc_add_symbol       = (pfn_add_symbol)       sym(lib, "tcc_add_symbol");
    lib.tcc_relocate         = (pfn_relocate)         sym(lib, "tcc_relocate");
    lib.tcc_get_symbol       = (pfn_get_symbol)       sym(lib, "tcc_get_symbol");

    lib.loaded = lib.tcc_new && lib.tcc_delete && lib.tcc_set_output_type &&
                 lib.tcc_compile_string && lib.tcc_add_symbol &&
                 lib.tcc_relocate && lib.tcc_get_symbol;
    return lib;
}

} // namespace

namespace N64Recomp {

TccRecompOutput::~TccRecompOutput() {
    if (state) {
        // The TCCState owns the executable memory `func` points into, so it can
        // only be freed once nothing will call `func` again (owner destruction).
        LibTcc& lib = load_libtcc(std::string());
        if (lib.loaded && lib.tcc_delete) {
            lib.tcc_delete(reinterpret_cast<TCCState*>(state));
        }
        state = nullptr;
    }
    func = nullptr;
    section_addrs_cell = nullptr;
}

TccRecompOutput& TccRecompOutput::operator=(TccRecompOutput&& rhs) noexcept {
    if (this != &rhs) {
        // Free any code we already own before taking rhs's.
        this->~TccRecompOutput();
        func = rhs.func;
        error = std::move(rhs.error);
        source = std::move(rhs.source);
        code_size = rhs.code_size;
        state = rhs.state;
        section_addrs_storage = std::move(rhs.section_addrs_storage);
        section_addrs_cell = rhs.section_addrs_cell;
        rhs.func = nullptr;
        rhs.state = nullptr;
        rhs.section_addrs_cell = nullptr;
        rhs.code_size = 0;
    }
    return *this;
}

bool tcc_backend_available(const TccToolchain& toolchain) {
    return load_libtcc(toolchain.toolchain_dir).loaded;
}

bool emit_function_c_source(const Context& context, size_t function_index,
                            std::string& source_out, std::string& func_name_out) {
    if (function_index >= context.functions.size()) {
        return false;
    }
    func_name_out = context.functions[function_index].name;

    std::ostringstream body;
    // recompile_function writes jal/jalr link targets into static_funcs_out by
    // section index; storage must exist per section even though we discard it.
    std::vector<std::vector<uint32_t>> static_funcs(context.sections.size());
    if (!recompile_function(context, function_index, body,
                            std::span<std::vector<uint32_t>>(static_funcs),
                            /*tag_reference_relocs=*/false)) {
        return false;
    }

    std::ostringstream src;
    src << g_tcc_recomp_prelude << "\n" << body.str();
    source_out = src.str();
    return true;
}

TccRecompOutput recompile_function_tcc(const Context& context, size_t function_index,
                                       const std::vector<TccSymbol>& symbols,
                                       const std::vector<int32_t>& section_addresses,
                                       const TccToolchain& toolchain) {
    TccRecompOutput out;

    LibTcc& lib = load_libtcc(toolchain.toolchain_dir);
    if (!lib.loaded) {
        out.error = "libtcc.dll not available";
        return out;
    }

    std::string func_name;
    if (!emit_function_c_source(context, function_index, out.source, func_name)) {
        out.error = "CGenerator failed to emit C for function";
        return out;
    }

    // Stable backing for the `section_addresses` data symbol (see header).
    out.section_addrs_storage = section_addresses;
    if (out.section_addrs_storage.empty()) {
        out.section_addrs_storage.push_back(0);
    }
    out.section_addrs_cell = out.section_addrs_storage.data();

    TCCState* s = lib.tcc_new();
    if (!s) {
        out.error = "tcc_new failed";
        return out;
    }

    std::string err_acc;
    lib.tcc_set_error_func(s, &err_acc, [](void* o, const char* m) {
        auto* acc = reinterpret_cast<std::string*>(o);
        if (!acc->empty()) acc->push_back('\n');
        acc->append(m);
    });

    // tcc needs its lib/ (libtcc1-64.a) and include/ from the bundled toolchain.
    if (!toolchain.toolchain_dir.empty()) {
        lib.tcc_set_lib_path(s, toolchain.toolchain_dir.c_str());
        std::string inc = toolchain.toolchain_dir + "/include";
        lib.tcc_add_include_path(s, inc.c_str());
    }
    if (lib.tcc_set_options) {
        lib.tcc_set_options(s, "-w");  // generated code is correct-by-construction; silence warnings
    }
    lib.tcc_set_output_type(s, TCC_OUTPUT_MEMORY);

    if (lib.tcc_compile_string(s, out.source.c_str()) < 0) {
        out.error = "tcc_compile_string failed: " + err_acc;
        lib.tcc_delete(s);
        return out;
    }

    // Bind the caller-provided host helpers + the section_addresses data symbol.
    for (const TccSymbol& sym_entry : symbols) {
        lib.tcc_add_symbol(s, sym_entry.name.c_str(), sym_entry.addr);
    }
    lib.tcc_add_symbol(s, "section_addresses", &out.section_addrs_cell);

    if (lib.tcc_relocate(s, TCC_RELOCATE_AUTO) < 0) {
        out.error = "tcc_relocate failed (unbound symbol?): " + err_acc;
        lib.tcc_delete(s);
        return out;
    }

    void* fn = lib.tcc_get_symbol(s, func_name.c_str());
    if (!fn) {
        out.error = "tcc_get_symbol could not find '" + func_name + "'";
        lib.tcc_delete(s);
        return out;
    }

    out.state = s;                              // owner now frees the TCCState
    out.func = reinterpret_cast<recomp_func_t*>(fn);
    if (!err_acc.empty()) out.error = err_acc;  // surface warnings non-fatally
    return out;
}

} // namespace N64Recomp
