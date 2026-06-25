#ifndef __TCC_RECOMPILER_H__
#define __TCC_RECOMPILER_H__

// In-process libtcc recompilation backend.
//
// This is the C-emitting counterpart to LiveRecomp's sljit `LiveGenerator`: it
// drives the existing `CGenerator` to emit ONE function's C, then compiles that
// C in-memory with libtcc (TinyCC) and returns a callable `recomp_func_t*`.
//
// Why it exists: the sljit live generator emits final, position-dependent
// machine code from a hand-written LIR backend (one emitter per opcode). The
// tcc backend instead reuses the already-proven `CGenerator` (the same emitter
// the offline/static build uses) and lets a real C compiler produce the code.
// That removes the second, independent codegen path (the sljit emitter, which
// mis-compiled some functions) in favor of a single C emitter shared with the
// static build. libtcc is loaded DYNAMICALLY at runtime (see tcc_generator.cpp),
// so a missing libtcc.dll simply makes this backend unavailable (the caller
// falls back to the interpreter floor) rather than a hard link dependency.
//
// The runtime helpers a shard calls (get_function, cop0_status_read/write,
// do_break, switch_error, the `section_addresses` data symbol, ...) live in the
// downstream runtime (librecomp), not here — so, mirroring LiveGeneratorInputs,
// the caller passes them in as name->pointer bindings that are resolved with
// tcc_add_symbol before relocation.

#include <string>
#include <vector>
#include "recompiler/context.h"
#include "recomp.h"

namespace N64Recomp {
    // One host symbol the compiled shard references (a runtime helper function,
    // or the `section_addresses` data pointer). `addr` is bound to `name` via
    // tcc_add_symbol before tcc_relocate.
    struct TccSymbol {
        std::string name;
        const void* addr;
    };

    // Filesystem locations of the bundled tcc toolchain. `toolchain_dir` is the
    // directory that contains libtcc.dll and the `lib/` (libtcc1-64.a) and
    // `include/` subdirectories shipped beside the host executable. May be empty
    // to use the process directory / PATH.
    struct TccToolchain {
        std::string toolchain_dir;
    };

    // Owns the compiled code. The libtcc TCCState that produced the function
    // also OWNS the executable memory the function lives in, so this object must
    // outlive every call to `func`. Move-only; frees the TCCState on destruction.
    class TccRecompOutput {
    public:
        TccRecompOutput() = default;
        ~TccRecompOutput();
        TccRecompOutput(const TccRecompOutput&) = delete;
        TccRecompOutput& operator=(const TccRecompOutput&) = delete;
        TccRecompOutput(TccRecompOutput&& rhs) noexcept { *this = std::move(rhs); }
        TccRecompOutput& operator=(TccRecompOutput&& rhs) noexcept;

        bool good() const { return func != nullptr; }

        // The compiled function, or null on failure (see `error`).
        recomp_func_t* func = nullptr;
        // Diagnostic on failure (or tcc warnings on success).
        std::string error;
        // The C source that was compiled (kept for post-mortem / dumping).
        std::string source;
        // Compiled size in bytes (best-effort; 0 if unknown).
        size_t code_size = 0;

    private:
        void* state = nullptr;  // TCCState* — owns the code memory.
        // Stable backing for the generated code's `section_addresses` data
        // symbol: `section_addrs_storage` holds the per-shard section bases and
        // `section_addrs_cell` is the int32_t* the symbol resolves to (its
        // address is what gets bound, so it must never move — hence heap-owned
        // here for the life of the compiled code).
        std::vector<int32_t> section_addrs_storage;
        int32_t* section_addrs_cell = nullptr;
        friend TccRecompOutput recompile_function_tcc(const Context&, size_t,
            const std::vector<TccSymbol>&, const std::vector<int32_t>&, const TccToolchain&);
    };

    // True if libtcc.dll can be loaded from `toolchain_dir` (or the default
    // search path when empty). Cached after the first call.
    bool tcc_backend_available(const TccToolchain& toolchain);

    // Build the full C translation unit for one function: the embedded recomp.h
    // prelude followed by the CGenerator output for `function_index`. Returns
    // false if the C emitter failed. `func_name_out` receives the emitted
    // function's symbol name (context.functions[function_index].name).
    bool emit_function_c_source(const Context& context, size_t function_index,
                                std::string& source_out, std::string& func_name_out);

    // Compile one function's C with libtcc in-memory and return a callable
    // recomp_func_t*. Drives CGenerator for `function_index`, prepends the
    // embedded recomp.h prelude, binds each `symbols` entry plus the
    // `section_addresses` data symbol (backed by `section_addresses`, copied
    // into the returned owner), then relocates and extracts the function.
    // Every host symbol the shard references that is not provided by recomp.h /
    // libtcc1 must appear in `symbols` (e.g. get_function, cop0_status_read,
    // cop0_status_write, switch_error, do_break).
    TccRecompOutput recompile_function_tcc(const Context& context, size_t function_index,
                                           const std::vector<TccSymbol>& symbols,
                                           const std::vector<int32_t>& section_addresses,
                                           const TccToolchain& toolchain);
}

#endif
