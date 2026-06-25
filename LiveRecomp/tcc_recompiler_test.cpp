// Standalone smoke test for the in-process libtcc backend.
//
// Builds a Context the same way librecomp's jit_compile_inner does (single
// section, single function, use_lookup_for_all_function_calls), hands it to
// recompile_function_tcc, then RUNS the compiled function and checks the result.
// This proves that actual CGenerator output — not a hand-written shard — flows
// through the embedded recomp.h prelude + libtcc and executes correctly.
//
// Usage: TccRecompTest <toolchain_dir>   (dir containing libtcc.dll + lib/ + include/)
// Defaults to the in-tree lib/tcc when no argument is given.

#include <cstdio>
#include <cstring>
#include <vector>
#include <string>
#include <cinttypes>

#include "recompiler/context.h"
#include "recompiler/tcc_recompiler.h"
#include "recomp.h"

using namespace N64Recomp;

// ---- host runtime helpers the shard may reference (bound via tcc_add_symbol) --
static void test_write1(uint8_t* rdram, recomp_context* ctx) { MEM_B(0, ctx->r4) = 1; }
static recomp_func_t* test_get_function(int32_t vram) {
    if (vram == 0x80100000) return test_write1;
    return nullptr;
}
static gpr  test_cop0_status_read(recomp_context*) { return 0; }
static void test_cop0_status_write(recomp_context*, gpr) {}
static void test_switch_error(const char*, uint32_t, uint32_t) {}
static void test_do_break(uint32_t) {}

static int g_fail = 0;
static void check(const char* what, uint64_t got, uint64_t want) {
    bool ok = got == want;
    printf("  %-28s got=0x%016" PRIX64 " want=0x%016" PRIX64 "  %s\n",
           what, got, want, ok ? "PASS" : "FAIL");
    if (!ok) g_fail++;
}

// Build the same minimal Context jit_compile_inner uses, from real MIPS words.
static TccRecompOutput compile(const std::vector<uint32_t>& real_instrs, uint32_t vram,
                               const TccToolchain& tk) {
    // jit_compile_inner stores Function::words such that byteswap(word) is the
    // real instruction (recompile_function_impl byteswaps before rabbitizer).
    std::vector<uint32_t> words(real_instrs.size());
    for (size_t i = 0; i < real_instrs.size(); i++) words[i] = byteswap(real_instrs[i]);

    Context ctx{};
    Section sec{};
    sec.rom_addr = 0; sec.ram_addr = vram;
    sec.size = (uint32_t)(words.size() * 4); sec.name = "jit"; sec.executable = true;
    ctx.sections.push_back(std::move(sec));
    ctx.functions.emplace_back(vram, 0u, words, "jit_" + std::to_string(vram), (uint16_t)0);
    ctx.section_functions.push_back(std::vector<size_t>{0});
    ctx.use_lookup_for_all_function_calls = true;

    std::vector<TccSymbol> syms = {
        {"get_function",      (const void*)&test_get_function},
        {"cop0_status_read",  (const void*)&test_cop0_status_read},
        {"cop0_status_write", (const void*)&test_cop0_status_write},
        {"switch_error",      (const void*)&test_switch_error},
        {"do_break",          (const void*)&test_do_break},
    };
    std::vector<int32_t> secaddrs = { (int32_t)vram };
    return recompile_function_tcc(ctx, 0, syms, secaddrs, tk);
}

int main(int argc, char** argv) {
    TccToolchain tk;
    tk.toolchain_dir = (argc > 1) ? argv[1] : "lib/tcc";

    if (!tcc_backend_available(tk)) {
        printf("libtcc not available at '%s' — cannot run test\n", tk.toolchain_dir.c_str());
        return 2;
    }
    printf("libtcc loaded from '%s'\n", tk.toolchain_dir.c_str());

    std::vector<uint8_t> rdram(0x1000, 0);

    // Test 1: addiu $v0, $a0, 1 ; jr $ra ; nop   -> v0 = (int32)(a0 + 1)
    {
        auto out = compile({0x24820001u, 0x03E00008u, 0x00000000u}, 0x80000000u, tk);
        if (!out.good()) { printf("addiu compile FAILED: %s\n", out.error.c_str()); g_fail++; }
        else {
            recomp_context ctx; std::memset(&ctx, 0, sizeof ctx);
            ctx.r4 = 0x00000000FFFFFFFFull;       // a0 = -1 (32-bit)
            out.func(rdram.data(), &ctx);
            check("addiu v0=a0+1 (sext32)", ctx.r2, 0x0000000000000000ull);
        }
    }

    // Test 2: dmultu $a0,$a1 ; mflo $v0 ; mfhi $v1 ; jr $ra ; nop
    {
        auto out = compile({0x0085001Du, 0x00001012u, 0x00001810u, 0x03E00008u, 0x00000000u},
                           0x80000100u, tk);
        if (!out.good()) { printf("dmultu compile FAILED: %s\n", out.error.c_str()); g_fail++; }
        else {
            recomp_context ctx; std::memset(&ctx, 0, sizeof ctx);
            ctx.r4 = 0x00000000DEADBEEFull;       // a0
            ctx.r5 = 0x00000000CAFE1234ull;       // a1
            out.func(rdram.data(), &ctx);
            check("dmultu lo (v0)", ctx.r2, 0xB09218E179D9968Cull);
            check("dmultu hi (v1)", ctx.r3, 0x0000000000000000ull);
        }
    }

    printf("\nTccRecompTest: %s\n", g_fail ? "FAIL" : "ALL PASS");
    return g_fail ? 1 : 0;
}
