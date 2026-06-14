// Standalone reproduction of librecomp's B3 jit_compile_inner for a single
// hardcoded function, with no game launch. Replicates the exact minimal
// single-section, no-reloc, use_lookup_for_all_function_calls context so the
// live recompiler sees byte-for-byte what B3 feeds it. Used to localize the
// LiveRecomp infinite loop on FUN_8000eebc (a float-heavy function) vs Main
// (integer prologue), which compiles fine.
#include <cstdio>
#include <cstdint>
#include <vector>
#include <string>
#include <sstream>
#include <memory>
#include <cmath>

#include "sljitLir.h"
#include "recompiler/live_recompiler.h"
#include "recomp.h"

// main @ 0x80000550, 27 words
static const uint32_t main_words[] = {
    0x27BDFFE0, 0xAFBF001C, 0x0C014860, 0x00000000, 0x0C0024F0, 0x00002025,
    0x0C000B56, 0x00000000, 0x3C0E8008, 0x25CE09B0, 0x3C048008, 0x3C068000,
    0x240F0064, 0xAFAF0014, 0x24C60460, 0x24840400, 0xAFAE0010, 0x24050001,
    0x0C0146C8, 0x00003825, 0x3C048008, 0x0C01704C, 0x24840400, 0x8FBF001C,
    0x27BD0020, 0x03E00008, 0x00000000,
};
static const uint32_t main_vram = 0x80000550;

// fun_eebc @ 0x8000eebc, 39 words
static const uint32_t fun_eebc_words[] = {
    0xAFA7000C, 0x00073C00, 0x00073C03, 0x30E3FFFF, 0x3C098007, 0x00031903,
    0x44866000, 0x2529EBB0, 0x00031880, 0x01233021, 0xC4C60000, 0x97A20012,
    0x3C088007, 0x46066202, 0x00021103, 0x2508DBB0, 0x00021080, 0x01027021,
    0xC5C40000, 0xC4900000, 0x01037821, 0x46082282, 0x0122C021, 0x46105480,
    0xE4B20000, 0xC5E60000, 0xC4880004, 0x460C3102, 0x46082280, 0xE4AA0004,
    0xC4D20000, 0xC7100000, 0xC4880008, 0x46126182, 0x00000000, 0x46068102,
    0x46082280, 0x03E00008, 0xE4AA0008,
};
static const uint32_t fun_eebc_vram = 0x8000EEBC;

// sqrt leaf @ 0x80055340 (jr ra; sqrt.s) — handoff "recompile failed"
static const uint32_t sqrt_words[] = { 0x03E00008, 0x46006004 };
static const uint32_t sqrt_vram = 0x80055340;

// 0x8000F114 (6 words) — handoff "works" case
static const uint32_t f114_words[] = {
    0x00031400, 0xD7B40010, 0xD7B60018, 0x27BD0028, 0x03E00008, 0x00021403,
};
static const uint32_t f114_vram = 0x8000F114;

static recomp_func_t* repro_get_function(int32_t) { return nullptr; }
static void repro_switch_error(const char*, uint32_t, uint32_t) {}
static void repro_do_break(uint32_t) {}
static void repro_cop0_status_write(recomp_context*, gpr) {}
static gpr repro_cop0_status_read(recomp_context*) { return 0; }

static bool compile_one(const char* name, uint32_t vram,
                        const uint32_t* words, size_t nwords) {
    using namespace N64Recomp;
    printf("=== compiling %s @ 0x%08X (%zu words) ===\n", name, vram, nwords);
    fflush(stdout);

    // func.words convention is host-little-endian (recompile_function_impl
    // byteswaps each word before handing it to rabbitizer). Our hardcoded
    // arrays are big-endian instruction values, so byteswap them in.
    auto bswap32 = [](uint32_t v) {
        return (v >> 24) | ((v >> 8) & 0xFF00u) | ((v << 8) & 0xFF0000u) | (v << 24);
    };
    std::vector<uint32_t> w(nwords);
    for (size_t i = 0; i < nwords; i++) w[i] = bswap32(words[i]);

    Context ctx{};
    Section sec{};
    sec.rom_addr = 0;
    sec.ram_addr = vram;
    sec.size = (uint32_t)(nwords * 4);
    sec.name = "jit";
    sec.executable = true;
    ctx.sections.push_back(std::move(sec));
    ctx.functions.emplace_back(vram, 0u, w, "jit_" + std::to_string(vram), (uint16_t)0);
    ctx.section_functions.push_back(std::vector<size_t>{0});
    ctx.use_lookup_for_all_function_calls = true;

    auto section_addrs = std::make_unique<int32_t[]>(1);
    section_addrs[0] = (int32_t)vram;

    LiveGeneratorInputs inputs{};
    inputs.base_event_index = 0;
    inputs.cop0_status_write = repro_cop0_status_write;
    inputs.cop0_status_read = repro_cop0_status_read;
    inputs.switch_error = repro_switch_error;
    inputs.do_break = repro_do_break;
    inputs.get_function = repro_get_function;
    inputs.syscall_handler = nullptr;
    inputs.pause_self = nullptr;
    inputs.trigger_event = nullptr;
    inputs.reference_section_addresses = section_addrs.get();
    inputs.local_section_addresses = section_addrs.get();
    inputs.run_hook = nullptr;
    inputs.original_section_indices = std::vector<size_t>{0};

    LiveGenerator generator{ ctx.functions.size(), inputs };
    std::ostringstream dummy_ostream;
    // One entry per section (recompiler writes link targets into it).
    std::vector<std::vector<uint32_t>> dummy_static_funcs(ctx.sections.size());
    printf("  -> recompile_function_live\n"); fflush(stdout);
    if (!recompile_function_live(generator, ctx, 0, dummy_ostream,
                                 dummy_static_funcs, false)) {
        printf("  recompile_function_live FAILED\n"); fflush(stdout);
        return false;
    }
    printf("  -> finish (sljit generate_code)\n"); fflush(stdout);
    LiveGeneratorOutput output = generator.finish();
    if (!output.good || output.functions.empty() || output.functions[0] == nullptr) {
        printf("  no usable function\n"); fflush(stdout);
        return false;
    }
    printf("  OK: code_size=%zu\n", output.code_size); fflush(stdout);
    return true;
}

// Compile a function and return its callable pointer (or nullptr). Keeps the
// LiveGeneratorOutput alive via the out-param so the code stays mapped.
static recomp_func_t* compile_callable(uint32_t vram, const uint32_t* words,
        size_t nwords,
        std::unique_ptr<N64Recomp::LiveGeneratorOutput>& out_keep,
        std::unique_ptr<int32_t[]>& sect_keep) {
    using namespace N64Recomp;
    auto bswap32 = [](uint32_t v) {
        return (v >> 24) | ((v >> 8) & 0xFF00u) | ((v << 8) & 0xFF0000u) | (v << 24);
    };
    std::vector<uint32_t> w(nwords);
    for (size_t i = 0; i < nwords; i++) w[i] = bswap32(words[i]);

    Context ctx{};
    Section sec{};
    sec.rom_addr = 0; sec.ram_addr = vram; sec.size = (uint32_t)(nwords * 4);
    sec.name = "jit"; sec.executable = true;
    ctx.sections.push_back(std::move(sec));
    ctx.functions.emplace_back(vram, 0u, w, "jit_" + std::to_string(vram), (uint16_t)0);
    ctx.section_functions.push_back(std::vector<size_t>{0});
    ctx.use_lookup_for_all_function_calls = true;

    sect_keep = std::make_unique<int32_t[]>(1);
    sect_keep[0] = (int32_t)vram;

    LiveGeneratorInputs inputs{};
    inputs.cop0_status_write = repro_cop0_status_write;
    inputs.cop0_status_read = repro_cop0_status_read;
    inputs.switch_error = repro_switch_error;
    inputs.do_break = repro_do_break;
    inputs.get_function = repro_get_function;
    inputs.reference_section_addresses = sect_keep.get();
    inputs.local_section_addresses = sect_keep.get();
    inputs.original_section_indices = std::vector<size_t>{0};

    LiveGenerator generator{ ctx.functions.size(), inputs };
    std::ostringstream dummy_ostream;
    std::vector<std::vector<uint32_t>> dummy_static_funcs(ctx.sections.size());
    if (!recompile_function_live(generator, ctx, 0, dummy_ostream,
                                 dummy_static_funcs, false)) {
        return nullptr;
    }
    out_keep = std::make_unique<LiveGeneratorOutput>(generator.finish());
    if (!out_keep->good || out_keep->functions.empty()) return nullptr;
    return out_keep->functions[0];
}

// Execution test: JIT the sqrt leaf (f0 = sqrt(f12)) and verify it actually
// runs and computes the right float. Proves the live recompiler's codegen is
// not just crash-free but numerically correct end-to-end.
static bool exec_test_sqrt() {
    std::unique_ptr<N64Recomp::LiveGeneratorOutput> keep;
    std::unique_ptr<int32_t[]> sect;
    recomp_func_t* fn = compile_callable(sqrt_vram, sqrt_words,
        sizeof(sqrt_words) / sizeof(sqrt_words[0]), keep, sect);
    if (!fn) { printf("exec sqrt: compile FAILED\n"); return false; }

    std::vector<uint8_t> rdram(0x800000, 0);
    bool all_ok = true;
    const float inputs[] = { 4.0f, 2.0f, 16.0f, 100.0f, 0.25f, 1234.5f };
    for (float in : inputs) {
        recomp_context ctx{};
        ctx.r29 = 0xFFFFFFFF80000000ull + rdram.size() - 0x20;
        ctx.f12.fl = in;
        fn(rdram.data(), &ctx);
        float got = ctx.f0.fl;
        float want = std::sqrt(in);
        bool ok = std::fabs(got - want) < 1e-4f * (want + 1.0f);
        printf("  sqrt(%.4f) = %.6f (want %.6f) %s\n", in, got, want,
               ok ? "OK" : "MISMATCH");
        all_ok = all_ok && ok;
    }
    printf("exec sqrt: %s\n", all_ok ? "PASS" : "FAIL");
    return all_ok;
}

int main(int argc, const char** argv) {
    N64Recomp::live_recompiler_init();
    {
        std::string a = argc > 1 ? argv[1] : "";
        if (a == "exec") { return exec_test_sqrt() ? 0 : 1; }
    }

    std::string which = argc > 1 ? argv[1] : "both";
    if (which == "main" || which == "both") {
        compile_one("main", main_vram, main_words,
                    sizeof(main_words) / sizeof(main_words[0]));
    }
    if (which == "fun" || which == "both") {
        compile_one("fun_eebc", fun_eebc_vram, fun_eebc_words,
                    sizeof(fun_eebc_words) / sizeof(fun_eebc_words[0]));
    }
    if (which == "sqrt" || which == "both") {
        compile_one("sqrt", sqrt_vram, sqrt_words,
                    sizeof(sqrt_words) / sizeof(sqrt_words[0]));
    }
    if (which == "f114" || which == "both") {
        compile_one("f114", f114_vram, f114_words,
                    sizeof(f114_words) / sizeof(f114_words[0]));
    }
    printf("DONE\n"); fflush(stdout);
    return 0;
}
