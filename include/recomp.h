// recomp.h — runtime ABI shared between the recompiler, the runtime, and
// every translation unit of recompiled guest code. It declares the guest
// CPU context (recomp_context), the load/store/arithmetic/float-conversion
// macros the generated C expands into, and the runtime entry points those
// expansions call back into. Anything generated code names by symbol lives
// here and must stay stable.
//
// Copyright (c) 2026 Matthew Stanley. Distributed under the project's MIT
// License; see the LICENSE file accompanying this distribution.
//
// One behavioral note worth recording up front: the byte-level memory
// macros (MEM_W / MEM_WU / MEM_H / MEM_HU / MEM_B / MEM_BU and the SD
// store) mask the computed host offset down to the mapped 1GB rdram
// window via RECOMP_MEM_MASK. That mirrors how the console's RDRAM bus
// silently wraps an out-of-range address rather than trapping, so a
// recompiled load fed a corrupt or mis-sign-extended register reads
// garbage from inside the window instead of taking a host access
// violation. See RECOMP_MEM_MASK below for the full rationale.
//
// ---------------------------------------------------------------------

#ifndef N64RECOMP_RECOMP_H
#define N64RECOMP_RECOMP_H

#include <stdint.h>

#include <stdlib.h>
#include <stdint.h>
#include <math.h>
#include <fenv.h>
#include <assert.h>

// Each recompiled guest function must keep its own identity at link time:
// no inter-procedural optimization may fold, inline, or specialize one into
// another, otherwise interposition between functions sharing a translation
// unit breaks. RECOMP_FUNC carries whatever per-compiler annotation achieves
// that, and SET_FENV_ACCESS() emits the matching floating-point-environment
// pragma where one exists.
#if defined(__TINYC__)
    // libtcc backend (in-process overlay/fragment shards): exactly one
    // function per TU, so there is nothing to interpose against and tcc
    // does no IPO regardless. No annotation, and tcc exposes no
    // FENV_ACCESS pragma.
    #define RECOMP_FUNC
    #define SET_FENV_ACCESS()
#elif defined(_MSC_VER) && !defined(__clang__) && !defined(__INTEL_COMPILER)
    // On MSVC, __declspec(noinline) is enough on its own to suppress the
    // cross-function optimization we need to avoid.
    #define RECOMP_FUNC __declspec(noinline)

    // MSVC spells the pragma fenv_access.
    #define SET_FENV_ACCESS() _Pragma("fenv_access(on)")
#elif defined(__clang__)
    // Clang offers no single "no IPO" attribute, so stack several. inline
    // permits the repeated definitions that linking produces, extern forces
    // an externally visible body, weak marks the symbol interposable (which
    // is what actually blocks IPO and, with inline present, real inlining),
    // and noinline is added belt-and-braces since it means something
    // orthogonal to the inline keyword.
    #define RECOMP_FUNC extern inline __attribute__((weak,noinline))

    // Clang honors the standard STDC FENV_ACCESS pragma.
    #define SET_FENV_ACCESS() _Pragma("STDC FENV_ACCESS ON")
#elif defined(__GNUC__) && !defined(__INTEL_COMPILER)
    // GCC has a direct attribute (noipa) to forbid inter-procedural
    // optimization. Pair it with the rounding-math optimization so constant
    // folding stops collapsing arithmetic that must observe the live FP
    // environment — GCC provides no FENV_ACCESS pragma to express that.
    #define RECOMP_FUNC __attribute__((noipa, optimize("rounding-math")))

    // GCC has no FENV_ACCESS pragma, so nothing to emit here.
    #define SET_FENV_ACCESS()
#else
    #error "No RECOMP_FUNC definition for this compiler"
#endif

#if defined(__clang__)
    #define RECOMP_MUSTTAIL __attribute__((musttail))
#else
    #define RECOMP_MUSTTAIL
#endif

// 64-bit multiply and divide helpers (the MIPS DMULT/DMULTU/DDIV/DDIVU ops).
#if defined(__TINYC__)

// libtcc backend (in-process overlay/fragment shards). tcc 0.9.27 lacks both
// __int128 and the MSVC _mul128 family, so the 64x64 -> 128 product is built
// by hand from four 32-bit limb partial products. The signed variant runs the
// unsigned one and then fixes its high word with the usual correction
// hi_signed = hi_unsigned - (a<0 ? b : 0) - (b<0 ? a : 0). The 64-bit
// divide/modulo paths (DDIV/DDIVU, further down) come from tcc's own libtcc1
// (__divdi3/__moddi3) and need nothing special here.
static inline void DMULTU(uint64_t a, uint64_t b, uint64_t* lo64, uint64_t* hi64) {
    uint64_t a_lo = (uint32_t)a, a_hi = a >> 32;
    uint64_t b_lo = (uint32_t)b, b_hi = b >> 32;
    uint64_t ll = a_lo * b_lo;
    uint64_t lh = a_lo * b_hi;
    uint64_t hl = a_hi * b_lo;
    uint64_t hh = a_hi * b_hi;
    uint64_t cross = (ll >> 32) + (uint32_t)lh + (uint32_t)hl;
    *lo64 = (ll & 0xFFFFFFFFull) | (cross << 32);
    *hi64 = hh + (lh >> 32) + (hl >> 32) + (cross >> 32);
}

static inline void DMULT(int64_t a, int64_t b, int64_t* lo64, int64_t* hi64) {
    uint64_t ulo, uhi;
    DMULTU((uint64_t)a, (uint64_t)b, &ulo, &uhi);
    if (a < 0) uhi -= (uint64_t)b;
    if (b < 0) uhi -= (uint64_t)a;
    *lo64 = (int64_t)ulo;
    *hi64 = (int64_t)uhi;
}

#elif defined(__SIZEOF_INT128__)

static inline void DMULT(int64_t a, int64_t b, int64_t* lo64, int64_t* hi64) {
    __int128 full128 = ((__int128)a) * ((__int128)b);

    *hi64 = (int64_t)(full128 >> 64);
    *lo64 = (int64_t)(full128 >> 0);
}

static inline void DMULTU(uint64_t a, uint64_t b, uint64_t* lo64, uint64_t* hi64) {
    unsigned __int128 full128 = ((unsigned __int128)a) * ((unsigned __int128)b);

    *hi64 = (uint64_t)(full128 >> 64);
    *lo64 = (uint64_t)(full128 >> 0);
}

#elif defined(_MSC_VER)

#include <intrin.h>
#pragma intrinsic(_mul128)
#pragma intrinsic(_umul128)

static inline void DMULT(int64_t a, int64_t b, int64_t* lo64, int64_t* hi64) {
    *lo64 = _mul128(a, b, hi64);
}

static inline void DMULTU(uint64_t a, uint64_t b, uint64_t* lo64, uint64_t* hi64) {
    *lo64 = _umul128(a, b, hi64);
}

#else
#error "128-bit integer type not found"
#endif

static inline void DDIV(int64_t a, int64_t b, int64_t* quot, int64_t* rem) {
    int overflow = ((uint64_t)a == 0x8000000000000000ull) && (b == -1ll);
    *quot = overflow ? a : (a / b);
    *rem = overflow ? 0 : (a % b);
}

static inline void DDIVU(uint64_t a, uint64_t b, uint64_t* quot, uint64_t* rem) {
    *quot = a / b;
    *rem = a % b;
}

typedef uint64_t gpr;

#define SIGNED(val) \
    ((int64_t)(val))

#define ADD32(a, b) \
    ((gpr)(int32_t)((a) + (b)))

#define SUB32(a, b) \
    ((gpr)(int32_t)((a) - (b)))

// Confine every computed host-side rdram offset to the mapped window so an
// out-of-range guest address wraps instead of faulting. A recompiled load
// can hold a garbage or wrongly sign-extended register value (for instance a
// short kuseg pointer that got sign-extended); without masking, the offset
// lands past the 1GB rdram allocation and the host takes an access
// violation. The console's RDRAM bus has a finite address width and simply
// wraps such addresses, so masking reproduces that — the program reads junk
// from inside the window rather than tearing down the host process. The
// constant must equal recomp::mem_size (1GB) declared in
// lib/N64ModernRuntime/librecomp/include/librecomp/addresses.hpp.
#define RECOMP_MEM_MASK 0x3FFFFFFFu

#define MEM_W(offset, reg) \
    (*(int32_t*)(rdram + ((((reg) + (offset)) - 0xFFFFFFFF80000000) & RECOMP_MEM_MASK)))

#define MEM_WU(offset, reg) \
    (*(uint32_t*)(rdram + ((((reg) + (offset)) - 0xFFFFFFFF80000000) & RECOMP_MEM_MASK)))

#define MEM_H(offset, reg) \
    (*(int16_t*)(rdram + (((((reg) + (offset)) ^ 2) - 0xFFFFFFFF80000000) & RECOMP_MEM_MASK)))

#define MEM_B(offset, reg) \
    (*(int8_t*)(rdram + (((((reg) + (offset)) ^ 3) - 0xFFFFFFFF80000000) & RECOMP_MEM_MASK)))

#define MEM_HU(offset, reg) \
    (*(uint16_t*)(rdram + (((((reg) + (offset)) ^ 2) - 0xFFFFFFFF80000000) & RECOMP_MEM_MASK)))

#define MEM_BU(offset, reg) \
    (*(uint8_t*)(rdram + (((((reg) + (offset)) ^ 3) - 0xFFFFFFFF80000000) & RECOMP_MEM_MASK)))

#define SD(val, offset, reg) { \
    *(uint32_t*)(rdram + ((((reg) + (offset) + 4) - 0xFFFFFFFF80000000) & RECOMP_MEM_MASK)) = (uint32_t)((gpr)(val) >> 0); \
    *(uint32_t*)(rdram + ((((reg) + (offset) + 0) - 0xFFFFFFFF80000000) & RECOMP_MEM_MASK)) = (uint32_t)((gpr)(val) >> 32); \
}

static inline uint64_t load_doubleword(uint8_t* rdram, gpr reg, gpr offset) {
    uint64_t ret = 0;
    uint64_t lo = (uint64_t)(uint32_t)MEM_W(reg, offset + 4);
    uint64_t hi = (uint64_t)(uint32_t)MEM_W(reg, offset + 0);
    ret = (lo << 0) | (hi << 32);
    return ret;
}

#define LD(offset, reg) \
    load_doubleword(rdram, offset, reg)

static inline gpr do_lwl(uint8_t* rdram, gpr initial_value, gpr offset, gpr reg) {
    // Effective byte address.
    gpr address = (offset + reg);

    // Fetch the word containing it, aligned down.
    gpr word_address = address & ~0x3;
    uint32_t loaded_value = MEM_W(0, word_address);

    // Keep the bytes that stay, slot in the bytes the load supplies.
    gpr misalignment = address & 0x3;
    gpr masked_value = initial_value & (gpr)(uint32_t)~(0xFFFFFFFFu << (misalignment * 8));
    loaded_value <<= (misalignment * 8);

    // int32_t cast first so the 32-bit result sign-extends into the gpr.
    return (gpr)(int32_t)(masked_value | loaded_value);
}

static inline gpr do_lwr(uint8_t* rdram, gpr initial_value, gpr offset, gpr reg) {
    // Effective byte address.
    gpr address = (offset + reg);
    
    // Fetch the word containing it, aligned down.
    gpr word_address = address & ~0x3;
    uint32_t loaded_value = MEM_W(0, word_address);

    // Keep the bytes that stay, slot in the bytes the load supplies.
    gpr misalignment = address & 0x3;
    gpr masked_value = initial_value & (gpr)(uint32_t)~(0xFFFFFFFFu >> (24 - misalignment * 8));
    loaded_value >>= (24 - misalignment * 8);

    // int32_t cast first so the 32-bit result sign-extends into the gpr.
    return (gpr)(int32_t)(masked_value | loaded_value);
}

static inline void do_swl(uint8_t* rdram, gpr offset, gpr reg, gpr val) {
    // Effective byte address.
    gpr address = (offset + reg);

    // Read back the current aligned word so the untouched bytes survive.
    gpr word_address = address & ~0x3;
    uint32_t initial_value = MEM_W(0, word_address);

    // Clear the bytes being overwritten, line the source bytes up to fill them.
    gpr misalignment = address & 0x3;
    uint32_t masked_initial_value = initial_value & ~(0xFFFFFFFFu >> (misalignment * 8));
    uint32_t shifted_input_value = ((uint32_t)val) >> (misalignment * 8);
    MEM_W(0, word_address) = masked_initial_value | shifted_input_value;
}

static inline void do_swr(uint8_t* rdram, gpr offset, gpr reg, gpr val) {
    // Effective byte address.
    gpr address = (offset + reg);

    // Read back the current aligned word so the untouched bytes survive.
    gpr word_address = address & ~0x3;
    uint32_t initial_value = MEM_W(0, word_address);

    // Clear the bytes being overwritten, line the source bytes up to fill them.
    gpr misalignment = address & 0x3;
    uint32_t masked_initial_value = initial_value & ~(0xFFFFFFFFu << (24 - misalignment * 8));
    uint32_t shifted_input_value = ((uint32_t)val) << (24 - misalignment * 8);
    MEM_W(0, word_address) = masked_initial_value | shifted_input_value;
}

static inline gpr do_ldl(uint8_t* rdram, gpr initial_value, gpr offset, gpr reg) {
    // Effective byte address.
    gpr address = (offset + reg);

    // Fetch the doubleword containing it, aligned down.
    gpr dword_address = address & ~0x7;
    uint64_t loaded_value = load_doubleword(rdram, 0, dword_address);

    // Keep the bytes that stay, slot in the bytes the load supplies.
    gpr misalignment = address & 0x7;
    gpr masked_value = initial_value & ~(0xFFFFFFFFFFFFFFFFu << (misalignment * 8));
    loaded_value <<= (misalignment * 8);

    return masked_value | loaded_value;
}

static inline gpr do_ldr(uint8_t* rdram, gpr initial_value, gpr offset, gpr reg) {
    // Effective byte address.
    gpr address = (offset + reg);
    
    // Fetch the doubleword containing it, aligned down.
    gpr dword_address = address & ~0x7;
    uint64_t loaded_value = load_doubleword(rdram, 0, dword_address);

    // Keep the bytes that stay, slot in the bytes the load supplies.
    gpr misalignment = address & 0x7;
    gpr masked_value = initial_value & ~(0xFFFFFFFFFFFFFFFFu >> (56 - misalignment * 8));
    loaded_value >>= (56 - misalignment * 8);

    return masked_value | loaded_value;
}

static inline void do_sdl(uint8_t* rdram, gpr offset, gpr reg, gpr val) {
    // Effective byte address.
    gpr address = (offset + reg);

    // Read back the current aligned doubleword so the untouched bytes survive.
    gpr dword_address = address & ~0x7;
    uint64_t initial_value = load_doubleword(rdram, 0, dword_address);

    // Clear the bytes being overwritten, line the source bytes up to fill them.
    gpr misalignment = address & 0x7;
    uint64_t masked_initial_value = initial_value & ~(0xFFFFFFFFFFFFFFFFu >> (misalignment * 8));
    uint64_t shifted_input_value = val >> (misalignment * 8);

    uint64_t ret = masked_initial_value | shifted_input_value;
    uint32_t lo = (uint32_t)ret;
    uint32_t hi = (uint32_t)(ret >> 32);

    MEM_W(0, dword_address + 4) = lo;
    MEM_W(0, dword_address + 0) = hi;
}

static inline void do_sdr(uint8_t* rdram, gpr offset, gpr reg, gpr val) {
    // Effective byte address.
    gpr address = (offset + reg);

    // Read back the current aligned doubleword so the untouched bytes survive.
    gpr dword_address = address & ~0x7;
    uint64_t initial_value = load_doubleword(rdram, 0, dword_address);

    // Clear the bytes being overwritten, line the source bytes up to fill them.
    gpr misalignment = address & 0x7;
    uint64_t masked_initial_value = initial_value & ~(0xFFFFFFFFFFFFFFFFu << (56 - misalignment * 8));
    uint64_t shifted_input_value = val << (56 - misalignment * 8);
    
    uint64_t ret = masked_initial_value | shifted_input_value;
    uint32_t lo = (uint32_t)ret;
    uint32_t hi = (uint32_t)(ret >> 32);

    MEM_W(0, dword_address + 4) = lo;
    MEM_W(0, dword_address + 0) = hi;
}

static inline uint32_t get_cop1_cs() {
    uint32_t rounding_mode = 0;
    switch (fegetround()) {
        // nearest
        case FE_TONEAREST:
        default:
            rounding_mode = 0;
            break;
        // toward zero (truncate)
        case FE_TOWARDZERO:
            rounding_mode = 1;
            break;
        // toward +inf (ceil)
        case FE_UPWARD:
            rounding_mode = 2;
            break;
        // toward -inf (floor)
        case FE_DOWNWARD:
            rounding_mode = 3;
            break;
    }
    return rounding_mode;
}

static inline void set_cop1_cs(uint32_t val) {
    uint32_t rounding_mode = val & 0x3;
    int round = FE_TONEAREST;
    switch (rounding_mode) {
        case 0: // nearest
            round = FE_TONEAREST;
            break;
        case 1: // toward zero (truncate)
            round = FE_TOWARDZERO;
            break;
        case 2: // toward +inf (ceil)
            round = FE_UPWARD;
            break;
        case 3: // toward -inf (floor)
            round = FE_DOWNWARD;
            break;
    }
    fesetround(round);
}

#define S32(val) \
    ((int32_t)(val))
    
#define U32(val) \
    ((uint32_t)(val))

#define S64(val) \
    ((int64_t)(val))

#define U64(val) \
    ((uint64_t)(val))

#define MUL_S(val1, val2) \
    ((val1) * (val2))

#define MUL_D(val1, val2) \
    ((val1) * (val2))

#define DIV_S(val1, val2) \
    ((val1) / (val2))

#define DIV_D(val1, val2) \
    ((val1) / (val2))

#define CVT_S_W(val) \
    ((float)((int32_t)(val)))

#define CVT_D_W(val) \
    ((double)((int32_t)(val)))

#define CVT_D_L(val) \
    ((double)((int64_t)(val)))

#define CVT_S_L(val) \
    ((float)((int64_t)(val)))

#define CVT_D_S(val) \
    ((double)(val))

#define CVT_S_D(val) \
    ((float)(val))

#define TRUNC_W_S(val) \
    ((int32_t)(val))

#define TRUNC_W_D(val) \
    ((int32_t)(val))

#define TRUNC_L_S(val) \
    ((int64_t)(val))

#define TRUNC_L_D(val) \
    ((int64_t)(val))

#define DEFAULT_ROUNDING_MODE 0

static inline int32_t do_cvt_w_s(float val) {
    // float -> 32-bit int honoring the current rounding mode.
    return (int32_t)lrintf(val);
}

#define CVT_W_S(val) \
    do_cvt_w_s(val)

static inline int64_t do_cvt_l_s(float val) {
    // float -> 64-bit int honoring the current rounding mode.
    return (int64_t)llrintf(val);
}

#define CVT_L_S(val) \
    do_cvt_l_s(val);

static inline int32_t do_cvt_w_d(double val) {
    // double -> 32-bit int honoring the current rounding mode.
    return (int32_t)lrint(val);
}

#define CVT_W_D(val) \
    do_cvt_w_d(val)

static inline int64_t do_cvt_l_d(double val) {
    // double -> 64-bit int honoring the current rounding mode.
    return (int64_t)llrint(val);
}

#define CVT_L_D(val) \
    do_cvt_l_d(val)

#define NAN_CHECK(val) \
    assert(val == val)

//#define NAN_CHECK(val)

typedef union {
    double d;
    struct {
        float fl;
        float fh;
    };
    struct {
        uint32_t u32l;
        uint32_t u32h;
    };
    uint64_t u64;
} fpr;

typedef struct recomp_context recomp_context;
typedef void (recomp_func_t)(uint8_t* rdram, recomp_context* ctx);

struct recomp_context {
    gpr r0,  r1,  r2,  r3,  r4,  r5,  r6,  r7,
        r8,  r9,  r10, r11, r12, r13, r14, r15,
        r16, r17, r18, r19, r20, r21, r22, r23,
        r24, r25, r26, r27, r28, r29, r30, r31;
    fpr f0,  f1,  f2,  f3,  f4,  f5,  f6,  f7,
        f8,  f9,  f10, f11, f12, f13, f14, f15,
        f16, f17, f18, f19, f20, f21, f22, f23,
        f24, f25, f26, f27, f28, f29, f30, f31;
    uint64_t hi, lo;
    uint32_t* f_odd;
    uint32_t status_reg;
    uint8_t mips3_float_mode;
    // Backing storage for COP0 registers that don't have a dedicated
    // helper. This is NOT a "stub" fallback — it is the architecturally
    // correct HLE model for every COP0 register whose hardware semantics
    // depend on subsystems we don't simulate.
    //
    // Per-register reasoning (see operations/cop0 dispatch in
    // src/recompilation.cpp for the corresponding emit decisions):
    //
    //   $0..$7   TLB regs (Index/Random/EntryLo0/EntryLo1/Context/
    //            PageMask/Wired). HLE has no TLB — virtual addresses
    //            translate via the constant offset in MEM_W. Writes
    //            here are stored; reads return the last write. libultra
    //            zeros these at boot then never reads them.
    //   $8       BadVAddr. Written by hardware on TLB miss; HLE has no
    //            CPU exceptions, so the only writes come from libultra
    //            init zeroing. Storage.
    //   $9       Count. Free-running cycle counter. Storage today;
    //            libultra games typically use the VI interrupt for
    //            timing. If a game polls Count for elapsed time we add
    //            a side-effecting read helper THEN.
    //   $10      EntryHi. TLB. Storage.
    //   $11      Compare. Write resets pending timer interrupt on real
    //            hardware. HLE has no timer interrupt path (interrupts
    //            come from VI/AI/SI events), so storage matches
    //            observable behavior.
    //   $12      Status. NOT in this array — has dedicated helpers
    //            cop0_status_read/write because it controls FR
    //            (FPU register layout) and interrupt enable bits.
    //   $13      Cause. Read returns pending IRQ bits set by hardware.
    //            HLE: VI/AI/SI events drive their own IRQ paths. If a
    //            game reads Cause to learn about pending IRQs we add a
    //            read helper THEN. Stadium only writes (clear) at boot.
    //   $14      EPC. Exception PC, written by exception entry. HLE has
    //            no exception entry. Storage.
    //   $15      PRId. Processor ID. Read-only on real hardware
    //            (R4300i = 0x00000B00). We allow writes to land in
    //            storage; the only consumer is debug code, which
    //            doesn't run in HLE.
    //   $16      Config. Cache configuration. HLE has no cache.
    //   $17      LLAddr. Load-linked address. HLE doesn't model LL/SC
    //            atomicity. Storage.
    //   $18,$19  WatchLo/WatchHi. Hardware data watchpoints. HLE has
    //            no debug exception path. Storage.
    //   $20      XContext. 64-bit TLB miss context. Storage.
    //   $21..$25 Reserved on real hardware. Loud abort if accessed.
    //   $26      PErr. Cache parity error. HLE never generates errors.
    //   $27      CacheErr. Same.
    //   $28,$29  TagLo/TagHi. Cache tag access. HLE has no cache.
    //   $30      ErrorEPC. Error exception PC. Storage.
    //   $31      Reserved. Loud abort.
    //
    // This is the "model is storage" decision, made deliberately per
    // register, not a fallback default. When a game surfaces a register
    // whose HLE semantics genuinely need a side effect (read of Count,
    // read of Cause, write of Compare with timer ack), we add a
    // dedicated helper for THAT register and the dispatch in
    // recompilation.cpp routes to it instead of cop0_regs[].
    uint32_t cop0_regs[32];

    uint32_t tailcall_target;
    uint32_t tailcall_pending;
    uint32_t tailcall_dispatching;
    recomp_func_t* tailcall_func;
    uint32_t host_return_target;
    uint32_t dispatch_entry_target;
    // Set by a generated function's dispatch-entry switch DEFAULT arm when the
    // requested interior entry PC is not one of that function's emitted labels:
    // it means "this compiled function cannot service that entry PC," so the
    // function returns WITHOUT executing guest code and librecomp's self-heal
    // interprets from the exact PC instead of mis-running the function from its
    // prologue. _target carries the rejected entry PC (interpreter + telemetry).
    uint32_t dispatch_entry_rejected;
    uint32_t dispatch_entry_rejected_target;
};

// Asserts the FPR index is legal: either even, or any index once the context
// has mips3 float mode turned on.
#define CHECK_FR(ctx, idx) \
    assert(((idx) & 1) == 0 || (ctx)->mips3_float_mode)

#ifdef __cplusplus
extern "C" {
#endif

void cop0_status_write(recomp_context* ctx, gpr value);
gpr cop0_status_read(recomp_context* ctx);
void switch_error(const char* func, uint32_t vram, uint32_t jtbl);
void do_break(uint32_t vram);

// Signature for the special functions that take an extra third argument.
// They are reached through generated shims, which is how per-caller context
// (such as a mod id) gets threaded in.
typedef void (recomp_func_ext_t)(uint8_t* rdram, recomp_context* ctx, uintptr_t arg);

recomp_func_t* get_function(int32_t vram);
void pms_gbexec_tailcall_probe(recomp_context* ctx, uint32_t target);
void pms_gbexec_r2minus1_probe(uint32_t site, uint8_t* rdram, recomp_context* ctx);
void pms_gbexec_r24_probe(uint32_t site, uint8_t* rdram, recomp_context* ctx);
void pms_gbexec_pc_probe(uint32_t site, uint8_t* rdram, recomp_context* ctx);

static inline void recomp_request_tailcall(recomp_context* ctx, gpr target) {
    pms_gbexec_tailcall_probe(ctx, (uint32_t)target);
    ctx->tailcall_target = (uint32_t)target;
    ctx->tailcall_func = NULL;
    ctx->tailcall_pending = 1;
}

static inline void recomp_request_tailcall_func(recomp_context* ctx, recomp_func_t* func) {
    ctx->tailcall_target = 0;
    ctx->tailcall_func = func;
    ctx->tailcall_pending = 1;
}

static inline void recomp_request_tailcall_func_target(recomp_context* ctx, recomp_func_t* func, uint32_t target) {
    pms_gbexec_tailcall_probe(ctx, target);
    ctx->tailcall_target = target;
    ctx->tailcall_func = func;
    ctx->tailcall_pending = 1;
}

void recomp_handle_tailcalls(uint8_t* rdram, recomp_context* ctx);
void recomp_cf_note(const char* kind, uint32_t value0, uint32_t value1, uint32_t value2, recomp_context* ctx);

#define LOOKUP_FUNC(val) \
    get_function((int32_t)(val))

extern int32_t* section_addresses;

#define LO16(x) \
    ((x) & 0xFFFF)

#define HI16(x) \
    (((x) >> 16) + (((x) >> 15) & 1))

#define RELOC_HI16(section_index, offset) \
    HI16(section_addresses[section_index] + (offset))

#define RELOC_LO16(section_index, offset) \
    LO16(section_addresses[section_index] + (offset))

void recomp_syscall_handler(uint8_t* rdram, recomp_context* ctx, int32_t instruction_vram);

void pause_self(uint8_t *rdram);

/* Voluntary-preemption checkpoint. The recompiler emits
 * RECOMP_LOOP_CHECKPOINT() on every intra-function loop back-edge,
 * UNCONDITIONALLY — this is cooperative-scheduler correctness, not
 * tracing. A tight intra-function spin loop never re-enters a function,
 * so without a back-edge checkpoint a CPU-bound guest loop (an idle
 * thread's while(1), GB Tower's osGbpakInit power-up wait) starves the
 * scheduler: externally-posted messages (VI retrace, SP/DP completions,
 * timer fires) are never drained into guest queues and every blocked
 * thread sleeps forever (black-screen boot deadlock). trace_mode gates
 * only the TRACE_ENTRY/TRACE_RETURN logging hooks, never this
 * checkpoint.
 *
 * The default routes to the runtime's tick (N64ModernRuntime
 * ultramodern/src/scheduler_tick.cpp): one relaxed atomic load on the
 * fast path; drains/yields only when external messages are pending or
 * the host monitor flagged the thread as stuck. New generated code uses
 * RECOMP_LOOP_CHECKPOINT_VRAM(pc) so diagnostics can identify the exact
 * guest back-edge. The zero-arg form remains for older generated code.
 * Consumers may redefine the macro before compiling generated code, but
 * any override must remain a real yield point. */
void ultramodern_scheduler_tick(void);
void ultramodern_scheduler_tick_vram(uint32_t pc);
#ifndef RECOMP_LOOP_CHECKPOINT
#define RECOMP_LOOP_CHECKPOINT() ultramodern_scheduler_tick();
#endif
#ifndef RECOMP_LOOP_CHECKPOINT_VRAM
#define RECOMP_LOOP_CHECKPOINT_VRAM(pc) ultramodern_scheduler_tick_vram(pc);
#endif

/* Tolerant-emit runtime entry points. The engine emits calls to these
 * for instructions/branches/calls it can't translate at compile time;
 * consumers implement them in a runtime hook file (e.g. extras.c).
 * See src/recompilation.cpp for the emit sites; these exist to make
 * untranslatable code fail as loud runtime aborts, NOT stubs. */
void recomp_unhandled_branch(uint8_t *rdram, recomp_context *ctx,
                             uint32_t instr_vram, uint32_t branch_target);
void recomp_unhandled_call(uint8_t *rdram, recomp_context *ctx,
                           uint32_t instr_vram, uint32_t target);
void recomp_unhandled_jalr(uint8_t *rdram, recomp_context *ctx,
                           uint32_t instr_vram, uint64_t target_value, int rd);
uint64_t recomp_unhandled_cop0_read(uint8_t *rdram, recomp_context *ctx,
                                    uint32_t instr_vram, int cop0_reg);
void recomp_unhandled_cop0_write(uint8_t *rdram, recomp_context *ctx,
                                 uint32_t instr_vram, int cop0_reg, uint64_t value);
void recomp_unhandled_instruction(uint8_t *rdram, recomp_context *ctx,
                                  uint32_t instr_vram, const char *opcode_name);

/* Runtime fragment registrar — invoked from a Memmap_RelocateFragment
 * hook (see Stadium's game.toml). Translates Stadium's encoded fragment
 * id to the matching section in the recompiled section_table and
 * registers all of that section's FuncEntry rows in func_map at
 * (fragment_ptr + offset). Also runs the trampoline scanner over the
 * fragment's textbin region. Implemented in
 * librecomp/src/overlays.cpp. */
void recomp_register_runtime_fragment(uint8_t *rdram, uint32_t id,
                                       int32_t fragment_ptr);
void recomp_unregister_runtime_fragment(uint32_t id);
void pms_diag_script_dispatch(uint8_t *rdram, recomp_context *ctx);

#ifdef __cplusplus
}
#endif

#endif
