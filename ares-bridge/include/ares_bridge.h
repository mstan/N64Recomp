// Part of N64Recomp's ares-bridge subsystem (added by Matthew Stanley
// in mstan fork; not present upstream). Distributed under the project's
// MIT License (see ../../LICENSE).
//
// Copyright (c) 2026 Matthew Stanley
//
// ---------------------------------------------------------------------

/*
 * ares_bridge.h — generic N64Recomp oracle bridge to Ares.
 *
 * Stable C API for embedding the Ares N64 core as a divergence
 * oracle. Header is intended to be consumed by any N64Recomp
 * runner regardless of the underlying game.
 *
 * Build modes:
 *   - Default (placeholder): every functional entry point in this
 *     header is linked against a body that abort()s on call. The
 *     only safe-to-call functions are ares_bridge_is_real() (which
 *     returns 0) and ares_bridge_version() (which returns "placeholder
 *     ..."). Consumers MUST gate all other calls behind
 *     ares_bridge_is_real() == 1.
 *   - Real (-DWITH_ARES_BRIDGE=ON): links the embedded Ares N64
 *     core. ares_bridge_is_real() returns 1. All entry points
 *     execute against Ares.
 *
 * ARES_BRIDGE_NOT_IMPLEMENTED is reserved for genuinely-unimplementable
 * sub-features inside the real build (e.g. an opcode the Ares core
 * does not support). It is NEVER returned just to mean "stub."
 */

#ifndef N64RECOMP_ARES_BRIDGE_H
#define N64RECOMP_ARES_BRIDGE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ */
/* Status codes returned by every API call                            */
/* ------------------------------------------------------------------ */

typedef enum {
    ARES_BRIDGE_OK                  = 0,
    ARES_BRIDGE_NOT_IMPLEMENTED     = 1,
    ARES_BRIDGE_NOT_INITIALIZED     = 2,
    ARES_BRIDGE_ALREADY_INITIALIZED = 3,
    ARES_BRIDGE_INVALID_ARGUMENT    = 4,
    ARES_BRIDGE_ROM_LOAD_FAILED     = 5,
    ARES_BRIDGE_STATE_BUFFER_TOO_SMALL = 6,
    ARES_BRIDGE_INTERNAL_ERROR      = 7,
} ares_status_t;

/* ------------------------------------------------------------------ */
/* Controller input (minimal N64 layout)                              */
/* ------------------------------------------------------------------ */

typedef struct {
    /* Buttons — bit-packed, layout matches N64 controller register */
    uint16_t buttons;        /* A, B, Z, Start, D-pad, L/R, C-pad */
    int8_t   stick_x;        /* analog stick, signed -128..127    */
    int8_t   stick_y;
    /* Reserved for rumble pak / mempak / transfer pak signaling   */
    uint16_t flags;
} ares_input_t;

/* ------------------------------------------------------------------ */
/* CPU register IDs (matches MIPS R4300 conventions)                  */
/* ------------------------------------------------------------------ */

enum {
    ARES_REG_R0 = 0, ARES_REG_AT, ARES_REG_V0, ARES_REG_V1,
    ARES_REG_A0, ARES_REG_A1, ARES_REG_A2, ARES_REG_A3,
    ARES_REG_T0, ARES_REG_T1, ARES_REG_T2, ARES_REG_T3,
    ARES_REG_T4, ARES_REG_T5, ARES_REG_T6, ARES_REG_T7,
    ARES_REG_S0, ARES_REG_S1, ARES_REG_S2, ARES_REG_S3,
    ARES_REG_S4, ARES_REG_S5, ARES_REG_S6, ARES_REG_S7,
    ARES_REG_T8, ARES_REG_T9, ARES_REG_K0, ARES_REG_K1,
    ARES_REG_GP, ARES_REG_SP, ARES_REG_FP, ARES_REG_RA,
    ARES_REG_COUNT_GPR
};

/* ------------------------------------------------------------------ */
/* Lifecycle                                                          */
/* ------------------------------------------------------------------ */

/* Initialize the embedded Ares N64 core and load `rom_path`. Returns
 * ARES_BRIDGE_ALREADY_INITIALIZED if called twice without an
 * intervening ares_shutdown(). */
ares_status_t ares_init(const char *rom_path);

/* Free all resources. Safe to call multiple times. */
void ares_shutdown(void);

/* Reset to power-on state. ROM remains loaded. */
ares_status_t ares_reset(void);

/* ------------------------------------------------------------------ */
/* Stepping                                                           */
/* ------------------------------------------------------------------ */

/* Advance one frame (until next VI vsync). Suitable for coarse
 * frame-by-frame divergence checks. */
ares_status_t ares_step_frame(void);

/* Advance one CPU instruction. Suitable for fine-grained
 * instruction-level divergence checks once a frame-level
 * divergence has been localized. */
ares_status_t ares_step_instruction(void);

/* ------------------------------------------------------------------ */
/* State read                                                         */
/* ------------------------------------------------------------------ */

/* Read a general-purpose register. `reg` is one of ARES_REG_*. */
ares_status_t ares_read_cpu_register(int reg, uint64_t *out);

/* Read the program counter. */
ares_status_t ares_read_pc(uint32_t *out);

/* Read the HI/LO multiply-divide registers. */
ares_status_t ares_read_hi_lo(uint64_t *hi, uint64_t *lo);

/* Read N bytes of RDRAM at virtual address `vaddr`. Performs MIPS
 * TLB translation if necessary. Returns ARES_BRIDGE_INVALID_ARGUMENT
 * for unmapped addresses. */
ares_status_t ares_read_memory(uint32_t vaddr, void *buf, size_t len);

/* ------------------------------------------------------------------ */
/* Single-task RSP replay (oracle): inject state + run one task        */
/* ------------------------------------------------------------------ */

/* Write N bytes into a physical region (symmetric to ares_read_memory):
 *   paddr 0x00000000-0x007FFFFF : RDRAM
 *   paddr 0x04000000-0x04000FFF : RSP DMEM
 *   paddr 0x04001000-0x04001FFF : RSP IMEM
 * `vaddr` is masked to physical (KSEG0/1 alias). */
ares_status_t ares_write_memory(uint32_t vaddr, const void *buf, size_t len);

/* Set the RSP scalar register file (gpr[0] ignored — r0 is hardwired 0) and
 * PC (IMEM-relative, 12-bit significant), clear halted/broken, and reset the
 * branch unit, so the next ares_rsp_run_until_halt() begins executing the
 * injected microcode from `pc`. */
ares_status_t ares_rsp_set_state(const uint32_t gpr[32], uint32_t pc,
                                 uint32_t dma_mem, uint32_t dma_dram);

/* Run the RSP from its current injected state until it halts (BREAK), pumping
 * DMA each step and draining in-flight DMA at the end. `max_steps` bounds a
 * runaway. `*out_steps` (optional) receives the instruction count. */
ares_status_t ares_rsp_run_until_halt(uint32_t max_steps, uint32_t *out_steps);

/* ------------------------------------------------------------------ */
/* Input                                                              */
/* ------------------------------------------------------------------ */

/* Set controller state for the given port (0-3). Persists until
 * the next ares_set_controller() call for that port. */
ares_status_t ares_set_controller(int port, const ares_input_t *in);

/* ------------------------------------------------------------------ */
/* State save / load (for rewind debugging)                           */
/* ------------------------------------------------------------------ */

/* Serialize complete emulator state into `buf`. If `buf` is NULL or
 * `buf_len` is too small, sets `*out_len` to the required size and
 * returns ARES_BRIDGE_STATE_BUFFER_TOO_SMALL. Otherwise writes the
 * state and sets `*out_len` to the bytes written. */
ares_status_t ares_save_state(void *buf, size_t buf_len, size_t *out_len);

/* Restore state previously serialized by ares_save_state. The ROM
 * must already be loaded; ares_load_state does not change the
 * loaded ROM. */
ares_status_t ares_load_state(const void *buf, size_t buf_len);

/* ------------------------------------------------------------------ */
/* RSP per-instruction trace ring (always-on, queryable)              */
/* ------------------------------------------------------------------ */

/* One captured RSP instruction event. Fields mirror what the Stadium
 * runtime's pc_trail captures plus the full GPR file and the cop0 DMA
 * registers — enough state to identify a divergence point and explain
 * its cause.
 *
 * Stable layout: do NOT reorder fields. Consumers may serialize this
 * over TCP / files. */
typedef struct {
    uint32_t pc;             /* RSP PC at instruction-fetch time, low
                              * 12 bits significant (RSP IMEM is 4 KiB) */
    uint32_t gpr[32];        /* $r0..$r31 just before the instruction
                              * dispatched */
    uint32_t dma_mem_addr;   /* SP_MEM_ADDR cop0 register */
    uint32_t dma_dram_addr;  /* SP_DRAM_ADDR cop0 register */
    uint32_t dma_rd_len;     /* SP_RD_LEN  (last-written; clears on
                              * DMA completion in real HW)             */
    uint32_t dma_wr_len;     /* SP_WR_LEN  (same)                     */
    uint32_t status;         /* SP_STATUS bitfield (halted, broken,
                              * dma_busy, dma_full, semaphore)         */
    uint64_t seq;            /* monotonic write index — used to detect
                              * tear when a slow reader competes with
                              * eviction. Equal to the absolute write
                              * count when written.                    */
} ares_rsp_trace_event_t;

/* Total events recorded since process start. Includes evicted ones. */
uint64_t ares_rsp_trace_count(void);

/* Fetch event by absolute index. Returns 1 on success, 0 if the
 * requested index has been evicted from the sliding ring. Idx is the
 * value that was equal to seq when the event was written; semantics
 * mirror recomp_ultra_trace_get(). */
int ares_rsp_trace_get(uint64_t idx, ares_rsp_trace_event_t *out);

/* Boot snapshot accessor — non-evicting capture of the first N
 * events ever recorded. Useful for "what did the RSP do at startup"
 * questions where the sliding ring has long since rolled over.
 * `pos` is 0-based into the snapshot, NOT an absolute seq. */
int ares_rsp_trace_boot_get(uint32_t pos, ares_rsp_trace_event_t *out);

/* Number of events available in the boot snapshot (capped at the
 * snapshot capacity). */
uint32_t ares_rsp_trace_boot_count(void);

/* Toggle trace recording. Default-on once the bridge is initialized
 * because the always-on ring philosophy is "record everything, query
 * windows." Disable only when validating that the hook itself is
 * cheap when not used (or for benchmarking the oracle without it). */
void ares_rsp_trace_set_enabled(int enabled);
int  ares_rsp_trace_is_enabled(void);

/* ------------------------------------------------------------------ */
/* Build / capability introspection                                   */
/* ------------------------------------------------------------------ */

/* Returns 1 if the bridge was compiled with WITH_ARES_BRIDGE=ON
 * (i.e., real Ares is linked in), 0 if this is a stub-only build. */
int ares_bridge_is_real(void);

/* Returns a const string identifying the linked Ares version, or
 * "stub" if ares_bridge_is_real() returns 0. */
const char *ares_bridge_version(void);

#ifdef __cplusplus
}
#endif

#endif /* N64RECOMP_ARES_BRIDGE_H */
