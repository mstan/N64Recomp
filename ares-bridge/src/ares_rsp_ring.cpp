// Part of N64Recomp's ares-bridge subsystem (added by Matthew Stanley
// in mstan fork; not present upstream). Distributed under the project's
// MIT License (see ../../LICENSE).
//
// Copyright (c) 2026 Matthew Stanley
//
// ---------------------------------------------------------------------

/*
 * ares_rsp_ring.cpp — always-on RSP per-instruction trace ring.
 *
 * Captures (PC, all 32 GPRs, DMA cop0 regs, SP_STATUS) every time
 * the Ares RSP core dispatches an instruction. The vendored Ares
 * core has a 4-line modification (extern "C" function pointer hook
 * declared in rsp.cpp; called at the top of RSP::instruction()) —
 * that pointer is set here at static-init time to point at our
 * `record_one_instruction` callback.
 *
 * Two storage tiers, mirroring the libultra-ring pattern from
 * lib/N64ModernRuntime/librecomp/include/librecomp/ultra_trace.hpp:
 *
 *   1. Sliding ring (16K events, ~2.5 MiB) — records every event,
 *      oldest evicts. Used for "what just happened" queries close
 *      to a hang or interesting moment.
 *
 *   2. Boot snapshot (32K events, ~5 MiB) — non-evicting; once the
 *      first 32K events are recorded, no more land here. Used for
 *      "what did the RSP do at startup" forensics.
 *
 * Total memory: ~7.5 MiB at process start, fixed thereafter. Cost
 * per recorded event: one branch (enabled check), GPR + DMA-reg
 * memcpy, atomic increment.
 *
 * Per the project rule "always-on ring buffer, never arm-then-capture":
 * the hook is installed unconditionally at process start and stays
 * recording until shutdown. Consumers QUERY a window of interest;
 * they don't ARM recording in advance.
 */

#include "ares_bridge.h"

#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstring>

/* Pull in just enough of Ares' RSP type to read its register file
 * without dragging the full <n64/n64.hpp> in twice (it's already
 * included by ares_core_glue.cpp; including from two TUs in the
 * same static lib has caused odd ODR warnings historically). The
 * field offsets we need — ipu.r[32], ipu.pc, dma.{mem,dram}Address,
 * dma.{read,write}Length, status bits — are stable across Ares
 * versions per their interpreter contract. */
#include <ares/ares.hpp>
#include <n64/n64.hpp>

/* Ares-side hook installation point: the bridge's modification to
 * ares/n64/rsp/rsp.cpp declares this function pointer extern "C" and
 * calls it at the top of RSP::instruction(). We assign it here and
 * the linker resolves both declarations to the same symbol. */
extern "C" void (*ares_rsp_external_instruction_hook)(void* rsp_instance);

namespace {

/* Ring sizes. Powers of two so the modulo collapses to a mask. */
constexpr uint32_t kSlidingCapacity = 1u << 14;   // 16384
constexpr uint32_t kSlidingMask     = kSlidingCapacity - 1;
constexpr uint32_t kBootCapacity    = 1u << 15;   // 32768

/* Audio-task ring: 8192 entries x ~4.1 KiB = ~34 MiB. At Stadium's
 * ~58 audio tasks/sec that is ~2.3 minutes of coverage — enough that
 * an attract-mode A/B session can drain once at the end rather than
 * polling. */
constexpr uint32_t kAudioTaskCapacity = 1u << 13; // 8192
constexpr uint32_t kAudioTaskMask     = kAudioTaskCapacity - 1;

struct RingState {
    /* Sliding ring storage. The seq field on each event matches the
     * write_idx value when written, allowing readers to detect an
     * overwrite mid-read by re-checking seq after copying. */
    ares_rsp_trace_event_t sliding[kSlidingCapacity] = {};

    /* Boot snapshot — first kBootCapacity events, then frozen. */
    ares_rsp_trace_event_t boot[kBootCapacity] = {};

    /* Monotonic write counter. Stored as 64-bit to avoid wrap during
     * a long oracle session (16K events/sec * 64 bits => essentially
     * forever). */
    std::atomic<uint64_t> write_idx{0};

    /* Number of events captured into the boot snapshot. Saturates at
     * kBootCapacity. Plain uint32 because writes to it are guarded by
     * the same hook that's already serialized via Ares' single-thread
     * scheduler — only one RSP thread fires the hook at a time. */
    uint32_t boot_count{0};

    /* Recording on/off. Defaults to enabled; consumers can toggle
     * via ares_rsp_trace_set_enabled(). */
    std::atomic<bool> enabled{true};

    /* Audio-task ring (see ares_audio_task_event_t in the header).
     * Same single-writer / seq-recheck protocol as the sliding ring. */
    ares_audio_task_event_t audio_tasks[kAudioTaskCapacity] = {};
    std::atomic<uint64_t> audio_task_idx{0};

    /* Previous hook-fire PC, for task-start edge detection. Tasks boot
     * at IMEM offset 0 (SP_PC is written 0x04001000 by osSpTaskStartGo)
     * and nothing inside rspboot/aspMain jumps back there, so the
     * 0 -> executing edge fires exactly once per task. */
    uint32_t last_pc = 0xFFFFFFFFu;
};

RingState g_ring;

/* Big-endian u32 out of RSP DMEM. The Byte accessor returns the byte
 * stream in N64 wire order (same ordering ares_read_memory yields), so
 * the byte at the lowest address is the MSB. */
uint32_t dmem_read_u32(ares::Nintendo64::RSP* rsp, uint32_t off) {
    uint32_t v = 0;
    for (int i = 0; i < 4; i++) {
        v = (v << 8) |
            (uint8_t)rsp->dmem.read<ares::Nintendo64::Byte>(off + (uint32_t)i);
    }
    return v;
}

/* Audio-task capture: called from the hook at each task's first
 * instruction. Reads the OSTask out of DMEM 0xFC0 (where osSpTaskLoad
 * put it) and, for M_AUDTASK, snapshots the Acmd list bytes from RDRAM
 * at exactly this moment — the CPU finished building the list before
 * it started the task, and cannot touch it again until the task ends. */
void record_audio_task_start(ares::Nintendo64::RSP* rsp, uint64_t instr_seq) {
    constexpr uint32_t kOSTaskDmem = 0xFC0;
    const uint32_t type = dmem_read_u32(rsp, kOSTaskDmem + 0x00);
    if (type != 2 /* M_AUDTASK */) return;

    uint64_t my_idx = g_ring.audio_task_idx.load(std::memory_order_relaxed);
    ares_audio_task_event_t& ev = g_ring.audio_tasks[my_idx & kAudioTaskMask];
    /* Publish-last protocol: write idx after the payload so readers'
     * seq recheck catches a mid-overwrite read. Stamp a sentinel first. */
    ev.idx = ~0ull;

    ev.instr_seq        = instr_seq;
    ev.task_type        = type;
    ev.task_flags       = dmem_read_u32(rsp, kOSTaskDmem + 0x04);
    ev.ucode            = dmem_read_u32(rsp, kOSTaskDmem + 0x10);
    ev.ucode_data       = dmem_read_u32(rsp, kOSTaskDmem + 0x18);
    ev.output_buff      = dmem_read_u32(rsp, kOSTaskDmem + 0x28);
    ev.output_buff_size = dmem_read_u32(rsp, kOSTaskDmem + 0x2C);
    ev.data_ptr         = dmem_read_u32(rsp, kOSTaskDmem + 0x30);
    ev.data_size        = dmem_read_u32(rsp, kOSTaskDmem + 0x34);

    uint32_t want = ev.data_size;
    if (want > ARES_AUDIO_TASK_DATA_CAP) want = ARES_AUDIO_TASK_DATA_CAP;
    auto& rdram = ares::Nintendo64::rdram;
    uint32_t paddr = ev.data_ptr & 0x1FFFFFFFu;
    if ((uint64_t)paddr + want > rdram.ram.size) {
        want = 0;
    }
    for (uint32_t i = 0; i < want; i++) {
        ev.data[i] = (uint8_t)rdram.ram.read<ares::Nintendo64::Byte>(
            paddr + i, "oracle");
    }
    ev.captured_len = want;
    ev.pad_ = 0;

    ev.idx = my_idx;
    g_ring.audio_task_idx.store(my_idx + 1, std::memory_order_release);
}

/* The hook itself. Reads RSP state via the Ares public-ish API and
 * writes one event into both rings.
 *
 * Single-writer assumption: Ares' scheduler never runs the RSP from
 * two host threads concurrently (cpu.main() invokes synchronize()
 * which runs RSP on the same thread). So this function does not need
 * an internal mutex even though it touches g_ring without one — the
 * atomic write_idx is purely so external readers see consistent
 * ordering. */
void record_one_instruction(void* rsp_instance) {
    if (!g_ring.enabled.load(std::memory_order_relaxed)) return;

    auto* rsp = static_cast<ares::Nintendo64::RSP*>(rsp_instance);

    /* Reserve a slot. memory_order_relaxed because we don't need to
     * synchronize anything except the seq field within the event. */
    uint64_t my_seq = g_ring.write_idx.fetch_add(1, std::memory_order_relaxed);

    /* Build the event on the stack first, then memcpy. This keeps the
     * window during which a partial event is visible as small as
     * possible — readers detect that window via the seq mismatch
     * check at end. */
    ares_rsp_trace_event_t ev = {};
    ev.pc = rsp->ipu.pc & 0xFFFu;
    for (int i = 0; i < 32; i++) {
        ev.gpr[i] = rsp->ipu.r[i].u32;
    }
    /* DMA registers. Ares splits these into `pending` (most recently
     * written via mtc0) and `current` (in-flight). For divergence
     * comparison against our runtime's RspContext.dma_mem_address /
     * dma_dram_address (which track the most-recently-written values),
     * we read pending. The length/skip/count fields combine the same
     * way SP_RD_LEN / SP_WR_LEN are encoded on real hardware. */
    ev.dma_mem_addr  = (uint32_t)rsp->dma.pending.pbusAddress;
    ev.dma_dram_addr = (uint32_t)rsp->dma.pending.dramAddress;
    ev.dma_rd_len    = (uint32_t)rsp->dma.pending.length;
    /* Ares only tracks one length; bit 0 of dma_wr_len doubles as the
     * read/write flag (1 = write was the last DMA direction). This
     * matches what consumers need to know: which kind of DMA is in
     * flight or was last triggered. */
    ev.dma_wr_len    = (uint32_t)rsp->dma.busy.write |
                       ((uint32_t)rsp->dma.busy.read << 1);
    /* SP_STATUS as a packed bitfield. Layout:
     *   bit 0  halted
     *   bit 1  broken
     *   bit 2  reserved (was dmaBusy — encoded in dma_wr_len above)
     *   bit 3  dmaFull
     *   bit 4  semaphore
     *   bit 5  interruptOnBreak
     *   bit 6  singleStep
     *   bits 8-15  signal[0..7] */
    uint32_t st = 0;
    st |= (rsp->status.halted          ? 1u : 0u) << 0;
    st |= (rsp->status.broken          ? 1u : 0u) << 1;
    st |= (rsp->status.full            ? 1u : 0u) << 3;
    st |= (rsp->status.semaphore       ? 1u : 0u) << 4;
    st |= (rsp->status.interruptOnBreak? 1u : 0u) << 5;
    st |= (rsp->status.singleStep      ? 1u : 0u) << 6;
    for (int i = 0; i < 8; i++) {
        st |= (rsp->status.signal[i] ? 1u : 0u) << (8 + i);
    }
    ev.status = st;
    ev.seq = my_seq;

    /* Copy into sliding ring. */
    g_ring.sliding[my_seq & kSlidingMask] = ev;

    /* Copy into boot snapshot if there's still room. */
    if (g_ring.boot_count < kBootCapacity) {
        g_ring.boot[g_ring.boot_count] = ev;
        g_ring.boot_count++;
    }

    /* Task-start edge: first instruction of a task boots at IMEM
     * offset 0. Feed the audio-task ring (it filters non-audio). */
    if (ev.pc == 0 && g_ring.last_pc != 0) {
        record_audio_task_start(rsp, my_seq);
    }
    g_ring.last_pc = ev.pc;
}

/* Hook installation. Originally an anonymous-namespace static-init
 * struct (`HookInstaller g_hook_installer;`), but clang-cl in Release
 * dead-stripped the global because it has internal linkage and no
 * referenced uses — the ctor (and therefore the hook) never ran in
 * downstream consumers using clang-cl + lld-link. Anchoring the
 * install in a function called from the always-on trace-query path
 * (every consumer hits ares_rsp_trace_count before step_frame) keeps
 * it alive under any toolchain without needing per-compiler
 * "[[gnu::used]]" / __pragma(comment) tricks. The atomic flag makes
 * the install happen exactly once even under concurrent first calls. */
std::atomic<bool> g_hook_installed{false};

void ensure_hook_installed() {
    bool expected = false;
    if (g_hook_installed.compare_exchange_strong(
            expected, true, std::memory_order_acq_rel)) {
        ares_rsp_external_instruction_hook = &record_one_instruction;
        std::fprintf(stderr,
            "ares-bridge: RSP per-instruction hook installed (recorder=%p, "
            "extern_var=%p)\n",
            (void*)&record_one_instruction,
            (void*)&ares_rsp_external_instruction_hook);
        std::fflush(stderr);
    }
}

} // namespace

extern "C" {

uint64_t ares_rsp_trace_count(void) {
    ensure_hook_installed();
    return g_ring.write_idx.load(std::memory_order_relaxed);
}

int ares_rsp_trace_get(uint64_t idx, ares_rsp_trace_event_t* out) {
    if (!out) return 0;
    uint64_t total = g_ring.write_idx.load(std::memory_order_relaxed);
    if (idx >= total) return 0;
    /* Eviction check: if total - idx > sliding capacity, the slot has
     * been overwritten. */
    if (total - idx > kSlidingCapacity) return 0;

    const auto& slot = g_ring.sliding[idx & kSlidingMask];
    /* Tear-detection read: copy then re-check seq. If the slot was
     * overwritten between the copy and the recheck, return 0 — the
     * caller should re-fetch with a more recent total. */
    *out = slot;
    if (out->seq != idx) return 0;
    return 1;
}

uint32_t ares_rsp_trace_boot_count(void) {
    return g_ring.boot_count;
}

int ares_rsp_trace_boot_get(uint32_t pos, ares_rsp_trace_event_t* out) {
    if (!out) return 0;
    if (pos >= g_ring.boot_count) return 0;
    *out = g_ring.boot[pos];
    return 1;
}

void ares_rsp_trace_set_enabled(int enabled) {
    ensure_hook_installed();
    g_ring.enabled.store(enabled != 0, std::memory_order_relaxed);
}

int ares_rsp_trace_is_enabled(void) {
    return g_ring.enabled.load(std::memory_order_relaxed) ? 1 : 0;
}

uint64_t ares_audio_task_count(void) {
    ensure_hook_installed();
    return g_ring.audio_task_idx.load(std::memory_order_acquire);
}

int ares_audio_task_get(uint64_t idx, ares_audio_task_event_t* out) {
    if (!out) return 0;
    uint64_t total = g_ring.audio_task_idx.load(std::memory_order_acquire);
    if (idx >= total) return 0;
    if (total - idx > kAudioTaskCapacity) return 0;   /* evicted */

    const auto& slot = g_ring.audio_tasks[idx & kAudioTaskMask];
    *out = slot;
    if (out->idx != idx) return 0;                    /* torn / overwritten */
    return 1;
}

} // extern "C"
