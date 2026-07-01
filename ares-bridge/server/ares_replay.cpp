// ares_replay.cpp — single-task aspMain replay oracle (mstan fork, MIT).
//
// Loads one captured aspMain audio task (from PSR_ASPMAIN_CAPTURE) into ares'
// RSP, runs it in isolation, and diffs ares' RDRAM output against the recomp's.
// A non-empty diff localizes the recompiled-RSP audio inaccuracy (issue #10).
//
// Usage:
//   ares_replay <rom.z64> <capture_dir>
// capture_dir must contain: rdram_before.bin (8MiB), dmem.bin (4KiB),
//   ctx.bin (34 u32: r1..r31, dma_mem, dma_dram, ucode_addr), rdram_after.bin.
// Writes <capture_dir>/ares_after.bin and prints a diff summary.

#include "ares_bridge.h"
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <string>

// Recomp <-> ares byte-order conversion. N64ModernRuntime stores RDRAM/DMEM
// word-byte-swapped (each aligned 4-byte word reversed) so recompiled code does
// native little-endian host loads; ares stores/accesses memory in true
// big-endian address order. Converting either way = reverse each aligned word.
// IMEM (aspmain_combined.bin) is already big-endian, so it is NOT converted.
static void rev4_inplace(std::vector<uint8_t>& b) {
    size_t n = b.size() & ~size_t(3);
    for (size_t i = 0; i < n; i += 4) {
        std::swap(b[i + 0], b[i + 3]);
        std::swap(b[i + 1], b[i + 2]);
    }
}

static bool read_file(const std::string& p, std::vector<uint8_t>& out, size_t expect = 0) {
    FILE* f = fopen(p.c_str(), "rb");
    if (!f) { fprintf(stderr, "cannot open %s\n", p.c_str()); return false; }
    fseek(f, 0, SEEK_END); long n = ftell(f); fseek(f, 0, SEEK_SET);
    out.resize(n);
    size_t got = fread(out.data(), 1, n, f); fclose(f);
    if (got != (size_t)n) { fprintf(stderr, "short read %s\n", p.c_str()); return false; }
    if (expect && (size_t)n != expect)
        fprintf(stderr, "warning: %s is %ld bytes, expected %zu\n", p.c_str(), n, expect);
    return true;
}

int main(int argc, char** argv) {
    if (argc < 3) { fprintf(stderr, "usage: ares_replay <rom> <capture_dir> [imem_combined.bin]\n"); return 2; }
    const std::string rom = argv[1];
    const std::string dir = argv[2];
    // IMEM image = the EXACT rspboot[0..0x80]+aspMain[0x80..] combined image the
    // recomp runs (real-hardware IMEM layout, entered at PC 0x000 = `j L_1064`).
    // Defaults to PSR's aspmain_combined.bin; override via argv[3].
    const std::string imem_path = (argc >= 4) ? argv[3]
        : std::string("F:/Projects/n64recomp/PokemonStadiumRecomp/aspmain_combined.bin");
    const uint32_t RDRAM = 0x800000u;

    if (!ares_bridge_is_real()) {
        fprintf(stderr, "ares bridge is a stub (build with -DWITH_ARES_BRIDGE=ON)\n");
        return 3;
    }

    std::vector<uint8_t> before, after_ours, dmem, ctx, imem;
    if (!read_file(dir + "/rdram_before.bin", before, RDRAM)) return 4;
    if (!read_file(dir + "/rdram_after.bin",  after_ours, RDRAM)) return 4;
    if (!read_file(dir + "/dmem.bin", dmem, 0x1000)) return 4;
    if (!read_file(dir + "/ctx.bin",  ctx, 34 * 4)) return 4;
    if (!read_file(imem_path, imem)) { fprintf(stderr, "need combined IMEM image: %s\n", imem_path.c_str()); return 4; }
    if (imem.size() < 0x1000) { fprintf(stderr, "imem image too small (%zu)\n", imem.size()); return 4; }
    const uint32_t* c = reinterpret_cast<const uint32_t*>(ctx.data());
    uint32_t ucode_addr = c[33];
    fprintf(stderr, "[ares_replay] ucode_addr=0x%08X  IMEM<-%s (rspboot+aspMain, BE)\n",
            ucode_addr, imem_path.c_str());

    ares_status_t s = ares_init(rom.c_str());
    if (s != ARES_BRIDGE_OK && s != ARES_BRIDGE_ALREADY_INITIALIZED) {
        fprintf(stderr, "ares_init failed: %d\n", (int)s); return 5;
    }
    ares_reset();

    // ARES_PREBOOT_REF=1: build an INDEPENDENT real-rspboot reference. Instead of
    // injecting the recomp hook's seeded DMEM/GPRs (which would bake in the very
    // seeds we're validating), we hand ares only the CPU-provided pre-boot input —
    // RDRAM (has ucode/ucode_data/cmd-list) + the OSTask the CPU left at
    // DMEM[0xFC0..0xFFF] — zero everything else, and let REAL rspboot compute
    // $29/$30/$27/$28 and DMA the command chunk itself. Then we diff rspboot's
    // computed entry state against the hook's seeds. (Default OFF = legacy
    // hook-seeded replay.)
    const bool preboot = getenv("ARES_PREBOOT_REF") != nullptr;

    // Inject the captured state, converting recomp word-swapped order -> ares BE.
    std::vector<uint8_t> before_be = before; rev4_inplace(before_be);
    // PREBOOT-REF keeps the FULL captured DMEM (the real OSTask the CPU left at
    // 0xFC0 is what rspboot reads; the hook's command chunk at 0x2B0 is harmless —
    // rspboot re-DMAs it). We only zero the injected GPRs so rspboot recomputes the
    // entry registers from scratch. (Zeroing DMEM starved rspboot — it never read
    // the OSTask, 0 DMAs fired.)
    std::vector<uint8_t> dmem_src  = dmem;   // recomp word-swapped order (full)
    if (preboot)
        fprintf(stderr, "[ares_replay] PREBOOT-REF: full DMEM (real OSTask), zero GPRs -> real rspboot recomputes\n");
    std::vector<uint8_t> dmem_be = dmem_src; rev4_inplace(dmem_be);
    if (ares_write_memory(0x00000000u, before_be.data(), RDRAM) != ARES_BRIDGE_OK) { fprintf(stderr,"write rdram failed\n"); return 6; }
    if (ares_write_memory(0x04000000u, dmem_be.data(), 0x1000) != ARES_BRIDGE_OK)  { fprintf(stderr,"write dmem failed\n");  return 6; }
    // IMEM = the EXACT combined image (already big-endian) the recomp executes:
    // rspboot at [0..0x80], aspMain at [0x80..]. Entry PC 0x000 = `j L_1064`.
    if (ares_write_memory(0x04001000u, imem.data(), 0x1000) != ARES_BRIDGE_OK)
        { fprintf(stderr,"write imem failed\n"); return 6; }

    // PREBOOT-REF: the combined image TRUNCATES rspboot to 0x80 bytes (cutting off
    // its task-load DMA + final jump), so running it just falls through to aspMain
    // on un-set-up state. The REAL rspboot lives in RDRAM at OSTask.ucode_boot
    // (size ucode_boot_size). Overlay the genuine rspboot into IMEM[0..size] so it
    // performs the authentic task-load (DMA ucode/ucode_data, set $29/commands) =
    // the independent reference the hook's seeds must match.
    if (preboot) {
        // OSTask fields are stored word-swapped in dmem (recomp order) => LE read
        // gives the correct value. ucode_boot @ +0x08, ucode_boot_size @ +0x0C.
        auto dmem_u32 = [&](uint32_t off)->uint32_t {
            return (uint32_t)dmem[0xFC0+off] | ((uint32_t)dmem[0xFC0+off+1]<<8)
                 | ((uint32_t)dmem[0xFC0+off+2]<<16) | ((uint32_t)dmem[0xFC0+off+3]<<24);
        };
        uint32_t ub_phys = dmem_u32(0x08) & 0x7FFFFFu;
        uint32_t ub_size = dmem_u32(0x0C);
        fprintf(stderr, "[ares_replay] PREBOOT-REF: real rspboot @ RDRAM 0x%06X size=0x%X -> IMEM\n",
                ub_phys, ub_size);
        if (ub_size == 0 || ub_size > 0x1000 || (size_t)ub_phys + ub_size > RDRAM) {
            fprintf(stderr, "[ares_replay] bad ucode_boot ptr/size; cannot build real-rspboot ref\n");
            return 7;
        }
        // Extract rspboot bytes from `before` (recomp word-swapped) -> BE for ares IMEM.
        std::vector<uint8_t> boot(before.begin() + ub_phys, before.begin() + ub_phys + ub_size);
        rev4_inplace(boot);
        if (ares_write_memory(0x04001000u, boot.data(), ub_size) != ARES_BRIDGE_OK)
            { fprintf(stderr,"write real-rspboot imem failed\n"); return 6; }
    }

    // hook_gpr[] = the recomp hook's seeded entry registers (always, for the diff).
    // gpr[]      = what we actually inject: hook seeds in legacy mode, all-zero in
    //              preboot mode so any non-zero entry reg is rspboot-COMPUTED.
    uint32_t hook_gpr[32]; hook_gpr[0] = 0;
    for (int i = 1; i < 32; i++) hook_gpr[i] = c[i - 1];
    uint32_t gpr[32];
    for (int i = 0; i < 32; i++) gpr[i] = preboot ? 0u : hook_gpr[i];
    uint32_t dma_mem = preboot ? 0u : c[31], dma_dram = preboot ? 0u : c[32]; // SP_MEM/DRAM residue
    if (ares_rsp_set_state(gpr, 0x000u, dma_mem, dma_dram) != ARES_BRIDGE_OK) {
        fprintf(stderr,"set_state failed\n"); return 6;
    }

    // Diagnostic: read IMEM/DMEM back from ares to confirm injection + order.
    {
        uint8_t chk[16];
        ares_read_memory(0x04001000u, chk, 16);
        fprintf(stderr, "[diag] ares IMEM[0..16] (BE): ");
        for (int i = 0; i < 16; i++) fprintf(stderr, "%02X", chk[i]);
        fprintf(stderr, "\n[diag] expect word0=09000419 (j L_1064)\n");
        ares_read_memory(0x04000FC0u + 0x30u, chk, 8);
        fprintf(stderr, "[diag] ares DMEM[0xFF0..0xFF8] (OSTask data_ptr/size, BE): ");
        for (int i = 0; i < 8; i++) fprintf(stderr, "%02X", chk[i]);
        fprintf(stderr, "  (expect data_ptr=800CAA10 size=000004D8)\n");
    }

    uint32_t steps = 0;
    s = ares_rsp_run_until_halt(200u * 1000u, &steps);
    fprintf(stderr, "[ares_replay] ran %u steps (status=%d)\n", steps, (int)s);

    // === Entry-state diff: rspboot-computed registers vs the recomp hook's seeds ===
    // The hook hand-reconstructs the rspboot residue ($29=0x2B0, $30, $27, $28, $3,
    // $31 + the command chunk). Here we read what REAL rspboot computes at the
    // rspboot->aspMain handoff and compare. First divergence = the hook's bug.
    // (Most meaningful with ARES_PREBOOT_REF=1, where injected GPRs start at 0.)
    {
        uint32_t bc = ares_rsp_trace_boot_count();
        fprintf(stderr, "\n[entry-diff] mode=%s  boot_events=%u\n",
                preboot ? "PREBOOT-REF (real rspboot)" : "hook-seeded", bc);
        fprintf(stderr, "[entry-trace] pos  pc    r3       r27      r28      r29      r30      r31\n");
        for (uint32_t i = 0; i < bc && i < 64; i++) {
            ares_rsp_trace_event_t ev;
            if (!ares_rsp_trace_boot_get(i, &ev)) continue;
            fprintf(stderr, "  %3u  0x%03X %08X %08X %08X %08X %08X %08X\n",
                    i, ev.pc & 0xFFF, ev.gpr[3], ev.gpr[27], ev.gpr[28],
                    ev.gpr[29], ev.gpr[30], ev.gpr[31]);
        }
        // Dump the window around the 0A0 "init" handler (where Stadium's aspMain
        // setup — the code the hook hand-emulates — actually computes the residue).
        fprintf(stderr, "[init-window] events whose pc is in the init range 0x0A0..0x0E8:\n");
        { int shown = 0;
          for (uint32_t i = 0; i < bc && shown < 48; i++) {
            ares_rsp_trace_event_t ev;
            if (!ares_rsp_trace_boot_get(i, &ev)) continue;
            uint32_t p = ev.pc & 0xFFF;
            if (p >= 0x0A0 && p <= 0x0E8) {
                fprintf(stderr, "  %5u 0x%03X r3=%08X r27=%08X r28=%08X r29=%08X r30=%08X\n",
                        i, p, ev.gpr[3], ev.gpr[27], ev.gpr[28], ev.gpr[29], ev.gpr[30]);
                shown++;
            }
          }
        }
        // Per-register verdict: does REAL rspboot ever PRODUCE the hook's seeded
        // value? Scan the whole boot trace. If it never does, the hook's seed is the
        // bug (or at least diverges from real rspboot) — first such register is the
        // candidate root cause. Address-like regs compared masked to 12 bits.
        const struct { const char* n; int r; bool addr; } K[] =
            {{"r3 ",3,false},{"r27",27,false},{"r28",28,false},
             {"r29",29,false},{"r30",30,false},{"r31",31,true}};
        fprintf(stderr, "[entry-diff] does real rspboot ever reach each hook seed?\n");
        int diverged = 0;
        for (const auto& k : K) {
            uint32_t h = hook_gpr[k.r];
            long hit = -1; uint32_t hit_pc = 0, last = 0;
            for (uint32_t i = 0; i < bc; i++) {
                ares_rsp_trace_event_t ev;
                if (!ares_rsp_trace_boot_get(i, &ev)) continue;
                uint32_t a = ev.gpr[k.r]; last = a;
                bool eq = k.addr ? ((a & 0xFFFu) == (h & 0xFFFu)) : (a == h);
                if (eq && hit < 0) { hit = (long)i; hit_pc = ev.pc & 0xFFF; }
            }
            if (hit >= 0)
                fprintf(stderr, "    %s seed=%08X  REACHED @ event %ld (pc=0x%03X)  OK\n",
                        k.n, h, hit, hit_pc);
            else {
                diverged++;
                fprintf(stderr, "    %s seed=%08X  NEVER reached (last=%08X)  <-- DIVERGES\n",
                        k.n, h, last);
            }
        }
        fprintf(stderr, "[entry-diff] %d/%d hook seeds NOT produced by real rspboot%s\n",
                diverged, (int)(sizeof(K)/sizeof(K[0])),
                diverged ? "  (candidate root cause of the crackle)" : "  (all seeds match rspboot)");
    }

    // If it didn't halt cleanly, show where the RSP is spinning (last PCs).
    if (steps >= 200u * 1000u - 1) {
        uint64_t tc = ares_rsp_trace_count();
        fprintf(stderr, "[trace] total=%llu  last 32 PCs (newest last):\n",
                (unsigned long long)tc);
        uint64_t start = tc > 32 ? tc - 32 : 0;
        for (uint64_t i = start; i < tc; i++) {
            ares_rsp_trace_event_t ev;
            if (ares_rsp_trace_get(i, &ev))
                fprintf(stderr, "  pc=0x%03X  r3=%08X r27=%08X r28=%08X r29=%08X r31=%08X  status=%X\n",
                        ev.pc & 0xFFF, ev.gpr[3], ev.gpr[27], ev.gpr[28], ev.gpr[29], ev.gpr[31], ev.status);
        }
    }

    // Coverage dump: the boot buffer captured the whole run. Summarize which
    // PCs ares executed + whether any DMA WRITE (DMEM->RDRAM output) fired.
    {
        uint32_t bc = ares_rsp_trace_boot_count();
        uint32_t maxpc = 0, writes = 0, reads = 0;
        // dispatch handler PCs (IMEM-relative) from the toml table.
        const uint32_t handlers[] = {0x0EC,0x39C,0x19C,0xA64,0x1C8,0x7EC,0x208,0x27C,0x348,0x248,0xC84,0x2D4,0x384,0x0A0};
        bool hit[14] = {false};
        uint32_t last_dram_w = 0, last_len_w = 0;
        for (uint32_t i = 0; i < bc; i++) {
            ares_rsp_trace_event_t ev;
            if (!ares_rsp_trace_boot_get(i, &ev)) continue;
            if (ev.pc > maxpc) maxpc = ev.pc;
            if (ev.dma_wr_len & 1) { writes++; last_dram_w = ev.dma_dram_addr; last_len_w = ev.dma_rd_len; }
            if (ev.dma_wr_len & 2) reads++;
            for (int h = 0; h < 14; h++) if (ev.pc == handlers[h]) hit[h] = true;
        }
        fprintf(stderr, "[cov] boot events=%u maxPC=0x%03X dma_write_evts=%u dma_read_evts=%u lastWriteDram=0x%06X len=%u\n",
                bc, maxpc, writes, reads, last_dram_w, last_len_w);
        fprintf(stderr, "[cov] handlers hit:");
        const char* hn[] = {"0EC","39C","19C","A64","1C8","7EC","208","27C","348","248","C84","2D4","384","0A0(init)"};
        for (int h = 0; h < 14; h++) if (hit[h]) fprintf(stderr, " %s", hn[h]);
        fprintf(stderr, "\n");
    }

    // DMEM check: did the audio handlers compute anything in DMEM? (rev4 ->
    // recomp order, diff vs injected dmem). If DMEM changed but RDRAM didn't,
    // compute happened but output DMA (DMEM->RDRAM) never fired.
    {
        std::vector<uint8_t> dmem_after(0x1000);
        ares_read_memory(0x04000000u, dmem_after.data(), 0x1000);
        rev4_inplace(dmem_after);
        size_t dch = 0; long dfirst = -1;
        for (uint32_t i = 0; i < 0x1000; i++) if (dmem_after[i] != dmem[i]) { if (dfirst<0) dfirst=i; dch++; }
        fprintf(stderr, "[dmem] ares DMEM changed %zu bytes vs input (first 0x%lX)\n", dch, dfirst);
    }

    // Read back ares' RDRAM (BE order) and convert to recomp word order so it
    // diffs apples-to-apples against rdram_after/rdram_before (recomp order).
    std::vector<uint8_t> after_ares(RDRAM);
    if (ares_read_memory(0x00000000u, after_ares.data(), RDRAM) != ARES_BRIDGE_OK)
        { fprintf(stderr,"read rdram failed\n"); return 6; }
    rev4_inplace(after_ares);
    FILE* fo = fopen((dir + "/ares_after.bin").c_str(), "wb");
    if (fo) { fwrite(after_ares.data(), 1, RDRAM, fo); fclose(fo); }

    // Diff: where ares and the recomp disagree on what aspMain wrote.
    // (Only meaningful where at least one of them changed vs `before`.)
    size_t diff = 0, ours_wrote = 0, ares_wrote = 0; long first = -1;
    for (uint32_t i = 0; i < RDRAM; i++) {
        bool ow = after_ours[i] != before[i];
        bool aw = after_ares[i] != before[i];
        if (ow) ours_wrote++;
        if (aw) ares_wrote++;
        if (after_ours[i] != after_ares[i]) { if (first < 0) first = i; diff++; }
    }
    printf("=== aspMain replay diff (capture: %s) ===\n", dir.c_str());
    printf("recomp wrote %zu bytes, ares wrote %zu bytes vs before\n", ours_wrote, ares_wrote);
    printf("recomp-vs-ares differing bytes: %zu  (first paddr 0x%lX)\n", diff, first);
    if (diff == 0) printf(">>> IDENTICAL — recompiled RSP matches ares for this task.\n");
    else printf(">>> DIVERGENCE — recompiled RSP audio differs from ares (the bug).\n");
    return 0;
}
