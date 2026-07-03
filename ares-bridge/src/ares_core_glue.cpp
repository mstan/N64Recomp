// Part of N64Recomp's ares-bridge subsystem (added by Matthew Stanley
// in mstan fork; not present upstream). Distributed under the project's
// MIT License (see ../../LICENSE).
//
// Copyright (c) 2026 Matthew Stanley
//
// ---------------------------------------------------------------------

/*
 * ares_core_glue.cpp — real Ares N64 core integration.
 *
 * This file is compiled only when WITH_ARES_BRIDGE=ON. It overrides
 * the placeholder bodies from ares_bridge.cpp by providing real
 * implementations linked at static-library level.
 *
 * Phase 1 (DONE): ROM open + header validation + lifecycle stubs.
 * Phase 2 (THIS): Node tree construction, ROM mount via cartridge,
 *                 frame stepping via system.run().
 * Phase 3:        Register/memory state read.
 * Phase 4:        Single-instruction stepping.
 * Phase 5:        Validation against Zelda64Recomp + OoT.
 * Phase 6:        Input plumbing.
 * Phase 7:        Save/load state.
 *
 * Symbol resolution: when WITH_ARES_BRIDGE=ON, both ares_bridge.cpp
 * and this file are compiled into the same static library. The
 * placeholder file is gated on N64RECOMP_ARES_BRIDGE_REAL so its
 * bodies disappear, leaving this file owning the symbols.
 */

#include "ares_bridge.h"
#include "ares_firmware_paths.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <fstream>
#include <vector>
#include <mutex>
#include <memory>
#include <span>
#include <string>

/*
 * Real Ares headers. Including <n64/n64.hpp> pulls in every subsystem
 * declaration (CPU, RSP, RDP, RDRAM, VI, AI, PI, SI, PIF, cartridge,
 * memory bus). All implementations live in ares.lib which we link
 * separately; this header gives us only declarations + the global
 * instances (system, cartridge, cpu, rsp, ...).
 *
 * The include order matches what Ares' own desktop UI uses; deviating
 * from it has historically caused unity-build dependency issues.
 */
#include <ares/ares.hpp>
#include <n64/n64.hpp>

namespace {

struct BridgeState {
    bool initialized = false;
    bool system_loaded = false;
    std::vector<uint8_t> rom_bytes;
    std::string rom_path;
};

BridgeState g_state;
std::mutex g_state_mutex;

[[noreturn]] void glue_unimplemented(const char *fn, const char *reason) {
    std::fprintf(stderr,
        "\nares-bridge (real): %s not yet implemented.\n"
        "                    %s\n"
        "                    See ares-bridge/DESIGN.md for phase plan.\n",
        fn, reason);
    std::fflush(stderr);
    std::abort();
}

/* Byteswap big-endian (.z64) ROM headers; .v64 / .n64 require a full
 * byteswap pass to canonicalize. We tolerate all three formats so the
 * oracle can consume whatever the test harness happens to have. */
bool detect_and_canonicalize_rom_format(std::vector<uint8_t> &bytes) {
    if (bytes.size() < 4) return false;
    uint32_t magic = (uint32_t(bytes[0]) << 24) |
                     (uint32_t(bytes[1]) << 16) |
                     (uint32_t(bytes[2]) <<  8) |
                     (uint32_t(bytes[3]) <<  0);
    switch (magic) {
        case 0x80371240u: /* .z64 — big-endian, native N64 layout */
            return true;
        case 0x37804012u: /* .v64 — byteswapped (16-bit) */
            for (size_t i = 0; i + 1 < bytes.size(); i += 2) {
                std::swap(bytes[i], bytes[i + 1]);
            }
            return true;
        case 0x40123780u: /* .n64 — wordswapped (32-bit) */
            for (size_t i = 0; i + 3 < bytes.size(); i += 4) {
                std::swap(bytes[i + 0], bytes[i + 3]);
                std::swap(bytes[i + 1], bytes[i + 2]);
            }
            return true;
        default:
            return false;
    }
}

/*
 * OraclePlatform — minimal ares::Platform implementation for headless
 * oracle use. Provides the cartridge ROM and a placeholder system pak;
 * ignores video/audio/input/event callbacks (defaults are no-ops in
 * the base class).
 *
 * Ares calls platform->pak(node) once for the System node and again
 * for the Cartridge node; we dispatch by node name. The system pak
 * normally contains pif.{ntsc,pal,sm5}.rom firmware blobs; for HLE
 * mode (Ares' default) the PIF code tolerates missing rom bytes per
 * pif.cpp — the `if (auto fp = pak->read("pif.ntsc.rom"))` guard
 * just skips the load when no file is present.
 */
struct OraclePlatform : public ares::Platform {
    std::shared_ptr<vfs::directory> system_pak_;
    std::shared_ptr<vfs::directory> cartridge_pak_;

    auto pak(ares::Node::Object node) -> std::shared_ptr<vfs::directory> override {
        if (!node) return {};
        auto name = string{node->name()};
        if (name == "Nintendo 64") return system_pak_;
        if (name.endsWith("Cartridge")) return cartridge_pak_;
        /* Controller pak / mempak slots fall through with empty pak —
         * Ares interprets "no pak" as "controller has no expansion
         * pak", which is the correct default for our oracle (we do
         * not save game state). */
        return {};
    }
};

OraclePlatform g_oracle_platform;
ares::Node::System g_root_node;

/* Hook the global ares::platform pointer at static-init time. Ares
 * checks `if(platform)` everywhere, so installing once is sufficient
 * for the lifetime of the process. */
struct PlatformInstaller {
    PlatformInstaller() { ares::platform = &g_oracle_platform; }
};
PlatformInstaller g_platform_installer;

/*
 * IPL2 checksum + CIC detection.
 *
 * Direct port of mia/medium/nintendo-64.cpp:ipl2checksum and
 * Nintendo64::cic_detect. The algorithm runs the IPL2 boot rom's
 * checksum (with various seeds matching different CIC chip variants)
 * over the IPL3 area of the ROM at offset 0x40 (size 0xFC0). The seed
 * that produces a known checksum identifies the CIC.
 *
 * The cic string is critical: Ares' PIF boot uses it to seed initial
 * register state. Wrong CIC → wrong RNG seed → divergent boot.
 */
auto ipl2checksum(uint32_t seed, std::span<const uint8_t> rom) -> uint64_t {
    auto rotl = [](uint32_t value, uint32_t shift) -> uint32_t {
        return (value << shift) | (value >> ((-shift) & 31));
    };
    auto rotr = [](uint32_t value, uint32_t shift) -> uint32_t {
        return (value >> shift) | (value << ((-shift) & 31));
    };
    auto csum = [](uint32_t a0, uint32_t a1, uint32_t a2) -> uint32_t {
        if (a1 == 0) a1 = a2;
        uint64_t prod = (uint64_t)a0 * (uint64_t)a1;
        uint32_t hi = (uint32_t)(prod >> 32);
        uint32_t lo = (uint32_t)prod;
        uint32_t diff = hi - lo;
        return diff ? diff : a0;
    };
    auto readm = [&rom](size_t& cursor) -> uint32_t {
        uint32_t v = ((uint32_t)rom[cursor + 0] << 24) |
                     ((uint32_t)rom[cursor + 1] << 16) |
                     ((uint32_t)rom[cursor + 2] <<  8) |
                     ((uint32_t)rom[cursor + 3] <<  0);
        cursor += 4;
        return v;
    };

    size_t cursor = 0;
    uint32_t init = 0x6c078965 * (seed & 0xff) + 1;
    uint32_t data = readm(cursor);
    init ^= data;

    uint32_t state[16];
    for (auto& s : state) s = init;

    uint32_t dataNext = data, dataLast;
    uint32_t loop = 0;
    while (true) {
        loop++;
        dataLast = data;
        data = dataNext;

        state[0] += csum(1007 - loop, data, loop);
        state[1]  = csum(state[1], data, loop);
        state[2] ^= data;
        state[3] += csum(data + 5, 0x6c078965, loop);
        state[9]  = (dataLast < data) ? csum(state[9], data, loop)
                                       : state[9] + data;
        state[4] += rotr(data, dataLast & 0x1f);
        state[7]  = csum(state[7], rotl(data, dataLast & 0x1f), loop);
        state[6]  = (data < state[6])
            ? (state[3] + state[6]) ^ (data + loop)
            : (state[4] + data) ^ state[6];
        state[5] += rotl(data, dataLast >> 27);
        state[8]  = csum(state[8], rotr(data, dataLast >> 27), loop);

        if (loop == 1008) break;

        dataNext   = readm(cursor);
        state[15]  = csum(csum(state[15], rotl(data, dataLast  >> 27), loop),
                          rotl(dataNext, data  >> 27), loop);
        state[14]  = csum(csum(state[14], rotr(data, dataLast & 0x1f), loop),
                          rotr(dataNext, data & 0x1f), loop);
        state[13] += rotr(data, data & 0x1f) + rotr(dataNext, dataNext & 0x1f);
        state[10]  = csum(state[10] + data, dataNext, loop);
        state[11]  = csum(state[11] ^ data, dataNext, loop);
        state[12] += state[8] ^ data;
    }

    uint32_t buf[4];
    for (auto& b : buf) b = state[0];

    for (loop = 0; loop < 16; loop++) {
        uint32_t d = state[loop];
        uint32_t tmp = buf[0] + rotr(d, d & 0x1f);
        buf[0] = tmp;
        buf[1] = d < tmp ? buf[1] + d : csum(buf[1], d, loop);

        uint32_t tmp_b = (d & 0x02) >> 1;
        uint32_t tmp2  =  d & 0x01;
        buf[2] = tmp_b == tmp2 ? buf[2] + d : csum(buf[2], d, loop);
        buf[3] = tmp2 == 1 ? buf[3] ^ d : csum(buf[3], d, loop);
    }

    uint64_t checksum = (uint64_t)csum(buf[0], buf[1], 16) << 32;
    checksum |= buf[3] ^ buf[2];
    return checksum & 0xffffffffffffull;
}

auto detect_cic(std::span<const uint8_t> ipl3, bool ntsc) -> std::string {
    /* Try each known CIC seed in turn — direct port of mia's table. */
    auto try_seed = [&](uint32_t seed) -> uint64_t {
        return ipl2checksum(seed, ipl3);
    };

    switch (try_seed(0x3f)) {
        case 0x45cc73ee317aull: return "CIC-NUS-6101";
        case 0x44160ec5d9afull: return "CIC-NUS-7102";
        case 0xa536c0f1d859ull: return ntsc ? "CIC-NUS-6102" : "CIC-NUS-7101";
    }
    switch (try_seed(0x78)) {
        case 0x586fd4709867ull: return ntsc ? "CIC-NUS-6103" : "CIC-NUS-7103";
    }
    switch (try_seed(0x91)) {
        case 0x8618a45bc2d3ull: return ntsc ? "CIC-NUS-6105" : "CIC-NUS-7105";
    }
    switch (try_seed(0x85)) {
        case 0x2bbad4e6eb74ull: return ntsc ? "CIC-NUS-6106" : "CIC-NUS-7106";
    }
    switch (try_seed(0xac)) {
        case 0x93e983a8f152ull: return "CIC-NUS-5101";
    }
    /* Unknown CIC — fall back to the most common (6102 NTSC / 7101 PAL).
     * Real ROMs almost never hit this path, but better a sensible default
     * than aborting the oracle. */
    return ntsc ? "CIC-NUS-6102" : "CIC-NUS-7101";
}

/*
 * Map ROM region byte (offset 0x3E) to NTSC or PAL.
 * Direct port of mia/medium/nintendo-64.cpp's region-byte switch.
 */
auto detect_region(uint8_t region_code) -> const char* {
    switch (region_code) {
        case 'D': case 'F': case 'H': case 'I': case 'L':
        case 'P': case 'S': case 'U': case 'W': case 'X':
        case 'Y': case 'Z':
            return "PAL";
        default:
            return "NTSC";
    }
}

/*
 * Build a cartridge pak from raw ROM bytes by deriving title / region
 * / CIC / id directly from the ROM header (offsets 0x20, 0x3B-0x3F).
 *
 * Ares' N64 cartridge code (cartridge.cpp:Connect) reads exactly
 * three pak attributes — title, region, cic — plus the program.rom
 * file. Save files (save.ram / save.eeprom / save.flash) are optional
 * and absent for our oracle (we don't persist game state).
 */
auto make_cartridge_pak(const std::vector<uint8_t>& rom)
    -> std::shared_ptr<vfs::directory>
{
    auto pak = std::make_shared<vfs::directory>();

    /* Title is the 20-byte ASCII field at ROM offset 0x20, padded with
     * spaces or NULs. We trim trailing whitespace/nulls for display. */
    std::string title(reinterpret_cast<const char*>(&rom[0x20]), 20);
    while (!title.empty() && (title.back() == ' ' || title.back() == '\0')) {
        title.pop_back();
    }

    /* Region is byte 0x3E. */
    const char* region = (rom.size() > 0x3E) ? detect_region(rom[0x3E])
                                              : "NTSC";

    /* CIC: run the IPL2 checksum over the IPL3 area at offset 0x40,
     * size 0xFC0 (= 4032 bytes). */
    std::string cic = "CIC-NUS-6102";
    if (rom.size() >= 0x40 + 0xFC0) {
        cic = detect_cic(std::span<const uint8_t>(&rom[0x40], 0xFC0),
                         std::strcmp(region, "NTSC") == 0);
    }

    pak->setAttribute("title",  string{title.c_str()});
    pak->setAttribute("region", string{region});
    pak->setAttribute("cic",    string{cic.c_str()});

    pak->append("program.rom", rom);

    std::fprintf(stderr,
        "ares-bridge: cartridge pak built — title='%s' region=%s cic=%s "
        "rom_size=0x%zX\n",
        title.c_str(), region, cic.c_str(), rom.size());

    return pak;
}

/*
 * Read a binary file fully into a byte vector. Used for loading
 * baked-in PIF firmware blobs at runtime.
 */
auto read_file_bytes(const char* path) -> std::vector<uint8_t> {
    std::ifstream f(path, std::ios::binary);
    if (!f) return {};
    f.seekg(0, std::ios::end);
    auto sz = f.tellg();
    if (sz <= 0) return {};
    f.seekg(0, std::ios::beg);
    std::vector<uint8_t> buf(static_cast<size_t>(sz));
    f.read(reinterpret_cast<char*>(buf.data()), sz);
    return buf;
}

/*
 * Build the system pak with PIF firmware blobs.
 *
 * Mirrors mia/system/nintendo-64.cpp:Nintendo64::load — the system
 * pak holds the three PIF firmware ROMs (NTSC, PAL, SM5/64DD) which
 * Ares' PIF HLE reads to seed boot state. We load them from the
 * paths baked in at configure time by ares_firmware_paths.hpp.
 */
auto make_system_pak() -> std::shared_ptr<vfs::directory>
{
    auto pak = std::make_shared<vfs::directory>();

    auto append_firmware = [&](const char* pak_name, const char* path) {
        auto bytes = read_file_bytes(path);
        if (bytes.empty()) {
            std::fprintf(stderr,
                "ares-bridge: WARNING — failed to read PIF firmware at "
                "'%s'. Ares' PIF HLE tolerates absence but boot may "
                "diverge from real hardware.\n", path);
            return;
        }
        pak->append(string{pak_name}, bytes);
    };

    append_firmware("pif.ntsc.rom", ares_bridge::kPifNtscRomPath);
    append_firmware("pif.pal.rom",  ares_bridge::kPifPalRomPath);
    append_firmware("pif.sm5.rom",  ares_bridge::kPifSm5RomPath);

    return pak;
}

} // namespace

extern "C" {

ares_status_t ares_init(const char *rom_path) {
    if (!rom_path || !*rom_path) {
        return ARES_BRIDGE_INVALID_ARGUMENT;
    }
    std::lock_guard<std::mutex> lock(g_state_mutex);
    if (g_state.initialized) {
        return ARES_BRIDGE_ALREADY_INITIALIZED;
    }

    std::ifstream in(rom_path, std::ios::binary);
    if (!in) {
        std::fprintf(stderr, "ares-bridge: cannot open ROM '%s'\n", rom_path);
        return ARES_BRIDGE_ROM_LOAD_FAILED;
    }
    in.seekg(0, std::ios::end);
    auto size = in.tellg();
    if (size <= 0) {
        return ARES_BRIDGE_ROM_LOAD_FAILED;
    }
    in.seekg(0, std::ios::beg);

    std::vector<uint8_t> bytes(static_cast<size_t>(size));
    if (!in.read(reinterpret_cast<char *>(bytes.data()), size)) {
        return ARES_BRIDGE_ROM_LOAD_FAILED;
    }

    if (!detect_and_canonicalize_rom_format(bytes)) {
        std::fprintf(stderr,
            "ares-bridge: unrecognized ROM magic in '%s'\n", rom_path);
        return ARES_BRIDGE_ROM_LOAD_FAILED;
    }

    g_state.rom_bytes = std::move(bytes);
    g_state.rom_path = rom_path;
    g_state.initialized = true;

    /* Force-anchor the RSP trace ring's hook installer. The installer
     * lives in ares_rsp_ring.cpp as an anonymous-namespace global; under
     * clang-cl + lld-link with /OPT:REF the dead-stripping eliminates
     * the global before its constructor runs. Calling a real entry point
     * here pulls the TU in and triggers the (idempotent) install. */
    ares_rsp_trace_set_enabled(ares_rsp_trace_is_enabled());

    return ARES_BRIDGE_OK;
}

void ares_shutdown(void) {
    std::lock_guard<std::mutex> lock(g_state_mutex);
    if (g_state.system_loaded) {
        ares::Nintendo64::system.unload();
        g_root_node.reset();
        g_state.system_loaded = false;
    }
    g_state = {};
}

/*
 * Phase 2 entry point: power-on construction of the Ares N64 system.
 *
 * Sequence (mirrors desktop-ui's program/load.cpp):
 *   1. Build paks for system + cartridge from g_state.rom_bytes
 *   2. Install paks into our OraclePlatform (which Ares queries via
 *      platform->pak(node) during system.load)
 *   3. Call ares::Nintendo64::load() — this dispatches to system.load
 *      which constructs the Node tree (Core::System root, with all
 *      subsystems attached) and mounts the cartridge from our pak
 *   4. Power on: ares::Nintendo64::system.power(false) initializes
 *      every subsystem (CPU, RSP, RDP, ...) to reset state
 *
 * After this call, the system is paused at the boot vector waiting
 * for ares_step_frame() to drive the CPU.
 */
ares_status_t ares_reset(void) {
    std::lock_guard<std::mutex> lock(g_state_mutex);
    if (!g_state.initialized) {
        return ARES_BRIDGE_NOT_INITIALIZED;
    }

    /* If we've already loaded a system, unload first — Ares' state
     * machine doesn't support double-load. */
    if (g_state.system_loaded) {
        ares::Nintendo64::system.unload();
        g_root_node.reset();
        g_state.system_loaded = false;
    }

    g_oracle_platform.system_pak_    = make_system_pak();
    g_oracle_platform.cartridge_pak_ = make_cartridge_pak(g_state.rom_bytes);

    /* Hand off to Ares' N64 platform loader. The string must exactly
     * match one of the values returned by ares::Nintendo64::enumerate()
     * — see system.cpp. We default to NTSC because Pokemon Stadium
     * v1.0 (our target ROM) is NTSC; future generalization should
     * detect from the ROM's region byte at offset 0x3E. */
    if (!ares::Nintendo64::load(g_root_node, "[Nintendo] Nintendo 64 (NTSC)")) {
        std::fprintf(stderr,
            "ares-bridge: ares::Nintendo64::load() returned false. "
            "Cartridge pak may be missing required attributes (check "
            "title/region/cic) or the system enumeration string may "
            "have changed in this Ares version.\n");
        return ARES_BRIDGE_INTERNAL_ERROR;
    }

    /* Connect the cartridge slot. Ares' system.load() registers the
     * Cartridge Slot port but doesn't auto-connect — the host must
     * call port->allocate() then port->connect() to trigger
     * Cartridge::connect() (which is where pak attributes get read
     * into cartridge.information.cic etc). Mirrors desktop-ui's
     * emulator/nintendo-64.cpp:123-126.
     *
     * Without this call, cartridge.cic() returns empty, the CIC
     * power-on uses an unconfigured model, and PIF::main fails
     * with "invalid IPL2 checksum" because the CIC reports zero
     * checksum bytes. */
    if (auto port = g_root_node->find<ares::Node::Port>(
            string{"Cartridge Slot"})) {
        port->allocate();
        port->connect();
    } else {
        std::fprintf(stderr,
            "ares-bridge: Cartridge Slot port not found after "
            "system.load() — Ares Node tree structure may have "
            "changed.\n");
        return ARES_BRIDGE_INTERNAL_ERROR;
    }

    /* Force the RSP into interpreter mode so the per-instruction
     * trace hook fires once per instruction (vs once per recompiled
     * block). Must be AFTER load() so the rsp object's recompiler
     * field exists; calling before load() can leave a stale
     * `enabled = true` if power() re-initializes recompiler defaults. */
    ares::Nintendo64::option(string{"Recompiler"}, string{"false"});

    /* Power-on. `false` = cold reset (not warm reset). Initializes
     * every subsystem; equivalent to plugging in the cart and pressing
     * the power button. Must come AFTER cartridge connect because
     * cic.power() reads cartridge.cic(). */
    ares::Nintendo64::system.power(false);
    g_state.system_loaded = true;
    return ARES_BRIDGE_OK;
}

/*
 * Step one frame: run until the next VI vsync.
 *
 * ares::Nintendo64::system.run() invokes cpu.main(), which is a
 * `while(!vi.refreshed && ...)` loop calling instruction() and
 * synchronize() (which drives RSP/VI/AI/RDP). When VI signals a
 * refresh, the loop exits and run() returns.
 *
 * This means one system.run() call == one frame from the CPU's
 * perspective, which is exactly the granularity our oracle needs
 * for divergence comparison.
 */
ares_status_t ares_step_frame(void) {
    std::lock_guard<std::mutex> lock(g_state_mutex);
    if (!g_state.initialized) {
        return ARES_BRIDGE_NOT_INITIALIZED;
    }
    if (!g_state.system_loaded) {
        return ARES_BRIDGE_NOT_INITIALIZED;
    }
    ares::Nintendo64::system.run();
    return ARES_BRIDGE_OK;
}

ares_status_t ares_step_instruction(void) {
    glue_unimplemented("ares_step_instruction",
        "Phase 4 — single-step requires accuracy-mode scheduler swap.");
}

ares_status_t ares_read_cpu_register(int reg, uint64_t *out) {
    if (!out) return ARES_BRIDGE_INVALID_ARGUMENT;
    if (reg < 0 || reg >= 32) return ARES_BRIDGE_INVALID_ARGUMENT;
    std::lock_guard<std::mutex> lock(g_state_mutex);
    if (!g_state.system_loaded) return ARES_BRIDGE_NOT_INITIALIZED;
    *out = ares::Nintendo64::cpu.ipu.r[reg].u64;
    return ARES_BRIDGE_OK;
}

ares_status_t ares_read_cp0_register(int reg, uint64_t *out) {
    if (!out) return ARES_BRIDGE_INVALID_ARGUMENT;
    if (reg < 0 || reg >= 32) return ARES_BRIDGE_INVALID_ARGUMENT;
    std::lock_guard<std::mutex> lock(g_state_mutex);
    if (!g_state.system_loaded) return ARES_BRIDGE_NOT_INITIALIZED;
    *out = ares::Nintendo64::cpu.getControlRegister((uint8_t)reg);
    return ARES_BRIDGE_OK;
}

ares_status_t ares_read_fpr(int reg, uint64_t *out) {
    if (!out) return ARES_BRIDGE_INVALID_ARGUMENT;
    if (reg < 0 || reg >= 32) return ARES_BRIDGE_INVALID_ARGUMENT;
    std::lock_guard<std::mutex> lock(g_state_mutex);
    if (!g_state.system_loaded) return ARES_BRIDGE_NOT_INITIALIZED;
    *out = ares::Nintendo64::cpu.fpu.r[reg].u64;
    return ARES_BRIDGE_OK;
}

ares_status_t ares_read_fpu_control(int reg, uint32_t *out) {
    if (!out) return ARES_BRIDGE_INVALID_ARGUMENT;
    if (reg != 0 && reg != 31) return ARES_BRIDGE_INVALID_ARGUMENT;
    std::lock_guard<std::mutex> lock(g_state_mutex);
    if (!g_state.system_loaded) return ARES_BRIDGE_NOT_INITIALIZED;
    *out = ares::Nintendo64::cpu.getControlRegisterFPU((uint8_t)reg);
    return ARES_BRIDGE_OK;
}

ares_status_t ares_read_pc(uint32_t *out) {
    if (!out) return ARES_BRIDGE_INVALID_ARGUMENT;
    std::lock_guard<std::mutex> lock(g_state_mutex);
    if (!g_state.system_loaded) return ARES_BRIDGE_NOT_INITIALIZED;
    *out = (uint32_t)(ares::Nintendo64::cpu.ipu.pc & 0xFFFFFFFFu);
    return ARES_BRIDGE_OK;
}

ares_status_t ares_read_hi_lo(uint64_t *hi, uint64_t *lo) {
    std::lock_guard<std::mutex> lock(g_state_mutex);
    if (!g_state.system_loaded) return ARES_BRIDGE_NOT_INITIALIZED;
    if (hi) *hi = ares::Nintendo64::cpu.ipu.hi.u64;
    if (lo) *lo = ares::Nintendo64::cpu.ipu.lo.u64;
    return ARES_BRIDGE_OK;
}

/*
 * Read N bytes of N64 memory at virtual address `vaddr`.
 *
 * Address decoding: we strip the segment bits and dispatch by physical
 * region. KSEG0 (0x80000000) and KSEG1 (0xA0000000) both alias to
 * physical 0x00000000-0x1FFFFFFF, and at this stage we don't need TLB
 * translation (the OSTask diagnostic targets fixed K0 audio buffers).
 *
 *   paddr 0x00000000-0x007FFFFF (or +4MiB w/ exp pak): RDRAM
 *   paddr 0x04000000-0x04000FFF                      : RSP DMEM
 *   paddr 0x04001000-0x04001FFF                      : RSP IMEM
 *
 * Reads are byte-by-byte through the Writable<Byte> accessor, which
 * applies the xor-3 endian swap for N64's big-endian memory layout.
 * That is correct but slow; if a future caller wants megabyte reads,
 * cluster into 8-byte Dual reads first.
 */
ares_status_t ares_read_memory(uint32_t vaddr, void *buf, size_t len) {
    if (!buf && len) return ARES_BRIDGE_INVALID_ARGUMENT;
    std::lock_guard<std::mutex> lock(g_state_mutex);
    if (!g_state.system_loaded) return ARES_BRIDGE_NOT_INITIALIZED;

    uint32_t paddr = vaddr & 0x1FFFFFFFu;
    uint8_t *dst = static_cast<uint8_t *>(buf);

    auto &rdram = ares::Nintendo64::rdram;
    auto &rsp   = ares::Nintendo64::rsp;

    if (paddr < rdram.ram.size) {
        uint64_t end = (uint64_t)paddr + (uint64_t)len;
        if (end > rdram.ram.size) return ARES_BRIDGE_INVALID_ARGUMENT;
        for (size_t i = 0; i < len; i++) {
            dst[i] = (uint8_t)rdram.ram.read<ares::Nintendo64::Byte>(paddr + (uint32_t)i, "oracle");
        }
        return ARES_BRIDGE_OK;
    }

    if (paddr >= 0x04000000u && paddr <  0x04001000u) {
        uint32_t off = paddr - 0x04000000u;
        if (off + len > 0x1000u) return ARES_BRIDGE_INVALID_ARGUMENT;
        for (size_t i = 0; i < len; i++) {
            dst[i] = (uint8_t)rsp.dmem.read<ares::Nintendo64::Byte>(off + (uint32_t)i);
        }
        return ARES_BRIDGE_OK;
    }

    if (paddr >= 0x04001000u && paddr <  0x04002000u) {
        uint32_t off = paddr - 0x04001000u;
        if (off + len > 0x1000u) return ARES_BRIDGE_INVALID_ARGUMENT;
        for (size_t i = 0; i < len; i++) {
            dst[i] = (uint8_t)rsp.imem.read<ares::Nintendo64::Byte>(off + (uint32_t)i);
        }
        return ARES_BRIDGE_OK;
    }

    return ARES_BRIDGE_INVALID_ARGUMENT;
}

/* Write — symmetric to ares_read_memory. RDRAM uses the peripheral-tagged
 * write; RSP DMEM/IMEM use the plain Writable write. */
ares_status_t ares_write_memory(uint32_t vaddr, const void *buf, size_t len) {
    if (!buf && len) return ARES_BRIDGE_INVALID_ARGUMENT;
    std::lock_guard<std::mutex> lock(g_state_mutex);
    if (!g_state.system_loaded) return ARES_BRIDGE_NOT_INITIALIZED;

    uint32_t paddr = vaddr & 0x1FFFFFFFu;
    const uint8_t *src = static_cast<const uint8_t *>(buf);
    auto &rdram = ares::Nintendo64::rdram;
    auto &rsp   = ares::Nintendo64::rsp;

    if (paddr < rdram.ram.size) {
        if ((uint64_t)paddr + len > rdram.ram.size) return ARES_BRIDGE_INVALID_ARGUMENT;
        for (size_t i = 0; i < len; i++)
            rdram.ram.write<ares::Nintendo64::Byte>(paddr + (uint32_t)i, src[i], "oracle");
        return ARES_BRIDGE_OK;
    }
    if (paddr >= 0x04000000u && paddr < 0x04001000u) {
        uint32_t off = paddr - 0x04000000u;
        if (off + len > 0x1000u) return ARES_BRIDGE_INVALID_ARGUMENT;
        for (size_t i = 0; i < len; i++)
            rsp.dmem.write<ares::Nintendo64::Byte>(off + (uint32_t)i, src[i]);
        return ARES_BRIDGE_OK;
    }
    if (paddr >= 0x04001000u && paddr < 0x04002000u) {
        uint32_t off = paddr - 0x04001000u;
        if (off + len > 0x1000u) return ARES_BRIDGE_INVALID_ARGUMENT;
        for (size_t i = 0; i < len; i++)
            rsp.imem.write<ares::Nintendo64::Byte>(off + (uint32_t)i, src[i]);
        return ARES_BRIDGE_OK;
    }
    return ARES_BRIDGE_INVALID_ARGUMENT;
}

ares_status_t ares_rsp_set_state(const uint32_t gpr[32], uint32_t pc,
                                 uint32_t dma_mem, uint32_t dma_dram) {
    if (!gpr) return ARES_BRIDGE_INVALID_ARGUMENT;
    std::lock_guard<std::mutex> lock(g_state_mutex);
    if (!g_state.system_loaded) return ARES_BRIDGE_NOT_INITIALIZED;
    auto &rsp = ares::Nintendo64::rsp;
    for (int i = 1; i < 32; i++) rsp.ipu.r[i].u32 = gpr[i];   // r0 hardwired 0
    rsp.ipu.r[0].u32 = 0;
    rsp.ipu.pc = (uint16_t)(pc & 0x0FFFu);
    rsp.branch.reset();
    rsp.oracleSetDma(dma_mem, dma_dram);   // SP DMA residue Stadium's boot expects
    rsp.status.halted = 0;
    rsp.status.broken = 0;
    return ARES_BRIDGE_OK;
}

ares_status_t ares_rsp_run_until_halt(uint32_t max_steps, uint32_t *out_steps) {
    std::lock_guard<std::mutex> lock(g_state_mutex);
    if (!g_state.system_loaded) return ARES_BRIDGE_NOT_INITIALIZED;
    uint32_t steps = ares::Nintendo64::rsp.oracleRunUntilHalt(max_steps);
    if (out_steps) *out_steps = steps;
    auto& n   = ares::Nintendo64::g_oracle_dmalog_n;
    auto& log = ares::Nintendo64::g_oracle_dmalog;
    uint32_t wr = 0, rd = 0;
    for (uint32_t i = 0; i < n; i++) { if (log[i][0]==1) wr++; else rd++; }
    std::fprintf(stderr, "[dma] %u transfers (%u read, %u write):\n", n, rd, wr);
    for (uint32_t i = 0; i < n; i++) {
        std::fprintf(stderr, "[dmarow] %3u %s dram=0x%06X dmem=0x%03X len=0x%X\n",
            i, log[i][0]==1?"WR":"RD", log[i][1], log[i][2], log[i][3]);
    }
    return ARES_BRIDGE_OK;
}

ares_status_t ares_set_controller(int, const ares_input_t *) {
    glue_unimplemented("ares_set_controller",
        "Phase 6 — controller plumbing not wired yet.");
}

ares_status_t ares_save_state(void *, size_t, size_t *out_len) {
    if (out_len) *out_len = 0;
    glue_unimplemented("ares_save_state",
        "Phase 7 — Ares serializer not wired yet.");
}

ares_status_t ares_load_state(const void *, size_t) {
    glue_unimplemented("ares_load_state",
        "Phase 7 — Ares serializer not wired yet.");
}

int ares_bridge_is_real(void) {
    return 1;
}

const char *ares_bridge_version(void) {
    /* TODO: replace with CMake-generated string carrying the actual
     * Ares submodule SHA. For now: a hand-pinned tag. */
    return "ares-bridge: real (Ares v147 / f533120df)";
}

} /* extern "C" */
