#include "decompressed.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <unordered_map>
#include <vector>

#include "compression/pers_szp.h"
#include "compression/yay0.h"
#include "fmt/format.h"
#include "rabbitizer.hpp"
#include <set>
#include "analysis.h"

namespace N64Recomp {

namespace {

uint32_t read_be_u32(const uint8_t* p) {
    return (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) |
           (uint32_t(p[2]) << 8)  |  uint32_t(p[3]);
}

void write_be_u32(uint8_t* p, uint32_t value) {
    p[0] = uint8_t(value >> 24);
    p[1] = uint8_t(value >> 16);
    p[2] = uint8_t(value >> 8);
    p[3] = uint8_t(value);
}

// FNV-1a 64-bit content hash. Used to deduplicate wrappers whose
// decompressed bytes are byte-for-byte identical (Stadium's 0x8FF00000
// slot has ~11 such pairs out of 279), and as the runtime dispatch key
// when multiple wrappers share a link vram.
uint64_t fnv1a_64(const uint8_t* data, size_t len) {
    uint64_t h = 0xCBF29CE484222325ull;
    for (size_t i = 0; i < len; i++) {
        h ^= uint64_t(data[i]);
        h *= 0x100000001B3ull;
    }
    return h;
}

struct RawFragmentInfo {
    uint32_t link_vram = 0;
    uint32_t j_target = 0;
    uint32_t reloc_offset = 0;
    uint32_t blob_size = 0;
};

bool fragment_id_from_vram(uint32_t vram, uint32_t& id_out) {
    const uint32_t bucket = (vram & 0x0FF00000u) >> 0x14;
    if (bucket < 0x10u) {
        return false;
    }
    id_out = bucket - 0x10u;
    return true;
}

bool apply_decompressed_section_patches(
    std::vector<uint8_t>& blob,
    uint32_t rom_wrapper,
    uint32_t vram,
    const std::vector<DecompressedSectionPatch>& patches,
    const std::string& section_name)
{
    if (patches.empty()) {
        return true;
    }

    uint32_t original_pattern_id = 0;
    const bool has_original_pattern_id =
        fragment_id_from_vram(vram, original_pattern_id);

    for (const DecompressedSectionPatch& patch : patches) {
        if (patch.has_rom_wrapper && patch.rom_wrapper != rom_wrapper) {
            continue;
        }
        if (patch.has_original_pattern_id &&
            (!has_original_pattern_id ||
             patch.original_pattern_id != original_pattern_id)) {
            continue;
        }

        if (uint64_t(patch.offset) + 4ull > blob.size()) {
            std::fprintf(stderr,
                "decompressed: patch for %s ROM 0x%X offset 0x%X is past "
                "decompressed blob size 0x%zX\n",
                section_name.c_str(), rom_wrapper, patch.offset,
                blob.size());
            return false;
        }

        const uint32_t old_value =
            read_be_u32(blob.data() + patch.offset);
        write_be_u32(blob.data() + patch.offset, patch.value);

        std::fprintf(stderr,
            "decompressed: patched %s ROM 0x%X offset 0x%X "
            "0x%08X -> 0x%08X\n",
            section_name.c_str(), rom_wrapper, patch.offset,
            old_value, patch.value);
    }

    return true;
}

bool decode_fragment_j_target(const uint8_t* bytes,
                              size_t bytes_size,
                              uint32_t& target_out) {
    if (bytes_size < 4) {
        return false;
    }
    const uint32_t j_instr = read_be_u32(bytes);
    if (((j_instr >> 26) & 0x3Fu) != 0x02u) {
        return false;
    }
    target_out = 0x80000000u | ((j_instr & 0x03FFFFFFu) << 2);
    return true;
}

bool decode_mips_jump_target(uint32_t instr,
                             uint32_t pc_delay_slot,
                             uint32_t& target_out) {
    const uint32_t opcode = (instr >> 26) & 0x3Fu;
    if (opcode != 0x02u && opcode != 0x03u) {
        return false;
    }
    target_out = (pc_delay_slot & 0xF0000000u) |
                 ((instr & 0x03FFFFFFu) << 2);
    return true;
}

bool decode_mips_conditional_branch_target(uint32_t instr,
                                           uint32_t pc,
                                           uint32_t& target_out) {
    const uint32_t opcode = (instr >> 26) & 0x3Fu;
    bool is_conditional_branch = false;
    if (opcode == 0x01u) {
        const uint32_t rt = (instr >> 16) & 0x1Fu;
        is_conditional_branch =
            rt == 0x00u || rt == 0x01u || rt == 0x02u || rt == 0x03u ||
            rt == 0x10u || rt == 0x11u || rt == 0x12u || rt == 0x13u;
    } else if ((opcode >= 0x04u && opcode <= 0x07u) ||
               (opcode >= 0x14u && opcode <= 0x17u)) {
        is_conditional_branch = true;
    } else if (opcode == 0x11u) {
        const uint32_t rs = (instr >> 21) & 0x1Fu;
        is_conditional_branch = rs == 0x08u; // bc1*
    }
    if (!is_conditional_branch) {
        return false;
    }

    const int16_t imm = int16_t(instr & 0xFFFFu);
    target_out = pc + 4u + (uint32_t(int32_t(imm)) << 2);
    return true;
}

bool decode_fragment_link_vram(const uint8_t* bytes,
                               size_t bytes_size,
                               uint32_t& link_vram_out) {
    if (bytes_size < 0x20) {
        return false;
    }
    if (read_be_u32(bytes + 4) != 0) {
        return false;
    }
    if (std::memcmp(bytes + 0x08, "FRAGMENT", 8) != 0) {
        return false;
    }

    uint32_t j_target = 0;
    if (!decode_fragment_j_target(bytes, bytes_size, j_target)) {
        return false;
    }

    const uint32_t entry_offset = read_be_u32(bytes + 0x10);
    if ((entry_offset & 3u) != 0) {
        return false;
    }

    const uint32_t rounded_link_vram = j_target & 0xFFF00000u;
    if (j_target - rounded_link_vram == entry_offset) {
        link_vram_out = j_target - entry_offset;
    } else {
        link_vram_out = rounded_link_vram;
    }
    return true;
}

bool try_extract_raw_fragment(const std::vector<uint8_t>& rom,
                              uint32_t rom_offset,
                              std::vector<uint8_t>& blob_out,
                              RawFragmentInfo* info_out = nullptr) {
    if (uint64_t(rom_offset) + 0x20ull > rom.size()) {
        return false;
    }

    const uint8_t* base = rom.data() + rom_offset;
    uint32_t j_target = 0;
    if (!decode_fragment_j_target(base, 4, j_target)) {
        return false;
    }
    uint32_t link_vram = 0;
    if (!decode_fragment_link_vram(base, 0x20, link_vram)) {
        return false;
    }
    if (read_be_u32(base + 4) != 0) {
        return false;
    }
    if (std::memcmp(base + 0x08, "FRAGMENT", 8) != 0) {
        return false;
    }

    const uint32_t reloc_offset = read_be_u32(base + 0x14);
    const uint32_t file_size_hint = read_be_u32(base + 0x18);
    const uint32_t size_in_ram = read_be_u32(base + 0x1C);
    if ((reloc_offset & 3u) != 0 || reloc_offset < 0x20u) {
        return false;
    }
    if (uint64_t(rom_offset) + uint64_t(reloc_offset) + 4ull >
        rom.size()) {
        return false;
    }

    const uint32_t n_relocs = read_be_u32(base + reloc_offset);
    // Reloc tables in these fragments are small; this guard keeps false
    // positives from treating arbitrary ROM bytes as a huge fragment.
    if (n_relocs > 0x10000u) {
        return false;
    }
    const uint64_t reloc_table_end =
        uint64_t(reloc_offset) + 4ull + 4ull * uint64_t(n_relocs);
    uint64_t blob_size = std::max<uint64_t>(reloc_table_end, size_in_ram);
    if (file_size_hint >= reloc_table_end) {
        blob_size = std::max<uint64_t>(blob_size, file_size_hint);
    }
    if (blob_size > 0x400000ull ||
        uint64_t(rom_offset) + blob_size > rom.size()) {
        return false;
    }

    blob_out.assign(size_t(blob_size), 0);
    std::memcpy(blob_out.data(), base, size_t(blob_size));

    if (info_out != nullptr) {
        info_out->j_target = j_target;
        info_out->link_vram = link_vram;
        info_out->reloc_offset = reloc_offset;
        info_out->blob_size = uint32_t(blob_size);
    }
    return true;
}

// Reads an entire file into memory. Returns empty vector on error.
std::vector<uint8_t> read_rom_file(const std::filesystem::path& path) {
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f.good()) return {};
    auto size = f.tellg();
    if (size <= 0) return {};
    std::vector<uint8_t> buf(static_cast<size_t>(size));
    f.seekg(0, std::ios::beg);
    f.read(reinterpret_cast<char*>(buf.data()), size);
    if (!f.good()) return {};
    return buf;
}

// Stadium's runtime reloc-table format (see disasm/src/memmap.c
// Memmap_RelocateFragment). One uint32 per reloc:
//   bits 31:24  type   (2 = R_MIPS_32, 4 = R_MIPS_26,
//                       5 = R_MIPS_HI16, 6 = R_MIPS_LO16)
//   bits 23:0   offset into the fragment
// The table is preceded by a uint32 count.
//
// Stadium's type codes don't match ELF type codes — translate.
RelocType translate_stadium_reloc_type(uint8_t stadium_type) {
    switch (stadium_type) {
        case 2: return RelocType::R_MIPS_32;
        case 4: return RelocType::R_MIPS_26;
        case 5: return RelocType::R_MIPS_HI16;
        case 6: return RelocType::R_MIPS_LO16;
        default: return RelocType::R_MIPS_NONE;
    }
}

// Parses the FRAGMENT-format header at the start of the decompressed
// blob and the trailing reloc table. Populates `section.relocs`. The
// per-reloc target_section is filled in by the caller after all
// decompressed sections are added (so cross-fragment R_MIPS_32 targets
// can be resolved against the full section list).
//
// Per-type computation of `target_section_offset` (the field the
// recompiler reads at codegen time):
//   - R_MIPS_32: word value is an absolute pointer; offset =
//       word - section_vram (then refined cross-section by caller).
//   - R_MIPS_26: J/JAL target = (word & 0x03FFFFFF) << 2 OR'd with
//       PC[31:28]; offset = target - section_vram.
//   - R_MIPS_HI16/LO16: paired. Combined immediate =
//       (HI << 16) + (int16_t)LO. Offset = combined - section_vram.
//       The recompiler emits both RELOC_HI16(idx, off) and
//       RELOC_LO16(idx, off) using each reloc's target_section_offset,
//       so both members of the pair carry the SAME computed offset.
//
// Stadium's reloc table orders HI16 immediately followed by its paired
// LO16 (matches the body's instruction order). We pair by adjacency.
//
// Returns false if the header is malformed.
bool parse_fragment_relocs(const std::vector<uint8_t>& bytes,
                           uint32_t section_vram,
                           uint16_t section_index,
                           Section& section_out) {
    if (bytes.size() < 0x20) {
        std::fprintf(stderr,
            "decompressed: blob smaller than FRAGMENT header (size=0x%zX)\n",
            bytes.size());
        return false;
    }
    if (std::memcmp(bytes.data() + 0x08, "FRAGMENT", 8) != 0) {
        std::fprintf(stderr,
            "decompressed: missing FRAGMENT magic at +0x08\n");
        return false;
    }

    const uint32_t reloc_offset = read_be_u32(bytes.data() + 0x14);
    const uint32_t size_in_ram  = read_be_u32(bytes.data() + 0x1C);

    if (reloc_offset > bytes.size() || size_in_ram > bytes.size()) {
        std::fprintf(stderr,
            "decompressed: relocOffset 0x%X / sizeInRam 0x%X exceed blob "
            "size 0x%zX\n",
            reloc_offset, size_in_ram, bytes.size());
        return false;
    }
    if (reloc_offset + 4 > bytes.size()) {
        std::fprintf(stderr,
            "decompressed: no room for reloc count at offset 0x%X\n",
            reloc_offset);
        return false;
    }

    const uint32_t n_relocs = read_be_u32(bytes.data() + reloc_offset);
    const size_t reloc_table_end = reloc_offset + 4 + 4 * size_t(n_relocs);
    if (reloc_table_end > bytes.size()) {
        std::fprintf(stderr,
            "decompressed: reloc table (count=%u) overruns blob\n", n_relocs);
        return false;
    }

    // First pass: parse raw entries.
    struct RawReloc {
        RelocType type;
        uint32_t  section_offset;
        uint32_t  word;        // instruction word at section_offset
    };
    std::vector<RawReloc> raw;
    raw.reserve(n_relocs);
    for (uint32_t i = 0; i < n_relocs; i++) {
        const uint32_t entry = read_be_u32(
            bytes.data() + reloc_offset + 4 + 4 * i);
        const uint8_t  stadium_type = uint8_t((entry >> 24) & 0x7F);
        const uint32_t section_offset = entry & 0x00FFFFFFu;
        const RelocType type = translate_stadium_reloc_type(stadium_type);
        if (type == RelocType::R_MIPS_NONE) {
            std::fprintf(stderr,
                "decompressed: unknown Stadium reloc type 0x%X at "
                "offset 0x%X — skipped\n", stadium_type, section_offset);
            continue;
        }
        if (section_offset + 4 > size_in_ram) {
            std::fprintf(stderr,
                "decompressed: reloc[%u] offset 0x%X out of body\n",
                i, section_offset);
            continue;
        }
        const uint32_t word = read_be_u32(bytes.data() + section_offset);
        raw.push_back({type, section_offset, word});
    }

    // Second pass: emit Reloc entries. HI16 pairs with the next LO16
    // in the list (Stadium's table orders them this way).
    section_out.relocs.reserve(raw.size());
    for (size_t i = 0; i < raw.size(); i++) {
        const RawReloc& rr = raw[i];

        Reloc r{};
        r.address = section_vram + rr.section_offset;
        r.target_section_offset = 0;
        r.target_section = section_index;  // default; cross-section pass refines
        r.symbol_index = uint32_t(-1);
        r.type = rr.type;
        r.reference_symbol = false;

        switch (rr.type) {
            case RelocType::R_MIPS_32: {
                r.target_section_offset = rr.word - section_vram;
                break;
            }
            case RelocType::R_MIPS_26: {
                const uint32_t pc_high = section_vram & 0xF0000000u;
                const uint32_t target  = pc_high |
                                         ((rr.word & 0x03FFFFFFu) << 2);
                r.target_section_offset = target - section_vram;
                break;
            }
            case RelocType::R_MIPS_HI16: {
                // Pair with next LO16 in raw list.
                size_t j = i + 1;
                while (j < raw.size() && raw[j].type != RelocType::R_MIPS_LO16) {
                    j++;
                }
                if (j >= raw.size()) {
                    std::fprintf(stderr,
                        "decompressed: HI16 at offset 0x%X has no paired "
                        "LO16 in reloc table\n", rr.section_offset);
                    break;
                }
                const uint16_t hi_imm = uint16_t(rr.word & 0xFFFFu);
                const int16_t  lo_imm = int16_t(raw[j].word & 0xFFFFu);
                const uint32_t combined =
                    (uint32_t(hi_imm) << 16) + uint32_t(int32_t(lo_imm));
                r.target_section_offset = combined - section_vram;
                break;
            }
            case RelocType::R_MIPS_LO16: {
                // Find preceding HI16. We scan backward for the most
                // recent HI16 (matches Stadium's adjacency convention).
                size_t j = i;
                bool found = false;
                while (j > 0) {
                    j--;
                    if (raw[j].type == RelocType::R_MIPS_HI16) {
                        const uint16_t hi_imm = uint16_t(raw[j].word & 0xFFFFu);
                        const int16_t  lo_imm = int16_t(rr.word & 0xFFFFu);
                        const uint32_t combined =
                            (uint32_t(hi_imm) << 16) +
                            uint32_t(int32_t(lo_imm));
                        r.target_section_offset = combined - section_vram;
                        found = true;
                        break;
                    }
                }
                if (!found) {
                    std::fprintf(stderr,
                        "decompressed: LO16 at offset 0x%X has no paired "
                        "HI16 in reloc table\n", rr.section_offset);
                }
                break;
            }
            default:
                break;
        }

        section_out.relocs.emplace_back(r);
        if (rr.type == RelocType::R_MIPS_32) {
            section_out.has_mips32_relocs = true;
        }
    }

    // The recompiler walks instructions linearly and advances
    // reloc_index only forward (recompilation.cpp: while
    // section.relocs[reloc_index].address < vram). It REQUIRES the
    // relocs to be sorted by address — out-of-order entries are
    // skipped silently and emitted as literal immediates.
    //
    // Stadium's raw reloc table is ordered by HI16+LO16 pair
    // adjacency, NOT by instruction address. For example, in
    // stadium_models sub-fragment 4 (variant 384), the table holds:
    //   [HI16 @ off 0x50][HI16 @ off 0x30][LO16 @ off 0x60]
    // Pairing has already baked target_section_offset above (the
    // HI16 at 0x30 pairs with the LO16 at 0x60 via raw-list
    // adjacency, which is independent of address). Now sort by
    // address so the recompiler's linear walk hits every entry.
    std::sort(section_out.relocs.begin(), section_out.relocs.end(),
              [](const Reloc& a, const Reloc& b) {
                  return a.address < b.address;
              });

    return true;
}

// Once every decompressed section is added, walk every reloc with
// target_section == its own index (the default we set above) and
// re-target R_MIPS_32 entries that actually point into a different
// section. Self-targeting relocs stay self-targeting.
void resolve_cross_section_targets(Context& context,
                                   uint16_t first_added_index) {
    for (size_t si = first_added_index; si < context.sections.size(); si++) {
        Section& section = context.sections[si];
        for (Reloc& r : section.relocs) {
            if (r.type != RelocType::R_MIPS_32) continue;

            // Compute the target absolute address.
            const uint32_t target_addr = section.ram_addr +
                                         r.target_section_offset;

            // Find the section that contains target_addr.
            for (size_t ti = 0; ti < context.sections.size(); ti++) {
                const Section& candidate = context.sections[ti];
                if (candidate.size == 0) continue;
                if (target_addr >= candidate.ram_addr &&
                    target_addr <  candidate.ram_addr + candidate.size) {
                    r.target_section = uint16_t(ti);
                    r.target_section_offset = target_addr -
                                              candidate.ram_addr;
                    break;
                }
            }
        }
    }
}

} // namespace

bool synthesize_decompressed_sections(
    Context& context,
    const std::filesystem::path& rom_path,
    const std::vector<DecompressedSection>& configs,
    const std::vector<DecompressedSectionPatch>& patches)
{
    if (configs.empty()) return true;

    const std::vector<uint8_t> rom = read_rom_file(rom_path);
    if (rom.empty()) {
        std::fprintf(stderr,
            "decompressed: failed to read ROM file: %s\n",
            rom_path.string().c_str());
        return false;
    }

    const uint16_t first_added_index = uint16_t(context.sections.size());

    for (const DecompressedSection& cfg : configs) {
        // Bounds-check the wrapper offset.
        if (cfg.rom_wrapper >= rom.size()) {
            std::fprintf(stderr,
                "decompressed: section %s rom_wrapper 0x%X is past EOF\n",
                cfg.name.c_str(), cfg.rom_wrapper);
            return false;
        }

        // Decompress per format.
        std::vector<uint8_t> blob;
        bool ok = false;
        if (cfg.wrapper_format == "pers_szp_yay0") {
            ok = compression::pers_szp_decompress(
                rom.data() + cfg.rom_wrapper,
                rom.size() - cfg.rom_wrapper,
                blob);
        } else if (cfg.wrapper_format == "yay0" ||
                   cfg.wrapper_format == "bare_yay0") {
            ok = compression::yay0_decompress(
                rom.data() + cfg.rom_wrapper,
                rom.size() - cfg.rom_wrapper,
                blob);
        } else if (cfg.wrapper_format == "raw_fragment") {
            RawFragmentInfo raw_info;
            ok = try_extract_raw_fragment(
                rom, cfg.rom_wrapper, blob, &raw_info);
            if (ok && raw_info.link_vram != cfg.vram) {
                std::fprintf(stderr,
                    "decompressed: section %s raw_fragment header derives "
                    "vram 0x%08X but config says 0x%08X\n",
                    cfg.name.c_str(), raw_info.link_vram, cfg.vram);
                return false;
            }
        } else {
            std::fprintf(stderr,
                "decompressed: section %s unknown wrapper_format '%s'\n",
                cfg.name.c_str(), cfg.wrapper_format.c_str());
            return false;
        }
        if (!ok) {
            std::fprintf(stderr,
                "decompressed: section %s failed to decompress wrapper "
                "at ROM 0x%X (format=%s)\n",
                cfg.name.c_str(), cfg.rom_wrapper,
                cfg.wrapper_format.c_str());
            return false;
        }
        if (!apply_decompressed_section_patches(
                blob, cfg.rom_wrapper, cfg.vram, patches, cfg.name)) {
            return false;
        }

        // Stash decompressed bytes at the end of context.rom so the
        // existing pipeline (which addresses sections via rom_addr)
        // finds them. The synthesized rom_addr deliberately encodes
        // the wrapper offset in the upper bits for traceability:
        //   synthetic_rom = 0xFE000000 | wrapper_offset
        // The 0xFE prefix is reserved for synthesized sections so it
        // never collides with real ROM offsets (ROM is at most 64MB).
        const uint32_t synthetic_rom = 0xFE000000u | cfg.rom_wrapper;

        // Section size = relocOffset (body + bss before relocs).
        const uint32_t reloc_offset = read_be_u32(blob.data() + 0x14);

        // Append decompressed bytes to context.rom at synthetic_rom.
        // Size we copy is reloc_offset (only the body, NOT the trailing
        // reloc table — that's metadata, not section content).
        const size_t needed_rom_size =
            size_t(synthetic_rom) + reloc_offset;
        if (context.rom.size() < needed_rom_size) {
            context.rom.resize(needed_rom_size, 0);
        }
        std::memcpy(context.rom.data() + synthetic_rom,
                    blob.data(), reloc_offset);

        // Build the Section struct.
        const uint16_t section_index =
            uint16_t(context.sections.size());

        Section section{};
        section.rom_addr   = synthetic_rom;
        section.ram_addr   = cfg.vram;
        section.size       = reloc_offset;
        section.bss_size   = 0;  // BSS is part of body in this format.
        section.name       = cfg.name;
        section.executable = true;
        section.relocatable = cfg.relocatable;

        if (!parse_fragment_relocs(blob, cfg.vram, section_index, section)) {
            std::fprintf(stderr,
                "decompressed: section %s reloc parsing failed\n",
                cfg.name.c_str());
            return false;
        }

        // Add the section to the context. We need to grow
        // section_functions in lockstep.
        context.sections.emplace_back(std::move(section));
        context.section_functions.emplace_back();
        context.section_dispatch_aliases.emplace_back();

        // Synthesize functions for the FRAGMENT layout:
        //
        //   1. fragment_entry at +0x00 — 8 bytes (J insn + nop) that
        //      jumps to the real implementation at +0x20.
        //   2. The implementation function at +0x20 — runs from +0x20
        //      to the first `jr $ra` (0x03E00008) we encounter in the
        //      body, plus its delay slot.
        //
        // Without (2), the recompiler's emit for (1) sees "branch to
        // 0x...0020 (no symbol)" and falls back to recomp_unhandled_
        // branch, which is a runtime abort. Once (2) exists in
        // functions_by_vram, the J becomes a tail call and dispatch
        // works the same way it does for ELF-symtab-listed functions.
        //
        // Function::words holds raw ROM bytes (big-endian instructions
        // stored in host-endian uint32 — numerically byteswapped from
        // the actual instruction value). The recompilation pass calls
        // byteswap(word) to recover the BE numeric form.

        auto add_function = [&](uint32_t vram, uint32_t rom,
                                std::vector<uint32_t> words,
                                std::string name) {
            const size_t fi = context.functions.size();
            context.functions.emplace_back(
                vram, rom, std::move(words), name,
                section_index, false, false, false);
            context.section_functions[section_index].push_back(fi);
            context.sections[section_index].function_addrs.push_back(vram);
            context.functions_by_vram[vram].push_back(fi);
            context.functions_by_name[name] = fi;
        };

        // (1) Entry trampoline: 8 bytes at vram+0.
        std::vector<uint32_t> entry_words(2);
        std::memcpy(entry_words.data(), blob.data() + 0x00, 8);
        add_function(cfg.vram, synthetic_rom,
                     std::move(entry_words),
                     cfg.name + "_entry");

        // (2) Implementation function at vram+0x20. Scan forward from
        // +0x20 for the first `jr $ra` (BE numeric 0x03E00008, stored
        // little-endian in our blob bytes as 08 00 E0 03). Include the
        // delay slot in the function size.
        constexpr uint32_t IMPL_OFFSET = 0x20;
        const uint8_t jr_ra_be[4] = { 0x03, 0xE0, 0x00, 0x08 };
        size_t impl_end = 0;
        for (size_t off = IMPL_OFFSET; off + 4 <= reloc_offset; off += 4) {
            if (std::memcmp(blob.data() + off, jr_ra_be, 4) == 0) {
                // Include this jr ra and its delay slot.
                impl_end = off + 8;
                if (impl_end > reloc_offset) impl_end = reloc_offset;
                break;
            }
        }
        if (impl_end > IMPL_OFFSET) {
            const size_t impl_size = impl_end - IMPL_OFFSET;
            std::vector<uint32_t> impl_words(impl_size / 4);
            std::memcpy(impl_words.data(),
                        blob.data() + IMPL_OFFSET, impl_size);
            // Use the convention func_<vram> so the name matches what
            // the recompiler would have generated from an ELF symbol.
            const std::string impl_name = fmt::format(
                "func_{:08X}", cfg.vram + IMPL_OFFSET);
            add_function(cfg.vram + IMPL_OFFSET,
                         synthetic_rom + IMPL_OFFSET,
                         std::move(impl_words),
                         impl_name);
        } else {
            std::fprintf(stderr,
                "decompressed: section %s — could not locate jr $ra "
                "in body at +0x20; only fragment_entry will be "
                "recompiled (jal targets through the entry will become "
                "runtime aborts)\n", cfg.name.c_str());
        }

        std::fprintf(stderr,
            "decompressed: synthesized section %s @ vram 0x%08X "
            "size 0x%X relocs=%zu (wrapper rom 0x%X format=%s)\n",
            cfg.name.c_str(), cfg.vram, reloc_offset,
            context.sections[section_index].relocs.size(),
            cfg.rom_wrapper, cfg.wrapper_format.c_str());
    }

    // Cross-section R_MIPS_32 retargeting now that all decompressed
    // sections are in context.sections.
    resolve_cross_section_targets(context, first_added_index);

    return true;
}

namespace {

// Adds one synthesized section + its functions + reloc table to the
// context. Used by both the explicit per-fragment path and the pattern
// auto-discovery path. `blob` is the decompressed body+relocs (must
// start with the FRAGMENT header). On success, returns the section
// index. On failure, returns size_t(-1) and prints to stderr.
size_t add_decompressed_section(Context& context,
                                const std::vector<uint8_t>& blob,
                                uint32_t rom_wrapper,
                                uint32_t vram,
                                const std::string& section_name,
                                bool relocatable,
                                uint64_t content_hash,
                                uint32_t override_link_ram_addr = 0,
                                uint32_t original_pattern_id = 0xFFFFFFFFu,
                                const std::set<uint32_t>* extra_entry_offsets = nullptr)
{
    // `vram` is the BYTES-ENCODED vram — what the body's R_MIPS_HI16/LO16
    // / R_MIPS_32 / J/JAL targets are encoded relative to. The CFG walker
    // and reloc parser need this value (otherwise jump-table entries
    // resolve to the wrong section, etc.).
    //
    // `override_link_ram_addr` (if non-zero) is the section's LINK
    // IDENTITY — what gets stored in section.ram_addr and used at
    // runtime as section_addresses[N]'s initial value. For pattern
    // variants we want this DIFFERENT from `vram` so multiple variants
    // can have unique link identities while sharing the canonical
    // bytes-encoded vram.
    const uint32_t link_ram_addr =
        (override_link_ram_addr != 0) ? override_link_ram_addr : vram;
    if (blob.size() < 0x20) {
        std::fprintf(stderr,
            "decompressed: section %s blob smaller than FRAGMENT header\n",
            section_name.c_str());
        return size_t(-1);
    }
    if (std::memcmp(blob.data() + 0x08, "FRAGMENT", 8) != 0) {
        std::fprintf(stderr,
            "decompressed: section %s missing FRAGMENT magic\n",
            section_name.c_str());
        return size_t(-1);
    }

    // Stash decompressed bytes in context.rom at a synthetic_rom that's
    // GUARANTEED not to overlap any other section. We use a cumulative
    // allocator: a static counter that grows as sections are added, so
    // each section's bytes occupy a fresh, non-overlapping range.
    //
    // The previous formula (0xFE000000 | wrap_off) was wrong because
    // Stadium's wrappers are densely packed in ROM — wrap_offs are
    // closer together than the SUM of their decompressed sizes — so
    // (0xFE000000 | wrap_offA) + size_A often overlapped
    // (0xFE000000 | wrap_offB). The second memcpy clobbered the first
    // section's body, including its jump-table entries.
    //
    // Cumulative allocation eliminates the overlap entirely. The
    // 0xFE000000 prefix is preserved for traceability (synthetic ranges
    // start above any real ROM offset, which is at most ~64 MB).
    const uint32_t reloc_offset = read_be_u32(blob.data() + 0x14);
    if (reloc_offset > blob.size()) {
        std::fprintf(stderr,
            "decompressed: section %s relocOffset 0x%X exceeds blob 0x%zX\n",
            section_name.c_str(), reloc_offset, blob.size());
        return size_t(-1);
    }

    // Cumulative synthetic-rom counter. Aligned to 4 bytes so MIPS
    // instruction reads are always aligned.
    static uint64_t next_synthetic_rom = 0xFE000000ull;
    const uint32_t synthetic_rom = uint32_t(next_synthetic_rom);
    next_synthetic_rom += (uint64_t(reloc_offset) + 3u) & ~uint64_t(3u);
    if (next_synthetic_rom > 0xFFFFFFFFull) {
        std::fprintf(stderr,
            "decompressed: section %s — synthetic_rom counter overflowed "
            "32 bits (next=0x%llX). Engine assumes < 256 MB of "
            "synthesized-section payload total.\n",
            section_name.c_str(),
            (unsigned long long)next_synthetic_rom);
        return size_t(-1);
    }

    const size_t needed_rom_size = size_t(synthetic_rom) + reloc_offset;
    if (context.rom.size() < needed_rom_size) {
        context.rom.resize(needed_rom_size, 0);
    }
    std::memcpy(context.rom.data() + synthetic_rom,
                blob.data(), reloc_offset);

    const uint16_t section_index = uint16_t(context.sections.size());

    Section section{};
    section.rom_addr   = synthetic_rom;
    // Section identity (link_ram_addr) may differ from the bytes-encoded
    // vram (`vram`) for pattern variants that get assigned a synthetic
    // per-variant link identity. The reloc parser stays with the
    // bytes-encoded vram so target_section_offset values are correct
    // intra-section byte distances.
    section.ram_addr   = link_ram_addr;
    section.size       = reloc_offset;
    section.bss_size   = 0;
    section.name       = section_name;
    section.executable = true;
    section.relocatable = relocatable;
    section.content_hash = content_hash;
    section.original_pattern_id = original_pattern_id;

    if (!parse_fragment_relocs(blob, vram, section_index, section)) {
        return size_t(-1);
    }

    context.sections.emplace_back(std::move(section));
    context.section_functions.emplace_back();
    context.section_dispatch_aliases.emplace_back();

    std::unordered_map<uint32_t, size_t> function_index_by_offset;

    auto add_function = [&](uint32_t f_vram, uint32_t f_rom,
                            std::vector<uint32_t> words,
                            std::string name,
                            uint32_t entry_vram = 0) -> size_t {
        const size_t fi = context.functions.size();
        context.functions.emplace_back(
            f_vram, f_rom, std::move(words), name,
            section_index, false, false, false, entry_vram);
        context.section_functions[section_index].push_back(fi);
        context.sections[section_index].function_addrs.push_back(f_vram);
        context.functions_by_vram[f_vram].push_back(fi);
        if (entry_vram != 0 && entry_vram != f_vram) {
            context.functions_by_vram[entry_vram].push_back(fi);
        }
        context.functions_by_name[name] = fi;
        if (f_vram >= vram && f_vram < vram + reloc_offset &&
            ((f_vram - vram) & 3u) == 0) {
            function_index_by_offset[f_vram - vram] = fi;
        }
        return fi;
    };

    // Stadium has two FRAGMENT shapes that share the same +0x00..0x20
    // header (J trampoline + magic + sizes):
    //
    //   Code fragment:  +0x20 is a real MIPS function ending in jr $ra
    //                   (and possibly more functions interspersed with
    //                   data). Stadium calls the J at +0x00 to dispatch
    //                   into the function.
    //
    //   Data fragment:  +0x20 onwards is pure data (tables of
    //                   (tag, pointer) records, etc.). The J at +0x00
    //                   is a dormant placeholder that Stadium NEVER
    //                   actually calls — Stadium reads the data
    //                   directly. No MIPS function exists.
    //
    // We distinguish by scanning the first 0x100 instructions of the
    // body for ANY jr $ra (0x03E00008). If absent, the fragment is
    // data-only: we register the section + R_MIPS_32 relocs but emit
    // NO FuncEntry rows. Stadium's dispatch never goes through a
    // func_map entry for these. If something ever does call the
    // entry-trampoline J, the runtime LOOKUP_FUNC reports the miss
    // loudly, which is the correct surface — NOT a stub.
    constexpr uint32_t IMPL_OFFSET = 0x20;
    bool has_jr_ra = false;
    {
        const size_t scan_end = std::min<size_t>(
            reloc_offset, IMPL_OFFSET + 0x400);  // first 256 insns
        for (size_t off = IMPL_OFFSET; off + 4 <= scan_end; off += 4) {
            if (read_be_u32(blob.data() + off) == 0x03E00008u) {
                has_jr_ra = true;
                break;
            }
        }
    }

    if (!has_jr_ra) {
        // Data-only fragment: section + relocs only, no functions.
        std::fprintf(stderr,
            "decompressed: section %s — data-only fragment (no jr $ra "
            "in first 0x400 bytes); registered as section + relocs "
            "with no FuncEntry rows. Stadium never dispatches the +0x00 "
            "J trampoline for these (would surface as a runtime "
            "lookup miss if it did, which is the correct diagnostic).\n",
            section_name.c_str());
        return section_index;
    }

    // Code fragment path: synthesize entry trampoline + direct targets.

    // (1) Entry trampoline at vram+0 (8 bytes).
    std::vector<uint32_t> entry_words(2);
    std::memcpy(entry_words.data(), blob.data() + 0x00, 8);
    add_function(vram, synthetic_rom,
                 std::move(entry_words),
                 section_name + "_entry");

    {
    std::set<uint32_t> seed_offsets;
    auto add_seed_if_in_body = [&](uint32_t offset) {
        if (offset == 0 || (offset & 3u) != 0) {
            return;
        }
        if (offset + 4 > reloc_offset) {
            return;
        }
        seed_offsets.insert(offset);
    };
    auto looks_like_function_entry = [&](uint32_t offset) {
        if ((offset & 3u) != 0 || offset + 4 > reloc_offset) {
            return false;
        }
        const uint32_t word = read_be_u32(blob.data() + offset);
        // Common MIPS prologue: addiu sp, sp, -frame_size.
        if ((word & 0xFFFF0000u) == 0x27BD0000u &&
            (word & 0x8000u) != 0) {
            return true;
        }
        // Tiny leaf/thunk functions can begin with jr ra.
        if (word == 0x03E00008u) {
            return true;
        }
        // Some Stadium callback tables point at tiny leaf routines that
        // do not allocate a stack frame. Keep this narrow so data table
        // words that merely decode as MIPS do not become function seeds.
        const auto is_stack_store = [](uint32_t insn) {
            const uint32_t op = (insn >> 26) & 0x3Fu;
            const uint32_t base = (insn >> 21) & 0x1Fu;
            return base == 29u && (
                op == 0x28u || // sb
                op == 0x29u || // sh
                op == 0x2Bu || // sw
                op == 0x39u || // swc1
                op == 0x3Du);  // sdc1
        };
        if (!is_stack_store(word)) {
            return false;
        }

        rabbitizer::InstructionCpu first_instr(word, vram + offset);
        if (!first_instr.isValid() ||
            first_instr.doesLink() ||
            first_instr.isBranch()) {
            return false;
        }

        constexpr uint32_t MAX_STACK_STORE_LEAF_SIZE = 0x40;
        size_t func_size = 0;
        std::string discover_err;
        if (!discover_function_bounds(
                blob.data(), reloc_offset,
                vram, offset,
                func_size, discover_err)) {
            return false;
        }

        const uint64_t func_end = uint64_t(offset) + func_size;
        if (func_size < 8 ||
            func_size > MAX_STACK_STORE_LEAF_SIZE ||
            (func_size & 3u) != 0 ||
            func_end > reloc_offset ||
            read_be_u32(blob.data() + uint32_t(func_end) - 8) !=
                0x03E00008u) {
            return false;
        }

        for (uint32_t cur = offset;
             cur + 4 < uint32_t(func_end);
             cur += 4) {
            const uint32_t cur_word = read_be_u32(blob.data() + cur);
            rabbitizer::InstructionCpu cur_instr(cur_word, vram + cur);
            if (!cur_instr.isValid() || cur_instr.doesLink()) {
                return false;
            }
            if (cur + 8 < uint32_t(func_end) && cur_instr.isBranch()) {
                return false;
            }
        }
        return true;
    };

    uint32_t header_j_target = 0;
    if (!decode_fragment_j_target(blob.data(), blob.size(), header_j_target) ||
        header_j_target < vram ||
        header_j_target >= vram + reloc_offset ||
        ((header_j_target - vram) & 3u) != 0) {
        std::fprintf(stderr,
            "decompressed: section %s â€” code fragment has invalid "
            "header J target 0x%08X for body [0x%08X..0x%08X)\n",
            section_name.c_str(), header_j_target, vram,
            vram + reloc_offset);
        return size_t(-1);
    }
    add_seed_if_in_body(header_j_target - vram);

    if (extra_entry_offsets != nullptr) {
        for (uint32_t entry_offset : *extra_entry_offsets) {
            if (looks_like_function_entry(entry_offset)) {
                add_seed_if_in_body(entry_offset);
            }
        }
    }

    for (const Reloc& reloc : context.sections[section_index].relocs) {
        if (reloc.type != RelocType::R_MIPS_26) {
            if (reloc.target_section == section_index &&
                looks_like_function_entry(reloc.target_section_offset)) {
                add_seed_if_in_body(reloc.target_section_offset);
            }
            continue;
        }
        if (reloc.target_section != section_index) {
            continue;
        }
        if (reloc.address < vram) {
            continue;
        }
        const uint32_t reloc_site_offset = reloc.address - vram;
        if (reloc_site_offset + 4 > reloc_offset) {
            continue;
        }
        const uint32_t reloc_site_word =
            read_be_u32(blob.data() + reloc_site_offset);
        const uint32_t reloc_site_opcode =
            (reloc_site_word >> 26) & 0x3Fu;
        if (reloc_site_opcode != 0x02u && reloc_site_opcode != 0x03u) {
            continue;
        }
        add_seed_if_in_body(reloc.target_section_offset);
    }

    if (seed_offsets.empty()) {
        std::fprintf(stderr,
            "decompressed: section %s â€” code fragment has no in-body "
            "direct jump targets to compile\n",
            section_name.c_str());
        return size_t(-1);
    }

    std::set<uint32_t> emitted_offsets;
    std::set<uint32_t> emitted_alias_offsets;
    std::vector<std::pair<uint32_t, uint32_t>> emitted_ranges;
    auto discover_and_add_function = [&](uint32_t entry_offset,
                                         uint32_t max_end_offset,
                                         bool hard_failure,
                                         bool* added_out = nullptr) -> bool {
        if (added_out != nullptr) {
            *added_out = false;
        }
        if (emitted_offsets.find(entry_offset) != emitted_offsets.end()) {
            return true;
        }

        size_t func_size = 0;
        std::string discover_err;
        bool ok = discover_function_bounds(
            blob.data(), reloc_offset,
            vram, entry_offset,
            func_size, discover_err);
        if (!ok) {
            if (!hard_failure) {
                return true;
            }
            std::fprintf(stderr,
                "decompressed: section %s â€” function-bounds discovery "
                "at +0x%X failed: %s\n"
                "  Build aborted. Resolutions, in order of preference:\n"
                "    1. If this is a recompiler analysis gap, fix the\n"
                "       analyzer in src/analysis.cpp.\n"
                "    2. If the fragment legitimately has a shape the\n"
                "       analyzer can't handle, declare it via the\n"
                "       single-block [[input.decompressed_section]] form\n"
                "       (manual analysis path).\n"
                "    3. If the wrapper is unused / unreachable in this\n"
                "       game's runtime path, exclude it via a future\n"
                "       pattern.exclude config field.\n"
                "  No graceful skip, no stub. Build refuses to ship.\n",
                section_name.c_str(), entry_offset,
                discover_err.c_str());
            return false;
        }

        const uint64_t func_end = uint64_t(entry_offset) + func_size;
        if (func_size == 0 || func_end > reloc_offset ||
            (func_size & 3u) != 0 ||
            (max_end_offset != 0 && func_end > max_end_offset)) {
            if (!hard_failure) {
                return true;
            }
            std::fprintf(stderr,
                "decompressed: section %s â€” invalid discovered size "
                "0x%zX for function at +0x%X (body size 0x%X)\n",
                section_name.c_str(), func_size, entry_offset,
                reloc_offset);
            return false;
        }

        std::vector<uint32_t> func_words(func_size / 4);
        std::memcpy(func_words.data(),
                    blob.data() + entry_offset, func_size);
        const std::string func_name = fmt::format(
            "func_{:08X}", vram + entry_offset);
        add_function(vram + entry_offset,
                     synthetic_rom + entry_offset,
                     std::move(func_words),
                     func_name);
        emitted_offsets.insert(entry_offset);
        emitted_ranges.emplace_back(entry_offset, uint32_t(func_end));
        if (added_out != nullptr) {
            *added_out = true;
        }
        return true;
    };

    auto add_known_size_function = [&](uint32_t entry_offset,
                                       size_t func_size,
                                       uint32_t max_end_offset,
                                       bool* added_out = nullptr,
                                       uint32_t dispatch_entry_offset = 0) -> bool {
        if (added_out != nullptr) {
            *added_out = false;
        }
        const uint32_t effective_entry_offset =
            dispatch_entry_offset != 0 ? dispatch_entry_offset : entry_offset;
        if (emitted_offsets.find(entry_offset) != emitted_offsets.end() ||
            emitted_offsets.find(effective_entry_offset) != emitted_offsets.end()) {
            return true;
        }

        const uint64_t func_end = uint64_t(entry_offset) + func_size;
        if (func_size == 0 || func_end > reloc_offset ||
            (func_size & 3u) != 0 ||
            effective_entry_offset < entry_offset ||
            effective_entry_offset >= func_end ||
            (max_end_offset != 0 && func_end > max_end_offset)) {
            return true;
        }

        std::vector<uint32_t> func_words(func_size / 4);
        std::memcpy(func_words.data(),
                    blob.data() + entry_offset, func_size);
        const std::string func_name = fmt::format(
            "func_{:08X}", vram + effective_entry_offset);
        add_function(vram + entry_offset,
                     synthetic_rom + entry_offset,
                     std::move(func_words),
                     func_name,
                     vram + effective_entry_offset);
        emitted_offsets.insert(entry_offset);
        emitted_offsets.insert(effective_entry_offset);
        emitted_ranges.emplace_back(entry_offset, uint32_t(func_end));
        if (added_out != nullptr) {
            *added_out = true;
        }
        return true;
    };

    auto add_dispatch_alias = [&](size_t parent_func_index,
                                  uint32_t entry_offset,
                                  bool* added_out = nullptr) -> bool {
        if (added_out != nullptr) {
            *added_out = false;
        }
        if ((entry_offset & 3u) != 0 ||
            entry_offset >= reloc_offset ||
            emitted_offsets.find(entry_offset) != emitted_offsets.end() ||
            emitted_alias_offsets.find(entry_offset) != emitted_alias_offsets.end()) {
            return true;
        }
        if (parent_func_index >= context.functions.size()) {
            return false;
        }

        N64Recomp::Function& parent_func = context.functions[parent_func_index];
        const uint32_t entry_vram = vram + entry_offset;
        const uint32_t parent_size =
            uint32_t(parent_func.words.size() * sizeof(parent_func.words[0]));
        if (entry_vram <= parent_func.vram ||
            entry_vram >= parent_func.vram + parent_size) {
            return true;
        }

        parent_func.dispatch_entry_vrams.insert(entry_vram);

        N64Recomp::DispatchAlias alias{};
        alias.section_index = uint16_t(section_index);
        alias.vram = entry_vram;
        alias.rom = synthetic_rom + entry_offset;
        alias.name = fmt::format(
            "dispatch_alias_s{}_{:08X}",
            section_index,
            entry_vram);
        alias.target_function_index = parent_func_index;
        const size_t alias_index = context.dispatch_aliases.size();
        context.dispatch_aliases.emplace_back(std::move(alias));
        if (section_index >= context.section_dispatch_aliases.size()) {
            context.section_dispatch_aliases.resize(section_index + 1);
        }
        context.section_dispatch_aliases[section_index].push_back(alias_index);
        emitted_alias_offsets.insert(entry_offset);
        if (added_out != nullptr) {
            *added_out = true;
        }
        return true;
    };

    for (uint32_t entry_offset : seed_offsets) {
        if (!discover_and_add_function(entry_offset, 0, true)) {
            return size_t(-1);
        }
    }

    auto looks_like_gap_function_entry = [&](uint32_t offset) {
        if ((offset & 3u) != 0 || offset + 4 > reloc_offset) {
            return false;
        }
        const uint32_t word = read_be_u32(blob.data() + offset);
        return (word & 0xFFFF0000u) == 0x27BD0000u &&
               (word & 0x8000u) != 0;
    };

    auto has_reloc_site_in_range = [&](uint32_t begin, uint32_t end) {
        for (const Reloc& reloc : context.sections[section_index].relocs) {
            if (reloc.address < vram) {
                continue;
            }
            const uint32_t reloc_site_offset = reloc.address - vram;
            if (reloc_site_offset >= begin && reloc_site_offset < end) {
                return true;
            }
        }
        return false;
    };

    auto has_leaf_entry_reloc_site_at = [&](uint32_t offset) {
        for (const Reloc& reloc : context.sections[section_index].relocs) {
            if (reloc.address < vram ||
                reloc.address - vram != offset) {
                continue;
            }
            switch (reloc.type) {
            case RelocType::R_MIPS_HI16:
            case RelocType::R_MIPS_32:
            case RelocType::R_MIPS_GPREL16:
                return true;
            default:
                break;
            }
        }
        return false;
    };

    auto has_self_pointer_reloc_target_at = [&](uint32_t offset) {
        for (const Reloc& reloc : context.sections[section_index].relocs) {
            if (reloc.target_section == section_index &&
                reloc.target_section_offset == offset &&
                reloc.type == RelocType::R_MIPS_32) {
                return true;
            }
        }
        return false;
    };

    auto has_link_instruction_in_range = [&](uint32_t begin, uint32_t end) {
        for (uint32_t offset = begin; offset + 4 <= end; offset += 4) {
            const uint32_t word = read_be_u32(blob.data() + offset);
            rabbitizer::InstructionCpu instr(word, vram + offset);
            if (instr.isValid() && instr.doesLink()) {
                return true;
            }
        }
        return false;
    };

    auto discover_bounded_no_link_leaf =
        [&](uint32_t offset, uint32_t gap_end, size_t& func_size_out) {
        if (gap_end > reloc_offset || offset >= gap_end ||
            (offset & 3u) != 0 || (gap_end & 3u) != 0) {
            return false;
        }

        std::set<uint32_t> visited;
        std::vector<uint32_t> worklist{offset};
        uint32_t max_reached = offset;
        bool saw_return = false;

        auto mark_delay = [&](uint32_t delay) {
            if (delay + 4 > gap_end) {
                return false;
            }
            visited.insert(delay);
            max_reached = std::max(max_reached, delay);
            return true;
        };
        auto enqueue_local_target = [&](uint32_t target_vram) {
            if (target_vram < vram + offset || target_vram >= vram + gap_end) {
                return false;
            }
            const uint32_t target_offset = target_vram - vram;
            if ((target_offset & 3u) != 0) {
                return false;
            }
            if (!visited.contains(target_offset)) {
                worklist.push_back(target_offset);
            }
            return true;
        };

        while (!worklist.empty()) {
            uint32_t cursor = worklist.back();
            worklist.pop_back();
            while (cursor + 4 <= gap_end) {
                if (visited.contains(cursor)) {
                    break;
                }
                visited.insert(cursor);
                max_reached = std::max(max_reached, cursor);

                const uint32_t word = read_be_u32(blob.data() + cursor);
                if (word == 0xFFFFFFFFu) {
                    return false;
                }
                rabbitizer::InstructionCpu instr(word, vram + cursor);
                if (!instr.isValid() || instr.doesLink()) {
                    return false;
                }

                const uint32_t opcode = (word >> 26) & 0x3Fu;
                const uint32_t funct = word & 0x3Fu;
                if (word == 0x03E00008u) {
                    if (!mark_delay(cursor + 4)) {
                        return false;
                    }
                    saw_return = true;
                    break;
                }
                if (opcode == 0x00u && (funct == 0x08u || funct == 0x09u)) {
                    return false;
                }

                uint32_t target_vram = 0;
                if (opcode == 0x02u) {
                    if (!decode_mips_jump_target(
                            word, vram + cursor + 4, target_vram) ||
                        !mark_delay(cursor + 4) ||
                        !enqueue_local_target(target_vram)) {
                        return false;
                    }
                    break;
                }

                if (decode_mips_conditional_branch_target(
                        word, vram + cursor, target_vram)) {
                    if (!mark_delay(cursor + 4) ||
                        !enqueue_local_target(target_vram)) {
                        return false;
                    }
                    cursor += 8;
                    continue;
                }

                cursor += 4;
            }
        }

        if (!saw_return) {
            return false;
        }
        const uint32_t func_end = max_reached + 4;
        if (func_end > gap_end || func_end <= offset) {
            return false;
        }
        func_size_out = func_end - offset;
        return true;
    };

    auto looks_like_leaf_gap_function_entry =
        [&](uint32_t offset,
            uint32_t gap_begin,
            uint32_t gap_end,
            size_t& func_size_out) {
        constexpr uint32_t MAX_LEAF_GAP_FUNCTION_SIZE = 0x100;
        if ((offset & 3u) != 0 || offset + 8 > gap_end) {
            return false;
        }
        const bool allow_initial_fragment_leaf = offset == IMPL_OFFSET;
        const bool allow_adjacent_fragment_leaf =
            offset == gap_begin && offset != IMPL_OFFSET;
        if (!allow_initial_fragment_leaf &&
            !allow_adjacent_fragment_leaf &&
            !has_leaf_entry_reloc_site_at(offset)) {
            return false;
        }

        const uint32_t first_word = read_be_u32(blob.data() + offset);
        if (first_word == 0 || first_word == 0xFFFFFFFFu) {
            return false;
        }

        rabbitizer::InstructionCpu first_instr(first_word, vram + offset);
        if (!first_instr.isValid() ||
            first_instr.doesLink() ||
            first_instr.isBranch()) {
            return false;
        }

        if (!discover_bounded_no_link_leaf(
                offset, gap_end, func_size_out)) {
            return false;
        }

        const auto starts_stack_frame_at = [&](uint32_t start) {
            if (start + 4 > reloc_offset) {
                return false;
            }
            const uint32_t word = read_be_u32(blob.data() + start);
            return ((word & 0xFFFF0000u) == 0x27BD0000u) &&
                   ((word & 0x8000u) != 0);
        };
        const auto valid_adjacent_leaf_chain_to_frame =
            [&](uint32_t chain_offset) {
            uint32_t cursor = chain_offset;
            for (size_t leaf_count = 0; leaf_count < 16; leaf_count++) {
                if (cursor == gap_end) {
                    return starts_stack_frame_at(gap_end);
                }
                if (cursor > gap_end || cursor + 8 > gap_end) {
                    return false;
                }

                const uint32_t chain_first_word =
                    read_be_u32(blob.data() + cursor);
                if (chain_first_word == 0 ||
                    chain_first_word == 0xFFFFFFFFu) {
                    return false;
                }
                rabbitizer::InstructionCpu chain_first_instr(
                    chain_first_word, vram + cursor);
                if (!chain_first_instr.isValid() ||
                    chain_first_instr.doesLink() ||
                    chain_first_instr.isBranch()) {
                    return false;
                }

                size_t leaf_size = 0;
                if (!discover_bounded_no_link_leaf(
                        cursor, gap_end, leaf_size)) {
                    return false;
                }

                const uint64_t leaf_end64 = uint64_t(cursor) + leaf_size;
                if (leaf_size < 8 ||
                    leaf_size > MAX_LEAF_GAP_FUNCTION_SIZE ||
                    (leaf_size & 3u) != 0 ||
                    leaf_end64 > gap_end) {
                    return false;
                }
                const uint32_t leaf_end = uint32_t(leaf_end64);
                if (read_be_u32(blob.data() + leaf_end - 8) !=
                    0x03E00008u) {
                    return false;
                }
                cursor = leaf_end;
            }
            return false;
        };

        const uint64_t func_end = uint64_t(offset) + func_size_out;
        if (func_size_out < 8 ||
            func_size_out > MAX_LEAF_GAP_FUNCTION_SIZE ||
            (func_size_out & 3u) != 0 ||
            func_end > gap_end) {
            return false;
        }
        const bool allow_adjacent_leaf_chain =
            allow_adjacent_fragment_leaf &&
            valid_adjacent_leaf_chain_to_frame(offset);
        if (!allow_initial_fragment_leaf &&
            !allow_adjacent_leaf_chain &&
            func_end != gap_end) {
            return false;
        }
        if (allow_initial_fragment_leaf && func_end < gap_end) {
            const uint32_t next_word =
                read_be_u32(blob.data() + uint32_t(func_end));
            if (next_word != 0x03E00008u &&
                !((next_word & 0xFFFF0000u) == 0x27BD0000u &&
                  (next_word & 0x8000u) != 0)) {
                return false;
            }
        }

        if (read_be_u32(blob.data() + uint32_t(func_end) - 8) !=
            0x03E00008u) {
            return false;
        }

        // Non-prologue leafs are easiest to confuse with embedded data.
        // Require a reloc inside the candidate body and a real return at
        // the discovered end before promoting it to a fragment entry. Some
        // loader-patched leaves are reached through runtime-computed function
        // pointers, leaving no durable relocation at the entry or body. Keep
        // that fallback narrow: adjacent to a known function, a chain of
        // small bounded no-link leaves that consumes the gap, and then a
        // stack-frame prologue.
        // Some valid Stadium first-body leafs load relocated state after a
        // couple of setup instructions, so +0x20 may lack an entry reloc.
        if ((!has_reloc_site_in_range(offset, uint32_t(func_end)) &&
             !allow_adjacent_leaf_chain) ||
            has_link_instruction_in_range(offset, uint32_t(func_end))) {
            return false;
        }

        return true;
    };

    auto looks_like_fallthrough_gap_function_entry =
        [&](uint32_t offset, uint32_t gap_end, uint32_t overlap_end) {
        constexpr uint32_t MAX_FALLTHROUGH_PREAMBLE_SIZE = 0x80;
        constexpr uint32_t MAX_FALLTHROUGH_FUNCTION_SIZE = 0x800;
        if ((offset & 3u) != 0 || offset + 4 > gap_end ||
            gap_end >= overlap_end ||
            gap_end + 4 > reloc_offset ||
            (!has_leaf_entry_reloc_site_at(offset) &&
             !has_self_pointer_reloc_target_at(offset)) ||
            gap_end - offset > MAX_FALLTHROUGH_PREAMBLE_SIZE) {
            return false;
        }

        const uint32_t next_word = read_be_u32(blob.data() + gap_end);
        if (!((next_word & 0xFFFF0000u) == 0x27BD0000u &&
              (next_word & 0x8000u) != 0)) {
            return false;
        }

        for (uint32_t cur = offset; cur + 4 <= gap_end; cur += 4) {
            const uint32_t word = read_be_u32(blob.data() + cur);
            if (word == 0 || word == 0xFFFFFFFFu) {
                return false;
            }
            rabbitizer::InstructionCpu instr(word, vram + cur);
            if (!instr.isValid() ||
                instr.doesLink() ||
                instr.isBranch()) {
                return false;
            }
        }

        size_t func_size = 0;
        std::string discover_err;
        if (!discover_function_bounds(
                blob.data(), reloc_offset,
                vram, offset,
                func_size, discover_err)) {
            return false;
        }

        const uint64_t func_end = uint64_t(offset) + func_size;
        if (func_size < 8 ||
            func_size > MAX_FALLTHROUGH_FUNCTION_SIZE ||
            (func_size & 3u) != 0 ||
            func_end <= gap_end ||
            func_end > overlap_end) {
            return false;
        }

        return read_be_u32(blob.data() + uint32_t(func_end) - 8) ==
            0x03E00008u;
    };

    size_t gap_added_count = 0;
    auto scan_gap_for_function = [&](uint32_t gap_begin,
                                     uint32_t gap_end,
                                     uint32_t overlap_end) -> bool {
        gap_begin = std::max(gap_begin, IMPL_OFFSET);
        gap_begin = (gap_begin + 3u) & ~3u;
        for (uint32_t offset = gap_begin;
             offset + 4 <= gap_end;
             offset += 4) {
            if (!looks_like_gap_function_entry(offset)) {
                continue;
            }

            bool added = false;
            if (!discover_and_add_function(
                    offset, gap_end, false, &added)) {
                return false;
            }
            if (added) {
                gap_added_count++;
                return true;
            }
        }
        for (uint32_t offset = gap_begin;
             offset + 4 <= gap_end;
             offset += 4) {
            if (!looks_like_fallthrough_gap_function_entry(
                    offset, gap_end, overlap_end)) {
                continue;
            }

            bool added = false;
            if (!discover_and_add_function(
                    offset, overlap_end, false, &added)) {
                return false;
            }
            if (added) {
                gap_added_count++;
                return true;
            }
        }
        for (uint32_t offset = gap_begin;
             offset + 8 <= gap_end;
             offset += 4) {
            size_t leaf_func_size = 0;
            if (!looks_like_leaf_gap_function_entry(
                    offset, gap_begin, gap_end, leaf_func_size)) {
                continue;
            }

            bool added = false;
            if (!add_known_size_function(
                    offset, leaf_func_size, gap_end, &added)) {
                return false;
            }
            if (added) {
                gap_added_count++;
                return true;
            }
        }
        return false;
    };

    bool added_gap_function = true;
    while (added_gap_function) {
        added_gap_function = false;
        std::vector<std::pair<uint32_t, uint32_t>> ranges = emitted_ranges;
        std::sort(ranges.begin(), ranges.end());

        uint32_t gap_start = IMPL_OFFSET;
        for (const auto& range : ranges) {
            const uint32_t range_start = range.first;
            const uint32_t range_end = range.second;
            if (range_end <= gap_start) {
                continue;
            }
            if (range_start > gap_start &&
                scan_gap_for_function(gap_start, range_start, range_end)) {
                added_gap_function = true;
                break;
            }
            gap_start = std::max(gap_start, range_end);
        }
        if (!added_gap_function && gap_start < reloc_offset &&
            scan_gap_for_function(gap_start, reloc_offset, reloc_offset)) {
            added_gap_function = true;
        }
    }

    if (gap_added_count != 0) {
        std::fprintf(stderr,
            "decompressed: section %s added %zu fragment-local gap "
            "function(s)\n",
            section_name.c_str(), gap_added_count);
    }

    size_t continuation_added_count = 0;
    {
        constexpr uint32_t MAX_CONTINUATION_PARENT_SIZE = 0x800;
        constexpr uint32_t MAX_LARGE_PARENT_CONTINUATION_SIZE = 0x800;
        // Every post-link instruction is a valid call-return continuation:
        // if a nested tailcall drain bubbles while this function is being
        // resumed from the runtime dispatcher, the return label can become an
        // exact func_map lookup. Emit the suffix entry for small discovered
        // functions so bounded drains do not depend on the original caller's
        // local label switch still being on the host stack.
        constexpr size_t MIN_SUFFIX_LINKS = 1;
        auto is_stack_load_ra = [](uint32_t insn) {
            const uint32_t op = (insn >> 26) & 0x3Fu;
            const uint32_t base = (insn >> 21) & 0x1Fu;
            const uint32_t rt = (insn >> 16) & 0x1Fu;
            return op == 0x23u && base == 29u && rt == 31u;
        };
        auto is_jalr_instruction = [](uint32_t insn) {
            return ((insn >> 26) & 0x3Fu) == 0u &&
                   (insn & 0x3Fu) == 0x09u;
        };

        auto find_dynamic_continuation_body_start =
            [&](uint32_t entry_offset,
                uint32_t range_start,
                uint32_t range_end) {
            uint32_t body_start = entry_offset;
            const uint32_t scan_end = std::min<uint32_t>(
                range_end,
                entry_offset + MAX_LARGE_PARENT_CONTINUATION_SIZE);

            for (uint32_t scan = entry_offset;
                 scan + 4 <= scan_end;
                 scan += 4) {
                const uint32_t scan_word = read_be_u32(blob.data() + scan);
                rabbitizer::InstructionCpu scan_instr(
                    scan_word, vram + scan);
                if (!scan_instr.isValid()) {
                    break;
                }

                uint32_t target_vram = 0;
                if (decode_mips_conditional_branch_target(
                        scan_word, vram + scan, target_vram) &&
                    target_vram >= vram + range_start &&
                    target_vram < vram + entry_offset &&
                    ((target_vram - vram) & 3u) == 0) {
                    body_start = std::min(body_start, target_vram - vram);
                }

                if (scan_word == 0x03E00008u) {
                    break;
                }

                const uint32_t opcode = (scan_word >> 26) & 0x3Fu;
                if (opcode == 0x02u) {
                    break;
                }
            }

            return body_start;
        };

        auto looks_like_large_parent_continuation =
            [&](uint32_t offset, uint32_t range_end) {
            if ((offset & 3u) != 0 || offset + 8 > range_end) {
                return false;
            }

            const uint32_t first_word = read_be_u32(blob.data() + offset);
            rabbitizer::InstructionCpu first_instr(first_word, vram + offset);
            if (!first_instr.isValid()) {
                return false;
            }

            const bool starts_with_link = first_instr.doesLink();
            const bool starts_with_resume_branch = first_instr.isBranch();
            const bool starts_with_epilogue = is_stack_load_ra(first_word);
            const bool starts_with_reloc =
                has_reloc_site_in_range(offset, offset + 4);
            if (!starts_with_link &&
                !starts_with_resume_branch &&
                !starts_with_epilogue &&
                !starts_with_reloc) {
                return false;
            }

            size_t func_size = 0;
            std::string discover_err;
            if (!discover_function_bounds(
                    blob.data(), reloc_offset,
                    vram, offset,
                    func_size, discover_err)) {
                return false;
            }

            const uint64_t func_end = uint64_t(offset) + func_size;
            if (func_size < 8 ||
                func_size > MAX_LARGE_PARENT_CONTINUATION_SIZE ||
                (func_size & 3u) != 0 ||
                func_end > range_end) {
                return false;
            }

            return read_be_u32(blob.data() + uint32_t(func_end) - 8) ==
                0x03E00008u;
        };

        bool added_continuation = true;
        while (added_continuation) {
            added_continuation = false;
            std::vector<std::pair<uint32_t, uint32_t>> ranges =
                emitted_ranges;
            std::sort(ranges.begin(), ranges.end());

            for (const auto& range : ranges) {
                const uint32_t range_start = range.first;
                const uint32_t range_end = range.second;
                if (range_end <= range_start ||
                    range_end - range_start > MAX_CONTINUATION_PARENT_SIZE ||
                    range_end > reloc_offset) {
                    continue;
                }

                for (uint32_t offset = range_start;
                     offset + 8 <= range_end;
                     offset += 4) {
                    const uint32_t instr_vram = vram + offset;
                    const uint32_t insn_word =
                        read_be_u32(blob.data() + offset);
                    rabbitizer::InstructionCpu instr(insn_word, instr_vram);
                    if (!instr.isValid() || !instr.doesLink()) {
                        continue;
                    }

                    const uint32_t continuation_offset = offset + 8;
                    if (continuation_offset >= range_end ||
                        emitted_offsets.find(continuation_offset) !=
                            emitted_offsets.end()) {
                        continue;
                    }

                    size_t suffix_links = 1;
                    for (uint32_t tail_offset = continuation_offset;
                         tail_offset + 8 <= range_end;
                         tail_offset += 4) {
                        const uint32_t tail_word =
                            read_be_u32(blob.data() + tail_offset);
                        rabbitizer::InstructionCpu tail_instr(
                            tail_word, vram + tail_offset);
                        if (tail_instr.isValid() && tail_instr.doesLink()) {
                            suffix_links++;
                        }
                    }
                    if (suffix_links < MIN_SUFFIX_LINKS) {
                        continue;
                    }

                    bool added = false;
                    if (!discover_and_add_function(
                            continuation_offset, range_end, false, &added)) {
                        return size_t(-1);
                    }
                    if (added) {
                        continuation_added_count++;
                        added_continuation = true;
                    }
                }
            }

            for (const auto& range : ranges) {
                const uint32_t range_start = range.first;
                const uint32_t range_end = range.second;
                if (range_end <= range_start ||
                    range_end - range_start <= MAX_CONTINUATION_PARENT_SIZE ||
                    range_end > reloc_offset) {
                    continue;
                }

                for (uint32_t offset = range_start;
                     offset + 8 <= range_end;
                     offset += 4) {
                    const uint32_t instr_vram = vram + offset;
                    const uint32_t insn_word =
                        read_be_u32(blob.data() + offset);
                    rabbitizer::InstructionCpu instr(insn_word, instr_vram);
                    if (!instr.isValid() || !instr.doesLink()) {
                        continue;
                    }

                    const uint32_t continuation_offset = offset + 8;
                    const bool is_dynamic_link = is_jalr_instruction(insn_word);
                    if (continuation_offset >= range_end ||
                        emitted_offsets.find(continuation_offset) !=
                            emitted_offsets.end()) {
                        continue;
                    }

                    bool added = false;
                    if (is_dynamic_link) {
                        const uint32_t body_start =
                            find_dynamic_continuation_body_start(
                                continuation_offset, range_start, range_end);
                        size_t func_size = 0;
                        std::string discover_err;
                        if (!discover_function_bounds(
                                blob.data(), reloc_offset,
                                vram, body_start,
                                func_size, discover_err)) {
                            continue;
                        }
                        const uint64_t func_end = uint64_t(body_start) +
                            func_size;
                        if (func_size < 8 ||
                            func_size > MAX_LARGE_PARENT_CONTINUATION_SIZE ||
                            (func_size & 3u) != 0 ||
                            func_end > range_end ||
                            read_be_u32(blob.data() +
                                uint32_t(func_end) - 8) != 0x03E00008u) {
                            continue;
                        }
                        if (!add_known_size_function(
                                body_start,
                                func_size,
                                range_end,
                                &added,
                                continuation_offset)) {
                            return size_t(-1);
                        }
                    }
                    else {
                        if (!looks_like_large_parent_continuation(
                                continuation_offset, range_end)) {
                            continue;
                        }
                        auto parent_func_it =
                            function_index_by_offset.find(range_start);
                        if (parent_func_it == function_index_by_offset.end()) {
                            continue;
                        }
                        if (!add_dispatch_alias(
                                parent_func_it->second,
                                continuation_offset,
                                &added)) {
                            return size_t(-1);
                        }
                    }
                    if (added) {
                        continuation_added_count++;
                        added_continuation = true;
                    }
                }
            }
        }
    }

    if (continuation_added_count != 0) {
        std::fprintf(stderr,
            "decompressed: section %s added %zu fragment-local "
            "continuation entry(s)\n",
            section_name.c_str(), continuation_added_count);
    }

    return section_index;
    }

    // (2) Implementation function at vram+0x20. The engine's
    // analysis.cpp::discover_function_bounds runs a real BFS-based
    // control-flow walk that follows conditional branches, j/jal
    // targets, and jr-via-jump-table dispatches (resolved using the
    // existing register-state simulator). On failure it reports a
    // specific offset and reason; we propagate that as a build error
    // — no graceful skip, no stub.
    if (reloc_offset <= IMPL_OFFSET + 4) {
        std::fprintf(stderr,
            "decompressed: section %s — body too small to contain a "
            "function at +0x20 (reloc_offset=0x%X)\n",
            section_name.c_str(), reloc_offset);
        return size_t(-1);
    }

    size_t impl_size = 0;
    std::string discover_err;
    bool ok = discover_function_bounds(
        blob.data(), reloc_offset,
        vram, IMPL_OFFSET,
        impl_size, discover_err);
    if (!ok) {
        std::fprintf(stderr,
            "decompressed: section %s — function-bounds discovery "
            "failed: %s\n"
            "  Build aborted. Resolutions, in order of preference:\n"
            "    1. If this is a recompiler analysis gap, fix the\n"
            "       analyzer in src/analysis.cpp.\n"
            "    2. If the fragment legitimately has a shape the\n"
            "       analyzer can't handle, declare it via the\n"
            "       single-block [[input.decompressed_section]] form\n"
            "       (manual analysis path).\n"
            "    3. If the wrapper is unused / unreachable in this\n"
            "       game's runtime path, exclude it via a future\n"
            "       pattern.exclude config field.\n"
            "  No graceful skip, no stub. Build refuses to ship.\n",
            section_name.c_str(), discover_err.c_str());
        return size_t(-1);
    }

    std::vector<uint32_t> impl_words(impl_size / 4);
    std::memcpy(impl_words.data(),
                blob.data() + IMPL_OFFSET, impl_size);
    const std::string impl_name = fmt::format(
        "func_{:08X}", vram + IMPL_OFFSET);
    add_function(vram + IMPL_OFFSET,
                 synthetic_rom + IMPL_OFFSET,
                 std::move(impl_words),
                 impl_name);

    return section_index;
}

// Decompress a wrapper at the given ROM offset using the named format.
// Returns true + populates blob on success.
bool decompress_wrapper_at(const std::vector<uint8_t>& rom,
                           uint32_t rom_wrapper,
                           const std::string& wrapper_format,
                           std::vector<uint8_t>& blob_out)
{
    if (rom_wrapper >= rom.size()) return false;
    if (wrapper_format == "pers_szp_yay0") {
        return compression::pers_szp_decompress(
            rom.data() + rom_wrapper,
            rom.size() - rom_wrapper, blob_out);
    } else if (wrapper_format == "yay0" ||
               wrapper_format == "bare_yay0") {
        return compression::yay0_decompress(
            rom.data() + rom_wrapper,
            rom.size() - rom_wrapper, blob_out);
    } else if (wrapper_format == "raw_fragment") {
        return try_extract_raw_fragment(
            rom, rom_wrapper, blob_out, nullptr);
    }
    return false;
}

} // namespace

bool synthesize_decompressed_patterns(
    Context& context,
    const std::filesystem::path& rom_path,
    const std::vector<DecompressedSectionPattern>& patterns,
    const std::vector<DecompressedSectionPatch>& patches)
{
    if (patterns.empty()) return true;

    const std::vector<uint8_t> rom = read_rom_file(rom_path);
    if (rom.empty()) {
        std::fprintf(stderr,
            "decompressed: failed to read ROM file: %s\n",
            rom_path.string().c_str());
        return false;
    }

    const uint16_t first_added_index = uint16_t(context.sections.size());
    size_t synthetic_variant_idx = 0;

    for (const DecompressedSectionPattern& p : patterns) {
        const uint8_t fragment_magic[8] = {
            'F', 'R', 'A', 'G', 'M', 'E', 'N', 'T'
        };

        // Resolve the base_name (default: "frag_<vram>").
        std::string base_name = p.base_name;
        if (base_name.empty()) {
            base_name = fmt::format("frag_{:08X}", p.vram);
        }

        // Scan the ROM for matching wrappers/fragments and retain the
        // bytes-encoded vram for each hit. When p.vram is 0, derive the
        // link vram from each FRAGMENT header so one pattern can cover all
        // runtime buckets in an archive.
        struct PatternHit {
            uint32_t wrap_off;
            uint32_t vram;
            std::vector<uint8_t> body;
        };
        std::vector<PatternHit> hits;
        if (p.wrapper_format == "raw_fragment") {
            size_t scan_pos = 0;
            while (scan_pos + 16 < rom.size()) {
                auto it = std::search(
                    rom.begin() + static_cast<std::vector<uint8_t>::difference_type>(scan_pos), rom.end(),
                    fragment_magic, fragment_magic + sizeof(fragment_magic));
                if (it == rom.end()) {
                    break;
                }
                const size_t magic_off = size_t(it - rom.begin());
                scan_pos = magic_off + sizeof(fragment_magic);
                if (magic_off < 8) {
                    continue;
                }

                const uint32_t raw_off = uint32_t(magic_off - 8);
                std::vector<uint8_t> body;
                RawFragmentInfo raw_info;
                if (!try_extract_raw_fragment(
                        rom, raw_off, body, &raw_info)) {
                    continue;
                }
                if (p.vram != 0 && raw_info.link_vram != p.vram) {
                    continue;
                }
                uint32_t raw_id = 0;
                if (!fragment_id_from_vram(raw_info.link_vram, raw_id)) {
                    continue;
                }
                const std::string patch_name = fmt::format(
                    "{}__rom_{:X}", base_name, raw_off);
                if (!apply_decompressed_section_patches(
                        body, raw_off, raw_info.link_vram, patches,
                        patch_name)) {
                    return false;
                }
                hits.push_back({raw_off, raw_info.link_vram,
                                std::move(body)});
            }
        } else {
        size_t scan_pos = 0;
        while (scan_pos + 16 < rom.size()) {
            // Find next "Yay0" magic.
            size_t y0 = std::string::npos;
            for (size_t i = scan_pos; i + 4 <= rom.size(); i++) {
                if (rom[i]   == 'Y' && rom[i+1] == 'a' &&
                    rom[i+2] == 'y' && rom[i+3] == '0') {
                    y0 = i;
                    break;
                }
            }
            if (y0 == std::string::npos) break;
            scan_pos = y0 + 4;

            // Quick prefix decompress to test the FRAGMENT shape.
            std::vector<uint8_t> prefix;
            if (!compression::yay0_decompress(
                    rom.data() + y0, rom.size() - y0, prefix)) {
                continue;
            }
            uint32_t hit_vram = 0;
            if (!decode_fragment_link_vram(
                    prefix.data(), prefix.size(), hit_vram)) {
                continue;
            }
            if (p.vram != 0 && hit_vram != p.vram) {
                continue;
            }

            // Match — figure out the wrapper offset (PERS-SZP wraps Yay0
            // at -0x18 if the format is pers_szp_yay0; otherwise the
            // wrapper offset IS the Yay0 offset). bare_yay0 is for
            // fragment streams that are not owned by a PERS-SZP wrapper.
            uint32_t wrap_off = uint32_t(y0);
            if (p.wrapper_format == "pers_szp_yay0") {
                if (y0 < 0x18) continue;
                if (std::memcmp(rom.data() + (y0 - 0x18),
                                "PERS-SZP", 8) != 0) {
                    continue;
                }
                wrap_off = uint32_t(y0 - 0x18);
            } else if (p.wrapper_format == "bare_yay0") {
                if (y0 >= 0x18 &&
                    std::memcmp(rom.data() + (y0 - 0x18),
                                "PERS-SZP", 8) == 0) {
                    continue;
                }
            } else if (p.wrapper_format != "yay0") {
                std::fprintf(stderr,
                    "decompressed: pattern %s unknown wrapper_format '%s'\n",
                    base_name.c_str(), p.wrapper_format.c_str());
                return false;
            }

            // Full decompress.
            std::vector<uint8_t> body;
            if (!decompress_wrapper_at(rom, wrap_off, p.wrapper_format, body)) {
                continue;
            }
            const std::string patch_name = fmt::format(
                "{}__rom_{:X}", base_name, wrap_off);
            if (!apply_decompressed_section_patches(
                    body, wrap_off, hit_vram, patches, patch_name)) {
                return false;
            }
            hits.push_back({wrap_off, hit_vram, std::move(body)});
        }
        }

        std::fprintf(stderr,
            "decompressed pattern %s @ vram 0x%08X format=%s: "
            "found %zu wrappers in ROM\n",
            base_name.c_str(), p.vram, p.wrapper_format.c_str(),
            hits.size());

        if (hits.empty()) continue;

        std::unordered_map<uint32_t, std::set<uint32_t>> jump_slot_entry_seeds;
        for (const PatternHit& hit : hits) {
            if (hit.body.size() < 0x28) {
                continue;
            }
            const uint32_t hit_reloc_offset =
                read_be_u32(hit.body.data() + 0x14);
            const uint32_t scan_limit =
                std::min<uint32_t>(hit_reloc_offset, uint32_t(hit.body.size()));
            for (uint32_t slot_off = 0x20;
                 slot_off + 8 <= scan_limit;
                 slot_off += 8) {
                const uint32_t instr =
                    read_be_u32(hit.body.data() + slot_off);
                const uint32_t delay =
                    read_be_u32(hit.body.data() + slot_off + 4);
                if (delay != 0) {
                    break;
                }

                uint32_t target = 0;
                if (!decode_mips_jump_target(
                        instr, hit.vram + slot_off + 4, target)) {
                    break;
                }

                const uint32_t target_base = target & 0xFFF00000u;
                const uint32_t target_offset = target - target_base;
                if ((target_offset & 3u) == 0) {
                    jump_slot_entry_seeds[target_base].insert(target_offset);
                }
            }
        }

        // Deduplicate by content hash. Hash window is the first 0x100
        // bytes — measured at 95% uniqueness for Stadium's 0x8FF00000
        // slot. The runtime side uses the SAME window over the bytes
        // Stadium decompressed into RDRAM, so build-time and runtime
        // hashes match. (Smaller fragments hash their full body.)
        constexpr size_t HASH_WINDOW = 0x100;
        std::unordered_map<uint64_t, size_t> seen_hashes;
        size_t added = 0;
        size_t deduped = 0;
        // Path 2: every unique pattern variant gets its own synthetic
        // per-variant ram_addr in the 0xC0000000+ sentinel pool. The
        // bytes-encoded vram (parsing/CFG) stays at p.vram for ALL
        // variants — only section.ram_addr (the link identity) changes,
        // so each variant's RELOC_HI16/LO16 macros emit a unique
        // 0xCXXXXXXX literal at runtime and the synthetic resolver
        // can translate that literal back to the variant's runtime
        // RDRAM buffer.
        //
        // Pool placement: 0xC0000000 is KSEG2, unused by N64 software,
        // so the sentinel is "obviously invalid as an N64 vaddr" and
        // can only be handled by the recomp synthetic resolver. KSEG1
        // (0xA0000000) was tried first but collides with the engine's
        // RSP code section at 0xA4000040.
        //
        // Stride 0x00100000 = 1 MB per variant. With Stadium's 219
        // variants, the pool occupies 0xC0000000..0xCDB00000 — well
        // within the 256-slot capacity (kSyntheticBucketCount on the
        // runtime side). If the variant count grows past 256 in some
        // future game, both sides need to bump the pool size.
        const uint32_t kSyntheticPoolBase = 0xC0000000u;
        const uint32_t kSyntheticPoolStride = 0x00100000u;
        for (PatternHit& hit : hits) {
            const size_t window = std::min(HASH_WINDOW, hit.body.size());
            const uint64_t content_hash =
                fnv1a_64(hit.body.data(), window);
            const uint32_t variant_id_vram = hit.vram;
            uint32_t orig_id = 0;
            if (!fragment_id_from_vram(variant_id_vram, orig_id)) {
                std::fprintf(stderr,
                    "decompressed: pattern %s skipping ROM 0x%X with "
                    "non-runtime fragment vram 0x%08X\n",
                    base_name.c_str(), hit.wrap_off, variant_id_vram);
                continue;
            }
            const uint64_t dedupe_key =
                content_hash ^ (uint64_t(orig_id) << 32);
            auto it = seen_hashes.find(dedupe_key);
            if (it != seen_hashes.end()) {
                deduped++;
                continue;
            }
            seen_hashes.emplace(dedupe_key, hit.wrap_off);

            // Original game-side fragment id derived from this hit's
            // bytes-encoded bucket. Wrapped patterns usually share one
            // id; raw-fragment scans can discover many buckets from one
            // config entry.
            // Per-variant synthetic link identity. The bytes-encoded
            // vram (used for parsing/CFG) stays at p.vram — only this
            // link identity changes per variant.
            const uint32_t variant_link_addr =
                kSyntheticPoolBase +
                uint32_t(synthetic_variant_idx) * kSyntheticPoolStride;
            synthetic_variant_idx++;

            const std::string section_name = fmt::format(
                "{}__rom_{:X}", base_name, hit.wrap_off);
            auto extra_seed_it = jump_slot_entry_seeds.find(variant_id_vram);
            const std::set<uint32_t>* extra_entry_offsets =
                (extra_seed_it != jump_slot_entry_seeds.end())
                    ? &extra_seed_it->second
                    : nullptr;
            size_t si = add_decompressed_section(
                context, hit.body, hit.wrap_off, variant_id_vram,
                section_name, p.relocatable, content_hash,
                variant_link_addr, orig_id, extra_entry_offsets);
            if (si == size_t(-1)) {
                // Hard failure: the section's bytes can't be bounded
                // by our CFG walk (or some other unrecoverable parse
                // error). NOT a soft-skip; the user has to decide.
                std::fprintf(stderr,
                    "decompressed: pattern %s aborted — section for "
                    "ROM 0x%X failed to synthesize. See message above.\n",
                    base_name.c_str(), hit.wrap_off);
                return false;
            }
            added++;
        }
        std::fprintf(stderr,
            "decompressed pattern %s: %zu sections added "
            "(%zu deduped as content-identical)\n",
            base_name.c_str(), added, deduped);
    }

    // Cross-section R_MIPS_32 retargeting once everything is in.
    resolve_cross_section_targets(context, first_added_index);

    return true;
}

} // namespace N64Recomp
