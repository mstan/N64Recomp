#include <limits>
#include <optional>

#include "fmt/format.h"

#include "recompiler/context.h"
#include "elfio/elfio.hpp"

// ELF front end. Loads the input ELF (produced by a disassembly/decompilation
// of the target binary), lays its allocated sections out into a flat ROM image
// the way objcopy's raw output would, reads the symbol table into the function
// and data-symbol lists, and resolves each section's relocations into the
// Context's Reloc records. The byte layout, symbol semantics, and the
// HI16/LO16 pairing rules are all fixed by the ELF format and the MIPS o32 ABI
// (see the MIPS System V ABI supplement); the organization here is ours.

namespace {

// One PT_LOAD-style segment, reduced to the fields needed to map a section's
// file offset to its physical (ROM) address.
struct SegmentEntry {
    ELFIO::Elf64_Off data_offset;
    ELFIO::Elf64_Addr physical_address;
    ELFIO::Elf_Xword memory_size;
};

// Find the segment whose file range fully contains [section_offset,
// section_offset + section_size). A linear scan is used deliberately: segments
// can overlap, so we cannot rely on ordering.
std::optional<size_t> find_containing_segment(const std::vector<SegmentEntry>& segments, ELFIO::Elf_Xword section_size, ELFIO::Elf64_Off section_offset) {
    for (size_t i = 0; i < segments.size(); i++) {
        const SegmentEntry& segment = segments[i];
        if (section_offset >= segment.data_offset && section_offset + section_size <= segment.data_offset + segment.memory_size) {
            return i;
        }
    }
    return std::nullopt;
}

// Resolve every relocation in reloc_section against section `section_index`,
// filling section_out.relocs. Returns false on a malformed relocation table.
bool parse_section_relocs(N64Recomp::Context& context, const ELFIO::elfio& elf_file, ELFIO::symbol_section_accessor& symbol_accessor, size_t section_index, ELFIO::section* reloc_section, const N64Recomp::ElfParsingConfig& elf_config) {
    N64Recomp::Section& section_out = context.sections[section_index];
    ELFIO::relocation_section_accessor rel_accessor{ elf_file, reloc_section };
    section_out.relocs.resize(rel_accessor.get_entries_num());

    // State carried across the o32 HI16/LO16 pairing rules.
    int prev_hi_count = 0;            // run length of consecutive HI16 relocs (GNU extension)
    bool prev_lo = false;            // whether the previous reloc was a LO16
    uint32_t prev_hi_immediate = 0;
    uint32_t prev_hi_symbol = std::numeric_limits<uint32_t>::max();

    // Some linkers emit a LO16 before its matching HI16 in the table even
    // though the LUI still comes first in the instruction stream. When a LO16
    // has no immediately-preceding HI16 run, locate the nearest earlier
    // same-symbol HI16 by address so several low-half users of one base
    // register don't inherit an unrelated stale HI16 immediate.
    auto find_nearest_preceding_hi16 = [&](ELFIO::Elf64_Addr lo_offset, ELFIO::Elf_Word lo_symbol, uint32_t& hi_immediate_out) {
        bool found = false;
        ELFIO::Elf64_Addr best_offset = 0;
        for (size_t hi_index = 0; hi_index < section_out.relocs.size(); hi_index++) {
            ELFIO::Elf64_Addr hi_offset;
            ELFIO::Elf_Word hi_symbol;
            unsigned int hi_type;
            ELFIO::Elf_Sxword hi_addend;
            rel_accessor.get_entry(hi_index, hi_offset, hi_symbol, hi_type, hi_addend);

            if (hi_type != static_cast<unsigned int>(N64Recomp::RelocType::R_MIPS_HI16) ||
                hi_symbol != lo_symbol || hi_offset >= lo_offset) {
                continue;
            }

            if (!found || hi_offset > best_offset) {
                uint32_t hi_rom_addr = section_out.rom_addr + hi_offset - section_out.ram_addr;
                uint32_t hi_rom_word = byteswap(*reinterpret_cast<const uint32_t*>(context.rom.data() + hi_rom_addr));
                hi_immediate_out = hi_rom_word & 0xFFFF;
                best_offset = hi_offset;
                found = true;
            }
        }
        return found;
    };

    for (size_t i = 0; i < section_out.relocs.size(); i++) {
        ELFIO::Elf64_Addr rel_offset;
        ELFIO::Elf_Word rel_symbol;
        unsigned int rel_type;
        ELFIO::Elf_Sxword unused_addend; // o32 RELs don't store addends; ignore.
        rel_accessor.get_entry(i, rel_offset, rel_symbol, rel_type, unused_addend);

        N64Recomp::Reloc& reloc_out = section_out.relocs[i];

        // Recover the instruction's encoded immediate from the ROM image.
        uint32_t reloc_rom_addr = section_out.rom_addr + rel_offset - section_out.ram_addr;
        uint32_t reloc_rom_word = byteswap(*reinterpret_cast<const uint32_t*>(context.rom.data() + reloc_rom_addr));

        reloc_out.address = rel_offset;
        reloc_out.symbol_index = rel_symbol;
        reloc_out.type = static_cast<N64Recomp::RelocType>(rel_type);

        std::string       rel_symbol_name;
        ELFIO::Elf64_Addr rel_symbol_value;
        ELFIO::Elf_Xword  rel_symbol_size;
        unsigned char     rel_symbol_bind;
        unsigned char     rel_symbol_type;
        ELFIO::Elf_Half   rel_symbol_section_index;
        unsigned char     rel_symbol_other;
        symbol_accessor.get_symbol(rel_symbol, rel_symbol_name, rel_symbol_value, rel_symbol_size,
            rel_symbol_bind, rel_symbol_type, rel_symbol_section_index, rel_symbol_other);

        uint32_t rel_section_vram = 0;
        uint32_t rel_symbol_offset = 0;

        // A symbol that lives in this section's bss is treated as belonging to
        // the section itself.
        if (rel_symbol_section_index == section_out.bss_section_index) {
            rel_symbol_section_index = section_index;
        }

        if (rel_symbol_section_index == ELFIO::SHN_UNDEF) {
            // Undefined here: it must resolve against the reference symbol set.
            N64Recomp::SymbolReference sym_ref;
            if (!context.find_reference_symbol(rel_symbol_name, sym_ref)) {
                fmt::print(stderr, "Undefined symbol: {}, not found in input or reference symbols!\n", rel_symbol_name);
                return false;
            }

            reloc_out.reference_symbol = true;
            rel_section_vram = 0;
            reloc_out.target_section = sym_ref.section_index;
            reloc_out.symbol_index = sym_ref.symbol_index;
            const auto& reference_symbol = context.get_reference_symbol(reloc_out.target_section, reloc_out.symbol_index);
            rel_symbol_offset = reference_symbol.section_offset;

            bool target_section_relocatable = context.is_reference_section_relocatable(reloc_out.target_section);
            if (reloc_out.type == N64Recomp::RelocType::R_MIPS_32 && target_section_relocatable) {
                fmt::print(stderr, "Cannot reference {} in a statically initialized variable as it's defined in a relocatable section!\n", rel_symbol_name);
                return false;
            }
        }
        else if (rel_symbol_section_index == ELFIO::SHN_ABS) {
            reloc_out.reference_symbol = false;
            reloc_out.target_section = N64Recomp::SectionAbsolute;
            rel_section_vram = 0;
        }
        else {
            reloc_out.reference_symbol = false;
            reloc_out.target_section = rel_symbol_section_index;
            if (rel_symbol_section_index >= context.sections.size()) {
                fmt::print(stderr, "Reloc {} references symbol {} which is in an unknown section 0x{:04X}!\n", i, rel_symbol_name, rel_symbol_section_index);
                return false;
            }
            rel_section_vram = context.sections[rel_symbol_section_index].ram_addr;
        }

        // HI16/LO16 pairing per the MIPS System V ABI supplement (p. 4-18).
        if (reloc_out.type == N64Recomp::RelocType::R_MIPS_LO16) {
            uint32_t rel_immediate = reloc_rom_word & 0xFFFF;
            uint32_t lo_hi_immediate = prev_hi_immediate;
            bool address_paired_hi = false;
            if (prev_hi_count == 0) {
                address_paired_hi = find_nearest_preceding_hi16(rel_offset, rel_symbol, lo_hi_immediate);
            }
            uint32_t full_immediate = (lo_hi_immediate << 16) + (int16_t)rel_immediate;
            reloc_out.target_section_offset = full_immediate + rel_symbol_offset - rel_section_vram;

            if (prev_hi_count != 0) {
                if (prev_hi_symbol != rel_symbol) {
                    fmt::print(stderr, "Paired HI16 and LO16 relocations have different symbols\n"
                                       "  LO16 reloc index {} in section {} referencing symbol {} with offset 0x{:08X}\n",
                        i, section_out.name, reloc_out.symbol_index, reloc_out.address);
                    return false;
                }
                // Now that the low half is known, finalize every HI16 in the run.
                for (size_t paired_index = i - prev_hi_count; paired_index < i; paired_index++) {
                    uint32_t hi_immediate = section_out.relocs[paired_index].target_section_offset;
                    uint32_t paired_full_immediate = hi_immediate + (int16_t)rel_immediate;
                    section_out.relocs[paired_index].target_section_offset = paired_full_immediate + rel_symbol_offset - rel_section_vram;
                }
            }
            else if (address_paired_hi) {
                // Already paired by address above; target_section_offset is set.
            }
            else {
                if (elf_config.unpaired_lo16_warnings) {
                    if (prev_lo) {
                        // Consecutive LO16s for the same symbol are a known linker idiom; only warn on a symbol change.
                        if (prev_hi_symbol != rel_symbol) {
                            fmt::print(stderr, "[WARN] LO16 reloc index {} in section {} referencing symbol {} with offset 0x{:08X} follows LO16 with different symbol\n",
                                i, section_out.name, reloc_out.symbol_index, reloc_out.address);
                        }
                    }
                    else {
                        fmt::print(stderr, "[WARN] Unpaired LO16 reloc index {} in section {} referencing symbol {} with offset 0x{:08X}\n",
                            i, section_out.name, reloc_out.symbol_index, reloc_out.address);
                    }
                }
                // Per the ABI, an orphaned LO16 still uses the previously seen
                // HI16 for its addend, which the calculation above already did,
                // so target_section_offset needs no further adjustment.
            }
            prev_lo = true;
        }
        else {
            // A non-HI16 reloc may not interrupt a HI16 run (ABI: each HI16
            // must be immediately followed by a LO16).
            if (reloc_out.type != N64Recomp::RelocType::R_MIPS_HI16 && prev_hi_count != 0) {
                fmt::print(stderr, "Unpaired HI16 reloc index {} in section {} referencing symbol {} with offset 0x{:08X}\n",
                    i - 1, section_out.name, section_out.relocs[i - 1].symbol_index, section_out.relocs[i - 1].address);
                return false;
            }
            prev_lo = false;
        }

        if (reloc_out.type == N64Recomp::RelocType::R_MIPS_HI16) {
            uint32_t rel_immediate = reloc_rom_word & 0xFFFF;
            if (prev_hi_count == 0) {
                // First HI16 of a run: stash its immediate and symbol.
                prev_hi_immediate = rel_immediate;
                prev_hi_symbol = rel_symbol;
            }
            else if (prev_hi_symbol != rel_symbol) {
                // Subsequent HI16 in a run must share the symbol.
                fmt::print(stderr, "HI16 reloc (index {} symbol {} offset 0x{:08X}) follows another HI16 reloc with a different symbol (index {} symbol {} offset 0x{:08X}) in section {}\n",
                    i, rel_symbol, section_out.relocs[i].address,
                    i - 1, prev_hi_symbol, section_out.relocs[i - 1].address,
                    section_out.name);
                return false;
            }
            // Hold the high half; the real offset is computed at LO16 pairing.
            reloc_out.target_section_offset = rel_immediate << 16;
            prev_hi_count++;
        }
        else {
            prev_hi_count = 0;
        }

        if (reloc_out.type == N64Recomp::RelocType::R_MIPS_32) {
            // The in-place word is the addend, so the offset is just the
            // symbol's section offset; the value is folded in at load time.
            reloc_out.target_section_offset = rel_symbol_offset;
            if (reloc_out.reference_symbol) {
                uint32_t reloc_target_section_addr = context.get_reference_section_vram(reloc_out.target_section);
                uint32_t updated_reloc_word = reloc_rom_word + reloc_target_section_addr + reloc_out.target_section_offset;
                *reinterpret_cast<uint32_t*>(context.rom.data() + reloc_rom_addr) = byteswap(updated_reloc_word);
            }
        }

        if (reloc_out.type == N64Recomp::RelocType::R_MIPS_26) {
            uint32_t rel_immediate = (reloc_rom_word & 0x3FFFFFF) << 2;
            if (reloc_out.reference_symbol) {
                // Reference relocs already carry a resolved section offset, so
                // the R_MIPS_26 upper-4-bit rule is skipped.
                reloc_out.target_section_offset = rel_immediate + rel_symbol_offset - rel_section_vram;
            }
            else {
                reloc_out.target_section_offset = rel_immediate + rel_symbol_offset + (section_out.ram_addr & 0xF0000000) - rel_section_vram;
            }
        }
    }

    // With every immediate fully resolved, ordering relocs by address lets the
    // recompiler binary-search them; pairing no longer depends on adjacency.
    std::sort(section_out.relocs.begin(), section_out.relocs.end(),
        [](const N64Recomp::Reloc& a, const N64Recomp::Reloc& b) {
            return a.address < b.address;
        });

    // For HI16/LO16 references into non-relocatable sections, bake the value
    // straight into the instruction word and drop the reloc.
    for (size_t i = 0; i < section_out.relocs.size(); i++) {
        N64Recomp::Reloc& reloc = section_out.relocs[i];
        if (reloc.reference_symbol && (reloc.type == N64Recomp::RelocType::R_MIPS_HI16 || reloc.type == N64Recomp::RelocType::R_MIPS_LO16)) {
            if (context.is_reference_section_relocatable(reloc.target_section)) {
                continue;
            }
            uint32_t reloc_rom_addr = reloc.address - section_out.ram_addr + section_out.rom_addr;
            uint32_t reloc_rom_word = byteswap(*reinterpret_cast<const uint32_t*>(context.rom.data() + reloc_rom_addr));

            uint32_t ref_section_vram = context.get_reference_section_vram(reloc.target_section);
            uint32_t full_immediate = reloc.target_section_offset + ref_section_vram;

            uint32_t imm;
            if (reloc.type == N64Recomp::RelocType::R_MIPS_HI16) {
                imm = (full_immediate >> 16) + ((full_immediate >> 15) & 1);
            }
            else {
                imm = full_immediate & 0xFFFF;
            }

            *reinterpret_cast<uint32_t*>(context.rom.data() + reloc_rom_addr) = byteswap(reloc_rom_word | imm);
            reloc.type = N64Recomp::RelocType::R_MIPS_NONE;
            reloc.reference_symbol = false;
            reloc.symbol_index = (uint32_t)-1;
        }
    }

    return true;
}

} // namespace

bool read_symbols(N64Recomp::Context& context, const ELFIO::elfio& elf_file, ELFIO::section* symtab_section, const N64Recomp::ElfParsingConfig& elf_config, bool dumping_context, std::unordered_map<uint16_t, std::vector<N64Recomp::DataSymbol>>& data_syms) {
    bool found_entrypoint_func = false;
    ELFIO::symbol_section_accessor symbols{ elf_file, symtab_section };

    // When dumping context for patches/mods, symbols that live in a bss
    // section need to be relocated against the corresponding loaded section.
    std::unordered_map<uint16_t, uint16_t> bss_section_to_target_section{};
    if (dumping_context) {
        for (size_t cur_section_index = 0; cur_section_index < context.sections.size(); cur_section_index++) {
            const N64Recomp::Section& cur_section = context.sections[cur_section_index];
            if (cur_section.bss_section_index != (uint16_t)-1) {
                bss_section_to_target_section[cur_section.bss_section_index] = cur_section_index;
            }
        }
    }

    for (int sym_index = 0; sym_index < symbols.get_symbols_num(); sym_index++) {
        std::string       name;
        ELFIO::Elf64_Addr value;
        ELFIO::Elf_Xword  size;
        unsigned char     bind;
        unsigned char     type;
        ELFIO::Elf_Half   section_index;
        unsigned char     other;
        symbols.get_symbol(sym_index, name, value, size, bind, type, section_index, other);

        bool ignored = false;
        bool reimplemented = false;
        bool recorded_symbol = false;

        // Absolute symbols become zero-instruction functions when enabled.
        if (section_index == ELFIO::SHN_ABS && elf_config.use_absolute_symbols) {
            uint32_t vram = static_cast<uint32_t>(value);
            context.functions_by_vram[vram].push_back(context.functions.size());
            context.functions.emplace_back(
                vram,
                0,
                std::vector<uint32_t>{},
                std::move(name),
                0,
                true,
                reimplemented,
                false
            );
            continue;
        }

        if (section_index < context.sections.size()) {
            // Entrypoint detection by value. NOTE: this branch never actually
            // fires because of a signedness mismatch in the comparison; the
            // working detection is by ROM address (0x1000) further down.
            if (elf_config.has_entrypoint && value == elf_config.entrypoint_address && type == ELFIO::STT_FUNC) {
                if (found_entrypoint_func) {
                    fmt::print(stderr, "Ambiguous entrypoint: {}\n", name);
                    return false;
                }
                found_entrypoint_func = true;
                fmt::print("Found entrypoint, original name: {}\n", name);
                size = 0x50; // dummy size; should cover any entrypoint
                name = "recomp_entrypoint";
            }

            // Apply a configured size override (also forces function type).
            auto size_find = elf_config.manually_sized_funcs.find(name);
            if (size_find != elf_config.manually_sized_funcs.end()) {
                size = size_find->second;
                type = ELFIO::STT_FUNC;
            }

            // Reimplemented/ignored functions get a _recomp suffix and are
            // skipped during recompilation (only when not dumping context).
            if (!dumping_context) {
                if (N64Recomp::reimplemented_funcs.contains(name)) {
                    reimplemented = true;
                    name = name + "_recomp";
                    ignored = true;
                }
                else if (N64Recomp::ignored_funcs.contains(name)) {
                    name = name + "_recomp";
                    ignored = true;
                }
            }

            N64Recomp::Section& section = context.sections[section_index];

            // Functions, untyped labels, and objects all get a function entry
            // so they can be resolved as call targets.
            if (ignored || type == ELFIO::STT_FUNC || type == ELFIO::STT_NOTYPE || type == ELFIO::STT_OBJECT) {
                if (!dumping_context && N64Recomp::renamed_funcs.contains(name)) {
                    name = name + "_recomp";
                    ignored = false;
                }

                if (section_index < context.sections.size()) {
                    auto section_offset = value - elf_file.sections[section_index]->get_address();
                    uint32_t vram = static_cast<uint32_t>(value);
                    uint32_t num_instructions = type == ELFIO::STT_FUNC ? size / 4 : 0;
                    uint32_t rom_address = static_cast<uint32_t>(section_offset + section.rom_addr);
                    const uint32_t* words = reinterpret_cast<const uint32_t*>(context.rom.data() + rom_address);

                    section.function_addrs.push_back(vram);
                    context.functions_by_vram[vram].push_back(context.functions.size());

                    // The entrypoint can be identified by its ROM address even
                    // when its symbol value isn't the entrypoint vram.
                    if (elf_config.has_entrypoint && rom_address == 0x1000 && type == ELFIO::STT_FUNC) {
                        vram = elf_config.entrypoint_address;
                        found_entrypoint_func = true;
                        name = "recomp_entrypoint";
                        if (size == 0) {
                            num_instructions = 0x50 / 4;
                        }
                    }

                    // Disambiguate local symbols by ROM address.
                    if (bind == ELFIO::STB_LOCAL) {
                        name = fmt::format("{}_{:08X}", name, rom_address);
                    }

                    if (num_instructions > 0) {
                        context.section_functions[section_index].push_back(context.functions.size());
                        recorded_symbol = true;
                    }
                    context.functions_by_name[name] = context.functions.size();

                    std::vector<uint32_t> insn_words(num_instructions);
                    insn_words.assign(words, words + num_instructions);

                    context.functions.emplace_back(
                        vram,
                        rom_address,
                        std::move(insn_words),
                        name,
                        section_index,
                        ignored,
                        reimplemented
                    );
                }
                else {
                    // TODO is this case needed anymore?
                    uint32_t vram = static_cast<uint32_t>(value);
                    section.function_addrs.push_back(vram);
                    context.functions_by_vram[vram].push_back(context.functions.size());
                    context.functions.emplace_back(
                        vram,
                        0,
                        std::vector<uint32_t>{},
                        name,
                        section_index,
                        ignored,
                        reimplemented
                    );
                }
            }
        }

        // Anything not recorded as a function becomes a data symbol when
        // dumping context (skipping internal-visibility symbols).
        if (!recorded_symbol && dumping_context && !name.empty()) {
            if (ELF_ST_VISIBILITY(other) != ELFIO::STV_INTERNAL) {
                uint32_t vram = static_cast<uint32_t>(value);

                uint16_t target_section_index = section_index;
                if (section_index == ELFIO::SHN_ABS) {
                    target_section_index = N64Recomp::SectionAbsolute;
                }
                else if (section_index >= context.sections.size()) {
                    fmt::print("Symbol \"{}\" not in a valid section ({})\n", name, section_index);
                }

                // Redirect bss-section symbols to their loaded section.
                auto find_bss_it = bss_section_to_target_section.find(target_section_index);
                if (find_bss_it != bss_section_to_target_section.end()) {
                    target_section_index = find_bss_it->second;
                }

                data_syms[target_section_index].emplace_back(
                    vram,
                    std::move(name)
                );
            }
        }
    }

    return found_entrypoint_func;
}

ELFIO::section* read_sections(N64Recomp::Context& context, const N64Recomp::ElfParsingConfig& elf_config, const ELFIO::elfio& elf_file) {
    ELFIO::section* symtab_section = nullptr;
    bool has_reference_symbols = context.has_reference_symbols();

    // Snapshot each segment's file/physical layout for section address mapping.
    std::vector<SegmentEntry> segments{};
    segments.resize(elf_file.segments.size());
    for (size_t segment_index = 0; segment_index < elf_file.segments.size(); segment_index++) {
        const ELFIO::segment& segment = *elf_file.segments[segment_index];
        segments[segment_index].data_offset = segment.get_offset();
        segments[segment_index].physical_address = segment.get_physical_address();
        segments[segment_index].memory_size = segment.get_file_size();
    }

    std::unordered_map<std::string, ELFIO::section*> reloc_sections_by_name;
    std::unordered_map<std::string, ELFIO::section*> bss_sections_by_name;

    // Pass 1: assign each loadable section a provisional ROM address from its
    // segment and track the lowest one (objcopy normalizes the image to it).
    uint32_t min_load_address = (uint32_t)-1;
    for (const auto& section : elf_file.sections) {
        N64Recomp::Section& section_out = context.sections[section->get_index()];
        ELFIO::Elf_Word type = section->get_type();
        ELFIO::Elf_Xword flags = section->get_flags();
        ELFIO::Elf_Xword section_size = section->get_size();

        // A section lands in the ROM if it has bits (not NOBITS), is allocated,
        // and is non-empty.
        if (type != ELFIO::SHT_NOBITS && (flags & ELFIO::SHF_ALLOC) && section_size != 0) {
            std::optional<size_t> segment_index = find_containing_segment(segments, section_size, section->get_offset());
            if (!segment_index.has_value()) {
                fmt::print(stderr, "Could not find segment that section {} belongs to!\n", section->get_name());
                return nullptr;
            }
            const SegmentEntry& segment = segments[segment_index.value()];
            section_out.rom_addr = segment.physical_address + (section->get_offset() - segment.data_offset);
            min_load_address = std::min(min_load_address, section_out.rom_addr);
        }
        else {
            section_out.rom_addr = (uint32_t)-1;
        }
    }

    // Pass 2: record vram/size/flags, find the symbol table, classify reloc and
    // bss sections, and copy ROM-resident section data into the image.
    for (const auto& section : elf_file.sections) {
        N64Recomp::Section& section_out = context.sections[section->get_index()];
        section_out.ram_addr = section->get_address();
        section_out.size = section->get_size();
        ELFIO::Elf_Word type = section->get_type();
        std::string section_name = section->get_name();

        if (type == ELFIO::SHT_SYMTAB) {
            symtab_section = section.get();
        }

        if (elf_config.all_sections_relocatable || elf_config.relocatable_sections.contains(section_name)) {
            section_out.relocatable = true;
        }

        if (type == ELFIO::SHT_REL) {
            if (!section_name.starts_with(".rel")) {
                fmt::print(stderr, "Could not determine corresponding section for reloc section {}\n", section_name.c_str());
                return nullptr;
            }
            // FIXME should map via SH_INFO rather than by stripping the ".rel" name prefix.
            std::string reloc_target_section = section_name.substr(strlen(".rel"));

            // Track reloc sections for relocatable targets, or all of them when
            // reference symbols are in use.
            bool section_is_relocatable = elf_config.all_sections_relocatable || elf_config.relocatable_sections.contains(reloc_target_section);
            if (has_reference_symbols || section_is_relocatable) {
                reloc_sections_by_name[reloc_target_section] = section.get();
            }
        }

        if (type == ELFIO::SHT_NOBITS && section_name.ends_with(elf_config.bss_section_suffix)) {
            std::string bss_target_section = section_name.substr(0, section_name.size() - elf_config.bss_section_suffix.size());
            if (elf_config.all_sections_relocatable || elf_config.relocatable_sections.contains(bss_target_section)) {
                bss_sections_by_name[bss_target_section] = section.get();
            }
        }

        if (section_out.rom_addr != (uint32_t)-1) {
            // Rebase to the minimum load address and grow the image to fit.
            section_out.rom_addr -= min_load_address;
            size_t required_rom_size = section_out.rom_addr + section_out.size;
            if (required_rom_size > context.rom.size()) {
                context.rom.resize(required_rom_size);
            }
            std::copy(section->get_data(), section->get_data() + section->get_size(), &context.rom[section_out.rom_addr]);
        }

        if (section->get_flags() & ELFIO::SHF_EXECINSTR) {
            section_out.executable = true;
        }
        section_out.name = section_name;
    }

    if (symtab_section == nullptr) {
        fmt::print(stderr, "No symtab section found\n");
        return nullptr;
    }

    ELFIO::symbol_section_accessor symbol_accessor{ elf_file, symtab_section };

    // TODO make sure that a reloc section was found for every section marked as relocatable

    // Pass 3: wire up bss sizes and resolve relocations for each relocatable,
    // ROM-resident section.
    for (size_t section_index = 0; section_index < context.sections.size(); section_index++) {
        N64Recomp::Section& section_out = context.sections[section_index];

        auto bss_find = bss_sections_by_name.find(section_out.name);
        if (bss_find != bss_sections_by_name.end()) {
            section_out.bss_section_index = bss_find->second->get_index();
            section_out.bss_size = bss_find->second->get_size();
            context.bss_section_to_section[section_out.bss_section_index] = section_index;
        }

        const ELFIO::section* elf_section = elf_file.sections[section_index];
        bool in_rom = (elf_section->get_type() != ELFIO::SHT_NOBITS) && (elf_section->get_flags() & ELFIO::SHF_ALLOC);
        bool is_relocatable = section_out.relocatable || context.has_reference_symbols();
        if (in_rom && is_relocatable) {
            auto reloc_find = reloc_sections_by_name.find(section_out.name);
            if (reloc_find != reloc_sections_by_name.end()) {
                if (!parse_section_relocs(context, elf_file, symbol_accessor, section_index, reloc_find->second, elf_config)) {
                    return nullptr;
                }
            }
        }
    }

    return symtab_section;
}

static void setup_context_for_elf(N64Recomp::Context& context, const ELFIO::elfio& elf_file) {
    context.sections.resize(elf_file.sections.size());
    context.section_functions.resize(elf_file.sections.size());
    context.section_dispatch_aliases.resize(elf_file.sections.size());
    context.functions.reserve(1024);
    context.functions_by_vram.reserve(context.functions.capacity());
    context.functions_by_name.reserve(context.functions.capacity());
    context.rom.reserve(8 * 1024 * 1024);
}

bool N64Recomp::Context::from_elf_file(const std::filesystem::path& elf_file_path, Context& out, const ElfParsingConfig& elf_config, bool for_dumping_context, DataSymbolMap& data_syms_out, bool& found_entrypoint_out) {
    ELFIO::elfio elf_file;

    if (!elf_file.load(elf_file_path.string())) {
        fmt::print("Elf file not found\n");
        return false;
    }

    if (elf_file.get_class() != ELFIO::ELFCLASS32) {
        fmt::print("Incorrect elf class\n");
        return false;
    }

    if (elf_file.get_encoding() != ELFIO::ELFDATA2MSB) {
        fmt::print("Incorrect endianness\n");
        return false;
    }

    setup_context_for_elf(out, elf_file);

    ELFIO::section* symtab_section = read_sections(out, elf_config, elf_file);
    if (symtab_section == nullptr) {
        return false;
    }

    found_entrypoint_out = read_symbols(out, elf_file, symtab_section, elf_config, for_dumping_context, data_syms_out);

    return true;
}
