#include <algorithm>
#include <iostream>

#include <toml++/toml.hpp>
#include "rabbitizer.hpp"
#include "fmt/format.h"
#include "config.h"
#include "recompiler/context.h"
#include "analysis.h"

std::filesystem::path concat_if_not_empty(const std::filesystem::path& parent, const std::filesystem::path& child) {
    if (!child.empty()) {
        return parent / child;
    }
    return child;
}

namespace {
    bool instruction_has_delay_slot(uint32_t instr_word) {
        const uint32_t op = (instr_word >> 26) & 0x3Fu;
        if (op == 2 || op == 3) {
            return true; // j, jal
        }
        if ((op >= 4 && op <= 7) || (op >= 0x14 && op <= 0x17)) {
            return true; // beq/bne/blez/bgtz and likely variants
        }
        if (op == 1) {
            const uint32_t rt = (instr_word >> 16) & 0x1Fu;
            return rt == 0 || rt == 1 || rt == 2 || rt == 3 ||
                   rt == 16 || rt == 17 || rt == 18 || rt == 19;
        }
        if (op == 0) {
            const uint32_t funct = instr_word & 0x3Fu;
            return funct == 8 || funct == 9; // jr, jalr
        }
        if (op == 0x11) {
            const uint32_t rs = (instr_word >> 21) & 0x1Fu;
            return rs == 8; // bc1*
        }
        return false;
    }

    bool is_jr_ra(uint32_t instr_word) {
        return instr_word == 0x03E00008u;
    }

    bool is_lw_ra_from_sp(uint32_t instr_word) {
        const uint32_t op = (instr_word >> 26) & 0x3Fu;
        const uint32_t base = (instr_word >> 21) & 0x1Fu;
        const uint32_t rt = (instr_word >> 16) & 0x1Fu;
        return op == 0x23 && base == 29 && rt == 31;
    }

    bool is_addiu_sp_sp_positive(uint32_t instr_word) {
        const uint32_t op = (instr_word >> 26) & 0x3Fu;
        const uint32_t rs = (instr_word >> 21) & 0x1Fu;
        const uint32_t rt = (instr_word >> 16) & 0x1Fu;
        const uint16_t imm = instr_word & 0xFFFFu;
        return op == 0x09 && rs == 29 && rt == 29 && (imm & 0x8000u) == 0 && imm != 0;
    }

    bool read_symbol_section_word(
        const std::vector<uint8_t>& rom,
        const N64Recomp::Section& section,
        uint32_t instr_vram,
        uint32_t* raw_word_out,
        uint32_t* instr_word_out = nullptr) {
        if (instr_vram < section.ram_addr ||
            instr_vram + sizeof(uint32_t) > section.ram_addr + section.size) {
            return false;
        }

        const uint32_t rom_addr = section.rom_addr + (instr_vram - section.ram_addr);
        if (rom_addr + sizeof(uint32_t) > rom.size()) {
            return false;
        }

        const uint32_t raw_word = *reinterpret_cast<const uint32_t*>(rom.data() + rom_addr);
        if (raw_word_out != nullptr) {
            *raw_word_out = raw_word;
        }
        if (instr_word_out != nullptr) {
            *instr_word_out = byteswap(raw_word);
        }
        return true;
    }

    bool is_symbol_delay_slot(
        const std::vector<uint8_t>& rom,
        const N64Recomp::Section& section,
        uint32_t instr_vram) {
        if (instr_vram < section.ram_addr + sizeof(uint32_t)) {
            return false;
        }

        uint32_t prev_instr = 0;
        if (!read_symbol_section_word(rom, section, instr_vram - sizeof(uint32_t), nullptr, &prev_instr)) {
            return false;
        }

        return instruction_has_delay_slot(prev_instr);
    }

    void repair_truncated_symbol_function_ranges(N64Recomp::Context& context, const std::vector<uint8_t>& rom) {
        if (rom.empty()) {
            return;
        }

        for (size_t section_index = 0; section_index < context.sections.size(); section_index++) {
            const auto& section = context.sections[section_index];
            if (!section.executable) {
                continue;
            }

            for (size_t func_index : context.section_functions[section_index]) {
                auto& func = context.functions[func_index];
                if (func.words.empty()) {
                    continue;
                }

                const uint32_t func_start = func.vram;
                const uint32_t func_end = func.vram + uint32_t(func.words.size() * sizeof(uint32_t));
                uint32_t next_boundary = section.ram_addr + section.size;

                for (size_t other_index : context.section_functions[section_index]) {
                    if (other_index == func_index) {
                        continue;
                    }
                    const auto& other = context.functions[other_index];
                    if (!other.words.empty() && other.vram > func_start && other.vram < next_boundary) {
                        next_boundary = other.vram;
                    }
                }

                auto append_word = [&](uint32_t instr_vram) {
                    uint32_t raw_word = 0;
                    if (!read_symbol_section_word(rom, section, instr_vram, &raw_word)) {
                        return false;
                    }
                    func.words.push_back(raw_word);
                    return true;
                };

                uint32_t end_instr = 0;
                const uint32_t last_instr = byteswap(func.words.back());
                uint32_t restore_sp_instr = 0;
                uint32_t jr_instr = 0;
                if (func_end + sizeof(uint32_t) * 3 <= next_boundary &&
                    is_lw_ra_from_sp(last_instr) &&
                    read_symbol_section_word(rom, section, func_end, nullptr, &restore_sp_instr) &&
                    read_symbol_section_word(rom, section, func_end + sizeof(uint32_t), nullptr, &jr_instr) &&
                    is_addiu_sp_sp_positive(restore_sp_instr) &&
                    is_jr_ra(jr_instr) &&
                    append_word(func_end) &&
                    append_word(func_end + sizeof(uint32_t)) &&
                    append_word(func_end + sizeof(uint32_t) * 2)) {
                    fmt::print(stderr,
                        "[Info] Extended symbol function {} from 0x{:X} to 0x{:X}: "
                        "range ended after restoring $ra at 0x{:08X}; included stack restore, return, and delay slot.\n",
                        func.name,
                        func_end - func_start,
                        uint32_t(func.words.size() * sizeof(uint32_t)),
                        func_end - sizeof(uint32_t));
                    continue;
                }

                if (func_end + sizeof(uint32_t) * 2 <= next_boundary &&
                    read_symbol_section_word(rom, section, func_end, nullptr, &end_instr) &&
                    is_jr_ra(end_instr) &&
                    append_word(func_end) &&
                    append_word(func_end + sizeof(uint32_t))) {
                    fmt::print(stderr,
                        "[Info] Extended symbol function {} from 0x{:X} to 0x{:X}: "
                        "range ended immediately before jr $ra at 0x{:08X}; included return and delay slot.\n",
                        func.name,
                        func_end - func_start,
                        uint32_t(func.words.size() * sizeof(uint32_t)),
                        func_end);
                    continue;
                }

                if (func_end + sizeof(uint32_t) <= next_boundary &&
                    instruction_has_delay_slot(last_instr) &&
                    append_word(func_end)) {
                    fmt::print(stderr,
                        "[Info] Extended symbol function {} from 0x{:X} to 0x{:X}: "
                        "range ended with branch/jump at 0x{:08X}; included delay slot.\n",
                        func.name,
                        func_end - func_start,
                        uint32_t(func.words.size() * sizeof(uint32_t)),
                        func_end - sizeof(uint32_t));
                }
            }
        }
    }

    void remap_function_vram(
        N64Recomp::Context& context,
        N64Recomp::Section& section,
        size_t function_index,
        uint32_t old_vram,
        uint32_t new_vram) {
        auto old_it = context.functions_by_vram.find(old_vram);
        if (old_it != context.functions_by_vram.end()) {
            auto& indices = old_it->second;
            indices.erase(std::remove(indices.begin(), indices.end(), function_index), indices.end());
            if (indices.empty()) {
                context.functions_by_vram.erase(old_it);
            }
        }

        context.functions_by_vram[new_vram].push_back(function_index);

        auto addr_it = std::find(section.function_addrs.begin(), section.function_addrs.end(), old_vram);
        if (addr_it != section.function_addrs.end()) {
            *addr_it = new_vram;
        }
        else {
            section.function_addrs.push_back(new_vram);
        }
    }

    void repair_late_symbol_function_starts(N64Recomp::Context& context, const std::vector<uint8_t>& rom) {
        if (rom.empty()) {
            return;
        }

        constexpr uint32_t kMaxPrefixGapToScan = 0x40;

        for (size_t section_index = 0; section_index < context.sections.size(); section_index++) {
            auto& section = context.sections[section_index];
            if (!section.executable || section.rom_addr + section.size > rom.size()) {
                continue;
            }

            std::vector<size_t> sorted_funcs = context.section_functions[section_index];
            std::sort(sorted_funcs.begin(), sorted_funcs.end(),
                [&](size_t lhs, size_t rhs) {
                    return context.functions[lhs].vram < context.functions[rhs].vram;
                });

            for (size_t i = 0; i + 1 < sorted_funcs.size(); i++) {
                const auto& prev_func = context.functions[sorted_funcs[i]];
                const size_t cur_index = sorted_funcs[i + 1];
                auto& cur_func = context.functions[cur_index];
                if (prev_func.words.empty() || cur_func.words.empty() || cur_func.vram <= prev_func.vram) {
                    continue;
                }

                const uint32_t prev_end = prev_func.vram + uint32_t(prev_func.words.size() * sizeof(uint32_t));
                const uint32_t old_start = cur_func.vram;
                const uint32_t old_end = cur_func.vram + uint32_t(cur_func.words.size() * sizeof(uint32_t));
                if (prev_end >= old_start || old_start - prev_end > kMaxPrefixGapToScan) {
                    continue;
                }

                for (uint32_t prefix_start = prev_end; prefix_start + sizeof(uint32_t) <= old_start; prefix_start += sizeof(uint32_t)) {
                    uint32_t instr_word = 0;
                    if (!read_symbol_section_word(rom, section, prefix_start, nullptr, &instr_word)) {
                        break;
                    }
                    if (instr_word == 0) {
                        continue;
                    }
                    if (context.functions_by_vram.find(prefix_start) != context.functions_by_vram.end()) {
                        continue;
                    }
                    if (is_symbol_delay_slot(rom, section, prefix_start)) {
                        continue;
                    }

                    size_t discovered_size = 0;
                    std::string discover_error;
                    const uint32_t entry_offset = prefix_start - section.ram_addr;
                    if (!N64Recomp::discover_function_bounds(
                            rom.data() + section.rom_addr,
                            section.size,
                            section.ram_addr,
                            entry_offset,
                            discovered_size,
                            discover_error)) {
                        continue;
                    }

                    if ((discovered_size & 3u) != 0) {
                        continue;
                    }
                    if (prefix_start + discovered_size <= old_start) {
                        break;
                    }
                    if (discovered_size <= old_start - prefix_start ||
                        prefix_start + discovered_size != old_end) {
                        continue;
                    }

                    const uint32_t new_rom = section.rom_addr + (prefix_start - section.ram_addr);
                    std::vector<uint32_t> repaired_words;
                    repaired_words.reserve(discovered_size / sizeof(uint32_t));
                    for (uint32_t rom_addr = new_rom; rom_addr < new_rom + discovered_size; rom_addr += sizeof(uint32_t)) {
                        repaired_words.push_back(*reinterpret_cast<const uint32_t*>(rom.data() + rom_addr));
                    }

                    cur_func.vram = prefix_start;
                    cur_func.rom = new_rom;
                    if (cur_func.entry_vram == old_start) {
                        cur_func.entry_vram = prefix_start;
                    }
                    cur_func.words = std::move(repaired_words);

                    remap_function_vram(context, section, cur_index, old_start, prefix_start);

                    fmt::print(stderr,
                        "[Info] Moved symbol function {} start from 0x{:08X} to 0x{:08X}: "
                        "decoded 0x{:X}-byte prefix in gap after {} and preserved end 0x{:08X}.\n",
                        cur_func.name,
                        old_start,
                        prefix_start,
                        old_start - prefix_start,
                        prev_func.name,
                        old_end);
                    break;
                }
            }
        }
    }

    void synthesize_small_symbol_gap_functions(N64Recomp::Context& context, const std::vector<uint8_t>& rom) {
        if (rom.empty()) {
            return;
        }

        constexpr uint32_t kMaxGapToScan = 0x400;
        auto rom_contains_be32 = [&](uint32_t value) {
            const uint8_t needle[4] = {
                uint8_t(value >> 24),
                uint8_t(value >> 16),
                uint8_t(value >> 8),
                uint8_t(value),
            };
            return std::search(
                rom.begin(), rom.end(),
                needle, needle + sizeof(needle)) != rom.end();
        };

        for (size_t section_index = 0; section_index < context.sections.size(); section_index++) {
            auto& section = context.sections[section_index];
            if (!section.executable || section.rom_addr + section.size > rom.size()) {
                continue;
            }

            std::vector<size_t> sorted_funcs = context.section_functions[section_index];
            std::sort(sorted_funcs.begin(), sorted_funcs.end(),
                [&](size_t lhs, size_t rhs) {
                    return context.functions[lhs].vram < context.functions[rhs].vram;
                });

            for (size_t i = 0; i + 1 < sorted_funcs.size(); i++) {
                const auto& prev_ref = context.functions[sorted_funcs[i]];
                const auto& next_ref = context.functions[sorted_funcs[i + 1]];
                if (prev_ref.words.empty() || next_ref.words.empty() || next_ref.vram <= prev_ref.vram) {
                    continue;
                }

                const std::string prev_name = prev_ref.name;
                const std::string next_name = next_ref.name;
                uint32_t cursor = prev_ref.vram + uint32_t(prev_ref.words.size() * sizeof(uint32_t));
                const uint32_t gap_end = next_ref.vram;
                if (cursor >= gap_end || gap_end - cursor > kMaxGapToScan) {
                    continue;
                }

                while (cursor + sizeof(uint32_t) * 2 <= gap_end) {
                    uint32_t instr_word = 0;
                    if (!read_symbol_section_word(rom, section, cursor, nullptr, &instr_word)) {
                        break;
                    }
                    if (instr_word == 0) {
                        cursor += sizeof(uint32_t);
                        continue;
                    }
                    if (context.functions_by_vram.find(cursor) != context.functions_by_vram.end()) {
                        cursor += sizeof(uint32_t);
                        continue;
                    }

                    size_t discovered_size = 0;
                    std::string discover_error;
                    const uint32_t entry_offset = cursor - section.ram_addr;
                    if (!N64Recomp::discover_function_bounds(
                            rom.data() + section.rom_addr,
                            section.size,
                            section.ram_addr,
                            entry_offset,
                            discovered_size,
                            discover_error)) {
                        cursor += sizeof(uint32_t);
                        continue;
                    }
                    const uint32_t next_end =
                        next_ref.vram +
                        uint32_t(next_ref.words.size() * sizeof(uint32_t));
                    const bool overlaps_next_entry =
                        cursor + discovered_size > gap_end &&
                        cursor + discovered_size == next_end &&
                        rom_contains_be32(cursor);
                    if (discovered_size < sizeof(uint32_t) * 2 ||
                        (cursor + discovered_size > gap_end && !overlaps_next_entry) ||
                        (discovered_size & 3u) != 0) {
                        cursor += sizeof(uint32_t);
                        continue;
                    }

                    bool has_return = false;
                    for (uint32_t off = 0; off + sizeof(uint32_t) <= discovered_size; off += sizeof(uint32_t)) {
                        uint32_t cur_word = 0;
                        if (read_symbol_section_word(rom, section, cursor + off, nullptr, &cur_word) &&
                            is_jr_ra(cur_word)) {
                            has_return = true;
                            break;
                        }
                    }
                    if (!has_return) {
                        cursor += sizeof(uint32_t);
                        continue;
                    }

                    N64Recomp::Function gap_func{};
                    gap_func.name = fmt::format("func_{:08X}", cursor);
                    gap_func.vram = cursor;
                    gap_func.rom = section.rom_addr + (cursor - section.ram_addr);
                    gap_func.section_index = uint16_t(section_index);
                    gap_func.words.reserve(discovered_size / sizeof(uint32_t));
                    for (uint32_t rom_addr = gap_func.rom;
                         rom_addr < gap_func.rom + discovered_size;
                         rom_addr += sizeof(uint32_t)) {
                        gap_func.words.push_back(*reinterpret_cast<const uint32_t*>(rom.data() + rom_addr));
                    }

                    const size_t function_index = context.functions.size();
                    section.function_addrs.push_back(gap_func.vram);
                    context.functions_by_name[gap_func.name] = function_index;
                    context.functions_by_vram[gap_func.vram].push_back(function_index);
                    context.section_functions[section_index].push_back(function_index);
                    context.functions.emplace_back(std::move(gap_func));

                    fmt::print(stderr,
                        "[Info] Synthesized symbol-gap function func_{:08X} "
                        "size 0x{:X} in section {} between {} and {}.\n",
                        cursor, uint32_t(discovered_size),
                        section.name, prev_name, next_name);

                    cursor += uint32_t(discovered_size);
                }
            }
        }
    }
}

std::vector<N64Recomp::ManualFunction> get_manual_funcs(const toml::array* manual_funcs_array) {
    std::vector<N64Recomp::ManualFunction> ret;

    // Reserve room for all the funcs in the map.
    ret.reserve(manual_funcs_array->size());
    manual_funcs_array->for_each([&ret](auto&& el) {
        if constexpr (toml::is_table<decltype(el)>) {
            std::optional<std::string> func_name = el["name"].template value<std::string>();
            std::optional<std::string> section_name = el["section"].template value<std::string>();
            std::optional<uint32_t> vram_in = el["vram"].template value<uint32_t>();
            std::optional<uint32_t> size = el["size"].template value<uint32_t>();

            if (func_name.has_value() && section_name.has_value() && vram_in.has_value() && size.has_value()) {
                ret.emplace_back(func_name.value(), section_name.value(), vram_in.value(), size.value());
            } else {
                throw toml::parse_error("Missing required value in manual_funcs array", el.source());
            }
        }
        else {
            throw toml::parse_error("Missing required value in manual_funcs array", el.source());
        }
    });

    return ret;
}

std::vector<N64Recomp::DecompressedSectionPattern> get_decompressed_section_patterns(const toml::array* arr) {
    std::vector<N64Recomp::DecompressedSectionPattern> ret;
    ret.reserve(arr->size());
    arr->for_each([&ret](auto&& el) {
        if constexpr (toml::is_table<decltype(el)>) {
            std::optional<std::string> base_name = el["base_name"].template value<std::string>();
            std::optional<uint32_t> vram = el["vram"].template value<uint32_t>();
            std::optional<std::string> wrapper_format = el["wrapper_format"].template value<std::string>();
            std::optional<bool> relocatable = el["relocatable"].template value<bool>();

            if (!vram.has_value() || !wrapper_format.has_value()) {
                throw toml::parse_error(
                    "decompressed_section_pattern requires vram and "
                    "wrapper_format", el.source());
            }

            N64Recomp::DecompressedSectionPattern p;
            p.base_name      = base_name.value_or("");
            p.vram           = vram.value();
            p.wrapper_format = wrapper_format.value();
            p.relocatable    = relocatable.value_or(true);
            ret.emplace_back(std::move(p));
        } else {
            throw toml::parse_error(
                "Invalid decompressed_section_pattern entry", el.source());
        }
    });
    return ret;
}

std::vector<N64Recomp::DecompressedSection> get_decompressed_sections(const toml::array* arr) {
    std::vector<N64Recomp::DecompressedSection> ret;
    ret.reserve(arr->size());
    arr->for_each([&ret](auto&& el) {
        if constexpr (toml::is_table<decltype(el)>) {
            std::optional<std::string> name = el["name"].template value<std::string>();
            std::optional<uint32_t> vram = el["vram"].template value<uint32_t>();
            std::optional<uint32_t> rom_wrapper = el["rom_wrapper"].template value<uint32_t>();
            std::optional<std::string> wrapper_format = el["wrapper_format"].template value<std::string>();
            std::optional<bool> relocatable = el["relocatable"].template value<bool>();

            if (!name.has_value() || !vram.has_value() ||
                !rom_wrapper.has_value() || !wrapper_format.has_value()) {
                throw toml::parse_error(
                    "decompressed_section requires name, vram, rom_wrapper, "
                    "wrapper_format", el.source());
            }

            N64Recomp::DecompressedSection ds;
            ds.name           = name.value();
            ds.vram           = vram.value();
            ds.rom_wrapper    = rom_wrapper.value();
            ds.wrapper_format = wrapper_format.value();
            ds.relocatable    = relocatable.value_or(true);
            ret.emplace_back(std::move(ds));
        } else {
            throw toml::parse_error(
                "Invalid decompressed_section entry", el.source());
        }
    });
    return ret;
}

std::vector<N64Recomp::DecompressedSectionPatch> get_decompressed_section_patches(const toml::array* arr) {
    std::vector<N64Recomp::DecompressedSectionPatch> ret;
    ret.reserve(arr->size());
    arr->for_each([&ret](auto&& el) {
        if constexpr (toml::is_table<decltype(el)>) {
            std::optional<uint32_t> rom_wrapper =
                el["rom_wrapper"].template value<uint32_t>();
            std::optional<uint32_t> original_pattern_id =
                el["original_pattern_id"].template value<uint32_t>();
            std::optional<uint32_t> offset =
                el["offset"].template value<uint32_t>();
            std::optional<uint32_t> value =
                el["value"].template value<uint32_t>();

            if (!offset.has_value() || !value.has_value() ||
                (!rom_wrapper.has_value() && !original_pattern_id.has_value())) {
                throw toml::parse_error(
                    "decompressed_section_patch requires offset, value, "
                    "and at least one selector: rom_wrapper or "
                    "original_pattern_id", el.source());
            }

            if ((offset.value() & 0b11) != 0) {
                throw toml::parse_error(
                    "decompressed_section_patch offset is not word-aligned",
                    el.source());
            }

            N64Recomp::DecompressedSectionPatch patch;
            patch.has_rom_wrapper = rom_wrapper.has_value();
            patch.rom_wrapper = rom_wrapper.value_or(0);
            patch.has_original_pattern_id = original_pattern_id.has_value();
            patch.original_pattern_id = original_pattern_id.value_or(0);
            patch.offset = offset.value();
            patch.value = value.value();
            ret.emplace_back(std::move(patch));
        } else {
            throw toml::parse_error(
                "Invalid decompressed_section_patch entry", el.source());
        }
    });
    return ret;
}

std::vector<std::filesystem::path> get_data_syms_paths(const toml::array* data_syms_paths_array, const std::filesystem::path& basedir) {
    std::vector<std::filesystem::path> ret;

    // Reserve room for all the funcs in the map.
    ret.reserve(data_syms_paths_array->size());
    data_syms_paths_array->for_each([&ret, &basedir](auto&& el) {
        if constexpr (toml::is_string<decltype(el)>) {
            ret.emplace_back(concat_if_not_empty(basedir, el.template value_exact<std::string>().value()));
        }
        else {
            throw toml::parse_error("Invalid type for data reference symbol file entry", el.source());
        }
    });

    return ret;
}

std::vector<std::string> get_stubbed_funcs(const toml::table* patches_data) {
    std::vector<std::string> stubbed_funcs{};

    // Check if the stubs array exists.
    const toml::node_view stubs_data = (*patches_data)["stubs"];

    if (stubs_data.is_array()) {
        const toml::array* stubs_array = stubs_data.as_array();

        // Make room for all the stubs in the array.
        stubbed_funcs.reserve(stubs_array->size());

        // Gather the stubs and place them into the array.
        stubs_array->for_each([&stubbed_funcs](auto&& el) {
            if constexpr (toml::is_string<decltype(el)>) {
                stubbed_funcs.push_back(*el);
            }
            else {
                throw toml::parse_error("Invalid stubbed function", el.source());
            }
        });
    }

    return stubbed_funcs;
}

std::vector<std::string> get_ignored_funcs(const toml::table* patches_data) {
    std::vector<std::string> ignored_funcs{};

    // Check if the ignored funcs array exists.
    const toml::node_view ignored_funcs_data = (*patches_data)["ignored"];

    if (ignored_funcs_data.is_array()) {
        const toml::array* ignored_funcs_array = ignored_funcs_data.as_array();

        // Make room for all the ignored funcs in the array.
        ignored_funcs.reserve(ignored_funcs_array->size());

        // Gather the ignored and place them into the array.
        ignored_funcs_array->for_each([&ignored_funcs](auto&& el) {
            if constexpr (toml::is_string<decltype(el)>) {
                ignored_funcs.push_back(*el);
            }
        });
    }

    return ignored_funcs;
}

std::vector<std::string> get_renamed_funcs(const toml::table* patches_data) {
    std::vector<std::string> renamed_funcs{};

    // Check if the renamed funcs array exists.
    const toml::node_view renamed_funcs_data = (*patches_data)["renamed"];

    if (renamed_funcs_data.is_array()) {
        const toml::array* renamed_funcs_array = renamed_funcs_data.as_array();

        // Make room for all the renamed funcs in the array.
        renamed_funcs.reserve(renamed_funcs_array->size());

        // Gather the renamed and place them into the array.
        renamed_funcs_array->for_each([&renamed_funcs](auto&& el) {
            if constexpr (toml::is_string<decltype(el)>) {
                renamed_funcs.push_back(*el);
            }
        });
    }

    return renamed_funcs;
}

std::vector<N64Recomp::FunctionSize> get_func_sizes(const toml::array* func_sizes_array) {
    std::vector<N64Recomp::FunctionSize> func_sizes{};

    // Reserve room for all the funcs in the map.
    func_sizes.reserve(func_sizes_array->size());
    func_sizes_array->for_each([&func_sizes](auto&& el) {
        if constexpr (toml::is_table<decltype(el)>) {
            std::optional<std::string> func_name = el["name"].template value<std::string>();
            std::optional<uint32_t> func_size = el["size"].template value<uint32_t>();

            if (func_name.has_value() && func_size.has_value()) {
                // Make sure the size is divisible by 4
                if (func_size.value() & (4 - 1)) {
                    // It's not, so throw an error (and make it look like a normal toml one).
                    throw toml::parse_error("Function size is not divisible by 4", el.source());
                }
                func_sizes.emplace_back(func_name.value(), func_size.value());
            }
            else {
                throw toml::parse_error("Manually sized function is missing required value(s)", el.source());
            }
        }
        else {
            throw toml::parse_error("Missing required value in function_sizes array", el.source());
        }
    });

    return func_sizes;
}

std::vector<N64Recomp::InstructionPatch> get_instruction_patches(const toml::table* patches_data) {
    std::vector<N64Recomp::InstructionPatch> ret;

    // Check if the instruction patch array exists.
    const toml::node_view insn_patch_data = (*patches_data)["instruction"];

    if (insn_patch_data.is_array()) {
        const toml::array* insn_patch_array = insn_patch_data.as_array();
        ret.reserve(insn_patch_array->size());

        // Copy all the patches into the output vector.
        insn_patch_array->for_each([&ret](auto&& el) {
            if constexpr (toml::is_table<decltype(el)>) {
                const toml::table& cur_patch = *el.as_table();

                // Get the vram and make sure it's 4-byte aligned.
                std::optional<uint32_t> vram = cur_patch["vram"].value<uint32_t>();
                std::optional<std::string> func_name = cur_patch["func"].value<std::string>();
                std::optional<uint32_t> value = cur_patch["value"].value<uint32_t>();

                if (!vram.has_value() || !func_name.has_value() || !value.has_value()) {
                    throw toml::parse_error("Instruction patch is missing required value(s)", el.source());
                }

                if (vram.value() & 0b11) {
                    // Not properly aligned, so throw an error (and make it look like a normal toml one).
                    throw toml::parse_error("Instruction patch is not word-aligned", el.source());
                }

                ret.push_back(N64Recomp::InstructionPatch{
                    .func_name = func_name.value(),
                    .vram = (int32_t)vram.value(),
                    .value = value.value(),
                });
            }
            else {
                throw toml::parse_error("Invalid instruction patch entry", el.source());
            }
        });
    }

    return ret;
}

std::vector<N64Recomp::FunctionTextHook> get_function_hooks(const toml::table* patches_data) {
    std::vector<N64Recomp::FunctionTextHook> ret;

    // Check if the function hook array exists.
    const toml::node_view func_hook_data = (*patches_data)["hook"];

    if (func_hook_data.is_array()) {
        const toml::array* func_hook_array = func_hook_data.as_array();
        ret.reserve(func_hook_array->size());

        // Copy all the hooks into the output vector.
        func_hook_array->for_each([&ret](auto&& el) {
            if constexpr (toml::is_table<decltype(el)>) {
                const toml::table& cur_hook = *el.as_table();

                // Get the vram and make sure it's 4-byte aligned.
                std::optional<uint32_t> before_vram = cur_hook["before_vram"].value<uint32_t>();
                std::optional<std::string> func_name = cur_hook["func"].value<std::string>();
                std::optional<std::string> text = cur_hook["text"].value<std::string>();

                if (!func_name.has_value() || !text.has_value()) {
                    throw toml::parse_error("Function hook is missing required value(s)", el.source());
                }

                if (before_vram.has_value() && before_vram.value() & 0b11) {
                    // Not properly aligned, so throw an error (and make it look like a normal toml one).
                    throw toml::parse_error("before_vram is not word-aligned", el.source());
                }

                ret.push_back(N64Recomp::FunctionTextHook{
                    .func_name = func_name.value(),
                    .before_vram = before_vram.has_value() ? (int32_t)before_vram.value() : 0,
                    .text = text.value(),
                });
            }
            else {
                throw toml::parse_error("Invalid function hook entry", el.source());
            }
        });
    }

    return ret;
}

N64Recomp::Config::Config(const char* path) {
    // Start this config out as bad so that it has to finish parsing without errors to be good.
    entrypoint = 0;
    bad = true;
    toml::table config_data{};

    try {
        config_data = toml::parse_file(path);
        std::filesystem::path basedir = std::filesystem::path{ path }.parent_path();

        // Input section (required)
        const auto input_data = config_data["input"];
        const auto entrypoint_data = input_data["entrypoint"];

        if (entrypoint_data) {
            const auto entrypoint_value = entrypoint_data.value<uint32_t>();
            if (entrypoint_value.has_value()) {
                entrypoint = (int32_t)entrypoint_value.value();
                has_entrypoint = true;
            }
            else {
                throw toml::parse_error("Invalid entrypoint", entrypoint_data.node()->source());
            }
        }
        else {
            has_entrypoint = false;
        }

        std::optional<std::string> elf_path_opt = input_data["elf_path"].value<std::string>();
        if (elf_path_opt.has_value()) {
            elf_path = concat_if_not_empty(basedir, elf_path_opt.value());
        }

        std::optional<std::string> symbols_file_path_opt = input_data["symbols_file_path"].value<std::string>();
        if (symbols_file_path_opt.has_value()) {
            symbols_file_path = concat_if_not_empty(basedir, symbols_file_path_opt.value());
        }

        std::optional<std::string> rom_file_path_opt = input_data["rom_file_path"].value<std::string>();
        if (rom_file_path_opt.has_value()) {
            rom_file_path = concat_if_not_empty(basedir, rom_file_path_opt.value());
        }

        std::optional<std::string> output_func_path_opt = input_data["output_func_path"].value<std::string>();
        if (output_func_path_opt.has_value()) {
            output_func_path = concat_if_not_empty(basedir, output_func_path_opt.value());
        }
        else {
            throw toml::parse_error("Missing output_func_path in config file", input_data.node()->source());
        }

        std::optional<std::string> relocatable_sections_path_opt = input_data["relocatable_sections_path"].value<std::string>();
        if (relocatable_sections_path_opt.has_value()) {
            relocatable_sections_path = concat_if_not_empty(basedir, relocatable_sections_path_opt.value());
        }
        else {
            relocatable_sections_path = "";
        }

        std::optional<bool> uses_mips3_float_mode_opt = input_data["uses_mips3_float_mode"].value<bool>();
        if (uses_mips3_float_mode_opt.has_value()) {
            uses_mips3_float_mode = uses_mips3_float_mode_opt.value();
        }
        else {
            uses_mips3_float_mode = false;
        }

        std::optional<std::string> bss_section_suffix_opt = input_data["bss_section_suffix"].value<std::string>();
        if (bss_section_suffix_opt.has_value()) {
            bss_section_suffix = bss_section_suffix_opt.value();
        }
        else {
            bss_section_suffix = ".bss";
        }

        std::optional<bool> single_file_output_opt = input_data["single_file_output"].value<bool>();
        if (single_file_output_opt.has_value()) {
            single_file_output = single_file_output_opt.value();
        }
        else {
            single_file_output = false;
        }

        std::optional<bool> use_absolute_symbols_opt = input_data["use_absolute_symbols"].value<bool>();
        if (use_absolute_symbols_opt.has_value()) {
            use_absolute_symbols = use_absolute_symbols_opt.value();
        }
        else {
            use_absolute_symbols = false;
        }

        // Manual functions (optional)
        toml::node_view manual_functions_data = input_data["manual_funcs"];
        if (manual_functions_data.is_array()) {
            const toml::array* array = manual_functions_data.as_array();
            manual_functions = get_manual_funcs(array);
        }

        // Manual function sizes (optional)
        toml::node_view function_sizes_data = input_data["function_sizes"];
        if (function_sizes_data.is_array()) {
            const toml::array* array = function_sizes_data.as_array();
            manual_func_sizes = get_func_sizes(array);
        }

        // Decompressed sections (optional). One [[input.decompressed_section]]
        // entry per CPU-decompressed runtime fragment we want recompiled.
        toml::node_view decompressed_data = input_data["decompressed_section"];
        if (decompressed_data.is_array()) {
            decompressed_sections = get_decompressed_sections(
                decompressed_data.as_array());
        }

        // Decompressed section patterns (optional). One
        // [[input.decompressed_section_pattern]] entry per slot where
        // multiple wrappers share a link vram (e.g. Stadium's
        // 0x8FF00000 dynamic-asset slot). The engine scans the ROM
        // for every wrapper that decompresses to a fragment at the
        // declared vram + format.
        toml::node_view decompressed_pattern_data =
            input_data["decompressed_section_pattern"];
        if (decompressed_pattern_data.is_array()) {
            decompressed_section_patterns = get_decompressed_section_patterns(
                decompressed_pattern_data.as_array());
        }

        // Decompressed section patches (optional). These are applied to
        // decompressed fragment bytes before analysis/hashing to mirror
        // loader fixups that happen before runtime registration.
        toml::node_view decompressed_patch_data =
            input_data["decompressed_section_patch"];
        if (decompressed_patch_data.is_array()) {
            decompressed_section_patches = get_decompressed_section_patches(
                decompressed_patch_data.as_array());
        }

        // Output policies (optional [output] table).
        toml::node_view output_data = config_data["output"];
        if (output_data.is_table()) {
            std::optional<std::string> policy_str =
                output_data["collision_policy"].value<std::string>();
            if (policy_str.has_value()) {
                if (policy_str.value() == "error") {
                    collision_policy = N64Recomp::CollisionPolicy::Error;
                } else if (policy_str.value() == "suffix") {
                    collision_policy = N64Recomp::CollisionPolicy::Suffix;
                } else {
                    throw toml::parse_error(
                        "output.collision_policy must be \"error\" or "
                        "\"suffix\"",
                        output_data.as_table()->source());
                }
            }
        }

        // Output binary path when using an elf file input, includes patching reference symbol MIPS32 relocs (optional)
        std::optional<std::string> output_binary_path_opt = input_data["output_binary_path"].value<std::string>();
        if (output_binary_path_opt.has_value()) {
            output_binary_path = concat_if_not_empty(basedir, output_binary_path_opt.value());
        }
        else {
            output_binary_path = "";
        }

        // Control whether the recompiler warns about unpaired LO16 relocs (optional, defaults to true)
        std::optional<bool> unpaired_lo16_warnings_opt = input_data["unpaired_lo16_warnings"].value<bool>();
        if (unpaired_lo16_warnings_opt.has_value()) {
            unpaired_lo16_warnings = unpaired_lo16_warnings_opt.value();
        }
        else {
            unpaired_lo16_warnings = true;
        }

        std::optional<std::string> recomp_include_opt = input_data["recomp_include"].value<std::string>();
        if (recomp_include_opt.has_value()) {
            recomp_include = recomp_include_opt.value();
        }
        else {
            recomp_include = "#include \"recomp.h\"";
        }

        std::optional<int32_t> funcs_per_file_opt = input_data["functions_per_output_file"].value<int32_t>();
        if (funcs_per_file_opt.has_value()) {
            functions_per_output_file = funcs_per_file_opt.value();
            if (functions_per_output_file <= 0) {
                throw toml::parse_error("Invalid functions_per_output_file value", input_data["functions_per_output_file"].node()->source());
            }
        }
        else {
            functions_per_output_file = 50;
        }

        // Patches section (optional)
        toml::node_view patches_data = config_data["patches"];
        if (patches_data.is_table()) {
            const toml::table* table = patches_data.as_table();

            // Stubs array (optional)
            stubbed_funcs = get_stubbed_funcs(table);

            // Ignored funcs array (optional)
            ignored_funcs = get_ignored_funcs(table);

            // Renamed funcs array (optional)
            renamed_funcs = get_renamed_funcs(table);

            // Single-instruction patches (optional)
            instruction_patches = get_instruction_patches(table);

            // Function hooks (optional)
            function_hooks = get_function_hooks(table);
        }

        // Use trace mode if enabled (optional)
        std::optional<bool> trace_mode_opt = input_data["trace_mode"].value<bool>();
        if (trace_mode_opt.has_value()) {
            trace_mode = trace_mode_opt.value();
            if (trace_mode) {
                recomp_include += "\n#include \"trace.h\"";
            }
        }
        else {
            trace_mode = false;
        }

        // Function reference symbols file (optional)
        std::optional<std::string> func_reference_syms_file_opt = input_data["func_reference_syms_file"].value<std::string>();
        if (func_reference_syms_file_opt.has_value()) {
            if (!symbols_file_path.empty()) {
                throw toml::parse_error("Reference symbol files can only be used in elf input mode", input_data["func_reference_syms_file"].node()->source());
            }
            func_reference_syms_file_path = concat_if_not_empty(basedir, func_reference_syms_file_opt.value());
        }

        // Data reference symbols files (optional)
        toml::node_view data_reference_syms_file_data = input_data["data_reference_syms_files"];
        if (data_reference_syms_file_data.is_array()) {
            if (!symbols_file_path.empty()) {
                throw toml::parse_error("Reference symbol files can only be used in elf input mode", data_reference_syms_file_data.node()->source());
            }
            if (func_reference_syms_file_path.empty()) {
                throw toml::parse_error("Data reference symbol files can only be used if a function reference symbol file is also in use", data_reference_syms_file_data.node()->source());
            }
            const toml::array* array = data_reference_syms_file_data.as_array();
            data_reference_syms_file_paths = get_data_syms_paths(array, basedir);
        }

        // Control whether the recompiler emits exported symbol data.
        std::optional<bool> allow_exports_opt = input_data["allow_exports"].value<bool>();
        if (allow_exports_opt.has_value()) {
            allow_exports = allow_exports_opt.value();
        }
        else {
            allow_exports = false;
        }

        // Enable patch recompilation strict mode, which ensures that patch functions are marked and that other functions are not marked as patches.
        std::optional<bool> strict_patch_mode_opt = input_data["strict_patch_mode"].value<bool>();
        if (strict_patch_mode_opt.has_value()) {
            strict_patch_mode = strict_patch_mode_opt.value();
        }
        else {
            // Default to strict patch mode if a function reference symbol file was provided.
            strict_patch_mode = !func_reference_syms_file_path.empty();
        }
    }
    catch (const toml::parse_error& err) {
        std::cerr << "Syntax error parsing toml: " << *err.source().path << " (" << err.source().begin <<  "):\n" << err.description() << std::endl;
        return;
    }

    // No errors occured, so mark this config file as good.
    bad = false;
}

const std::unordered_map<std::string, N64Recomp::RelocType> reloc_type_name_map {
    { "R_MIPS_NONE", N64Recomp::RelocType::R_MIPS_NONE },
    { "R_MIPS_16", N64Recomp::RelocType::R_MIPS_16 },
    { "R_MIPS_32", N64Recomp::RelocType::R_MIPS_32 },
    { "R_MIPS_REL32", N64Recomp::RelocType::R_MIPS_REL32 },
    { "R_MIPS_26", N64Recomp::RelocType::R_MIPS_26 },
    { "R_MIPS_HI16", N64Recomp::RelocType::R_MIPS_HI16 },
    { "R_MIPS_LO16", N64Recomp::RelocType::R_MIPS_LO16 },
    { "R_MIPS_GPREL16", N64Recomp::RelocType::R_MIPS_GPREL16 },
};

N64Recomp::RelocType reloc_type_from_name(const std::string& reloc_type_name) {
    auto find_it = reloc_type_name_map.find(reloc_type_name);
    if (find_it != reloc_type_name_map.end()) {
        return find_it->second;
    }
    return N64Recomp::RelocType::R_MIPS_NONE;
}

bool N64Recomp::Context::from_symbol_file(const std::filesystem::path& symbol_file_path, std::vector<uint8_t>&& rom, N64Recomp::Context& out, bool with_relocs) {
    N64Recomp::Context ret{};

    try {
        const toml::table config_data = toml::parse_file(symbol_file_path.u8string());
        const toml::node_view config_sections_value = config_data["section"];

        if (!config_sections_value.is_array()) {
            return false;
        }

        const toml::array* config_sections = config_sections_value.as_array();
        ret.section_functions.resize(config_sections->size());
        ret.section_dispatch_aliases.resize(config_sections->size());

        config_sections->for_each([&ret, &rom, with_relocs](auto&& el) {
            if constexpr (toml::is_table<decltype(el)>) {
                std::optional<uint32_t> rom_addr = el["rom"].template value<uint32_t>();
                std::optional<uint32_t> vram_addr = el["vram"].template value<uint32_t>();
                std::optional<uint32_t> size = el["size"].template value<uint32_t>();
                std::optional<std::string> name = el["name"].template value<std::string>();
                std::optional<uint32_t> got_ram_addr = el["got_address"].template value<uint32_t>();

                if (!rom_addr.has_value() || !vram_addr.has_value() || !size.has_value() || !name.has_value()) {
                    throw toml::parse_error("Section entry missing required field(s)", el.source());
                }

                uint16_t section_index = (uint16_t)ret.sections.size();

                Section& section = ret.sections.emplace_back(Section{});
                section.rom_addr = rom_addr.value();
                section.ram_addr = vram_addr.value();
                section.size = size.value();
                section.name = name.value();
                section.got_ram_addr = got_ram_addr;
                section.executable = true;

                // Read functions for the section.
                const toml::node_view cur_functions_value = el["functions"];
                if (!cur_functions_value.is_array()) {
                    throw toml::parse_error("Invalid functions array", cur_functions_value.node()->source());
                }

                const toml::array* cur_functions = cur_functions_value.as_array();
                cur_functions->for_each([&ret, &rom, &section, section_index](auto&& func_el) {
                    size_t function_index = ret.functions.size();

                    if constexpr (toml::is_table<decltype(func_el)>) {
                        std::optional<std::string> name = func_el["name"].template value<std::string>();
                        std::optional<uint32_t> vram_addr = func_el["vram"].template value<uint32_t>();
                        std::optional<uint32_t> func_size_ = func_el["size"].template value<uint32_t>();

                        if (!name.has_value() || !vram_addr.has_value() || !func_size_.has_value()) {
                            throw toml::parse_error("Function symbol entry is missing required field(s)", func_el.source());
                        }

                        uint32_t func_size = func_size_.value();

                        Function cur_func{};
                        cur_func.name = name.value();
                        cur_func.vram = vram_addr.value();
                        cur_func.rom = cur_func.vram - section.ram_addr + section.rom_addr;
                        cur_func.section_index = section_index;

                        if (cur_func.vram & 0b11) {
                            // Function isn't word aligned in vram.
                            throw toml::parse_error("Function's vram address isn't word aligned", func_el.source());
                        }

                        if (cur_func.rom & 0b11) {
                            // Function isn't word aligned in rom.
                            throw toml::parse_error("Function's rom address isn't word aligned", func_el.source());
                        }

                        // Read the function's words if a rom was provided.
                        if (!rom.empty()) {
                            if (cur_func.rom + func_size > rom.size()) {
                                // Function is out of bounds of the provided rom.
                                throw toml::parse_error("Function is out of bounds of the provided rom", func_el.source());
                            }

                            // Get the function's words from the rom.
                            cur_func.words.reserve(func_size / sizeof(uint32_t));
                            for (size_t rom_addr = cur_func.rom; rom_addr < cur_func.rom + func_size; rom_addr += sizeof(uint32_t)) {
                                cur_func.words.push_back(*reinterpret_cast<const uint32_t*>(rom.data() + rom_addr));
                            }
                        }

                        section.function_addrs.push_back(cur_func.vram);
                        ret.functions_by_name[cur_func.name] = function_index;
                        ret.functions_by_vram[cur_func.vram].push_back(function_index);
                        ret.section_functions[section_index].push_back(function_index);

                        ret.functions.emplace_back(std::move(cur_func));
                    }
                    else {
                        throw toml::parse_error("Invalid function symbol entry", func_el.source());
                    }
                });

                // Check if relocs exist for the section and read them if so.
                const toml::node_view relocs_value = el["relocs"];
                if (relocs_value.is_array()) {
                    // Mark the section as relocatable, since it has relocs.
                    section.relocatable = true;

                    if (with_relocs) {
                        // Read relocs for the section.
                        const toml::array* relocs_array = relocs_value.as_array();
                        relocs_array->for_each([&ret, &rom, &section, section_index](auto&& reloc_el) {
                            if constexpr (toml::is_table<decltype(reloc_el)>) {
                                std::optional<uint32_t> vram = reloc_el["vram"].template value<uint32_t>();
                                std::optional<uint32_t> target_vram = reloc_el["target_vram"].template value<uint32_t>();
                                std::optional<std::string> type_string = reloc_el["type"].template value<std::string>();

                                if (!vram.has_value() || !target_vram.has_value() || !type_string.has_value()) {
                                    throw toml::parse_error("Reloc entry missing required field(s)", reloc_el.source());
                                }

                                RelocType reloc_type = reloc_type_from_name(type_string.value());

                                if (reloc_type != RelocType::R_MIPS_HI16 && reloc_type != RelocType::R_MIPS_LO16 && reloc_type != RelocType::R_MIPS_26 && reloc_type != RelocType::R_MIPS_32) {
                                    throw toml::parse_error("Invalid reloc entry type", reloc_el.source());
                                }

                                Reloc cur_reloc{};
                                cur_reloc.address = vram.value();
                                cur_reloc.target_section_offset = target_vram.value() - section.ram_addr;
                                cur_reloc.symbol_index = (uint32_t)-1;
                                cur_reloc.target_section = section_index;
                                cur_reloc.type = reloc_type;

                                section.relocs.emplace_back(cur_reloc);
                            }
                            else {
                                throw toml::parse_error("Invalid reloc entry", reloc_el.source());
                            }
                        });
                    }
                }
                else {
                    section.relocatable = false;
                }
            } else {
                throw toml::parse_error("Invalid section entry", el.source());
            }
        });
    }
    catch (const toml::parse_error& err) {
        std::cerr << "Syntax error parsing toml: " << *err.source().path << " (" << err.source().begin <<  "):\n" << err.description() << std::endl;
        return false;
    }

    repair_truncated_symbol_function_ranges(ret, rom);
    repair_late_symbol_function_starts(ret, rom);
    synthesize_small_symbol_gap_functions(ret, rom);

    ret.rom = std::move(rom);
    out = std::move(ret);
    return true;
}

bool N64Recomp::Context::import_reference_context(const N64Recomp::Context& reference_context) {
    reference_sections.resize(reference_context.sections.size());
    reference_symbols.reserve(reference_context.functions.size());

    // Copy the reference context's sections into the real context's reference sections. 
    for (size_t section_index = 0; section_index < reference_context.sections.size(); section_index++) {
        const N64Recomp::Section& section_in = reference_context.sections[section_index];
        N64Recomp::ReferenceSection& section_out = reference_sections[section_index];

        section_out.rom_addr = section_in.rom_addr;
        section_out.ram_addr = section_in.ram_addr;
        section_out.size = section_in.size;
        section_out.relocatable = section_in.relocatable;
    }

    // Copy the functions from the reference context into the reference context's function map.
    for (const N64Recomp::Function& func_in: reference_context.functions) {
        if (!add_reference_symbol(func_in.name, func_in.section_index, func_in.vram, true)) {
            return false;
        }
    }
    
    return true;
}

// Reads a data symbol file and adds its contents into this context's reference data symbols.
bool N64Recomp::Context::read_data_reference_syms(const std::filesystem::path& data_syms_file_path) {
    try {
        const toml::table data_syms_file_data = toml::parse_file(data_syms_file_path.u8string());
        const toml::node_view data_sections_value = data_syms_file_data["section"];

        if (!data_sections_value.is_array()) {
            return false;
        }

        // Create a mapping of rom address to section to ensure that the same section indexes are used for both function and data reference symbols.
        std::unordered_map<uint32_t, uint16_t> ref_section_indices_by_vrom;

        for (uint16_t section_index = 0; section_index < reference_sections.size(); section_index++) {
            ref_section_indices_by_vrom.emplace(reference_sections[section_index].rom_addr, section_index);
        }
        
        const toml::array* data_sections = data_sections_value.as_array();
        
        data_sections->for_each([this, &ref_section_indices_by_vrom](auto&& el) {
            if constexpr (toml::is_table<decltype(el)>) {
                std::optional<uint64_t> rom_addr = el["rom"].template value<uint64_t>();
                std::optional<uint32_t> vram_addr = el["vram"].template value<uint32_t>();
                std::optional<uint32_t> size = el["size"].template value<uint32_t>();
                std::optional<std::string> name = el["name"].template value<std::string>();

                if (!vram_addr.has_value() || !size.has_value() || !name.has_value()) {
                    throw toml::parse_error("Section entry missing required field(s)", el.source());
                }

                uint16_t ref_section_index;
                if (!rom_addr.has_value()) {
                    ref_section_index = N64Recomp::SectionAbsolute; // Non-relocatable bss section or absolute symbols, mark this as an absolute symbol
                }
                else if (rom_addr.value() > 0xFFFFFFFF) {
                    throw toml::parse_error("Section has invalid ROM address", el.source());
                }
                else {
                    // Find the matching section from the function reference symbol file to ensure 
                    auto find_section_it = ref_section_indices_by_vrom.find(rom_addr.value());
                    if (find_section_it != ref_section_indices_by_vrom.end()) {
                        ref_section_index = find_section_it->second;
                    }
                    else {
                        ref_section_index = N64Recomp::SectionAbsolute; // Not in the function symbol reference file, so this section can be treated as non-relocatable.
                    }
                }

                static ReferenceSection dummy_absolute_section {
                    .rom_addr = 0,
                    .ram_addr = 0,
                    .size = 0,
                    .relocatable = 0
                };
                const ReferenceSection& ref_section = ref_section_index == N64Recomp::SectionAbsolute ? dummy_absolute_section : this->reference_sections[ref_section_index];

                // Sanity check this section against the matching one in the function reference symbol file if one exists.
                if (ref_section_index != N64Recomp::SectionAbsolute) {
                    if (ref_section.ram_addr != vram_addr.value()) {
                        throw toml::parse_error("Section vram address differs from matching ROM address section in the function symbol reference file", el.source());
                    }

                    if (ref_section.size != size.value()) {
                        throw toml::parse_error("Section size address differs from matching ROM address section in the function symbol reference file", el.source());
                    }
                }

                // Read functions for the section.
                const toml::node_view cur_symbols_value = el["symbols"];
                if (!cur_symbols_value.is_array()) {
                    throw toml::parse_error("Invalid symbols array", cur_symbols_value.node()->source());
                }

                uint32_t ref_section_vram = ref_section.ram_addr;
                const toml::array* cur_symbols = cur_symbols_value.as_array();
                cur_symbols->for_each([this, ref_section_index, ref_section_vram](auto&& data_sym_el) {
                    
                    if constexpr (toml::is_table<decltype(data_sym_el)>) {
                        std::optional<std::string> name = data_sym_el["name"].template value<std::string>();
                        std::optional<uint32_t> vram_addr = data_sym_el["vram"].template value<uint32_t>();

                        if (!name.has_value() || !vram_addr.has_value()) {
                            throw toml::parse_error("Reference data symbol entry is missing required field(s)", data_sym_el.source());
                        }

                        if (!this->add_reference_symbol(name.value(), ref_section_index, vram_addr.value(), false)) {
                            throw toml::parse_error("Internal error: Failed to add reference symbol to context. Please report this issue.", data_sym_el.source());
                        }
                    }
                    else {
                        throw toml::parse_error("Invalid data symbol entry", data_sym_el.source());
                    }
                });
            } else {
                throw toml::parse_error("Invalid section entry", el.source());
            }
        });
    }
    catch (const toml::parse_error& err) {
        std::cerr << "Syntax error parsing toml: " << *err.source().path << " (" << err.source().begin <<  "):\n" << err.description() << std::endl;
        return false;
    }

    return true;
}
