#include <cstdio>
#include <cstdlib>
#include <unordered_set>
#include <span>
#include <filesystem>
#include <optional>

#include "rabbitizer.hpp"
#include "fmt/format.h"
#include "fmt/ostream.h"

#include "recompiler/context.h"
#include "config.h"
#include "decompressed.h"
#include "analysis.h"
#include <set>

void add_manual_functions(N64Recomp::Context& context, const std::vector<N64Recomp::ManualFunction>& manual_funcs) {
    auto exit_failure = [](const std::string& error_str) {
        fmt::vprint(stderr, error_str, fmt::make_format_args());
        std::exit(EXIT_FAILURE);
    };

    // Build a lookup from section name to section index.
    std::unordered_map<std::string, size_t> section_indices_by_name{};
    section_indices_by_name.reserve(context.sections.size());

    for (size_t i = 0; i < context.sections.size(); i++) {
        section_indices_by_name.emplace(context.sections[i].name, i);
    }

    for (const N64Recomp::ManualFunction& cur_func_def : manual_funcs) {
        const auto section_find_it = section_indices_by_name.find(cur_func_def.section_name);
        if (section_find_it == section_indices_by_name.end()) {
            exit_failure(fmt::format("Manual function {} specified with section {}, which doesn't exist!\n", cur_func_def.func_name, cur_func_def.section_name));
        }
        size_t section_index = section_find_it->second;

        const auto func_find_it = context.functions_by_name.find(cur_func_def.func_name);
        if (func_find_it != context.functions_by_name.end()) {
            exit_failure(fmt::format("Manual function {} already exists!\n", cur_func_def.func_name));
        }

        if ((cur_func_def.size & 0b11) != 0) {
            exit_failure(fmt::format("Manual function {} has a size that isn't divisible by 4!\n", cur_func_def.func_name));
        }

        auto& section = context.sections[section_index];
        uint32_t section_offset = cur_func_def.vram - section.ram_addr;
        uint32_t rom_address = section_offset + section.rom_addr;

        std::vector<uint32_t> words;
        words.resize(cur_func_def.size / 4);
        const uint32_t* elf_words = reinterpret_cast<const uint32_t*>(context.rom.data() + context.sections[section_index].rom_addr + section_offset);

        words.assign(elf_words, elf_words + words.size());

        size_t function_index = context.functions.size();
        context.functions.emplace_back(
            cur_func_def.vram,
            rom_address,
            std::move(words),
            cur_func_def.func_name,
            uint16_t(section_index),
            false,
            false,
            false
        );

        context.section_functions[section_index].push_back(function_index);
        section.function_addrs.push_back(function_index);
        context.functions_by_vram[cur_func_def.vram].push_back(function_index);
        context.functions_by_name[cur_func_def.func_name] = function_index;
    }
}

bool read_list_file(const std::filesystem::path& filename, std::vector<std::string>& entries_out) {
    std::ifstream input_file{ filename };
    if (!input_file.good()) {
        return false;
    }

    std::string entry;

    while (input_file >> entry) {
        entries_out.emplace_back(std::move(entry));
    }

    return true;
}

bool compare_files(const std::filesystem::path& file1_path, const std::filesystem::path& file2_path) {
    static std::vector<char> file1_buf(65536);
    static std::vector<char> file2_buf(65536);

    std::ifstream file1(file1_path, std::ifstream::ate | std::ifstream::binary); //open file at the end
    std::ifstream file2(file2_path, std::ifstream::ate | std::ifstream::binary); //open file at the end
    const std::ifstream::pos_type fileSize = file1.tellg();

    file1.rdbuf()->pubsetbuf(file1_buf.data(), file1_buf.size());
    file2.rdbuf()->pubsetbuf(file2_buf.data(), file2_buf.size());

    if (fileSize != file2.tellg()) {
        return false; //different file size
    }

    file1.seekg(0); //rewind
    file2.seekg(0); //rewind

    std::istreambuf_iterator<char> begin1(file1);
    std::istreambuf_iterator<char> begin2(file2);

    return std::equal(begin1, std::istreambuf_iterator<char>(), begin2); //Second argument is end-of-range iterator
}

size_t find_exact_function_in_section(const N64Recomp::Context& context, uint32_t vram, size_t section_index) {
    auto find_it = context.functions_by_vram.find(vram);
    if (find_it == context.functions_by_vram.end()) {
        return (size_t)-1;
    }

    for (size_t func_index : find_it->second) {
        const auto& func = context.functions[func_index];
        if (func.section_index == section_index &&
            (!func.words.empty() || func.reimplemented || N64Recomp::is_manual_patch_symbol(func.vram))) {
            return func_index;
        }
    }

    return (size_t)-1;
}

size_t find_containing_function_in_section(const N64Recomp::Context& context, uint32_t vram, size_t section_index) {
    if (section_index >= context.section_functions.size()) {
        return (size_t)-1;
    }

    for (size_t func_index : context.section_functions[section_index]) {
        const auto& func = context.functions[func_index];
        if (func.words.empty()) {
            continue;
        }

        uint32_t func_start = func.vram;
        uint32_t func_end = func_start + uint32_t(func.words.size() * sizeof(func.words[0]));
        if (vram > func_start && vram < func_end) {
            return func_index;
        }
    }

    return (size_t)-1;
}

size_t find_unique_executable_section_containing_vram(const N64Recomp::Context& context, uint32_t vram) {
    size_t containing_section = (size_t)-1;

    for (size_t section_index = 0; section_index < context.sections.size(); section_index++) {
        const auto& section = context.sections[section_index];
        if (!section.executable) {
            continue;
        }

        uint32_t section_start = section.ram_addr;
        uint32_t section_end = section_start + section.size;
        if (vram >= section_start && vram < section_end) {
            if (containing_section != (size_t)-1) {
                return (size_t)-1;
            }
            containing_section = section_index;
        }
    }

    return containing_section;
}

uint32_t infer_section_encoded_vram_base(const N64Recomp::Context& context, size_t section_index) {
    if (section_index >= context.sections.size() || section_index >= context.section_functions.size()) {
        return 0;
    }

    const auto& section = context.sections[section_index];
    uint32_t encoded_base = section.ram_addr;
    bool found_base = false;

    for (size_t func_index : context.section_functions[section_index]) {
        const auto& func = context.functions[func_index];
        if (func.words.empty() && !func.reimplemented) {
            continue;
        }
        uint64_t section_rom_start = section.rom_addr;
        uint64_t section_rom_end = section_rom_start + section.size;
        if (func.rom < section_rom_start || func.rom >= section_rom_end) {
            continue;
        }

        uint32_t candidate_base = func.vram - (func.rom - section.rom_addr);
        if (!found_base) {
            encoded_base = candidate_base;
            found_base = true;
        }
        else if (encoded_base != candidate_base) {
            return section.ram_addr;
        }
    }

    return encoded_base;
}

uint32_t reloc_offset_in_section(const N64Recomp::Context& context, size_t section_index, uint32_t reloc_address) {
    const auto& section = context.sections[section_index];
    uint32_t encoded_base = infer_section_encoded_vram_base(context, section_index);

    uint64_t encoded_start = encoded_base;
    uint64_t encoded_end = encoded_start + section.size;
    if (reloc_address >= encoded_start && reloc_address < encoded_end) {
        return reloc_address - encoded_base;
    }

    return reloc_address - section.ram_addr;
}

bool instruction_writes_zero_gpr(const rabbitizer::InstructionCpu& instr, uint32_t insn_word) {
    if (insn_word == 0) {
        return false;
    }

    using InstrId = rabbitizer::InstrId::UniqueId;
    const auto id = instr.getUniqueId();
    switch (id) {
        case InstrId::cpu_add:
        case InstrId::cpu_addu:
        case InstrId::cpu_sub:
        case InstrId::cpu_subu:
        case InstrId::cpu_dadd:
        case InstrId::cpu_daddu:
        case InstrId::cpu_dsub:
        case InstrId::cpu_dsubu:
        case InstrId::cpu_and:
        case InstrId::cpu_or:
        case InstrId::cpu_xor:
        case InstrId::cpu_nor:
        case InstrId::cpu_sll:
        case InstrId::cpu_sllv:
        case InstrId::cpu_srl:
        case InstrId::cpu_srlv:
        case InstrId::cpu_sra:
        case InstrId::cpu_srav:
        case InstrId::cpu_dsll:
        case InstrId::cpu_dsllv:
        case InstrId::cpu_dsll32:
        case InstrId::cpu_dsrl:
        case InstrId::cpu_dsrlv:
        case InstrId::cpu_dsrl32:
        case InstrId::cpu_dsra:
        case InstrId::cpu_dsrav:
        case InstrId::cpu_dsra32:
        case InstrId::cpu_slt:
        case InstrId::cpu_sltu:
        case InstrId::cpu_mfhi:
        case InstrId::cpu_mflo:
            return int(instr.GetO32_rd()) == 0;

        case InstrId::cpu_addi:
        case InstrId::cpu_addiu:
        case InstrId::cpu_daddi:
        case InstrId::cpu_daddiu:
        case InstrId::cpu_andi:
        case InstrId::cpu_ori:
        case InstrId::cpu_xori:
        case InstrId::cpu_slti:
        case InstrId::cpu_sltiu:
        case InstrId::cpu_lui:
        case InstrId::cpu_lb:
        case InstrId::cpu_lbu:
        case InstrId::cpu_lh:
        case InstrId::cpu_lhu:
        case InstrId::cpu_lw:
        case InstrId::cpu_lwu:
        case InstrId::cpu_ld:
        case InstrId::cpu_lwl:
        case InstrId::cpu_lwr:
        case InstrId::cpu_ldl:
        case InstrId::cpu_ldr:
        case InstrId::cpu_mfc1:
        case InstrId::cpu_dmfc1:
            return int(instr.GetO32_rt()) == 0;

        default:
            return false;
    }
}

bool discovered_entrypoint_looks_like_code(
    const N64Recomp::Context& context,
    size_t section_index,
    uint32_t target_vram,
    size_t discovered_size) {
    const auto& section = context.sections[section_index];
    const uint32_t entry_offset = target_vram - section.ram_addr;
    const uint8_t* body = context.rom.data() + section.rom_addr;

    for (size_t offset = entry_offset; offset < entry_offset + discovered_size; offset += sizeof(uint32_t)) {
        uint32_t insn_word = byteswap(*reinterpret_cast<const uint32_t*>(body + offset));
        rabbitizer::InstructionCpu instr(insn_word, section.ram_addr + uint32_t(offset));
        if (!instr.isValid() || (insn_word != 0 && instruction_writes_zero_gpr(instr, insn_word))) {
            return false;
        }
    }

    return true;
}

bool discover_static_code_entrypoint(
    const N64Recomp::Context& context,
    size_t section_index,
    uint32_t target_vram,
    size_t* size_out = nullptr) {
    if (section_index >= context.sections.size()) {
        return false;
    }

    const auto& section = context.sections[section_index];
    if (!section.executable || (target_vram & 3u) != 0) {
        return false;
    }

    const uint32_t section_start = section.ram_addr;
    const uint32_t section_end = section_start + section.size;
    if (target_vram < section_start || target_vram >= section_end) {
        return false;
    }

    if (section.rom_addr >= 0xF0000000u ||
        uint64_t(section.rom_addr) + uint64_t(section.size) > context.rom.size()) {
        return false;
    }

    size_t discovered_size = 0;
    std::string discover_error;
    if (!N64Recomp::discover_function_bounds(
            context.rom.data() + section.rom_addr,
            section.size,
            section.ram_addr,
            target_vram - section.ram_addr,
            discovered_size,
            discover_error)) {
        return false;
    }

    if (size_out != nullptr) {
        *size_out = discovered_size;
    }
    return discovered_size != 0 &&
        discovered_entrypoint_looks_like_code(context, section_index, target_vram, discovered_size);
}

bool is_resident_text_section(const N64Recomp::Section& section) {
    return section.name == ".text";
}

void seed_static_entrypoints_from_code_relocs(
    const N64Recomp::Context& context,
    std::vector<std::vector<uint32_t>>& static_funcs_by_section) {
    size_t seeded_count = 0;
    std::set<std::pair<size_t, uint32_t>> seeded_entries;
    constexpr size_t max_reloc_static_entry_size = 0x400;

    for (size_t section_index = 0; section_index < static_funcs_by_section.size(); section_index++) {
        for (uint32_t static_func : static_funcs_by_section[section_index]) {
            seeded_entries.emplace(section_index, static_func);
        }
    }

    auto entry_is_seeded = [&](size_t section_index, uint32_t vram) {
        return seeded_entries.contains({ section_index, vram });
    };

    auto entry_falls_through_to_seeded_static = [&](size_t section_index, uint32_t vram) {
        if (section_index >= context.sections.size()) {
            return false;
        }

        const auto& section = context.sections[section_index];
        if (!section.executable ||
            section.rom_addr >= 0xF0000000u ||
            uint64_t(section.rom_addr) + uint64_t(section.size) > context.rom.size() ||
            vram < section.ram_addr ||
            vram + 8 > section.ram_addr + section.size) {
            return false;
        }

        const uint32_t instr_word = byteswap(*reinterpret_cast<const uint32_t*>(
            context.rom.data() + section.rom_addr + (vram - section.ram_addr)));
        rabbitizer::InstructionCpu instr(instr_word, vram);
        return instr.isValid() &&
            entry_is_seeded(section_index, vram + 8);
    };

    for (size_t source_section_index = 0; source_section_index < context.sections.size(); source_section_index++) {
        const auto& source_section = context.sections[source_section_index];
        if (!source_section.relocatable) {
            continue;
        }

        for (const auto& reloc : source_section.relocs) {
            if (reloc.type != N64Recomp::RelocType::R_MIPS_HI16 &&
                reloc.type != N64Recomp::RelocType::R_MIPS_LO16 &&
                reloc.type != N64Recomp::RelocType::R_MIPS_32) {
                continue;
            }

            bool source_is_small_code_label = false;
            if (source_section.executable &&
                find_exact_function_in_section(context, reloc.address, source_section_index) == (size_t)-1 &&
                find_containing_function_in_section(context, reloc.address, source_section_index) == (size_t)-1 &&
                !entry_is_seeded(source_section_index, reloc.address)) {
                size_t discovered_source_size = 0;
                if (!discover_static_code_entrypoint(context, source_section_index, reloc.address, &discovered_source_size) ||
                    discovered_source_size > max_reloc_static_entry_size) {
                    continue;
                }
                source_is_small_code_label = true;
            }

            uint32_t target_vram = reloc.target_section_offset;
            size_t target_section_index = (size_t)-1;
            bool absolute_target = reloc.target_section == N64Recomp::SectionAbsolute;

            if (!reloc.reference_symbol && reloc.target_section < context.sections.size()) {
                target_section_index = reloc.target_section;
                target_vram = context.sections[target_section_index].ram_addr + reloc.target_section_offset;
            }
            else if (absolute_target) {
                target_section_index = find_unique_executable_section_containing_vram(context, target_vram);
            }

            if (target_section_index == (size_t)-1 || target_section_index >= context.sections.size()) {
                continue;
            }

            const auto& target_section = context.sections[target_section_index];
            if (!target_section.executable ||
                !target_section.relocatable ||
                is_resident_text_section(target_section) ||
                (target_vram & 3u) != 0) {
                continue;
            }

            uint32_t section_start = target_section.ram_addr;
            uint32_t section_end = section_start + target_section.size;
            if (target_vram < section_start || target_vram >= section_end) {
                continue;
            }

            if (find_exact_function_in_section(context, target_vram, target_section_index) != (size_t)-1) {
                continue;
            }

            size_t containing_func_index = find_containing_function_in_section(context, target_vram, target_section_index);
            if (containing_func_index != (size_t)-1) {
                const auto& containing_func = context.functions[containing_func_index];
                const size_t word_index = (target_vram - containing_func.vram) / sizeof(uint32_t);
                const uint32_t insn_word = byteswap(containing_func.words[word_index]);
                rabbitizer::InstructionCpu instr(insn_word, target_vram);
                if (!instr.isValid() || (insn_word != 0 && instruction_writes_zero_gpr(instr, insn_word))) {
                    continue;
                }
            }
            else {
                if (!absolute_target) {
                    continue;
                }
                bool falls_through_to_seeded_static =
                    entry_falls_through_to_seeded_static(target_section_index, target_vram);
                size_t discovered_size = 0;
                if (!discover_static_code_entrypoint(context, target_section_index, target_vram, &discovered_size) &&
                    !falls_through_to_seeded_static) {
                    continue;
                }
                if (discovered_size > max_reloc_static_entry_size &&
                    !falls_through_to_seeded_static &&
                    !source_is_small_code_label) {
                    continue;
                }
            }

            if (!seeded_entries.emplace(target_section_index, target_vram).second) {
                continue;
            }
            static_funcs_by_section[target_section_index].push_back(target_vram);
            seeded_count++;
        }
    }

    if (seeded_count != 0) {
        fmt::print(
            "[Info] Seeded {} static code-label entr{} from relocation targets\n",
            seeded_count,
            seeded_count == 1 ? "y" : "ies");
    }
}

bool static_entrypoint_inside_function_looks_valid(
    const N64Recomp::Function& func,
    uint32_t target_vram);

void seed_static_entrypoints_from_pointer_tables(
    const N64Recomp::Context& context,
    std::vector<std::vector<uint32_t>>& static_funcs_by_section) {
    size_t seeded_count = 0;
    std::set<std::pair<size_t, uint32_t>> seeded_entries;
    constexpr size_t max_pointer_static_entry_size = 0x400;

    for (size_t section_index = 0; section_index < static_funcs_by_section.size(); section_index++) {
        for (uint32_t static_func : static_funcs_by_section[section_index]) {
            seeded_entries.emplace(section_index, static_func);
        }
    }

    struct ExecutableRange {
        uint32_t start;
        uint32_t end;
        size_t section_index;
    };
    std::vector<ExecutableRange> executable_ranges;
    executable_ranges.reserve(context.sections.size());
    for (size_t section_index = 0; section_index < context.sections.size(); section_index++) {
        const auto& section = context.sections[section_index];
        if (!section.executable ||
            !section.relocatable ||
            is_resident_text_section(section)) {
            continue;
        }

        executable_ranges.push_back({
            section.ram_addr,
            section.ram_addr + section.size,
            section_index
        });
    }
    std::sort(
        executable_ranges.begin(),
        executable_ranges.end(),
        [](const ExecutableRange& lhs, const ExecutableRange& rhs) {
            if (lhs.start != rhs.start) {
                return lhs.start < rhs.start;
            }
            return lhs.end < rhs.end;
        });

    auto find_indexed_executable_sections = [&](uint32_t target_vram) {
        std::vector<size_t> matches;
        auto it = std::upper_bound(
            executable_ranges.begin(),
            executable_ranges.end(),
            target_vram,
            [](uint32_t value, const ExecutableRange& range) {
                return value < range.start;
            });

        while (it != executable_ranges.begin()) {
            --it;
            if (target_vram - it->start > 0x400000u) {
                break;
            }
            if (target_vram >= it->start && target_vram < it->end) {
                matches.push_back(it->section_index);
            }
        }
        return matches;
    };

    auto word_points_to_section = [&](size_t offset, size_t section_index) {
        if (offset + sizeof(uint32_t) > context.rom.size()) {
            return false;
        }

        const uint32_t target_vram =
            byteswap(*reinterpret_cast<const uint32_t*>(context.rom.data() + offset));
        for (size_t match : find_indexed_executable_sections(target_vram)) {
            if (match == section_index) {
                return true;
            }
        }

        return false;
    };

    auto word_is_in_raw_code_pointer_table = [&](size_t offset, size_t section_index) {
        const size_t strides[] = {
            sizeof(uint32_t),
            sizeof(uint32_t) * 2,
            sizeof(uint32_t) * 4,
            sizeof(uint32_t) * 8
        };

        for (size_t stride : strides) {
            const bool prev_1 =
                offset >= stride &&
                word_points_to_section(offset - stride, section_index);
            const bool prev_2 =
                offset >= stride * 2 &&
                word_points_to_section(offset - stride * 2, section_index);
            const bool next_1 =
                offset + stride + sizeof(uint32_t) <= context.rom.size() &&
                word_points_to_section(offset + stride, section_index);
            const bool next_2 =
                offset + stride * 2 + sizeof(uint32_t) <= context.rom.size() &&
                word_points_to_section(offset + stride * 2, section_index);

            if ((prev_1 && next_1) || (prev_1 && prev_2) || (next_1 && next_2)) {
                return true;
            }
        }

        return false;
    };

    auto seed_target = [&](size_t target_section_index, uint32_t target_vram, bool raw_table_entry) {
        if (target_section_index == (size_t)-1 || target_section_index >= context.sections.size()) {
            return;
        }

        const auto& target_section = context.sections[target_section_index];
        if (!target_section.executable ||
            !target_section.relocatable ||
            is_resident_text_section(target_section) ||
            (target_vram & 3u) != 0 ||
            target_vram < target_section.ram_addr ||
            target_vram >= target_section.ram_addr + target_section.size) {
            return;
        }

        if (find_exact_function_in_section(context, target_vram, target_section_index) != (size_t)-1) {
            return;
        }

        auto is_non_return_indirect_jump_at = [&](uint32_t instr_vram) {
            if (instr_vram < target_section.ram_addr ||
                instr_vram + sizeof(uint32_t) > target_section.ram_addr + target_section.size) {
                return false;
            }

            const uint32_t instr_word = byteswap(*reinterpret_cast<const uint32_t*>(
                context.rom.data() + target_section.rom_addr + (instr_vram - target_section.ram_addr)));
            rabbitizer::InstructionCpu instr(instr_word, instr_vram);
            return instr.isValid() &&
                instr.getUniqueId() == rabbitizer::InstrId::UniqueId::cpu_jr &&
                int(instr.GetO32_rs()) != (int)rabbitizer::Registers::Cpu::GprO32::GPR_O32_ra;
        };

        auto discovered_entry_ends_with_non_return_indirect_jump =
            [&](uint32_t entry_vram, size_t discovered_size) {
                if (discovered_size < sizeof(uint32_t) * 2) {
                    return false;
                }

                return is_non_return_indirect_jump_at(
                    entry_vram + uint32_t(discovered_size - sizeof(uint32_t) * 2));
            };

        auto direct_unconditional_jump_target_at = [&](uint32_t instr_vram, uint32_t* branch_target_out = nullptr) {
            if (instr_vram < target_section.ram_addr ||
                instr_vram + sizeof(uint32_t) > target_section.ram_addr + target_section.size) {
                return false;
            }

            const uint32_t instr_word = byteswap(*reinterpret_cast<const uint32_t*>(
                context.rom.data() + target_section.rom_addr + (instr_vram - target_section.ram_addr)));
            rabbitizer::InstructionCpu instr(instr_word, instr_vram);
            if (!instr.isValid()) {
                return false;
            }

            using InstrId = rabbitizer::InstrId::UniqueId;
            const auto id = instr.getUniqueId();
            const bool is_direct_jump = id == InstrId::cpu_j ||
                id == InstrId::cpu_b ||
                (id == InstrId::cpu_beq &&
                 int(instr.GetO32_rs()) == 0 &&
                 int(instr.GetO32_rt()) == 0);
            if (!is_direct_jump) {
                return false;
            }

            if (branch_target_out != nullptr) {
                *branch_target_out = uint32_t(instr.getBranchVramGeneric());
            }
            return true;
        };

        auto direct_unconditional_jump_targets_same_section = [&](uint32_t instr_vram) {
            uint32_t branch_target = 0;
            if (!direct_unconditional_jump_target_at(instr_vram, &branch_target)) {
                return false;
            }

            return branch_target >= target_section.ram_addr &&
                branch_target < target_section.ram_addr + target_section.size;
        };

        auto discovered_entry_ends_with_backward_direct_unconditional_jump =
            [&](uint32_t entry_vram, size_t discovered_size) {
                if (discovered_size < sizeof(uint32_t) * 2) {
                    return false;
                }

                uint32_t branch_target = 0;
                if (!direct_unconditional_jump_target_at(
                        entry_vram + uint32_t(discovered_size - sizeof(uint32_t) * 2),
                        &branch_target)) {
                    return false;
                }

                return branch_target >= target_section.ram_addr &&
                    branch_target < target_section.ram_addr + target_section.size &&
                    branch_target < entry_vram;
            };

        auto discovered_entry_contains_direct_call =
            [&](uint32_t entry_vram, size_t discovered_size) {
                using InstrId = rabbitizer::InstrId::UniqueId;
                for (size_t offset = 0; offset < discovered_size; offset += sizeof(uint32_t)) {
                    const uint32_t instr_vram = entry_vram + uint32_t(offset);
                    if (instr_vram < target_section.ram_addr ||
                        instr_vram + sizeof(uint32_t) > target_section.ram_addr + target_section.size) {
                        return true;
                    }

                    const uint32_t instr_word = byteswap(*reinterpret_cast<const uint32_t*>(
                        context.rom.data() + target_section.rom_addr + (instr_vram - target_section.ram_addr)));
                    rabbitizer::InstructionCpu instr(instr_word, instr_vram);
                    if (!instr.isValid()) {
                        return true;
                    }

                    const auto id = instr.getUniqueId();
                    if (id == InstrId::cpu_jal || id == InstrId::cpu_jalr) {
                        return true;
                    }
                }

                return false;
            };

        auto is_conditional_branch_at = [&](uint32_t instr_vram) {
            if (instr_vram < target_section.ram_addr ||
                instr_vram + sizeof(uint32_t) > target_section.ram_addr + target_section.size) {
                return false;
            }

            const uint32_t instr_word = byteswap(*reinterpret_cast<const uint32_t*>(
                context.rom.data() + target_section.rom_addr + (instr_vram - target_section.ram_addr)));
            rabbitizer::InstructionCpu instr(instr_word, instr_vram);
            if (!instr.isValid()) {
                return false;
            }

            using InstrId = rabbitizer::InstrId::UniqueId;
            switch (instr.getUniqueId()) {
                case InstrId::cpu_beq:
                case InstrId::cpu_beql:
                case InstrId::cpu_bne:
                case InstrId::cpu_bnel:
                case InstrId::cpu_bgez:
                case InstrId::cpu_bgezl:
                case InstrId::cpu_bgtz:
                case InstrId::cpu_bgtzl:
                case InstrId::cpu_blez:
                case InstrId::cpu_blezl:
                case InstrId::cpu_bltz:
                case InstrId::cpu_bltzl:
                case InstrId::cpu_bgezal:
                case InstrId::cpu_bgezall:
                case InstrId::cpu_bltzal:
                case InstrId::cpu_bltzall:
                case InstrId::cpu_bc1f:
                case InstrId::cpu_bc1fl:
                case InstrId::cpu_bc1t:
                case InstrId::cpu_bc1tl:
                    return true;
                default:
                    return false;
            }
        };

        auto discovered_entry_ends_after_conditional_branch_delay =
            [&](uint32_t entry_vram, size_t discovered_size) {
                if (discovered_size < sizeof(uint32_t) * 2) {
                    return false;
                }

                return is_conditional_branch_at(
                    entry_vram + uint32_t(discovered_size - sizeof(uint32_t) * 2));
            };

        auto follows_unconditional_control_transfer = [&](const N64Recomp::Function& func) {
            using InstrId = rabbitizer::InstrId::UniqueId;
            if (target_vram < func.vram + sizeof(uint32_t) * 2) {
                return false;
            }

            const size_t word_index = (target_vram - func.vram) / sizeof(uint32_t);
            if (word_index < 2 || word_index > func.words.size()) {
                return false;
            }

            const uint32_t branch_vram = target_vram - sizeof(uint32_t) * 2;
            const uint32_t branch_word = byteswap(func.words[word_index - 2]);
            rabbitizer::InstructionCpu branch_instr(branch_word, branch_vram);
            if (!branch_instr.isValid()) {
                return false;
            }

            const auto id = branch_instr.getUniqueId();
            return id == InstrId::cpu_j ||
                id == InstrId::cpu_b ||
                (id == InstrId::cpu_beq &&
                 int(branch_instr.GetO32_rs()) == 0 &&
                 int(branch_instr.GetO32_rt()) == 0);
        };

        bool target_looks_valid = false;
        size_t containing_func_index = find_containing_function_in_section(
            context, target_vram, target_section_index);
        if (containing_func_index != (size_t)-1) {
            const auto& containing_func = context.functions[containing_func_index];
            target_looks_valid =
                static_entrypoint_inside_function_looks_valid(containing_func, target_vram) &&
                ((raw_table_entry &&
                  (follows_unconditional_control_transfer(containing_func) ||
                   is_non_return_indirect_jump_at(target_vram) ||
                   direct_unconditional_jump_targets_same_section(target_vram))) ||
                 is_non_return_indirect_jump_at(target_vram + 4) ||
                 is_non_return_indirect_jump_at(target_vram + 8));
        }
        else {
            size_t discovered_size = 0;
            bool discovered_entry = discover_static_code_entrypoint(
                context, target_section_index, target_vram, &discovered_size);
            target_looks_valid =
                discovered_entry &&
                discovered_size <= max_pointer_static_entry_size &&
                ((raw_table_entry && is_non_return_indirect_jump_at(target_vram)) ||
                 is_non_return_indirect_jump_at(target_vram + 4) ||
                 is_non_return_indirect_jump_at(target_vram + 8) ||
                 (raw_table_entry &&
                  discovered_size <= sizeof(uint32_t) * 8 &&
                  !discovered_entry_contains_direct_call(target_vram, discovered_size) &&
                  discovered_entry_ends_with_backward_direct_unconditional_jump(target_vram, discovered_size)) ||
                 (raw_table_entry &&
                  discovered_entry_ends_with_non_return_indirect_jump(target_vram, discovered_size)) ||
                 (raw_table_entry &&
                  discovered_entry_ends_after_conditional_branch_delay(target_vram, discovered_size)));
        }

        if (!target_looks_valid) {
            return;
        }

        if (!seeded_entries.emplace(target_section_index, target_vram).second) {
            return;
        }

        static_funcs_by_section[target_section_index].push_back(target_vram);
        seeded_count++;
    };

    for (size_t offset = 0; offset + sizeof(uint32_t) <= context.rom.size(); offset += sizeof(uint32_t)) {
        const uint32_t target_vram =
            byteswap(*reinterpret_cast<const uint32_t*>(context.rom.data() + offset));
        for (size_t target_section_index : find_indexed_executable_sections(target_vram)) {
            seed_target(
                target_section_index,
                target_vram,
                word_is_in_raw_code_pointer_table(offset, target_section_index));
        }
    }

    if (seeded_count != 0) {
        fmt::print(
            "[Info] Seeded {} static code-label entr{} from raw code-pointer tables\n",
            seeded_count,
            seeded_count == 1 ? "y" : "ies");
    }
}

bool function_contains_indirect_dispatch(const N64Recomp::Function& func) {
    using InstrId = rabbitizer::InstrId::UniqueId;
    constexpr int ra_reg = (int)rabbitizer::Registers::Cpu::GprO32::GPR_O32_ra;

    uint32_t vram = func.vram;
    for (uint32_t word : func.words) {
        uint32_t insn_word = byteswap(word);
        rabbitizer::InstructionCpu instr(insn_word, vram);
        if (!instr.isValid()) {
            vram += sizeof(uint32_t);
            continue;
        }

        const auto id = instr.getUniqueId();
        if (id == InstrId::cpu_jr && int(instr.GetO32_rs()) != ra_reg) {
            return true;
        }

        vram += sizeof(uint32_t);
    }

    return false;
}

bool is_unconditional_branch_or_jump(const rabbitizer::InstructionCpu& instr) {
    using InstrId = rabbitizer::InstrId::UniqueId;
    const auto id = instr.getUniqueId();
    if (id == InstrId::cpu_j || id == InstrId::cpu_b) {
        return true;
    }

    if (id == InstrId::cpu_beq &&
        int(instr.GetO32_rs()) == 0 &&
        int(instr.GetO32_rt()) == 0) {
        return true;
    }

    return false;
}

bool is_conditional_branch(const rabbitizer::InstructionCpu& instr) {
    using InstrId = rabbitizer::InstrId::UniqueId;
    switch (instr.getUniqueId()) {
        case InstrId::cpu_beq:
        case InstrId::cpu_beql:
        case InstrId::cpu_bne:
        case InstrId::cpu_bnel:
        case InstrId::cpu_bgez:
        case InstrId::cpu_bgezl:
        case InstrId::cpu_bgtz:
        case InstrId::cpu_bgtzl:
        case InstrId::cpu_blez:
        case InstrId::cpu_blezl:
        case InstrId::cpu_bltz:
        case InstrId::cpu_bltzl:
        case InstrId::cpu_bgezal:
        case InstrId::cpu_bgezall:
        case InstrId::cpu_bltzal:
        case InstrId::cpu_bltzall:
        case InstrId::cpu_bc1f:
        case InstrId::cpu_bc1fl:
        case InstrId::cpu_bc1t:
        case InstrId::cpu_bc1tl:
            return true;
        default:
            return false;
    }
}

bool static_entrypoint_inside_function_looks_valid(
    const N64Recomp::Function& func,
    uint32_t target_vram) {
    const uint32_t func_end = func.vram + uint32_t(func.words.size() * sizeof(func.words[0]));
    if (target_vram <= func.vram || target_vram >= func_end || (target_vram & 3u) != 0) {
        return false;
    }

    size_t word_index = (target_vram - func.vram) / sizeof(uint32_t);
    uint32_t insn_word = byteswap(func.words[word_index]);
    rabbitizer::InstructionCpu instr(insn_word, target_vram);
    return instr.isValid() && (insn_word == 0 || !instruction_writes_zero_gpr(instr, insn_word));
}

void seed_static_branch_continuations_from_indirect_dispatch_entries(
    const N64Recomp::Context& context,
    std::vector<std::vector<uint32_t>>& static_funcs_by_section) {
    using InstrId = rabbitizer::InstrId::UniqueId;
    constexpr int ra_reg = (int)rabbitizer::Registers::Cpu::GprO32::GPR_O32_ra;
    constexpr size_t max_dispatch_function_size = 0x2000;
    constexpr size_t max_static_dispatch_scan_size = 0x800;
    size_t seeded_count = 0;

    for (size_t section_index = 0; section_index < context.sections.size(); section_index++) {
        const auto& section = context.sections[section_index];
        if (!section.executable ||
            !section.relocatable ||
            is_resident_text_section(section) ||
            section.rom_addr >= 0xF0000000u ||
            uint64_t(section.rom_addr) + uint64_t(section.size) > context.rom.size()) {
            continue;
        }

        std::set<uint32_t> seeded_entries{
            static_funcs_by_section[section_index].begin(),
            static_funcs_by_section[section_index].end()
        };

        std::vector<uint32_t> entry_snapshot{
            static_funcs_by_section[section_index].begin(),
            static_funcs_by_section[section_index].end()
        };
        std::sort(entry_snapshot.begin(), entry_snapshot.end());
        entry_snapshot.erase(
            std::unique(entry_snapshot.begin(), entry_snapshot.end()),
            entry_snapshot.end());
        std::set<size_t> processed_functions;

        auto add_entry = [&](const N64Recomp::Function& func, uint32_t target_vram) {
            if (!static_entrypoint_inside_function_looks_valid(func, target_vram)) {
                return;
            }

            if (find_exact_function_in_section(context, target_vram, section_index) != (size_t)-1) {
                return;
            }

            if (!seeded_entries.emplace(target_vram).second) {
                return;
            }

            static_funcs_by_section[section_index].push_back(target_vram);
            seeded_count++;
        };

        for (uint32_t entry_vram : entry_snapshot) {
            if ((entry_vram & 3u) != 0 ||
                find_exact_function_in_section(context, entry_vram, section_index) != (size_t)-1) {
                continue;
            }

            const size_t containing_func_index = find_containing_function_in_section(
                context, entry_vram, section_index);
            if (containing_func_index == (size_t)-1) {
                continue;
            }

            const auto& func = context.functions[containing_func_index];
            const size_t func_size = func.words.size() * sizeof(func.words[0]);
            if (func.words.empty() ||
                func.ignored ||
                func.reimplemented ||
                func_size > max_dispatch_function_size ||
                entry_vram < func.vram ||
                entry_vram >= func.vram + func_size) {
                continue;
            }

            if (!processed_functions.emplace(containing_func_index).second) {
                continue;
            }

            const uint32_t scan_start = func.vram;
            const uint32_t scan_end = std::min<uint32_t>(
                func.vram + uint32_t(func_size),
                func.vram + uint32_t(max_static_dispatch_scan_size));
            if (scan_end <= scan_start + sizeof(uint32_t)) {
                continue;
            }

            size_t start_word_index = (scan_start - func.vram) / sizeof(func.words[0]);
            size_t end_word_index = (scan_end - func.vram) / sizeof(func.words[0]);
            for (size_t word_index = start_word_index; word_index < end_word_index; word_index++) {
                uint32_t instr_vram = func.vram + uint32_t(word_index * sizeof(func.words[0]));
                uint32_t insn_word = byteswap(func.words[word_index]);
                rabbitizer::InstructionCpu instr(insn_word, instr_vram);
                if (!instr.isValid()) {
                    continue;
                }

                const auto id = instr.getUniqueId();
                if (is_unconditional_branch_or_jump(instr) ||
                    (id == InstrId::cpu_jr &&
                     int(instr.GetO32_rs()) == ra_reg)) {
                    add_entry(func, instr_vram + 8);
                }
                else if (is_conditional_branch(instr)) {
                    add_entry(func, instr_vram + 8);
                }
            }
        }
    }

    if (seeded_count != 0) {
        fmt::print(
            "[Info] Seeded {} static branch-continuation entr{} from indirect dispatch labels\n",
            seeded_count,
            seeded_count == 1 ? "y" : "ies");
    }
}

void seed_static_entrypoints_from_indirect_dispatch(
    const N64Recomp::Context& context,
    std::vector<std::vector<uint32_t>>& static_funcs_by_section) {
    using InstrId = rabbitizer::InstrId::UniqueId;
    constexpr int ra_reg = (int)rabbitizer::Registers::Cpu::GprO32::GPR_O32_ra;
    constexpr size_t max_dispatch_function_size = 0x2000;
    constexpr size_t max_control_entry_function_size = 0x100;
    size_t seeded_count = 0;

    for (size_t section_index = 0; section_index < context.sections.size(); section_index++) {
        const auto& section = context.sections[section_index];
        if (!section.executable || !section.relocatable ||
            is_resident_text_section(section)) {
            continue;
        }

        if (section.rom_addr >= 0xF0000000u ||
            uint64_t(section.rom_addr) + uint64_t(section.size) > context.rom.size()) {
            continue;
        }

        bool section_contains_indirect_dispatch = false;
        for (size_t func_index : context.section_functions[section_index]) {
            const auto& func = context.functions[func_index];
            if (!func.words.empty() &&
                func.words.size() * sizeof(func.words[0]) <= max_dispatch_function_size &&
                function_contains_indirect_dispatch(func)) {
                section_contains_indirect_dispatch = true;
                break;
            }
        }
        if (!section_contains_indirect_dispatch) {
            continue;
        }

        std::set<uint32_t> seeded_entries{
            static_funcs_by_section[section_index].begin(),
            static_funcs_by_section[section_index].end()
        };

        auto add_entry = [&](const N64Recomp::Function& func, uint32_t target_vram) {
            if (!static_entrypoint_inside_function_looks_valid(func, target_vram)) {
                return;
            }

            if (find_exact_function_in_section(context, target_vram, section_index) != (size_t)-1) {
                return;
            }

            if (!seeded_entries.emplace(target_vram).second) {
                return;
            }

            static_funcs_by_section[section_index].push_back(target_vram);
            seeded_count++;
        };

        for (size_t func_index : context.section_functions[section_index]) {
            const auto& func = context.functions[func_index];
            const size_t func_size = func.words.size() * sizeof(func.words[0]);
            if (func.words.empty() ||
                func.ignored ||
                func.reimplemented ||
                func_size > max_dispatch_function_size ||
                !function_contains_indirect_dispatch(func)) {
                continue;
            }

            for (size_t word_index = 0; word_index < func.words.size(); word_index++) {
                uint32_t instr_vram = func.vram + uint32_t(word_index * sizeof(func.words[0]));
                uint32_t word = func.words[word_index];
                uint32_t insn_word = byteswap(word);
                rabbitizer::InstructionCpu instr(insn_word, instr_vram);
                if (instr.isValid()) {
                    if (instr.doesLink()) {
                        add_entry(func, instr_vram + 8);
                    }

                    if (is_unconditional_branch_or_jump(instr)) {
                        if (func_size <= max_control_entry_function_size) {
                            add_entry(func, instr_vram);
                        }
                        add_entry(func, instr_vram + 8);
                    }
                    else if (is_conditional_branch(instr)) {
                        add_entry(func, instr_vram + 8);
                    }
                    else if (instr.getUniqueId() == InstrId::cpu_jr &&
                             int(instr.GetO32_rs()) != 0) {
                        if (func_size <= max_control_entry_function_size) {
                            add_entry(func, instr_vram);
                        }
                        add_entry(func, instr_vram + 8);
                    }
                }
            }
        }

        auto add_raw_entry = [&](uint32_t target_vram) {
            if ((target_vram & 3u) != 0 ||
                target_vram < section.ram_addr ||
                target_vram >= section.ram_addr + section.size) {
                return;
            }

            if (find_exact_function_in_section(context, target_vram, section_index) != (size_t)-1) {
                return;
            }

            bool target_looks_valid = false;
            size_t containing_func_index = find_containing_function_in_section(context, target_vram, section_index);
            if (containing_func_index != (size_t)-1) {
                target_looks_valid = static_entrypoint_inside_function_looks_valid(
                    context.functions[containing_func_index],
                    target_vram);
            }
            else {
                size_t discovered_size = 0;
                target_looks_valid =
                    discover_static_code_entrypoint(context, section_index, target_vram, &discovered_size) &&
                    discovered_size <= max_dispatch_function_size;
            }

            if (!target_looks_valid) {
                return;
            }

            if (!seeded_entries.emplace(target_vram).second) {
                return;
            }

            static_funcs_by_section[section_index].push_back(target_vram);
            seeded_count++;
        };

        const uint8_t* section_body = context.rom.data() + section.rom_addr;
        std::vector<uint32_t> seeded_snapshot{ seeded_entries.begin(), seeded_entries.end() };
        for (uint32_t entry_vram : seeded_snapshot) {
            if (entry_vram + 8 < section.ram_addr ||
                entry_vram + 8 >= section.ram_addr + section.size) {
                continue;
            }

            const uint32_t return_vram = entry_vram + 8;
            const uint32_t return_word = byteswap(*reinterpret_cast<const uint32_t*>(
                section_body + (return_vram - section.ram_addr)));
            rabbitizer::InstructionCpu return_instr(return_word, return_vram);
            if (return_instr.isValid() &&
                return_instr.getUniqueId() == InstrId::cpu_jr &&
                int(return_instr.GetO32_rs()) != 0 &&
                int(return_instr.GetO32_rs()) != ra_reg) {
                add_raw_entry(entry_vram + 4);
            }
        }

        for (size_t dispatch_func_index : context.section_functions[section_index]) {
            const auto& dispatch_func = context.functions[dispatch_func_index];
            const size_t dispatch_func_size = dispatch_func.words.size() * sizeof(dispatch_func.words[0]);
            if (dispatch_func.words.empty() ||
                dispatch_func.ignored ||
                dispatch_func.reimplemented ||
                dispatch_func_size > max_dispatch_function_size ||
                !function_contains_indirect_dispatch(dispatch_func)) {
                continue;
            }

            uint32_t scan_start = dispatch_func.vram;
            uint32_t scan_end = std::min<uint32_t>(
                section.ram_addr + section.size,
                dispatch_func.vram + uint32_t(max_dispatch_function_size));

            for (size_t other_func_index : context.section_functions[section_index]) {
                const auto& other_func = context.functions[other_func_index];
                if (!other_func.words.empty() &&
                    other_func.vram > dispatch_func.vram &&
                    other_func.vram < scan_end) {
                    scan_end = other_func.vram;
                }
            }

            if (scan_end <= scan_start + 8) {
                continue;
            }

            uint32_t scan_offset = scan_start - section.ram_addr;
            const uint32_t scan_end_offset = scan_end - section.ram_addr;
            for (; scan_offset + 8 <= scan_end_offset; scan_offset += sizeof(uint32_t)) {
                const uint32_t instr_word =
                    byteswap(*reinterpret_cast<const uint32_t*>(section_body + scan_offset));
                const uint32_t instr_vram = section.ram_addr + scan_offset;
                rabbitizer::InstructionCpu instr(instr_word, instr_vram);
                if (!instr.isValid()) {
                    continue;
                }

                const auto id = instr.getUniqueId();
                if (id == InstrId::cpu_jr || is_unconditional_branch_or_jump(instr)) {
                    if (dispatch_func_size <= max_control_entry_function_size) {
                        add_raw_entry(instr_vram);
                    }
                    add_raw_entry(instr_vram + 8);
                }
            }
        }
    }

    if (seeded_count != 0) {
        fmt::print(
            "[Info] Seeded {} static code-label entr{} from indirect dispatch sections\n",
            seeded_count,
            seeded_count == 1 ? "y" : "ies");
    }
}

bool recompile_single_function(const N64Recomp::Context& context, size_t func_index, const std::string& recomp_include, const std::filesystem::path& output_path, std::span<std::vector<uint32_t>> static_funcs_out) {
    // Open the temporary output file
    std::filesystem::path temp_path = output_path;
    temp_path.replace_extension(".tmp");
    std::ofstream output_file{ temp_path };
    if (!output_file.good()) {
        fmt::print(stderr, "Failed to open file for writing: {}\n", temp_path.string() );
        return false;
    }

    // Write the file header
    fmt::print(output_file,
        "{}\n"
        "\n",
        recomp_include);

    if (!N64Recomp::recompile_function(context, func_index, output_file, static_funcs_out, false)) {
        return false;
    }
    
    output_file.close();

    // If a file of the target name exists and it's identical to the output file, delete the output file.
    // This prevents updating the existing file so that it doesn't need to be rebuilt.
    if (std::filesystem::exists(output_path) && compare_files(output_path, temp_path)) {
        std::filesystem::remove(temp_path);
    }
    // Otherwise, rename the new file to the target path.
    else {
        std::filesystem::rename(temp_path, output_path);
    }

    return true;
}

std::vector<std::string> reloc_names {
    "R_MIPS_NONE ",
    "R_MIPS_16",
    "R_MIPS_32",
    "R_MIPS_REL32",
    "R_MIPS_26",
    "R_MIPS_HI16",
    "R_MIPS_LO16",
    "R_MIPS_GPREL16",
};

void dump_context(const N64Recomp::Context& context, const std::unordered_map<uint16_t, std::vector<N64Recomp::DataSymbol>>& data_syms, const std::filesystem::path& func_path, const std::filesystem::path& data_path) {
    std::ofstream func_context_file {func_path};
    std::ofstream data_context_file {data_path};
    
    fmt::print(func_context_file, "# Autogenerated from an ELF via N64Recomp\n");
    fmt::print(data_context_file, "# Autogenerated from an ELF via N64Recomp\n");

    auto print_section = [](std::ofstream& output_file, const std::string& name, uint32_t rom_addr, uint32_t ram_addr, uint32_t size) {
        if (rom_addr == (uint32_t)-1) {
            fmt::print(output_file,
                "[[section]]\n"
                "name = \"{}\"\n"
                "vram = 0x{:08X}\n"
                "size = 0x{:X}\n"
                "\n",
                name, ram_addr, size);
        }
        else {
            fmt::print(output_file,
                "[[section]]\n"
                "name = \"{}\"\n"
                "rom = 0x{:08X}\n"
                "vram = 0x{:08X}\n"
                "size = 0x{:X}\n"
                "\n",
                name, rom_addr, ram_addr, size);
        }
    };

    for (size_t section_index = 0; section_index < context.sections.size(); section_index++) {
        const N64Recomp::Section& section = context.sections[section_index];
        const std::vector<size_t>& section_funcs = context.section_functions[section_index];
        if (!section_funcs.empty()) {
            print_section(func_context_file, section.name, section.rom_addr, section.ram_addr, section.size);

            // Dump relocs into the function context file.
            if (!section.relocs.empty()) {
                fmt::print(func_context_file, "relocs = [\n");

                for (const N64Recomp::Reloc& reloc : section.relocs) {
                    if (reloc.target_section == section_index || reloc.target_section == section.bss_section_index) {
                        // TODO allow emitting MIPS32 relocs for specific sections via a toml option for TLB mapping support.
                        if (reloc.type == N64Recomp::RelocType::R_MIPS_HI16 || reloc.type == N64Recomp::RelocType::R_MIPS_LO16 || reloc.type == N64Recomp::RelocType::R_MIPS_26) {
                            fmt::print(func_context_file, "    {{ type = \"{}\", vram = 0x{:08X}, target_vram = 0x{:08X} }},\n",
                                reloc_names[static_cast<int>(reloc.type)], reloc.address, reloc.target_section_offset + section.ram_addr);
                        }
                    }
                }

                fmt::print(func_context_file, "]\n\n");
            }

            // Dump functions into the function context file.
            fmt::print(func_context_file, "functions = [\n");

            for (const size_t& function_index : section_funcs) {
                const N64Recomp::Function& func = context.functions[function_index];
                fmt::print(func_context_file, "    {{ name = \"{}\", vram = 0x{:08X}, size = 0x{:X} }},\n",
                    func.name, func.vram, func.words.size() * sizeof(func.words[0]));
            }

            fmt::print(func_context_file, "]\n\n");
        }
        
        const auto find_syms_it = data_syms.find((uint16_t)section_index);
        if (find_syms_it != data_syms.end() && !find_syms_it->second.empty()) {
            print_section(data_context_file, section.name, section.rom_addr, section.ram_addr, section.size);

            // Dump other symbols into the data context file.
            fmt::print(data_context_file, "symbols = [\n");

            for (const N64Recomp::DataSymbol& cur_sym : find_syms_it->second) {
                fmt::print(data_context_file, "    {{ name = \"{}\", vram = 0x{:08X} }},\n", cur_sym.name, cur_sym.vram);
            }
            
            fmt::print(data_context_file, "]\n\n");
        }
    }

    const auto find_abs_syms_it = data_syms.find(N64Recomp::SectionAbsolute);
    if (find_abs_syms_it != data_syms.end() && !find_abs_syms_it->second.empty()) {
        // Dump absolute symbols into the data context file.
        print_section(data_context_file, "ABSOLUTE_SYMS", (uint32_t)-1, 0, 0);
        fmt::print(data_context_file, "symbols = [\n");

        for (const N64Recomp::DataSymbol& cur_sym : find_abs_syms_it->second) {
            fmt::print(data_context_file, "    {{ name = \"{}\", vram = 0x{:08X} }},\n", cur_sym.name, cur_sym.vram);
        }

        fmt::print(data_context_file, "]\n\n");
    }
}

static std::vector<uint8_t> read_file(const std::filesystem::path& path) {
    std::vector<uint8_t> ret;

    std::ifstream file{ path, std::ios::binary};

    if (file.good()) {
        file.seekg(0, std::ios::end);
        ret.resize(file.tellg());
        file.seekg(0, std::ios::beg);

        file.read(reinterpret_cast<char*>(ret.data()), ret.size());
    }

    return ret;
}

int main(int argc, char** argv) {
    auto exit_failure = [] (const std::string& error_str) {
        fmt::vprint(stderr, error_str, fmt::make_format_args());
        std::exit(EXIT_FAILURE);
    };

    bool dumping_context;

    if (argc < 2) {
        fmt::print(stderr, "Usage: {} <config file> [--dump-context]\n",
                   argc >= 1 ? argv[0] : "N64Recomp");
        std::exit(EXIT_FAILURE);
    }

    if (argc >= 3) {
        std::string arg2 = argv[2];
        if (arg2 == "--dump-context") {
            dumping_context = true;
        } else {
            fmt::print("Usage: {} <config file> [--dump-context]\n", argv[0]);
            std::exit(EXIT_SUCCESS);
        }
    } else {
        dumping_context = false;
    }

    const char* config_path = argv[1];

    N64Recomp::Config config{ config_path };
    if (!config.good()) {
        exit_failure(fmt::format("Failed to load config file: {}\n", config_path));
    }

    RabbitizerConfig_Cfg.pseudos.pseudoMove = false;
    RabbitizerConfig_Cfg.pseudos.pseudoBeqz = false;
    RabbitizerConfig_Cfg.pseudos.pseudoBnez = false;
    RabbitizerConfig_Cfg.pseudos.pseudoNot = false;
    RabbitizerConfig_Cfg.pseudos.pseudoBal = false;

    std::vector<std::string> relocatable_sections_ordered{};

    if (!config.relocatable_sections_path.empty()) {
        if (!read_list_file(config.relocatable_sections_path, relocatable_sections_ordered)) {
            exit_failure(fmt::format("Failed to load the relocatable section list file: {}\n", (const char*)config.relocatable_sections_path.u8string().c_str()));
        }
    }

    std::unordered_set<std::string> relocatable_sections{};
    relocatable_sections.insert(relocatable_sections_ordered.begin(), relocatable_sections_ordered.end());

    N64Recomp::Context context{};
    
    if (!config.elf_path.empty() && !config.symbols_file_path.empty()) {
        exit_failure("Config file cannot provide both an elf and a symbols file\n");
    }

    // Build a context from the provided elf file.
    if (!config.elf_path.empty()) {
        // Lists of data symbols organized by section, only used if dumping context.
        std::unordered_map<uint16_t, std::vector<N64Recomp::DataSymbol>> data_syms;

        // Import symbols from any reference symbols files that were provided.
        if (!config.func_reference_syms_file_path.empty()) {
            {
                // Create a new temporary context to read the function reference symbol file into, since it's the same format as the recompilation symbol file.
                std::vector<uint8_t> dummy_rom{};
                N64Recomp::Context reference_context{};
                if (!N64Recomp::Context::from_symbol_file(config.func_reference_syms_file_path, std::move(dummy_rom), reference_context, false)) {
                    exit_failure("Failed to load provided function reference symbol file\n");
                }

                // Use the reference context to build a reference symbol list for the actual context.
                if (!context.import_reference_context(reference_context)) {
                    exit_failure("Internal error: Failed to import reference context. Please report this issue.\n");
                }
            }

            for (const std::filesystem::path& cur_data_sym_path : config.data_reference_syms_file_paths) {
                if (!context.read_data_reference_syms(cur_data_sym_path)) {
                    exit_failure(fmt::format("Failed to load provided data reference symbol file: {}\n", cur_data_sym_path.string()));
                }
            }
        }

        N64Recomp::ElfParsingConfig elf_config {
            .bss_section_suffix = config.bss_section_suffix,
            .relocatable_sections = std::move(relocatable_sections),
            .has_entrypoint = config.has_entrypoint,
            .entrypoint_address = config.entrypoint,
            .use_absolute_symbols = config.use_absolute_symbols,
            .unpaired_lo16_warnings = config.unpaired_lo16_warnings,
            .all_sections_relocatable = false,
        };

        for (const auto& func_size : config.manual_func_sizes) {
            elf_config.manually_sized_funcs.emplace(func_size.func_name, func_size.size_bytes);
        }

        bool found_entrypoint_func;
        N64Recomp::Context::from_elf_file(config.elf_path, context, elf_config, dumping_context, data_syms, found_entrypoint_func);

        // Synthesize decompressed sections (CPU-decompressed-at-runtime
        // fragments). The recompiler decompresses them now from the ROM
        // wrapper bytes and adds them as in-memory sections, so the rest
        // of the pipeline treats them like any other ELF section.
        if (!N64Recomp::synthesize_decompressed_sections(
                context, config.rom_file_path,
                config.decompressed_sections)) {
            exit_failure("Failed to synthesize decompressed sections\n");
        }

        // Pattern-driven auto-discovery of decompressed sections. For
        // slots like Stadium's vram 0x8FF00000 where many wrappers
        // share a link addr, this scans the ROM and synthesizes one
        // section per distinct decompressed content. With suffix-style
        // names (<base>__rom_<offset>) per wrapper.
        if (!N64Recomp::synthesize_decompressed_patterns(
                context, config.rom_file_path,
                config.decompressed_section_patterns)) {
            exit_failure("Failed to synthesize decompressed patterns\n");
        }

        // Add any manual functions
        add_manual_functions(context, config.manual_functions);

        if (config.has_entrypoint && !found_entrypoint_func) {
            exit_failure("Could not find entrypoint function\n");
        }
        
        if (dumping_context) {
            fmt::print("Dumping context\n");
            // Sort the data syms by address so the output is nicer.
            for (auto& [section_index, section_syms] : data_syms) {
                std::sort(section_syms.begin(), section_syms.end(),
                    [](const N64Recomp::DataSymbol& a, const N64Recomp::DataSymbol& b) {
                        return a.vram < b.vram;
                    }
                );
            }

            dump_context(context, data_syms, "dump.toml", "data_dump.toml");
            return 0;
        }
    }
    // Build a context from the provided symbols file.
    else if (!config.symbols_file_path.empty()) {
        if (config.rom_file_path.empty()) {
            exit_failure("A ROM file must be provided when using a symbols file\n");
        }

        if (dumping_context) {
            exit_failure("Cannot dump context when using a symbols file\n");
        }

        std::vector<uint8_t> rom = read_file(config.rom_file_path);
        if (rom.empty()) {
            exit_failure("Failed to load ROM file: " + config.rom_file_path.string() + "\n");
        }
        
        if (!N64Recomp::Context::from_symbol_file(config.symbols_file_path, std::move(rom), context, true)) {
            exit_failure("Failed to load symbols file\n");
        }

        auto rename_function = [&context](size_t func_index, const std::string& new_name) {
            N64Recomp::Function& func = context.functions[func_index];

            context.functions_by_name.erase(func.name);
            func.name = new_name;
            context.functions_by_name[func.name] = func_index;
        };

        for (size_t func_index = 0; func_index < context.functions.size(); func_index++) {
            N64Recomp::Function& func = context.functions[func_index];
            if (N64Recomp::reimplemented_funcs.contains(func.name)) {
                rename_function(func_index, func.name + "_recomp");
                func.reimplemented = true;
                func.ignored = true;
            } else if (N64Recomp::ignored_funcs.contains(func.name)) {
                rename_function(func_index, func.name + "_recomp");
                func.ignored = true;
            } else if (N64Recomp::renamed_funcs.contains(func.name)) {
                rename_function(func_index, func.name + "_recomp");
                func.ignored = false;
            }
        }


        if (config.has_entrypoint) {
            bool found_entrypoint = false;

            for (uint32_t func_index : context.functions_by_vram[config.entrypoint]) {
                auto& func = context.functions[func_index];
                if (func.rom == 0x1000) {
                    rename_function(func_index, "recomp_entrypoint");
                    found_entrypoint = true;
                    break;
                }
            }

            if (!found_entrypoint) {
                exit_failure("No entrypoint provided in symbol file\n");
            }
        }

    }
    else {
        exit_failure("Config file must provide either an elf or a symbols file\n");
    }


    fmt::print("Function count: {}\n", context.functions.size());

    // Collision detection. If two functions ended up with the same name
    // (e.g. two sections at the same link vram), the user must opt in to
    // the suffix policy or fix the collision structurally. Default policy
    // is Error so silent name collisions never ship.
    {
        std::unordered_map<std::string, std::vector<size_t>> by_name;
        by_name.reserve(context.functions.size());
        for (size_t i = 0; i < context.functions.size(); i++) {
            const N64Recomp::Function& f = context.functions[i];
            if (f.name.empty()) continue;
            by_name[f.name].push_back(i);
        }

        std::vector<std::pair<std::string, std::vector<size_t>>> collisions;
        for (auto& [name, indices] : by_name) {
            if (indices.size() > 1) {
                collisions.emplace_back(name, indices);
            }
        }

        if (!collisions.empty()) {
            if (config.collision_policy == N64Recomp::CollisionPolicy::Error) {
                fmt::print(stderr,
                    "\nERROR: {} function name collision(s) detected.\n"
                    "Two or more sections emit functions with the same name; "
                    "the build cannot proceed without disambiguation.\n\n",
                    collisions.size());
                for (const auto& [name, indices] : collisions) {
                    fmt::print(stderr, "  `{}` is emitted by:\n", name);
                    for (size_t fi : indices) {
                        const N64Recomp::Function& f = context.functions[fi];
                        const N64Recomp::Section& s = context.sections[f.section_index];
                        fmt::print(stderr,
                            "    section {} ({}) — function vram 0x{:08X}, rom 0x{:X}\n",
                            f.section_index, s.name, f.vram, f.rom);
                    }
                }
                fmt::print(stderr,
                    "\nFix options:\n"
                    "  1. Set [output] collision_policy = \"suffix\" in your\n"
                    "     game.toml to auto-disambiguate by appending\n"
                    "     __rom_<rom_addr> to each colliding symbol. The\n"
                    "     suffix is only added where collisions exist; the\n"
                    "     other 99% of symbols stay unchanged.\n"
                    "  2. Remove one of the colliding sections (e.g. if a\n"
                    "     decompressed_section duplicates an ELF section).\n"
                    "  3. Rename via [[input.section_alias]] (not yet\n"
                    "     implemented; use option 1 for now).\n");
                std::exit(EXIT_FAILURE);
            } else {
                // Suffix policy: rename every colliding function. We
                // append __rom_<rom_addr> so the suffix encodes a stable
                // identity (the rom_addr is unique per section in a given
                // ROM; for synthesized decompressed sections it carries
                // the wrapper offset).
                size_t renamed = 0;
                for (const auto& [name, indices] : collisions) {
                    for (size_t fi : indices) {
                        N64Recomp::Function& f = context.functions[fi];
                        std::string new_name = fmt::format(
                            "{}__rom_{:X}", f.name, f.rom);
                        context.functions_by_name.erase(f.name);
                        f.name = new_name;
                        context.functions_by_name[f.name] = fi;
                        renamed++;
                    }
                    fmt::print(stderr,
                        "[collision] `{}` disambiguated across {} section(s)\n",
                        name, indices.size());
                }
                fmt::print(stderr,
                    "[collision] suffix policy applied: {} function(s) "
                    "renamed across {} collision group(s)\n",
                    renamed, collisions.size());
            }
        }
    }

    std::filesystem::create_directories(config.output_func_path);

    std::ofstream func_header_file{ config.output_func_path / "funcs.h" };

    fmt::print(func_header_file,
        "{}\n"
        "\n"
        "#ifdef __cplusplus\n"
        "extern \"C\" {{\n"
        "#endif\n"
        "\n",
        config.recomp_include
    );

    std::vector<std::vector<uint32_t>> static_funcs_by_section{ context.sections.size() };
    seed_static_entrypoints_from_code_relocs(context, static_funcs_by_section);
    seed_static_entrypoints_from_pointer_tables(context, static_funcs_by_section);
    seed_static_entrypoints_from_code_relocs(context, static_funcs_by_section);
    seed_static_branch_continuations_from_indirect_dispatch_entries(context, static_funcs_by_section);
    seed_static_entrypoints_from_code_relocs(context, static_funcs_by_section);

    fmt::print("Working dir: {}\n", std::filesystem::current_path().string());

    // Stub out any functions specified in the config file.
    for (const std::string& stubbed_func : config.stubbed_funcs) {
        // Check if the specified function exists.
        auto func_find = context.functions_by_name.find(stubbed_func);
        if (func_find == context.functions_by_name.end()) {
            // Function doesn't exist, present an error to the user instead of silently failing to stub it out.
            // This helps prevent typos in the config file or functions renamed between versions from causing issues.
            exit_failure(fmt::format("Function {} is stubbed out in the config file but does not exist!", stubbed_func));
        }
        // Mark the function as stubbed.
        context.functions[func_find->second].stubbed = true;
    }

    // Ignore any functions specified in the config file.
    for (const std::string& ignored_func : config.ignored_funcs) {
        // Check if the specified function exists.
        auto func_find = context.functions_by_name.find(ignored_func);
        if (func_find == context.functions_by_name.end()) {
            // Function doesn't exist, present an error to the user instead of silently failing to mark it as ignored.
            // This helps prevent typos in the config file or functions renamed between versions from causing issues.
            exit_failure(fmt::format("Function {} is set as ignored in the config file but does not exist!", ignored_func));
        }
        // Mark the function as ignored.
        context.functions[func_find->second].ignored = true;
    }

    // Rename any functions specified in the config file.
    for (const std::string& renamed_func : config.renamed_funcs) {
        // Check if the specified function exists.
        auto func_find = context.functions_by_name.find(renamed_func);
        if (func_find == context.functions_by_name.end()) {
            // Function doesn't exist, present an error to the user instead of silently failing to rename it.
            // This helps prevent typos in the config file or functions renamed between versions from causing issues.
            exit_failure(fmt::format("Function {} is set as renamed in the config file but does not exist!", renamed_func));
        }
        // Rename the function.
        N64Recomp::Function* func = &context.functions[func_find->second];
        func->name = func->name + "_recomp";
    }

    // Propogate the trace mode parameter.
    context.trace_mode = config.trace_mode;

    // Apply any single-instruction patches.
    for (const N64Recomp::InstructionPatch& patch : config.instruction_patches) {
        // Check if the specified function exists.
        auto func_find = context.functions_by_name.find(patch.func_name);
        if (func_find == context.functions_by_name.end()) {
            // Function doesn't exist, present an error to the user instead of silently failing to stub it out.
            // This helps prevent typos in the config file or functions renamed between versions from causing issues.
            exit_failure(fmt::format("Function {} has an instruction patch but does not exist!", patch.func_name));
        }

        N64Recomp::Function& func = context.functions[func_find->second];
        int32_t func_vram = func.vram;

        // Check that the function actually contains this vram address.
        if (patch.vram < func_vram || patch.vram >= func_vram + func.words.size() * sizeof(func.words[0])) {
            exit_failure(fmt::format("Function {} has an instruction patch for vram 0x{:08X} but doesn't contain that vram address!", patch.func_name, (uint32_t)patch.vram));
        }

        // Calculate the instruction index and modify the instruction.
        size_t instruction_index = (static_cast<size_t>(patch.vram) - func_vram) / sizeof(uint32_t);
        func.words[instruction_index] = byteswap(patch.value);
    }

    // Apply any function hooks.
    for (const N64Recomp::FunctionTextHook& patch : config.function_hooks) {
        // Check if the specified function exists.
        auto func_find = context.functions_by_name.find(patch.func_name);
        if (func_find == context.functions_by_name.end()) {
            // Function doesn't exist, present an error to the user instead of silently failing to stub it out.
            // This helps prevent typos in the config file or functions renamed between versions from causing issues.
            exit_failure(fmt::format("Function {} has a function hook but does not exist!", patch.func_name));
        }

        N64Recomp::Function& func = context.functions[func_find->second];
        int32_t func_vram = func.vram;

        // Check that the function actually contains this vram address.
        if (patch.before_vram < func_vram || patch.before_vram >= func_vram + func.words.size() * sizeof(func.words[0])) {
            exit_failure(fmt::format("Function {} has a function hook for vram 0x{:08X} but doesn't contain that vram address!", patch.func_name, (uint32_t)patch.before_vram));
        }

        // No after_vram means this will be placed at the start of the function
        size_t instruction_index = -1;

        // Calculate the instruction index.
        if (patch.before_vram != 0) {
          instruction_index = (static_cast<size_t>(patch.before_vram) - func_vram) / sizeof(uint32_t);
        }

        // Check if a function hook already exits for that instruction index.
        auto hook_find = func.function_hooks.find(instruction_index);
        if (hook_find != func.function_hooks.end()) {
            exit_failure(fmt::format("Function {} already has a function hook for vram 0x{:08X}!", patch.func_name, (uint32_t)patch.before_vram));
        }

        func.function_hooks[instruction_index] = patch.text;
    }

    std::ofstream current_output_file;
    size_t output_file_count = 0;
    size_t cur_file_function_count = 0;
    
    auto open_new_output_file = [&config, &current_output_file, &output_file_count, &cur_file_function_count]() {
        current_output_file = std::ofstream{config.output_func_path / fmt::format("funcs_{}.c", output_file_count)};
        // Write the file header
        fmt::print(current_output_file,
            "{}\n"
            "#include \"funcs.h\"\n"
            "\n",
            config.recomp_include);

        // Print the extern for the base event index and the define to rename it if exports are allowed.
        if (config.allow_exports) {
            fmt::print(current_output_file,
                "extern uint32_t builtin_base_event_index;\n"
                "#define base_event_index builtin_base_event_index\n"
                "\n"
            );
        }

        cur_file_function_count = 0;
        output_file_count++;
    };

    if (config.single_file_output) {
        current_output_file.open(config.output_func_path / config.elf_path.stem().replace_extension(".c"));
        // Write the file header
        fmt::print(current_output_file,
            "{}\n"
            "#include \"funcs.h\"\n"
            "\n",
            config.recomp_include);

        // Print the extern for the base event index and the define to rename it if exports are allowed.
        if (config.allow_exports) {
            fmt::print(current_output_file,
                "extern uint32_t builtin_base_event_index;\n"
                "#define base_event_index builtin_base_event_index\n"
                "\n"
            );
        }
    }
    else if (config.functions_per_output_file > 1) {
        open_new_output_file();
    }

    std::unordered_map<size_t, size_t> function_index_to_event_index{};

    // If exports are enabled, scan all the relocs and modify ones that point to an event function.
    if (config.allow_exports) {
        // First, find the event section by scanning for a section with the special name.
        bool event_section_found = false;
        size_t event_section_index = 0;
        uint32_t event_section_vram = 0;
        for (size_t section_index = 0; section_index < context.sections.size(); section_index++) {
            const auto& section = context.sections[section_index];
            if (section.name == N64Recomp::EventSectionName) {
                event_section_found = true;
                event_section_index = section_index;
                event_section_vram = section.ram_addr;
                break;
            }
        }

        // If an event section was found, proceed with the reloc scanning.
        if (event_section_found) {
            for (auto& section : context.sections) {
                for (auto& reloc : section.relocs) {
                    // Event symbols aren't reference symbols, since they come from the elf itself.
                    // Therefore, skip reference symbol relocs.
                    if (reloc.reference_symbol) {
                        continue;
                    }

                    // Check if the reloc points to the event section.
                    if (reloc.target_section == event_section_index) {
                        // It does, so find the function it's pointing at.
                        size_t func_index = context.find_function_by_vram_section(reloc.target_section_offset + event_section_vram, event_section_index);

                        if (func_index == (size_t)-1) {
                            exit_failure(fmt::format("Failed to find event function with vram {}.\n", reloc.target_section_offset + event_section_vram));
                        }

                        // Ensure the reloc is a MIPS_R_26 one before modifying it, since those are the only type allowed to reference
                        if (reloc.type != N64Recomp::RelocType::R_MIPS_26) {
                            const auto& function = context.functions[func_index];
                            exit_failure(fmt::format("Function {} is an import and cannot have its address taken.\n",
                                function.name));
                        }

                        // Check if this function has been assigned an event index already, and assign it if not.
                        size_t event_index;
                        auto find_event_it = function_index_to_event_index.find(func_index);
                        if (find_event_it != function_index_to_event_index.end()) {
                            event_index = find_event_it->second;
                        }
                        else {
                            event_index = function_index_to_event_index.size();
                            function_index_to_event_index.emplace(func_index, event_index);
                        }

                        // Modify the reloc's fields accordingly.
                        reloc.target_section_offset = 0;
                        reloc.symbol_index = event_index;
                        reloc.target_section = N64Recomp::SectionEvent;
                        reloc.reference_symbol = true;
                    }
                }
            }
        }
    }

    std::vector<size_t> export_function_indices{};

    bool failed_strict_mode = false;

    //#pragma omp parallel for
    for (size_t i = 0; i < context.functions.size(); i++) {
        const auto& func = context.functions[i];

        if (!func.ignored && func.words.size() != 0) {
            fmt::print(func_header_file,
                "void {}(uint8_t* rdram, recomp_context* ctx);\n", func.name);
            bool result;
            const auto& func_section = context.sections[func.section_index];
            // Apply strict patch mode validation if enabled.
            if (config.strict_patch_mode) {
                bool in_normal_patch_section = func_section.name == N64Recomp::PatchSectionName;
                bool in_force_patch_section = func_section.name == N64Recomp::ForcedPatchSectionName;
                bool in_patch_section = in_normal_patch_section || in_force_patch_section;
                N64Recomp::SymbolReference dummy_ref;
                bool reference_symbol_found = context.reference_symbol_exists(func.name);

                // This is a patch function, but no corresponding symbol was found in the original symbol list.
                if (in_patch_section && !reference_symbol_found) {
                    fmt::print(stderr, "Function {} is marked as a replacement, but no function with the same name was found in the reference symbols!\n", func.name);
                    failed_strict_mode = true;
                    continue;
                }
                // This is not a patch function, but it has the same name as a function in the original symbol list.
                else if (!in_patch_section && reference_symbol_found) {
                    fmt::print(stderr, "Function {} is not marked as a replacement, but a function with the same name was found in the reference symbols!\n", func.name);
                    failed_strict_mode = true;
                    continue;
                }
            }
            // Check if this is an export and add it to the list if exports are enabled.
            if (config.allow_exports && func_section.name == N64Recomp::ExportSectionName) {
                export_function_indices.push_back(i);
            }

            // Recompile the function.
            if (config.single_file_output || config.functions_per_output_file > 1) {
                result = N64Recomp::recompile_function(context, i, current_output_file, static_funcs_by_section, false);
                if (!config.single_file_output) {
                    cur_file_function_count++;
                    if (cur_file_function_count >= config.functions_per_output_file) {
                        open_new_output_file();
                    }
                }
            }
            else {
                result = recompile_single_function(context, i, config.recomp_include, config.output_func_path / (func.name + ".c"), static_funcs_by_section);
            }
            if (result == false) {
                fmt::print(stderr, "Error recompiling {}\n", func.name);
                std::exit(EXIT_FAILURE);
            }
        } else if (func.reimplemented) {
            fmt::print(func_header_file,
                       "void {}(uint8_t* rdram, recomp_context* ctx);\n", func.name);
        }
    }

    if (failed_strict_mode) {
        if (config.single_file_output || config.functions_per_output_file > 1) {
            current_output_file.close();
            std::error_code ec;
            std::filesystem::remove(config.output_func_path / config.elf_path.stem().replace_extension(".c"), ec);
        }
        exit_failure("Strict mode validation failed!\n");
    }

    for (size_t section_index = 0; section_index < context.sections.size(); section_index++) {
        auto& section = context.sections[section_index];
        auto& section_funcs = section.function_addrs;

        // Sort the section's functions
        std::sort(section_funcs.begin(), section_funcs.end());
        // Sort and deduplicate the static functions via a set
        std::set<uint32_t> statics_set{ static_funcs_by_section[section_index].begin(), static_funcs_by_section[section_index].end() };
        std::vector<uint32_t> section_statics{};
        section_statics.assign(statics_set.begin(), statics_set.end());

        auto span_ends_after_conditional_branch_delay = [&](uint32_t span_end) {
            if (span_end < section.ram_addr + sizeof(uint32_t) * 2 ||
                span_end > section.ram_addr + section.size) {
                return false;
            }

            const uint32_t branch_vram = span_end - sizeof(uint32_t) * 2;
            const uint32_t branch_word = byteswap(*reinterpret_cast<const uint32_t*>(
                context.rom.data() + section.rom_addr + (branch_vram - section.ram_addr)));
            rabbitizer::InstructionCpu branch_instr(branch_word, branch_vram);
            return branch_instr.isValid() && is_conditional_branch(branch_instr);
        };

        for (size_t static_func_index = 0; static_func_index < section_statics.size(); static_func_index++) {
            uint32_t static_func_addr = section_statics[static_func_index];
            size_t exact_func_index = find_exact_function_in_section(context, static_func_addr, section_index);
            if (exact_func_index != (size_t)-1) {
                const auto& exact_func = context.functions[exact_func_index];
                std::string alias_name = fmt::format("static_{}_{:08X}", section_index, static_func_addr);
                fmt::print(func_header_file,
                           "void {}(uint8_t* rdram, recomp_context* ctx);\n", alias_name);
                fmt::print(current_output_file,
                           "RECOMP_FUNC void {}(uint8_t* rdram, recomp_context* ctx) {{\n"
                           "    {}(rdram, ctx);\n"
                           "}}\n",
                           alias_name,
                           exact_func.name);
                if (!config.single_file_output) {
                    cur_file_function_count++;
                    if (cur_file_function_count >= config.functions_per_output_file) {
                        open_new_output_file();
                    }
                }
                continue;
            }

            // Determine the code span for this static function.
            uint32_t code_func_start = static_func_addr;
            uint32_t code_rom_addr = static_cast<uint32_t>(static_func_addr - section.ram_addr + section.rom_addr);
            uint32_t cur_func_end = static_cast<uint32_t>(section.size + section.ram_addr);
            size_t containing_func_index = find_containing_function_in_section(context, static_func_addr, section_index);

            if (containing_func_index != (size_t)-1) {
                const auto& containing_func = context.functions[containing_func_index];
                code_func_start = containing_func.vram;
                code_rom_addr = containing_func.rom;
                cur_func_end = containing_func.vram + uint32_t(containing_func.words.size() * sizeof(containing_func.words[0]));
            }
            else {
            // Search for the closest function. The bounds check must come
            // first — the previous order read section_funcs[size] before
            // exiting, which is OOB and segfaults for static funcs whose
            // address lies past the last known function in the section
            // (observed in Stadium's .fragment1 once it was marked
            // relocatable, which exposes more CreateStatic targets).
                for (size_t func_index : context.section_functions[section_index]) {
                    const auto& boundary_func = context.functions[func_index];
                    if (boundary_func.words.empty() || boundary_func.name.rfind("static_", 0) == 0) {
                        continue;
                    }
                    if (boundary_func.vram > static_func_addr && boundary_func.vram < cur_func_end) {
                        cur_func_end = boundary_func.vram;
                    }
                }

                size_t discovered_size = 0;
                std::string discover_error;
                const size_t entry_offset = static_func_addr - section.ram_addr;
                if (N64Recomp::discover_function_bounds(
                        context.rom.data() + section.rom_addr,
                        section.size,
                        section.ram_addr,
                        entry_offset,
                        discovered_size,
                        discover_error)) {
                    cur_func_end = static_func_addr + uint32_t(discovered_size);
                    cur_func_end = std::min(cur_func_end, static_cast<uint32_t>(section.ram_addr + section.size));

                    while (statics_set.contains(cur_func_end) &&
                           span_ends_after_conditional_branch_delay(cur_func_end)) {
                        size_t fallthrough_size = 0;
                        if (!N64Recomp::discover_function_bounds(
                                context.rom.data() + section.rom_addr,
                                section.size,
                                section.ram_addr,
                                cur_func_end - section.ram_addr,
                                fallthrough_size,
                                discover_error) ||
                            fallthrough_size == 0) {
                            break;
                        }

                        const uint32_t extended_end =
                            std::min<uint32_t>(
                                cur_func_end + uint32_t(fallthrough_size),
                                section.ram_addr + section.size);
                        if (extended_end <= cur_func_end) {
                            break;
                        }
                        cur_func_end = extended_end;
                    }
                }

            }

            const uint32_t* func_rom_start = reinterpret_cast<const uint32_t*>(context.rom.data() + code_rom_addr);

            std::vector<uint32_t> insn_words((cur_func_end - code_func_start) / sizeof(uint32_t));
            insn_words.assign(func_rom_start, func_rom_start + insn_words.size());

            // Create the new function and add it to the context.
            size_t new_func_index = context.functions.size();
            context.functions.emplace_back(
                code_func_start,
                code_rom_addr,
                std::move(insn_words),
                fmt::format("static_{}_{:08X}", section_index, static_func_addr),
                static_cast<uint16_t>(section_index),
                false,
                false,
                false,
                static_func_addr
            );
            context.section_functions[section_index].push_back(new_func_index);
            context.functions_by_vram[static_func_addr].push_back(new_func_index);
            const N64Recomp::Function& new_func = context.functions[new_func_index];

            fmt::print(func_header_file,
                       "void {}(uint8_t* rdram, recomp_context* ctx);\n", new_func.name);

            bool result;
            size_t prev_num_statics = static_funcs_by_section[new_func.section_index].size();
            if (config.single_file_output || config.functions_per_output_file > 1) {
                result = N64Recomp::recompile_function(context, new_func_index, current_output_file, static_funcs_by_section, false);
                if (!config.single_file_output) {
                    cur_file_function_count++;
                    if (cur_file_function_count >= config.functions_per_output_file) {
                        open_new_output_file();
                    }
                }
            }
            else {
                result = recompile_single_function(context, new_func_index, config.recomp_include, config.output_func_path / (new_func.name + ".c"), static_funcs_by_section);
            }

            // Add any new static functions that were found while recompiling this one.
            size_t cur_num_statics = static_funcs_by_section[new_func.section_index].size();
            if (cur_num_statics != prev_num_statics) {
                for (size_t new_static_index = prev_num_statics; new_static_index < cur_num_statics; new_static_index++) {
                    uint32_t new_static_vram = static_funcs_by_section[new_func.section_index][new_static_index];

                    if (!statics_set.contains(new_static_vram)) {
                        statics_set.emplace(new_static_vram);
                        section_statics.push_back(new_static_vram);
                    }
                }
            }

            if (result == false) {
                fmt::print(stderr, "Error recompiling {}\n", new_func.name);
                std::exit(EXIT_FAILURE);
            }
        }
    }

    if (config.has_entrypoint) {
        std::ofstream lookup_file{ config.output_func_path / "lookup.cpp" };
        
        fmt::print(lookup_file,
            "{}\n"
            "\n",
            config.recomp_include
        );

        fmt::print(lookup_file,
            "gpr get_entrypoint_address() {{ return (gpr)(int32_t)0x{:08X}u; }}\n"
            "\n"
            "const char* get_rom_name() {{ return \"{}\"; }}\n"
            "\n",
            static_cast<uint32_t>(config.entrypoint),
            config.elf_path.filename().replace_extension(".z64").string()
        );
    }

    {
        std::ofstream overlay_file(config.output_func_path / "recomp_overlays.inl");
        std::string section_load_table = "static SectionTableEntry section_table[] = {\n";

        fmt::print(overlay_file, 
            "{}\n"
            "#include \"funcs.h\"\n"
            "#include \"librecomp/sections.h\"\n"
            "\n",
            config.recomp_include
        );

        std::unordered_map<std::string, size_t> relocatable_section_indices{};
        size_t written_sections = 0;

        for (size_t section_index = 0; section_index < context.sections.size(); section_index++) {
            const auto& section = context.sections[section_index];
            const auto& section_funcs = context.section_functions[section_index];
            const auto& section_relocs = section.relocs;

            if (section.has_mips32_relocs || !section_funcs.empty()) {
                std::string_view section_name_trimmed{ section.name };

                if (section.relocatable) {
                    relocatable_section_indices.emplace(section.name, written_sections);
                }

                while (section_name_trimmed.size() > 0 && section_name_trimmed[0] == '.') {
                    section_name_trimmed.remove_prefix(1);
                }

                std::string section_funcs_array_name = fmt::format("section_{}_{}_funcs", section_index, section_name_trimmed);
                std::string section_relocs_array_name = section_relocs.empty() ? "nullptr" : fmt::format("section_{}_{}_relocs", section_index, section_name_trimmed);
                std::string section_relocs_array_size = section_relocs.empty() ? "0" : fmt::format("ARRLEN({})", section_relocs_array_name);

                // Write the section's table entry.
                section_load_table += fmt::format("    {{ .rom_addr = 0x{0:08X}, .ram_addr = 0x{1:08X}, .size = 0x{2:08X}, .funcs = {3}, .num_funcs = ARRLEN({3}), .relocs = {4}, .num_relocs = {5}, .index = {6}, .content_hash = 0x{7:016X}ull, .original_pattern_id = 0x{8:08X}u }},\n",
                                                  section.rom_addr, section.ram_addr, section.size, section_funcs_array_name,
                                                  section_relocs_array_name, section_relocs_array_size, section_index,
                                                  section.content_hash, section.original_pattern_id);

                // Write the section's functions.
                fmt::print(overlay_file, "static FuncEntry {}[] = {{\n", section_funcs_array_name);

                for (size_t func_index : section_funcs) {
                    const auto& func = context.functions[func_index];
                    size_t func_size = func.reimplemented ? 0 : func.words.size() * sizeof(func.words[0]);

                    if (func.reimplemented || (!func.name.empty() && !func.ignored && func.words.size() != 0)) {
                        uint32_t func_offset = func.rom - section.rom_addr;
                        if (func.entry_vram != 0 && func.entry_vram != func.vram) {
                            func_offset += func.entry_vram - func.vram;
                        }
                        fmt::print(overlay_file, "    {{ .func = {}, .offset = 0x{:08X}, .rom_size = 0x{:08X} }},\n",
                            func.name, func_offset, func_size);
                    }
                }

                fmt::print(overlay_file, "}};\n");

                // Write the section's relocations.
                if (!section_relocs.empty()) {
                    // Determine if reference symbols are being used.
                    bool reference_symbol_mode = !config.func_reference_syms_file_path.empty();

                    fmt::print(overlay_file, "static RelocEntry {}[] = {{\n", section_relocs_array_name);

                    for (const N64Recomp::Reloc& reloc : section_relocs) {
                        bool emit_reloc = false;
                        uint16_t target_section = reloc.target_section;
                        // Skip relocs whose type the runtime doesn't understand
                        // (e.g. R_MIPS_PC16, R_MIPS_GOT16) — these come through
                        // the ELF parser as raw cast values and would index
                        // reloc_names out of bounds, producing a NUL byte in
                        // the .type field of the emitted RelocEntry. Stadium's
                        // .rel.fragment* sections include R_MIPS_PC16 (type
                        // 10) for branches; the recompiler resolves those
                        // statically already, so dropping them here is safe.
                        size_t type_idx = static_cast<size_t>(reloc.type);
                        if (type_idx >= reloc_names.size()) {
                            continue;
                        }
                        // In reference symbol mode, only emit relocations into the table that point to
                        // non-absolute reference symbols, events, or manual patch symbols.
                        if (reference_symbol_mode) {
                            bool manual_patch_symbol = N64Recomp::is_manual_patch_symbol(reloc.target_section_offset);
                            bool is_absolute = reloc.target_section == N64Recomp::SectionAbsolute;
                            emit_reloc = (reloc.reference_symbol && !is_absolute) || target_section == N64Recomp::SectionEvent || manual_patch_symbol;
                        }
                        // Otherwise, emit all relocs.
                        else {
                            emit_reloc = true;
                        }
                        if (emit_reloc) {
                            uint32_t target_section_offset;
                            if (reloc.target_section == N64Recomp::SectionEvent) {
                                target_section_offset = reloc.symbol_index;
                            }
                            else {
                                target_section_offset = reloc.target_section_offset;
                            }
                            fmt::print(overlay_file, "    {{ .offset = 0x{:08X}, .target_section_offset = 0x{:08X}, .target_section = {}, .type = {} }}, \n",
                                reloc_offset_in_section(context, section_index, reloc.address), target_section_offset, reloc.target_section, reloc_names[static_cast<size_t>(reloc.type)] );
                        }
                    }

                    fmt::print(overlay_file, "}};\n");
                }

                written_sections++;
            }
        }
        section_load_table += "};\n";

        fmt::print(overlay_file, "{}", section_load_table);

        fmt::print(overlay_file, "const size_t num_sections = {};\n", context.sections.size());


        fmt::print(overlay_file, "static int overlay_sections_by_index[] = {{\n");
        if (relocatable_sections_ordered.empty()) {
            fmt::print(overlay_file, "    -1,\n");
        } else {
            for (const std::string& section : relocatable_sections_ordered) {
                // Check if this is an empty overlay
                if (section == "*") {
                    fmt::print(overlay_file, "    -1,\n");
                }
                else {
                    auto find_it = relocatable_section_indices.find(section);
                    if (find_it == relocatable_section_indices.end()) {
                        fmt::print(stderr, "Failed to find written section index of relocatable section: {}\n", section);
                        std::exit(EXIT_FAILURE);
                    }
                    fmt::print(overlay_file, "    {},\n", relocatable_section_indices[section]);
                }
            }
        }
        fmt::print(overlay_file, "}};\n");

        if (config.allow_exports) {
            // Emit the exported function table.
            fmt::print(overlay_file, 
                "\n"
                "static FunctionExport export_table[] = {{\n"
            );
            for (size_t func_index : export_function_indices) {
                const auto& func = context.functions[func_index];
                fmt::print(overlay_file, "    {{ \"{}\", 0x{:08X} }},\n", func.name, func.entry_vram != 0 ? func.entry_vram : func.vram);
            }
            // Add a dummy element at the end to ensure the array has a valid length because C doesn't allow zero-size arrays.
            fmt::print(overlay_file, "    {{ NULL, 0 }}\n");
            fmt::print(overlay_file, "}};\n");

            // Emit the event table.
            std::vector<size_t> functions_by_event{};
            functions_by_event.resize(function_index_to_event_index.size());
            for (auto [func_index, event_index] : function_index_to_event_index) {
                functions_by_event[event_index] = func_index;
            }

            fmt::print(overlay_file,
                "\n"
                "static const char* event_names[] = {{\n"
            );
            for (size_t func_index : functions_by_event) {
                const auto& func = context.functions[func_index];
                fmt::print(overlay_file, "    \"{}\",\n", func.name);
            }
            // Add a dummy element at the end to ensure the array has a valid length because C doesn't allow zero-size arrays.
            fmt::print(overlay_file, "    NULL\n");
            fmt::print(overlay_file, "}};\n");

            // Collect manual patch symbols.
            std::vector<std::pair<uint32_t, std::string>> manual_patch_syms{};

            for (const auto& func : context.functions) {
                if (func.words.empty() && N64Recomp::is_manual_patch_symbol(func.vram)) {
                    manual_patch_syms.emplace_back(func.vram, func.name);
                }
            }            

            // Sort the manual patch symbols by vram.
            std::sort(manual_patch_syms.begin(), manual_patch_syms.end(), [](const auto& lhs, const auto& rhs) {
                return lhs.first < rhs.first;
            });

            // Emit the manual patch symbols.
            fmt::print(overlay_file,
                "\n"
                "static const ManualPatchSymbol manual_patch_symbols[] = {{\n"
            );
            for (const auto& manual_patch_sym_entry : manual_patch_syms) {
                fmt::print(overlay_file, "    {{ 0x{:08X}, {} }},\n", manual_patch_sym_entry.first, manual_patch_sym_entry.second);

                fmt::print(func_header_file,
                    "void {}(uint8_t* rdram, recomp_context* ctx);\n", manual_patch_sym_entry.second);
            }
            // Add a dummy element at the end to ensure the array has a valid length because C doesn't allow zero-size arrays.
            fmt::print(overlay_file, "    {{ 0, NULL }}\n");
            fmt::print(overlay_file, "}};\n");
        }
    }

    fmt::print(func_header_file,
        "\n"
        "#ifdef __cplusplus\n"
        "}}\n"
        "#endif\n"
    );

    if (!config.output_binary_path.empty()) {
        std::ofstream output_binary{config.output_binary_path, std::ios::binary};
        output_binary.write(reinterpret_cast<const char*>(context.rom.data()), context.rom.size());
    }

    return 0;
}
