#include <vector>
#include <set>
#include <sstream>
#include <unordered_set>
#include <unordered_map>
#include <cassert>

#include "rabbitizer.hpp"
#include "fmt/format.h"
#include "fmt/ostream.h"

#include "recompiler/context.h"
#include "analysis.h"
#include "recompiler/operations.h"
#include "recompiler/generator.h"

enum class JalResolutionResult {
    NoMatch,
    Match,
    CreateStatic,
    Ambiguous,
    Error
};

static uint32_t infer_recomp_section_encoded_vram_base(
    const N64Recomp::Context& context,
    size_t section_index) {
    if (section_index >= context.sections.size() ||
        section_index >= context.section_functions.size()) {
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
        const uint64_t section_rom_start = section.rom_addr;
        const uint64_t section_rom_end = section_rom_start + section.size;
        if (func.rom < section_rom_start || func.rom >= section_rom_end) {
            continue;
        }

        const uint32_t candidate_base =
            func.vram - uint32_t(func.rom - section.rom_addr);
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

JalResolutionResult resolve_jal(const N64Recomp::Context& context, size_t cur_section_index, uint32_t target_func_vram, size_t& matched_function_index, size_t& static_section_index) {
    // When the caller has opted every call into runtime lookup, there is
    // nothing to resolve statically — report it as ambiguous straight away.
    if (context.use_lookup_for_all_function_calls) {
        return JalResolutionResult::Ambiguous;
    }

    // Collect every function symbol that sits at the target address.
    const N64Recomp::Section& cur_section = context.sections[cur_section_index];
    const auto matching_funcs_find = context.functions_by_vram.find(target_func_vram);
    // A section can be present at two address windows: the encoded (link-time)
    // base inferred from its functions, and the canonical ram_addr base. The
    // target counts as "in this section" if it lands in either window.
    uint32_t section_vram_start =
        infer_recomp_section_encoded_vram_base(context, cur_section_index);
    uint32_t section_vram_end = section_vram_start + cur_section.size;
    const uint32_t link_vram_start = cur_section.ram_addr;
    const uint32_t link_vram_end = link_vram_start + cur_section.size;
    bool in_current_section =
        (target_func_vram >= section_vram_start &&
         target_func_vram < section_vram_end) ||
        (target_func_vram >= link_vram_start &&
         target_func_vram < link_vram_end);
    bool exact_match_found = false;
    static_section_index = cur_section_index;

    // Thread-local scratch so the candidate buffer survives between calls
    // without reallocating, and so this stays safe to parallelize later.
    thread_local std::vector<size_t> matched_funcs{};
    matched_funcs.clear();

    // Walk the symbols at this address and keep the viable JAL candidates.
    if (matching_funcs_find != context.functions_by_vram.end()) {
        for (size_t target_func_index : matching_funcs_find->second) {
            const auto& target_func = context.functions[target_func_index];

            // A zero-word symbol is only usable here if it's a manual patch.
            if (target_func.words.empty()) {
                if (!N64Recomp::is_manual_patch_symbol(target_func.vram)) {
                    continue;
                }
            }

            // A target in our own section is guaranteed loaded whenever we
            // are, so take it outright and stop searching.
            if (target_func.section_index == cur_section_index) {
                exact_match_found = true;
                matched_funcs.clear();
                matched_funcs.push_back(target_func_index);
                break;
            }

            // Non-relocatable sections live at a fixed address, so their
            // functions are always safe to name directly — keep as candidate.
            const auto& target_func_section = context.sections[target_func.section_index];
            if (!target_func_section.relocatable) {
                matched_funcs.push_back(target_func_index);
            }
        }
    }

    // A target inside our own section may only resolve to an exact symbol.
    if (in_current_section) {
        if (exact_match_found) {
            matched_function_index = matched_funcs[0];
            return JalResolutionResult::Match;
        }
        // No symbol there — synthesize a static function at that address.
        else {
            return JalResolutionResult::CreateStatic;
        }
    }
    // Target lives elsewhere: pick a winner from the candidate set.
    else {
        // Nothing matched by symbol. Try to pin the target to the one section
        // whose address range contains it and emit a static function there.
        // This covers direct JALs from overlays into code that only carries
        // linker-script symbols — e.g. libultra helpers outside the caller.
        if (matched_funcs.size() == 0) {
            size_t containing_section = (size_t)-1;
            for (size_t section_index = 0; section_index < context.sections.size(); section_index++) {
                const auto& candidate_section = context.sections[section_index];
                const uint32_t section_start =
                    infer_recomp_section_encoded_vram_base(
                        context, section_index);
                const uint32_t section_end = section_start + candidate_section.size;
                const uint32_t candidate_link_start =
                    candidate_section.ram_addr;
                const uint32_t candidate_link_end =
                    candidate_link_start + candidate_section.size;
                if ((target_func_vram >= section_start &&
                     target_func_vram < section_end) ||
                    (target_func_vram >= candidate_link_start &&
                     target_func_vram < candidate_link_end)) {
                    if (containing_section != (size_t)-1) {
                        return JalResolutionResult::Ambiguous;
                    }
                    containing_section = section_index;
                }
            }

            if (containing_section != (size_t)-1) {
                for (size_t target_func_index = 0; target_func_index < context.functions.size(); target_func_index++) {
                    const auto& target_func = context.functions[target_func_index];
                    if (target_func.vram == target_func_vram &&
                        target_func.section_index == containing_section &&
                        (!target_func.words.empty() ||
                         target_func.reimplemented ||
                         N64Recomp::is_manual_patch_symbol(target_func.vram))) {
                        matched_function_index = target_func_index;
                        return JalResolutionResult::Match;
                    }
                }

                static_section_index = containing_section;
                return JalResolutionResult::CreateStatic;
            }

            return JalResolutionResult::NoMatch;
        }
        // Exactly one candidate — name it directly.
        else if (matched_funcs.size() == 1) {
            matched_function_index = matched_funcs[0];
            return JalResolutionResult::Match;
        }
        // Several candidates — defer to a runtime indirect lookup.
        else {
            return JalResolutionResult::Ambiguous;
        }
    }

    // Unreachable; present so every path returns a value.
    return JalResolutionResult::Error;
}

bool discover_static_code_entrypoint(
    const N64Recomp::Context& context,
    size_t section_index,
    uint32_t target_vram) {
    if (section_index >= context.sections.size()) {
        return false;
    }

    const auto& section = context.sections[section_index];
    if (!section.executable || (target_vram & 3u) != 0) {
        return false;
    }

    const uint32_t section_start =
        infer_recomp_section_encoded_vram_base(context, section_index);
    const uint32_t section_end = section_start + section.size;
    const uint32_t link_section_start = section.ram_addr;
    const uint32_t link_section_end = link_section_start + section.size;
    bool target_uses_encoded_base =
        target_vram >= section_start && target_vram < section_end;
    bool target_uses_link_base =
        target_vram >= link_section_start && target_vram < link_section_end;
    if (!target_uses_encoded_base && !target_uses_link_base) {
        return false;
    }
    const uint32_t decode_base =
        target_uses_encoded_base ? section_start : link_section_start;

    if (uint64_t(section.rom_addr) + uint64_t(section.size) > context.rom.size()) {
        return false;
    }

    size_t discovered_size = 0;
    std::string discover_error;
    if (!N64Recomp::discover_function_bounds(
            context.rom.data() + section.rom_addr,
            section.size,
            decode_base,
            target_vram - decode_base,
            discovered_size,
            discover_error)) {
        return false;
    }

    return discovered_size != 0;
}

bool section_has_backing_rom(const N64Recomp::Context& context, size_t section_index) {
    if (section_index >= context.sections.size()) {
        return false;
    }

    const auto& section = context.sections[section_index];
    return uint64_t(section.rom_addr) + uint64_t(section.size) <=
        context.rom.size();
}

bool static_entry_requested(
    std::span<std::vector<uint32_t>> static_funcs_out,
    size_t section_index,
    uint32_t target_vram) {
    if (section_index >= static_funcs_out.size()) {
        return false;
    }

    for (uint32_t static_vram : static_funcs_out[section_index]) {
        if (static_vram == target_vram) {
            return true;
        }
    }
    return false;
}

bool function_can_be_called_by_name(const N64Recomp::Function& func) {
    return func.reimplemented ||
        (!func.ignored && (!func.words.empty() || N64Recomp::is_manual_patch_symbol(func.vram)));
}

size_t find_callable_function_in_section(
    const N64Recomp::Context& context,
    uint32_t target_vram,
    size_t section_index) {
    auto find_it = context.functions_by_vram.find(target_vram);
    if (find_it == context.functions_by_vram.end()) {
        return (size_t)-1;
    }

    for (size_t function_index : find_it->second) {
        const auto& candidate = context.functions[function_index];
        if (candidate.section_index == section_index && function_can_be_called_by_name(candidate)) {
            return function_index;
        }
    }

    return (size_t)-1;
}

bool control_instruction_allows_fallthrough(const rabbitizer::InstructionCpu& instr) {
    using InstrId = rabbitizer::InstrId::UniqueId;
    const auto id = instr.getUniqueId();

    switch (id) {
    case InstrId::cpu_j:
    case InstrId::cpu_b:
    case InstrId::cpu_jr:
    case InstrId::cpu_syscall:
    case InstrId::cpu_break:
        return false;
    case InstrId::cpu_jalr:
        return int(instr.GetO32_rd()) == int(rabbitizer::Registers::Cpu::GprO32::GPR_O32_ra);
    default:
        return true;
    }
}

bool function_end_allows_fallthrough(const std::vector<rabbitizer::InstructionCpu>& instructions) {
    if (instructions.empty()) {
        return false;
    }

    const auto& last = instructions.back();
    if (instructions.size() >= 2) {
        const auto& previous = instructions[instructions.size() - 2];
        if (previous.isBranch() || previous.isJump()) {
            return control_instruction_allows_fallthrough(previous);
        }
    }

    if (last.isBranch() || last.isJump()) {
        return control_instruction_allows_fallthrough(last);
    }

    return control_instruction_allows_fallthrough(last);
}

using InstrId = rabbitizer::InstrId::UniqueId;
using Cop0Reg = rabbitizer::Registers::Cpu::Cop0;

std::string_view ctx_gpr_prefix(int reg) {
    if (reg != 0) {
        return "ctx->r";
    }
    return "";
}

template <typename GeneratorType>
bool process_instruction(GeneratorType& generator, const N64Recomp::Context& context, const N64Recomp::Function& func, size_t func_index, const N64Recomp::FunctionStats& stats, const std::unordered_set<uint32_t>& jtbl_lw_instructions, const std::set<uint32_t>& branch_labels, const std::set<uint32_t>& local_tailcall_labels, size_t instr_index, const std::vector<rabbitizer::InstructionCpu>& instructions, std::ostream& output_file, bool indent, bool emit_link_branch, int link_branch_index, size_t reloc_index, bool& needs_link_branch, bool& is_branch_likely, bool tag_reference_relocs, std::span<std::vector<uint32_t>> static_funcs_out) {
    using namespace N64Recomp;

    const auto& section = context.sections[func.section_index];
    const auto& instr = instructions[instr_index];
    needs_link_branch = false;
    is_branch_likely = false;
    uint32_t instr_vram = instr.getVram();
    InstrId instr_id = instr.getUniqueId();

#ifdef JIT_REPRO_TRACE
    {
        std::string _dis = instr.disassemble(0);
        std::fprintf(stderr, "[JITTRACE] idx=%zu vram=0x%08X id=%d : %s\n",
            instr_index, (unsigned)instr_vram, (int)instr_id, _dis.c_str());
        std::fflush(stderr);
    }
#endif

    auto indent_line = [&]() {
        fmt::print(output_file, "    ");
    };

    auto hook_find = func.function_hooks.find(instr_index);
    if (hook_find != func.function_hooks.end()) {
        fmt::print(output_file, "    {}\n", hook_find->second);
        if (indent) {
            indent_line();
        }
    }

    // Prefix the translated code with a comment showing the source instruction.
    // Branch/jump targets are rendered symbolically so the comment matches the
    // emitted label names.
    indent_line();
    if (instr.isBranch() || instr_id == InstrId::cpu_j) {
        generator.emit_comment(fmt::format("0x{:08X}: {}", instr_vram, instr.disassemble(0, fmt::format("L_{:08X}", (uint32_t)instr.getBranchVramGeneric()))));
    } else if (instr_id == InstrId::cpu_jal) {
        generator.emit_comment(fmt::format("0x{:08X}: {}", instr_vram, instr.disassemble(0, fmt::format("0x{:08X}", (uint32_t)instr.getBranchVramGeneric()))));
    } else {
        generator.emit_comment(fmt::format("0x{:08X}: {}", instr_vram, instr.disassemble(0)));
    }

    // For a load that reads a jump-table entry, rewrite it as an addiu so the
    // output register ends up holding the ENTRY's address rather than its
    // value. That address later yields the offset into the jump table.
    if (jtbl_lw_instructions.contains(instr_vram)) {
        assert(instr_id == InstrId::cpu_lw);
        instr_id = InstrId::cpu_addiu;
    }

    N64Recomp::RelocType reloc_type = N64Recomp::RelocType::R_MIPS_NONE;
    bool has_reloc = false;
    uint32_t reloc_section = 0;
    uint32_t reloc_target_section_offset = 0;
    size_t reloc_reference_symbol = (size_t)-1;

    uint32_t func_vram_end = func.vram + func.words.size() * sizeof(func.words[0]);

    auto get_local_tailcall_labels = [&]() {
        std::set<uint32_t> ret;
        for (uint32_t target : local_tailcall_labels) {
            if (target >= func.vram && target < func_vram_end) {
                ret.insert(target);
            }
        }
        return ret;
    };
    auto get_call_return_label = [&]() {
        const uint32_t ret = instr_vram + 8;
        return branch_labels.contains(ret) ? ret : 0u;
    };
    uint16_t imm = instr.Get_immediate();

    // Pull in relocation data if a reloc is attached to this instruction.
    if (section.relocs.size() > 0 && section.relocs[reloc_index].address == instr_vram) {
        has_reloc = true;
        const auto& reloc = section.relocs[reloc_index];
        reloc_section = reloc.target_section;

        // BSS-targeted relocs (e.g. .fragment34_bss) need to be
        // remapped to the parent code section BEFORE the relocatable
        // check below — bss reference sections are not themselves
        // marked relocatable, but their parent text sections are.
        // Without this remap, a HI16/LO16 pair targeting a bss
        // counterpart of a relocatable text section is silently
        // dropped (target_relocatable=false) and the lui/addiu emit
        // as link-time literals. At runtime, when the parent text
        // section is loaded at a non-canonical address, those
        // literal addresses miss the section's actual location.
        // Producer/consumer asymmetry (e.g. fragment62 writes
        // D_8140E720 via literal link addr, fragment34 reads via
        // RELOC against runtime base) → near-NULL deref.
        //
        // The reloc's target_section_offset is RELATIVE to the bss
        // section's link vram. After remapping to the parent text
        // section, we must add (bss_vram - parent_vram) so the
        // offset stays relative to the new (parent) base — bss
        // typically starts at parent + parent_text_size.
        uint32_t bss_remap_offset_adjustment = 0;
        auto find_bss_it = context.bss_section_to_section.find(reloc_section);
        if (find_bss_it != context.bss_section_to_section.end()) {
            const auto& bss_section = context.sections[reloc_section];
            const auto& parent_section = context.sections[find_bss_it->second];
            bss_remap_offset_adjustment =
                uint32_t(bss_section.ram_addr) - uint32_t(parent_section.ram_addr);
            reloc_section = find_bss_it->second;
        }

        // SectionAbsolute → relocatable-section remap. When splat marks
        // a symbol as undefined (e.g. D_8140DD78 = 0x8140DD78 lives in
        // undefined_syms_auto.ld), the elf parser writes
        // target_section = SectionAbsolute and target_section_offset =
        // the symbol's literal vram. Without remapping, the HI16/LO16
        // emit path below treats it as a non-relocatable reference and
        // bakes in the link-time literal. At runtime, when the symbol's
        // containing fragment is loaded at a non-canonical address, the
        // access misses by the relocation delta — same bug pattern as
        // the BSS-remap case (producer/consumer asymmetry: properly
        // resolved peers get RELOC, this one gets a literal).
        //
        // Walk the registered relocatable sections; if the absolute
        // value falls inside one, redirect the reloc to that section.
        // The downstream relocatable check then treats it correctly.
        if (reloc_section == N64Recomp::SectionAbsolute && !reloc.reference_symbol) {
            const uint32_t abs_value = uint32_t(reloc.target_section_offset);
            for (size_t si = 0; si < context.sections.size(); si++) {
                const auto& s = context.sections[si];
                if (!s.relocatable) continue;
                const uint32_t s_start = uint32_t(s.ram_addr);
                const uint32_t s_end = s_start + uint32_t(s.size);
                // Use STRICT > for the lower bound. References to the EXACT
                // section base (abs_value == s_start) are typically arithmetic
                // constants — e.g. PokemonStadium's fragment-id derivation
                //   `((D_8D000000 & 0x0FF00000) >> 20) - 0x10`
                // where D_8D000000 is the link base of section 380. If we
                // remap such a reference, the LUI loads the runtime base of
                // the section instead of the literal 0x8D000000, and the
                // bit-arithmetic produces garbage (not the intended id 0xC0).
                // Real fragment-internal data references (the original
                // 2026-05-03 case D_8140DD78 = 0x8140DD78) have abs_value
                // strictly past s_start, so they still get remapped correctly.
                if (abs_value > s_start && abs_value < s_end) {
                    reloc_section = uint32_t(si);
                    // The downstream code computes
                    //   reloc_target_section_offset =
                    //     reloc.target_section_offset + bss_remap_offset_adjustment;
                    // For ABS, reloc.target_section_offset is the literal
                    // vram (e.g. 0x8140DD78). To get the offset within
                    // the new section base s_start, subtract s_start by
                    // adding -s_start into the same adjustment slot
                    // (bss/abs paths are mutually exclusive — bss_remap
                    // is 0 here because target wasn't a bss section).
                    bss_remap_offset_adjustment = uint32_t(0) - s_start;
                    break;
                }
            }
        }

        // Determine whether the reloc points into a relocatable section.
        bool target_relocatable = false;
        if (!reloc.reference_symbol && reloc_section != N64Recomp::SectionAbsolute) {
            const auto& target_section = context.sections[reloc_section];
            target_relocatable = target_section.relocatable;

            // Section-base reference exclusion. If a HI16/LO16 reloc points
            // EXACTLY at the relocatable section's base (target_section_offset
            // == 0 after any bss/abs adjustment), the source code is
            // overwhelmingly using this as an ARITHMETIC CONSTANT (not as a
            // pointer to runtime data). PokemonStadium has e.g.:
            //
            //   func_80004454((((u32)&D_81000000 & 0x0FF00000) >> 0x14) - 0x10, ...)
            //
            // where D_81000000 IS the link base of fragment31. The linker
            // resolves the reloc to fragment31's section, but the source
            // intent is the literal 0x81000000 used to derive a fragment id
            // via bit-arithmetic. If we relocate this to the runtime base,
            // the bit-math computes a garbage id and Stadium then writes
            // gFragments[garbage_id] which can clobber gSegments via
            // out-of-bounds (gFragments[-15] aliases gSegments[1]).
            //
            // Concrete fix: emit literal for offset==0 references. The
            // legitimate "I want the runtime base of this section as a
            // pointer" case is rare in practice; Stadium uses
            // Memmap_GetFragmentVaddr/Memmap_GetSegmentVaddr functions for
            // that, not direct LUI/ADDIU at offset 0.
            if (target_relocatable
                && (reloc.type == N64Recomp::RelocType::R_MIPS_HI16
                    || reloc.type == N64Recomp::RelocType::R_MIPS_LO16)) {
                const uint32_t adjusted_offset =
                    uint32_t(reloc.target_section_offset) + bss_remap_offset_adjustment;
                if (adjusted_offset == 0) {
                    target_relocatable = false;
                }
            }
        }

        // Act on the reloc only when it lands in a relocatable section or names
        // a reference symbol; otherwise leave it as a baked-in literal.
        if (target_relocatable || reloc.reference_symbol) {
            // Capture the reloc fields we will act on.
            reloc_type = reloc.type;
            reloc_target_section_offset = reloc.target_section_offset + bss_remap_offset_adjustment;
            // We only handle MIPS_HI16, MIPS_LO16 and MIPS_26; skip the rest.
            if (reloc_type == N64Recomp::RelocType::R_MIPS_HI16 || reloc_type == N64Recomp::RelocType::R_MIPS_LO16 || reloc_type == N64Recomp::RelocType::R_MIPS_26) {
                if (reloc.reference_symbol) {
                    reloc_reference_symbol = reloc.symbol_index;
                    // Special section symbols must not be relocated.
                    if (context.is_regular_reference_section(reloc.target_section) || reloc_section == N64Recomp::SectionAbsolute) {
                        // TODO this may not be needed anymore as HI16/LO16 relocs to non-relocatable sections is handled directly in elf parsing.
                        bool ref_section_relocatable = context.is_reference_section_relocatable(reloc.target_section);
                        // For HI16/LO16 references into a non-relocatable section, fold the
                        // address straight into the instruction immediate instead.
                        if (!ref_section_relocatable && (reloc_type == N64Recomp::RelocType::R_MIPS_HI16 || reloc_type == N64Recomp::RelocType::R_MIPS_LO16)) {
                            // Clear the reloc now that it's handled so code generation
                            // doesn't apply it a second time.
                            reloc_type = N64Recomp::RelocType::R_MIPS_NONE;
                            reloc_reference_symbol = (size_t)-1;
                        }
                    }
                }
            }

            // (bss → parent remap moved above the target_relocatable
            // check; this block was its original home.)
        }
    }

    auto emit_delay_slot = [&](bool use_indent) {
        if (instr_index >= instructions.size() - 1) {
            // The branch/jump at the FINAL word of the function has its delay
            // slot outside the function's word range. Emitting the branch
            // without its delay slot is a silent miscompile — the skipped
            // instruction's effect simply vanishes (observed in Pocket
            // Monsters Stadium: a Yay0 decompressor whose `b` delay slot
            // `addi t3, t3, 0x12` was cut off by a too-small function size,
            // turning a bounded copy loop into a 4-billion-iteration rdram
            // scribble). The function's size in the symbols input is wrong —
            // refuse to generate and name the exact fix.
            fmt::print(stderr,
                "[Error] Function {} ends with a branch/jump at 0x{:08X} whose delay slot "
                "(0x{:08X}) is outside the function bounds — the function's size in the "
                "symbols file is too small (truncated by at least one instruction). "
                "Extend the function size to include the delay slot.\n",
                func.name, instr_vram, instr_vram + 4);
            return false;
        }
        {
            bool dummy_needs_link_branch;
            bool dummy_is_branch_likely;
            size_t next_reloc_index = reloc_index;
            uint32_t next_vram = instr_vram + 4;
            if (reloc_index + 1 < section.relocs.size() && next_vram > section.relocs[reloc_index].address) {
                next_reloc_index++;
            }
            if (!process_instruction(generator, context, func, func_index, stats, jtbl_lw_instructions, branch_labels, local_tailcall_labels, instr_index + 1, instructions, output_file, use_indent, false, link_branch_index, next_reloc_index, dummy_needs_link_branch, dummy_is_branch_likely, tag_reference_relocs, static_funcs_out)) {
                return false;
            }
        }
        return true;
    };

    auto emit_link_continuation = [&]() {
        if (needs_link_branch) {
            indent_line();
            generator.emit_goto(fmt::format("after_{}", link_branch_index));
        }
    };

    auto emit_jr_ra_return = [&]() {
        const std::string jr_target_var = fmt::format("jr_target_{:08X}", instr_vram);
        indent_line();
        fmt::print(output_file, "{{\n");
        indent_line();
        fmt::print(output_file, "gpr {} = ctx->r31;\n", jr_target_var);
        if (!emit_delay_slot(false)) {
            return false;
        }
        bool emitted_local_dispatch = false;
        const std::string jr_target_vram_var = fmt::format("jr_target_vram_{:08X}", instr_vram);
        indent_line();
        fmt::print(output_file, "uint32_t {} = U32({});\n", jr_target_vram_var, jr_target_var);
        indent_line();
        fmt::print(output_file, "{{\n");
        indent_line();
        fmt::print(output_file, "uint32_t jr_section_base = (uint32_t)section_addresses[{}];\n", func.section_index);
        indent_line();
        fmt::print(output_file,
            "uint32_t jr_section_offset = {} - jr_section_base;\n",
            jr_target_vram_var);
        indent_line();
        fmt::print(output_file,
            "if (jr_section_base != 0x{:08X}u && jr_section_offset < 0x{:08X}u) {{\n",
            section.ram_addr, section.size);
        indent_line();
        fmt::print(output_file,
            "{} = 0x{:08X}u + jr_section_offset;\n",
            jr_target_vram_var, section.ram_addr);
        indent_line();
        fmt::print(output_file, "}}\n");
        indent_line();
        fmt::print(output_file, "}}\n");
        for (uint32_t label_vram : branch_labels) {
            if (label_vram >= func.vram && label_vram < func_vram_end) {
                if (!emitted_local_dispatch) {
                    indent_line();
                    fmt::print(output_file, "switch ({}) {{\n", jr_target_vram_var);
                    emitted_local_dispatch = true;
                }
                indent_line();
                fmt::print(output_file, "case 0x{:08X}u: goto L_{:08X};\n", label_vram, label_vram);
            }
        }
        if (emitted_local_dispatch) {
            indent_line();
            fmt::print(output_file, "default: break;\n");
            indent_line();
            fmt::print(output_file, "}}\n");
        }
        indent_line();
        fmt::print(output_file, "if ({} != ctx->host_return_target) {{\n", jr_target_vram_var);
        indent_line();
        fmt::print(output_file, "    recomp_request_tailcall(ctx, (gpr)(int32_t){});\n", jr_target_vram_var);
        if (context.trace_mode) {
            indent_line();
            fmt::print(output_file, "    TRACE_RETURN()\n");
        }
        indent_line();
        fmt::print(output_file, "    return;\n");
        indent_line();
        fmt::print(output_file, "}}\n");
        indent_line();
        generator.emit_return(context, func_index);
        indent_line();
        fmt::print(output_file, "}}\n");
        emit_link_continuation();
        return true;
    };

    auto emit_goto_with_slot = [&](const std::string& target) {
        if (!emit_delay_slot(false)) {
            return false;
        }
        indent_line();
        generator.emit_goto(target);
        emit_link_continuation();
        return true;
    };

    auto emit_call_by_register = [&](int reg) {
        if (!emit_delay_slot(false)) {
            return false;
        }
        indent_line();
        generator.emit_function_call_by_register(reg, get_local_tailcall_labels(), get_call_return_label());
        emit_link_continuation();
        return true;
    };

    auto gpr_expr = [](int reg) {
        return reg == 0 ? std::string{"0"} : fmt::format("ctx->r{}", reg);
    };

    auto emit_trace_return = [&]() {
        if (context.trace_mode) {
            indent_line();
            fmt::print(output_file, "TRACE_RETURN()\n");
        }
    };

    auto emit_tailcall_by_register = [&](int reg) {
        if (!emit_delay_slot(false)) {
            return false;
        }
        indent_line();
        fmt::print(output_file, "recomp_request_tailcall(ctx, (gpr)(int32_t){});\n", gpr_expr(reg));
        emit_trace_return();
        indent_line();
        fmt::print(output_file, "return;\n");
        return true;
    };

    auto emit_tailcall_by_address = [&](uint32_t target_vram) {
        if (!emit_delay_slot(false)) {
            return false;
        }
        indent_line();
        fmt::print(output_file, "if (0x{:08X}u == ctx->host_return_target) {{\n", target_vram);
        if (context.trace_mode) {
            indent_line();
            fmt::print(output_file, "    TRACE_RETURN()\n");
        }
        indent_line();
        fmt::print(output_file, "    return;\n");
        indent_line();
        fmt::print(output_file, "}}\n");
        indent_line();
        fmt::print(output_file, "recomp_request_tailcall(ctx, (gpr)(int32_t)0x{:08X}u);\n", target_vram);
        emit_trace_return();
        indent_line();
        fmt::print(output_file, "return;\n");
        return true;
    };

    auto emit_tailcall_by_function = [&](const std::string& target_name, uint32_t target_vram) {
        if (!emit_delay_slot(false)) {
            return false;
        }
        indent_line();
        fmt::print(output_file, "if (0x{:08X}u == ctx->host_return_target) {{\n", target_vram);
        if (context.trace_mode) {
            indent_line();
            fmt::print(output_file, "    TRACE_RETURN()\n");
        }
        indent_line();
        fmt::print(output_file, "    return;\n");
        indent_line();
        fmt::print(output_file, "}}\n");
        indent_line();
        fmt::print(output_file, "recomp_request_tailcall_func_target(ctx, {}, 0x{:08X}u);\n", target_name, target_vram);
        emit_trace_return();
        indent_line();
        fmt::print(output_file, "return;\n");
        return true;
    };

    auto emit_call_by_address = [&generator, reloc_target_section_offset, has_reloc, reloc_section, reloc_reference_symbol, reloc_type, &context, &func, &static_funcs_out, &needs_link_branch, &indent_line, &emit_delay_slot, &emit_link_continuation, &output_file, instr_vram, &get_local_tailcall_labels, &get_call_return_label]
        (uint32_t target_func_vram, bool tail_call = false, bool indent = false)
    {
        bool call_by_lookup = false;
        bool call_by_name = false;
        // Event symbol, emit a call to the runtime to trigger this event.
        if (reloc_section == N64Recomp::SectionEvent) {
            needs_link_branch = !tail_call;
            if (indent) {
                indent_line();
            }
            if (!emit_delay_slot(false)) {
                return false;
            }
            indent_line();
            generator.emit_trigger_event((uint32_t)reloc_reference_symbol);
            emit_link_continuation();
        }
        // Normal symbol or reference symbol, 
        else {
            std::string jal_target_name{};
            size_t matched_func_index = (size_t)-1;
            if (reloc_reference_symbol != (size_t)-1) {
                if (reloc_type != N64Recomp::RelocType::R_MIPS_26) {
                    fmt::print(stderr, "Unsupported reloc type {} on jal instruction in {}\n", (int)reloc_type, func.name);
                    return false;
                }

                if (!context.skip_validating_reference_symbols) {
                    const auto& ref_symbol = context.get_reference_symbol(reloc_section, reloc_reference_symbol);
                    if (ref_symbol.section_offset != reloc_target_section_offset) {
                        fmt::print(stderr, "Function {} uses a MIPS_R_26 addend, which is not supported yet\n", func.name);
                        return false;
                    }
                }
            }
            else {
                uint32_t target_section = func.section_index;
                // Only override target_section when the reloc points at a real
                // section. SectionAbsolute / SectionImport / SectionEvent are
                // special sentinels (negative when interpreted signed) and
                // would index context.sections out of bounds — observed when
                // marking Stadium's .fragment1 relocatable, which surfaces
                // R_MIPS_26 relocs whose ELF symbol lives in SHN_ABS (the
                // absolute address is already encoded in the JAL immediate,
                // so the in-section function lookup against the caller's
                // section is the right fallback).
                if (has_reloc && reloc_section < context.sections.size()) {
                    target_section = reloc_section;
                }
                size_t static_section_index = target_section;
                JalResolutionResult jal_result = resolve_jal(context, target_section, target_func_vram, matched_func_index, static_section_index);

                switch (jal_result) {
                    case JalResolutionResult::NoMatch:
                        // No symbol found for this jal target. Instead of failing
                        // the whole recompile (which would block ~hundreds of
                        // downstream functions for one missing symbol), emit a
                        // runtime call that aborts loudly with diagnostic info.
                        // The function still compiles; only the unsupported call
                        // path crashes if reached. This is NOT a stub — no
                        // behavior is simulated; the call is left as an
                        // unimplementable hole that surfaces at runtime with
                        // full context.
                        fmt::print(stderr, "[Warn] No function found for jal target 0x{:08X} in {} — emitting runtime abort\n", target_func_vram, func.name);
                        if (indent) fmt::print(output_file, "    ");
                        fmt::print(output_file, "    recomp_unhandled_call(rdram, ctx, 0x{:08X}u, 0x{:08X}u);\n", instr_vram, target_func_vram);
                        return true;
                    case JalResolutionResult::Match:
                        jal_target_name = context.functions[matched_func_index].name;
                        break;
                    case JalResolutionResult::CreateStatic:
                        // Create a static function add it to the static function list for this section.
                        jal_target_name = fmt::format("static_{}_{:08X}", static_section_index, target_func_vram);
                        static_funcs_out[static_section_index].push_back(target_func_vram);
                        call_by_name = true;
                        break;
                    case JalResolutionResult::Ambiguous:
                        // Print a warning if lookup isn't forced for all non-reloc function calls.
                        if (!context.use_lookup_for_all_function_calls) {
                            fmt::print(stderr, "[Info] Ambiguous jal target 0x{:08X} in function {}, falling back to function lookup\n", target_func_vram, func.name);
                        }
                        // Relocation isn't necessary for jumps inside a relocatable section, as this code path will never run if the target vram
                        // is in the current function's section (see the branch for `in_current_section` above).
                        // If a game ever needs to jump between multiple relocatable sections, relocation will be necessary here.
                        call_by_lookup = true;
                        break;
                    case JalResolutionResult::Error:
                        fmt::print(stderr, "Internal error when resolving jal to address 0x{:08X} in function {}. Please report this issue.\n", target_func_vram, func.name);
                        return false;
                }
            }
            needs_link_branch = !tail_call;
            if (indent) {
                indent_line();
            }
            if (!emit_delay_slot(false)) {
                return false;
            }
            indent_line();
            if (reloc_reference_symbol != (size_t)-1) {
                generator.emit_function_call_reference_symbol(context, reloc_section, reloc_reference_symbol, reloc_target_section_offset, get_local_tailcall_labels(), get_call_return_label());
            }
            else if (call_by_lookup) {
                generator.emit_function_call_lookup(target_func_vram, get_local_tailcall_labels(), get_call_return_label());
            }
            else if (call_by_name) {
                generator.emit_named_function_call(jal_target_name, get_local_tailcall_labels(), get_call_return_label());
            }
            else {
                generator.emit_function_call(context, matched_func_index, get_local_tailcall_labels(), get_call_return_label());
            }
            emit_link_continuation();
        }
        return true;
    };

    auto emit_branch_tree = [&](uint32_t branch_target) {
        // If the branch target is outside the current function, check if it can be treated as a tail call.
        if (branch_target < func.vram || branch_target >= func_vram_end) {
            size_t matched_func_index = (size_t)-1;
            size_t static_section_index = func.section_index;
            JalResolutionResult branch_result = resolve_jal(
                context, func.section_index, branch_target,
                matched_func_index, static_section_index);
            bool target_contained_in_function = false;
            if (static_section_index < context.section_functions.size()) {
                for (size_t target_func_index : context.section_functions[static_section_index]) {
                    const auto& target_func = context.functions[target_func_index];
                    if (target_func.words.empty()) {
                        continue;
                    }

                    uint32_t target_func_end = target_func.vram + uint32_t(target_func.words.size() * sizeof(target_func.words[0]));
                    if (branch_target > target_func.vram && branch_target < target_func_end) {
                        target_contained_in_function = true;
                        break;
                    }
                }
            }
            const bool can_create_static_branch =
                branch_result == JalResolutionResult::CreateStatic &&
                static_section_index < context.sections.size() &&
                section_has_backing_rom(context, static_section_index) &&
                (target_contained_in_function ||
                 static_entry_requested(static_funcs_out, static_section_index, branch_target) ||
                 (context.sections[static_section_index].relocatable &&
                  discover_static_code_entrypoint(context, static_section_index, branch_target)));
            if (branch_result == JalResolutionResult::Match ||
                can_create_static_branch ||
                branch_result == JalResolutionResult::Ambiguous) {
                const char* resolution_name =
                    branch_result == JalResolutionResult::Match ? "function" :
                    (branch_result == JalResolutionResult::CreateStatic ? "static continuation" : "function lookup");
                fmt::print(
                    "[Info] Tail branch in {} to 0x{:08X} resolved through {}\n",
                    func.name,
                    branch_target,
                    resolution_name);
                if (branch_result == JalResolutionResult::Match) {
                    if (!emit_tailcall_by_function(context.functions[matched_func_index].name, branch_target)) {
                        return false;
                    }
                }
                else if (can_create_static_branch) {
                    std::string static_target_name = fmt::format("static_{}_{:08X}", static_section_index, branch_target);
                    static_funcs_out[static_section_index].push_back(branch_target);
                    if (!emit_tailcall_by_function(static_target_name, branch_target)) {
                        return false;
                    }
                }
                else {
                    if (!emit_tailcall_by_address(branch_target)) {
                        return false;
                    }
                }
                return true;
            }

            // Branch out of function with no symbol at target. Emit a
            // runtime abort instead of `goto L_<vram>` to a label that
            // never exists. No stub — an unimplementable hole surfaced
            // loudly at runtime.
            fmt::print(stderr, "[Warn] Function {} is branching outside of the function (to 0x{:08X}) — emitting runtime abort\n", func.name, branch_target);
            if (!emit_delay_slot(true)) {
                return false;
            }
            indent_line();
            indent_line();
            fmt::print(output_file, "recomp_unhandled_branch(rdram, ctx, 0x{:08X}u, 0x{:08X}u);\n", instr_vram, branch_target);
            indent_line();
            indent_line();
            generator.emit_return(context, func_index);
            return true;
        }

        if (!emit_delay_slot(true)) {
            return false;
        }

        // Voluntary-preemption checkpoint on loop back-edges. A tight
        // intra-function loop (branch target at or before this branch)
        // never re-enters a function, so the function-entry TRACE_ENTRY
        // tick never fires inside it — the thread can spin forever and
        // starve the cooperative scheduler (e.g. Pokemon Stadium's GB
        // Tower osGbpakInit power-up busy-wait, or an idle thread's
        // while(1) starving external-message drain into a black-screen
        // boot deadlock).
        //
        // Emitted UNCONDITIONALLY: this is cooperative-scheduler
        // correctness, not tracing. It was previously gated by
        // trace_mode "to mirror TRACE_ENTRY's emission", which made
        // games built with trace_mode=false deadlock the moment every
        // guest thread blocked while one spun (Pocket Monsters Stadium
        // first-boot, 2026-06). trace_mode now gates only the logging
        // hooks. The default RECOMP_LOOP_CHECKPOINT_VRAM lives in
        // recomp.h and routes to ultramodern_scheduler_tick_vram();
        // consumers may redefine it, but it must remain a real yield
        // point.
        if (branch_target <= instr_vram) {
            indent_line();
            indent_line();
            fmt::print(output_file, "RECOMP_LOOP_CHECKPOINT_VRAM(0x{:08X}u)\n", instr_vram);
        }

        indent_line();
        indent_line();
        generator.emit_goto(fmt::format("L_{:08X}", branch_target));
        // TODO check if this link branch ever exists.
        if (needs_link_branch) {
            indent_line();
            indent_line();
            generator.emit_goto(fmt::format("after_{}", link_branch_index));
        }
        return true;
    };

    if (indent) {
        indent_line();
    }

    int rd = (int)instr.GetO32_rd();
    int rs = (int)instr.GetO32_rs();
    int rt = (int)instr.GetO32_rt();
    int sa = (int)instr.Get_sa();

    int fd = (int)instr.GetO32_fd();
    int fs = (int)instr.GetO32_fs();
    int ft = (int)instr.GetO32_ft();

    int cop1_cs = (int)instr.Get_cop1cs();

    bool handled = true;

    switch (instr_id) {
    case InstrId::cpu_nop:
        fmt::print(output_file, "\n");
        break;
    // `cache op, offset(base)` — collapses to nothing here. The recompiled
    // target has no CPU cache to flush or invalidate, and the instruction
    // touches neither registers nor memory, so it has no observable effect.
    // It shows up in libultra cache routines (osInvalDCache /
    // osWritebackDCache / osInvalICache) and in game code priming DMA source
    // buffers. Emitting a nop is the correct HLE choice for the same reason
    // the cop0 status/cause storage path is: we don't model the hardware
    // subsystem the instruction is addressing.
    case InstrId::cpu_cache:
        fmt::print(output_file, "\n");
        break;
    // COP0 register access.
    //
    // The register is routed explicitly rather than through a catch-all:
    //   - Status (12)           -> a dedicated helper (FR + interrupt enable)
    //   - Reserved (21..25, 31) -> a loud abort (genuinely undefined access)
    //   - all others            -> plain ctx->cop0_regs[reg] storage
    //
    // Backing the remaining registers with storage is the right HLE model:
    // their real semantics hang off subsystems we never simulate (TLB,
    // cache, exception entry, debug watchpoints). The per-register rationale
    // lives next to the cop0_regs[32] declaration in include/recomp.h.
    //
    // If a title ever needs a register with an actual side effect (reading
    // Count for elapsed time, reading Cause for pending IRQs, writing
    // Compare to ack a timer), give THAT register its own helper here rather
    // than quietly broadening the storage path.
    case InstrId::cpu_mfc0:
        {
            Cop0Reg reg = instr.Get_cop0d();
            int reg_index = (int)reg;
            if (reg == Cop0Reg::COP0_Status) {
                indent_line();
                generator.emit_cop0_status_read(rt);
            } else if ((reg_index >= 21 && reg_index <= 25) || reg_index == 31) {
                // These indices are reserved on hardware — a true
                // "can't happen" read. Surface it loudly.
                fmt::print(stderr, "[Warn] mfc0 from reserved cop0 register {} — emitting runtime abort\n", reg_index);
                indent_line();
                fmt::print(output_file, "ctx->r{} = recomp_unhandled_cop0_read(rdram, ctx, 0x{:08X}u, {});\n",
                    (int)rt, instr_vram, reg_index);
            } else {
                // Plain storage read, sign-extended into the 64-bit gpr
                // exactly as the former default path did for non-Status regs.
                indent_line();
                fmt::print(output_file, "ctx->r{} = (int32_t)ctx->cop0_regs[{}];\n",
                    (int)rt, reg_index);
            }
            break;
        }
    case InstrId::cpu_mtc0:
        {
            Cop0Reg reg = instr.Get_cop0d();
            int reg_index = (int)reg;
            if (reg == Cop0Reg::COP0_Status) {
                indent_line();
                generator.emit_cop0_status_write(rt);
            } else if ((reg_index >= 21 && reg_index <= 25) || reg_index == 31) {
                fmt::print(stderr, "[Warn] mtc0 to reserved cop0 register {} — emitting runtime abort\n", reg_index);
                indent_line();
                fmt::print(output_file, "recomp_unhandled_cop0_write(rdram, ctx, 0x{:08X}u, {}, ctx->r{});\n",
                    instr_vram, reg_index, (int)rt);
            } else {
                indent_line();
                fmt::print(output_file, "ctx->cop0_regs[{}] = (uint32_t)ctx->r{};\n",
                    reg_index, (int)rt);
            }
            break;
        }
    // Arithmetic
    case InstrId::cpu_add:
    case InstrId::cpu_addu:
        {
            // Does this addu form part of a jump-table address computation?
            auto find_result = std::find_if(stats.jump_tables.begin(), stats.jump_tables.end(),
                [instr_vram](const N64Recomp::JumpTable& jtbl) {
                return jtbl.addu_vram == instr_vram;
            });
            // If so, stash the addend register's value in a temporary first.
            if (find_result != stats.jump_tables.end()) {
                const N64Recomp::JumpTable& cur_jtbl = *find_result;
                indent_line();
                generator.emit_jtbl_addend_declaration(cur_jtbl, cur_jtbl.addend_reg);
            }
        }
        break;
    case InstrId::cpu_mult:
    case InstrId::cpu_dmult:
    case InstrId::cpu_multu:
    case InstrId::cpu_dmultu:
    case InstrId::cpu_div:
    case InstrId::cpu_ddiv:
    case InstrId::cpu_divu:
    case InstrId::cpu_ddivu:
        indent_line();
        generator.emit_muldiv(instr_id, rs, rt);
        break;
    // Branches
    case InstrId::cpu_jal:
        // The MIPS link write ($ra := PC+8) is committed before the delay
        // slot runs. Handwritten code that derives addresses from $ra relies
        // on this ordering (e.g. Stadium's audio synth doing
        // `addiu $t3, $ra, OFFSET` as a PC-arithmetic trick).
        indent_line();
        {
            uint32_t link_target = instr_vram + 8;
            fmt::print(output_file, "ctx->r31 = 0x{:08X}u;\n", link_target);

            uint64_t section_start = section.ram_addr;
            uint64_t section_end = section_start + section.size;
            if (link_target >= section_start && link_target < section_end) {
                static_funcs_out[func.section_index].push_back(link_target);
            }
        }
        {
            const uint32_t branch_target = instr.getBranchVramGeneric();
            if (branch_target >= func.vram && branch_target < func_vram_end) {
                if (!emit_goto_with_slot(fmt::format("L_{:08X}", branch_target))) {
                    return false;
                }
            }
            else if (!emit_call_by_address(branch_target)) {
                return false;
            }
        }
        break;
    case InstrId::cpu_jalr:
        if (rd != (int)rabbitizer::Registers::Cpu::GprO32::GPR_O32_ra) {
            uint32_t link_target = instr_vram + 8;

            if (rd != 0) {
                indent_line();
                fmt::print(output_file, "ctx->r{} = 0x{:08X}u;\n", rd, link_target);

                uint64_t section_start = section.ram_addr;
                uint64_t section_end = section_start + section.size;
                if (link_target >= section_start && link_target < section_end) {
                    static_funcs_out[func.section_index].push_back(link_target);
                }
            }

            if (!emit_tailcall_by_register(rs)) {
                return false;
            }
            break;
        }
        // MIPS link side-effect: $ra := PC+8 (see cpu_jal comment).
        indent_line();
        {
            uint32_t link_target = instr_vram + 8;
            fmt::print(output_file, "ctx->r31 = 0x{:08X}u;\n", link_target);

            uint64_t section_start = section.ram_addr;
            uint64_t section_end = section_start + section.size;
            if (link_target >= section_start && link_target < section_end) {
                static_funcs_out[func.section_index].push_back(link_target);
            }
        }
        needs_link_branch = true;
        // Propagate failure (delay-slot-out-of-bounds guard) — see cpu_jr.
        if (!emit_call_by_register(rs)) {
            return false;
        }
        break;
    case InstrId::cpu_j:
    case InstrId::cpu_b:
        {
            uint32_t branch_target = instr.getBranchVramGeneric();
            if (branch_target == instr_vram) {
                indent_line();
                generator.emit_pause_self();
            }
            else {
                if (!emit_branch_tree(branch_target)) {
                    return false;
                }
            }
        }
        break;
    case InstrId::cpu_jr:
        if (rs == (int)rabbitizer::Registers::Cpu::GprO32::GPR_O32_ra) {
            // Bubble the failure up (e.g. emit_delay_slot's
            // delay-slot-out-of-bounds guard). Swallowing it used to drop the
            // jr-ra delay slot for any function whose symbols-file size cut it
            // off — frequently a load-bearing instruction (sp restore, return
            // value), which is a silent miscompile.
            if (!emit_jr_ra_return()) {
                return false;
            }
        } else {
            auto jtbl_find_result = std::find_if(stats.jump_tables.begin(), stats.jump_tables.end(),
                [instr_vram](const N64Recomp::JumpTable& jtbl) {
                    return jtbl.jr_vram == instr_vram;
                });

            if (jtbl_find_result != stats.jump_tables.end()) {
                const N64Recomp::JumpTable& cur_jtbl = *jtbl_find_result;
                if (!emit_delay_slot(false)) {
                    return false;
                }
                indent_line();
                generator.emit_switch(context, cur_jtbl, rs);
                for (size_t entry_index = 0; entry_index < cur_jtbl.entries.size(); entry_index++) {
                    indent_line();
                    indent_line();
                    generator.emit_case(entry_index, fmt::format("L_{:08X}", cur_jtbl.entries[entry_index]));
                }
                indent_line();
                indent_line();
                generator.emit_switch_error(instr_vram, cur_jtbl.vram);
                indent_line();
                generator.emit_switch_close();
                break;
            }

            fmt::print("[Info] Indirect tail call in {}\n", func.name);
            uint32_t fallthrough_target = instr_vram + 8;
            if (fallthrough_target > func.vram && fallthrough_target < func_vram_end) {
                size_t fallthrough_index = (fallthrough_target - func.vram) / sizeof(uint32_t);
                if (fallthrough_index < instructions.size() && instructions[fallthrough_index].isValid()) {
                    static_funcs_out[func.section_index].push_back(fallthrough_target);
                }
            }
            emit_tailcall_by_register(rs);
            break;
        }
        break;
    case InstrId::cpu_syscall:
        indent_line();
        generator.emit_syscall(instr_vram);
        // A syscall doesn't set a link register, so wind up like a tail call.
        indent_line();
        generator.emit_return(context, func_index);
        break;
    case InstrId::cpu_break:
        indent_line();
        generator.emit_do_break(instr_vram);
        break;

    // Cop1 rounding mode
    case InstrId::cpu_ctc1:
        if (cop1_cs != 31) {
            fmt::print(stderr, "Invalid FP control register for ctc1: {}\n", cop1_cs);
            return false;
        }
        indent_line();
        generator.emit_cop1_cs_write(rt);
        break;
    case InstrId::cpu_cfc1:
        if (cop1_cs != 31) {
            fmt::print(stderr, "Invalid FP control register for cfc1: {}\n", cop1_cs);
            return false;
        }
        indent_line();
        generator.emit_cop1_cs_read(rt);
        break;
    default:
        handled = false;
        break;
    }

    InstructionContext instruction_context{};
    instruction_context.rd = rd;
    instruction_context.rs = rs;
    instruction_context.rt = rt;
    instruction_context.sa = sa;
    instruction_context.fd = fd;
    instruction_context.fs = fs;
    instruction_context.ft = ft;
    instruction_context.cop1_cs = cop1_cs;
    instruction_context.imm16 = imm;
    instruction_context.reloc_tag_as_reference = (reloc_reference_symbol != (size_t)-1) && tag_reference_relocs;
    instruction_context.reloc_type = reloc_type;
    instruction_context.reloc_section_index = reloc_section;
    instruction_context.reloc_target_section_offset = reloc_target_section_offset;
    
    auto do_check_fr = [](const GeneratorType& generator, const InstructionContext& ctx, Operand operand) {
        switch (operand) {
            case Operand::Fd:
            case Operand::FdDouble:
            case Operand::FdU32L:
            case Operand::FdU32H:
            case Operand::FdU64:
                generator.emit_check_fr(ctx.fd);
                break;
            case Operand::Fs:
            case Operand::FsDouble:
            case Operand::FsU32L:
            case Operand::FsU32H:
            case Operand::FsU64:
                generator.emit_check_fr(ctx.fs);
                break;
            case Operand::Ft:
            case Operand::FtDouble:
            case Operand::FtU32L:
            case Operand::FtU32H:
            case Operand::FtU64:
                generator.emit_check_fr(ctx.ft);
                break;
            default:
                // Integer operands carry no MIPS3 FR check.
                break;
        }
    };
    
    auto do_check_nan = [](const GeneratorType& generator, const InstructionContext& ctx, Operand operand) {
        switch (operand) {
            case Operand::Fd:
                generator.emit_check_nan(ctx.fd, false);
                break;
            case Operand::Fs:
                generator.emit_check_nan(ctx.fs, false);
                break;
            case Operand::Ft:
                generator.emit_check_nan(ctx.ft, false);
                break;
            case Operand::FdDouble:
                generator.emit_check_nan(ctx.fd, true);
                break;
            case Operand::FsDouble:
                generator.emit_check_nan(ctx.fs, true);
                break;
            case Operand::FtDouble:
                generator.emit_check_nan(ctx.ft, true);
                break;
            default:
                // Integer operands need no NaN check.
                break;
        }
    };

    auto find_binary_it = binary_ops.find(instr_id);
    if (find_binary_it != binary_ops.end()) {
        indent_line();
        const BinaryOp& op = find_binary_it->second;
        
        if (op.check_fr) {
            do_check_fr(generator, instruction_context, op.output);
            do_check_fr(generator, instruction_context, op.operands.operands[0]);
            do_check_fr(generator, instruction_context, op.operands.operands[1]);
        }

        if (op.check_nan) {
            do_check_nan(generator, instruction_context, op.operands.operands[0]);
            do_check_nan(generator, instruction_context, op.operands.operands[1]);
            fmt::print(output_file, "\n");
            indent_line();
        }

        generator.process_binary_op(op, instruction_context);
        handled = true;
    }

    auto find_unary_it = unary_ops.find(instr_id);
    if (find_unary_it != unary_ops.end()) {
        indent_line();
        const UnaryOp& op = find_unary_it->second;
        
        if (op.check_fr) {
            do_check_fr(generator, instruction_context, op.output);
            do_check_fr(generator, instruction_context, op.input);
        }

        if (op.check_nan) {
            do_check_nan(generator, instruction_context, op.input);
            fmt::print(output_file, "\n");
            indent_line();
        }

        generator.process_unary_op(op, instruction_context);
        handled = true;
    }

    auto find_conditional_branch_it = conditional_branch_ops.find(instr_id);
    if (find_conditional_branch_it != conditional_branch_ops.end()) {
        // For the linking conditional branches (bltzal/bgezal/bltzall/
        // bgezall) the $ra := PC+8 write happens unconditionally, whether or
        // not the branch is taken. Emit it ahead of the if-block so it lands
        // on both paths. Handwritten code leans on this — e.g. Stadium's audio
        // synth uses `bltzal $zero, X` as a PC-arithmetic primitive: the
        // branch can never be taken ($zero is never negative), yet $ra is
        // still loaded so the following `addiu $t3, $ra, OFFSET` can form a
        // function pointer.
        if (find_conditional_branch_it->second.link) {
            indent_line();
            {
                uint32_t link_target = instr_vram + 8;
                fmt::print(output_file, "ctx->r31 = 0x{:08X}u;\n", link_target);

                uint64_t section_start = section.ram_addr;
                uint64_t section_end = section_start + section.size;
                if (link_target >= section_start && link_target < section_end) {
                    static_funcs_out[func.section_index].push_back(link_target);
                }
            }
        }
        indent_line();
        // TODO combining the branch condition and branch target into one generator call would allow better optimization in the runtime's JIT generator.
        // This would require splitting into a conditional jump method and conditional function call method.
        generator.emit_branch_condition(find_conditional_branch_it->second, instruction_context);

        indent_line();
        if (find_conditional_branch_it->second.link) {
            const uint32_t branch_target = instr.getBranchVramGeneric();
            if (branch_target >= func.vram && branch_target < func_vram_end) {
                if (!emit_branch_tree(branch_target)) {
                    return false;
                }
            }
            else if (!emit_call_by_address(branch_target)) {
                return false;
            }
        }
        else {
            if (!emit_branch_tree((uint32_t)instr.getBranchVramGeneric())) {
                return false;
            }
        }

        indent_line();
        generator.emit_branch_close();
        
        is_branch_likely = find_conditional_branch_it->second.likely;
        handled = true;
    }

    auto find_store_it = store_ops.find(instr_id);
    if (find_store_it != store_ops.end()) {
        indent_line();
        const StoreOp& op = find_store_it->second;

        if (op.type == StoreOpType::SDC1) {
            do_check_fr(generator, instruction_context, op.value_input);
        }

        generator.process_store_op(op, instruction_context);
        handled = true;
    }

    if (!handled) {
        // No decoder matched this opcode. Rather than abort the whole
        // recompile, emit a runtime call: the function still builds, and if
        // control ever reaches this instruction it fails loudly with the
        // opcode name. This is not a stub — it's an unimplementable hole that
        // announces itself at runtime with full context.
        fmt::print(stderr, "[Warn] Unhandled instruction '{}' in {} at 0x{:08X} — emitting runtime abort\n", instr.getOpcodeName(), func.name, instr_vram);
        indent_line();
        fmt::print(output_file, "recomp_unhandled_instruction(rdram, ctx, 0x{:08X}u, \"{}\");\n", instr_vram, instr.getOpcodeName());
    }

    // TODO is this used?
    if (emit_link_branch) {
        indent_line();
        generator.emit_label(fmt::format("after_{}", link_branch_index));
    }

    return true;
}

template <typename GeneratorType>
bool recompile_function_impl(GeneratorType& generator, const N64Recomp::Context& context, size_t func_index, std::ostream& output_file, std::span<std::vector<uint32_t>> static_funcs_out, bool tag_reference_relocs) {
    const N64Recomp::Function& func = context.functions[func_index];
    //fmt::print("Recompiling {}\n", func.name);
    std::vector<rabbitizer::InstructionCpu> instructions;

    generator.emit_function_start(func.name, func_index);

    if (context.trace_mode) {
        fmt::print(output_file,
            "    TRACE_ENTRY()\n",
            func.name);
    }

    // A stubbed function has no body to analyze or translate.
    if (!func.stubbed) {
        // std::set keeps the label vrams sorted and unique.
        std::set<uint32_t> branch_labels;
        std::set<uint32_t> local_tailcall_labels;
        instructions.reserve(func.words.size());
        const uint32_t func_vram_end = func.vram + uint32_t(func.words.size() * sizeof(func.words[0]));
        for (uint32_t dispatch_entry_vram : func.dispatch_entry_vrams) {
            if (dispatch_entry_vram > func.vram &&
                dispatch_entry_vram < func_vram_end) {
                branch_labels.insert(dispatch_entry_vram);
            }
        }
        if (!func.dispatch_entry_vrams.empty()) {
            fmt::print(output_file,
                "    if (ctx->dispatch_entry_target != 0) {{\n"
                "        uint32_t recomp_dispatch_entry = ctx->dispatch_entry_target;\n"
                "        ctx->dispatch_entry_target = 0;\n"
                "        switch (recomp_dispatch_entry) {{\n");
            for (uint32_t dispatch_entry_vram : func.dispatch_entry_vrams) {
                if (dispatch_entry_vram > func.vram &&
                    dispatch_entry_vram < func_vram_end) {
                    fmt::print(output_file,
                        "        case 0x{:08X}u: goto L_{:08X};\n",
                        dispatch_entry_vram,
                        dispatch_entry_vram);
                }
            }
            // A requested interior dispatch entry that is NOT one of this
            // function's emitted labels means "this compiled function cannot
            // service that entry PC" — NOT "run this function from its
            // prologue." Falling through to the prologue (the old
            // `default: break;`) silently executed the WRONG function body for
            // an indirect-only function-start that the recompiler merged into a
            // neighbor's range (e.g. GB-CPU opcode handlers), producing a
            // garbage computed pointer. Instead REJECT: flag it + record the
            // target and return WITHOUT executing any guest code, so the
            // librecomp self-heal falls through to the interpreter floor which
            // runs the function correctly from the exact missed PC. The switch
            // is the authoritative legal-entry set, so the default arm is
            // exactly where this is detected. (This is the first guest-semantic
            // statement in the function — only host-local inits / TRACE precede
            // it — so a bare return here leaves no half-mutated guest state.)
            fmt::print(output_file,
                "        default:\n"
                "            ctx->dispatch_entry_rejected = 1;\n"
                "            ctx->dispatch_entry_rejected_target = recomp_dispatch_entry;\n"
                "            return;\n"
                "        }}\n"
                "    }}\n");
        }
        if (func.entry_vram != 0 && func.entry_vram != func.vram) {
            branch_labels.insert(func.entry_vram);
            fmt::print(output_file, "    goto L_{:08X};\n", func.entry_vram);
        }

        auto hook_find = func.function_hooks.find(-1);
        if (hook_find != func.function_hooks.end()) {
            fmt::print(output_file, "    {}\n", hook_find->second);
        }
        generator.emit_label(fmt::format("L_{:08X}", func.vram));

        // Pass one: decode every word and gather the local branch labels.
        uint32_t vram = func.vram;
        for (uint32_t word : func.words) {
            const auto& instr = instructions.emplace_back(byteswap(word), vram);
            const auto instr_id = instr.getUniqueId();
            const uint32_t branch_target = (uint32_t)instr.getBranchVramGeneric();
            const uint32_t link_return_vram = vram + 8;
            const auto add_link_return_label = [&]() {
                if (link_return_vram >= func.vram && link_return_vram < func_vram_end) {
                    branch_labels.insert(link_return_vram);
                }
            };

            // Branches and direct jumps contribute their target as a label.
            if (instr.isBranch() || instr_id == rabbitizer::InstrId::UniqueId::cpu_j) {
                branch_labels.insert(branch_target);
            }

            // Local link branches are emitted as gotos within this C function.
            // Their original MIPS return PCs must be labels so local `jr $ra`
            // dispatch can resume after the delay slot.
            const auto conditional_branch_it = N64Recomp::conditional_branch_ops.find(instr_id);
            if (conditional_branch_it != N64Recomp::conditional_branch_ops.end() && conditional_branch_it->second.link) {
                if (branch_target >= func.vram && branch_target < func_vram_end) {
                    branch_labels.insert(branch_target);
                }
                add_link_return_label();
            }
            else if (instr_id == rabbitizer::InstrId::UniqueId::cpu_jal) {
                if (branch_target >= func.vram && branch_target < func_vram_end) {
                    branch_labels.insert(branch_target);
                }
                add_link_return_label();
            }
            else if (instr_id == rabbitizer::InstrId::UniqueId::cpu_jalr &&
                     instr.GetO32_rd() == rabbitizer::Registers::Cpu::GprO32::GPR_O32_ra) {
                add_link_return_label();
            }

            // Step to the next instruction address.
            vram += 4;
        }

        // Run the per-function analysis pass.
        N64Recomp::FunctionStats stats{};
        if (!N64Recomp::analyze_function(context, func, instructions, stats)) {
            fmt::print(stderr, "Failed to analyze {}\n", func.name);
            return false;
        }

        std::unordered_set<uint32_t> jtbl_lw_instructions{};

        // Fold every jump-table destination into the label set.
        for (const auto& jtbl : stats.jump_tables) {
            jtbl_lw_instructions.insert(jtbl.lw_vram);
            for (uint32_t jtbl_entry : jtbl.entries) {
                branch_labels.insert(jtbl_entry);
            }
        }
        constexpr size_t max_static_local_tailcall_function_size = 0x2000;
        constexpr size_t max_static_local_tailcall_labels = 256;
        if (func.section_index < static_funcs_out.size() &&
            func.name.rfind("static_", 0) != 0 &&
            func.words.size() * sizeof(func.words[0]) <= max_static_local_tailcall_function_size) {
            std::set<uint32_t> static_local_tailcall_labels;
            for (uint32_t static_vram : static_funcs_out[func.section_index]) {
                if (static_vram > func.vram && static_vram < func_vram_end) {
                    static_local_tailcall_labels.insert(static_vram);
                    if (static_local_tailcall_labels.size() > max_static_local_tailcall_labels) {
                        static_local_tailcall_labels.clear();
                        break;
                    }
                }
            }
            branch_labels.insert(static_local_tailcall_labels.begin(), static_local_tailcall_labels.end());
            local_tailcall_labels.insert(static_local_tailcall_labels.begin(), static_local_tailcall_labels.end());
        }

        for (auto label_it = branch_labels.begin(); label_it != branch_labels.end();) {
            if (*label_it < func.vram || *label_it >= func_vram_end) {
                label_it = branch_labels.erase(label_it);
            }
            else {
                ++label_it;
            }
        }
        for (auto label_it = local_tailcall_labels.begin(); label_it != local_tailcall_labels.end();) {
            if (*label_it < func.vram || *label_it >= func_vram_end || !branch_labels.contains(*label_it)) {
                label_it = local_tailcall_labels.erase(label_it);
            }
            else {
                ++label_it;
            }
        }
        branch_labels.erase(func.vram);

        // Pass two: walk the instructions, dropping labels and translated code.
        auto cur_label = branch_labels.cbegin();
        vram = func.vram;
        int num_link_branches = 0;
        int num_likely_branches = 0;
        bool needs_link_branch = false;
        bool in_likely_delay_slot = false;
        const auto& section = context.sections[func.section_index];
        size_t reloc_index = 0;
        for (size_t instr_index = 0; instr_index < instructions.size(); ++instr_index) {
            bool had_link_branch = needs_link_branch;
            bool is_branch_likely = false;
            // While sitting in a likely branch's delay slot, jump past the
            // duplicated instruction before any label can be emitted.
            if (in_likely_delay_slot) {
                generator.emit_goto(fmt::format("skip_{}", num_likely_branches));
            }
            // Drop the next pending label once this address reaches it.
            if (cur_label != branch_labels.end() && vram >= *cur_label) {
                generator.emit_label(fmt::format("L_{:08X}", *cur_label));
                ++cur_label;
            }

            // Move the reloc cursor forward until it lines up with (or just
            // before) the current instruction, without running off the end.
            while ((reloc_index + 1) < section.relocs.size() && section.relocs[reloc_index].address < vram) {
                reloc_index++;
            }
            // Translate the current instruction, bailing on any error.
            if (process_instruction(generator, context, func, func_index, stats, jtbl_lw_instructions, branch_labels, local_tailcall_labels, instr_index, instructions, output_file, false, needs_link_branch, num_link_branches, reloc_index, needs_link_branch, is_branch_likely, tag_reference_relocs, static_funcs_out) == false) {
                fmt::print(stderr, "Error in recompiling {} at instr {}\n", func.name, instr_index);
                return false;
            }
            // Count the link-return branch that was just emitted, if any.
            if (had_link_branch) {
                num_link_branches++;
            }
            // With the instruction emitted, close out the likely branch by
            // dropping its skip label.
            if (in_likely_delay_slot) {
                fmt::print(output_file, "    ");
                generator.emit_label(fmt::format("skip_{}", num_likely_branches));
                num_likely_branches++;
            }
            // Remember whether the upcoming instruction is a likely delay slot.
            in_likely_delay_slot = is_branch_likely;
            // Step to the next instruction address.
            vram += 4;
        }

        if (function_end_allows_fallthrough(instructions)) {
            const uint32_t fallthrough_vram = func.vram + uint32_t(func.words.size() * sizeof(func.words[0]));
            const size_t fallthrough_func_index = find_callable_function_in_section(
                context,
                fallthrough_vram,
                func.section_index);

            // A bodyless fall-through target (e.g. a fragmentN_TEXT_END
            // section-end label) is not an emitted function — the declaration
            // loop skips zero-word symbols — so a named tailcall to it would be
            // an undeclared identifier. Resolve those by vram at runtime
            // instead; real functions still take the direct named tailcall.
            const bool fallthrough_has_body =
                fallthrough_func_index != (size_t)-1 &&
                !context.functions[fallthrough_func_index].words.empty();
            if (fallthrough_func_index != (size_t)-1 && fallthrough_func_index != func_index) {
                fmt::print(
                    output_file,
                    "    if (0x{:08X}u == ctx->host_return_target) {{\n",
                    fallthrough_vram);
                if (context.trace_mode) {
                    fmt::print(output_file, "        TRACE_RETURN()\n");
                }
                fmt::print(output_file, "        return;\n");
                fmt::print(output_file, "    }}\n");
                if (fallthrough_has_body) {
                    fmt::print(
                        output_file,
                        "    recomp_request_tailcall_func_target(ctx, {}, 0x{:08X}u);\n",
                        context.functions[fallthrough_func_index].name,
                        fallthrough_vram);
                } else {
                    fmt::print(
                        output_file,
                        "    recomp_request_tailcall(ctx, (gpr)(int32_t)0x{:08X}u);\n",
                        fallthrough_vram);
                }
                if (context.trace_mode) {
                    fmt::print(output_file, "    TRACE_RETURN()\n");
                }
                fmt::print(output_file, "    return;\n");
            }
        }
    }

    // Terminate the function
    generator.emit_function_end();

    return true;
}

// Public entry point specialized on CGenerator.
//
// Emission is staged into a scratch ostringstream and flushed to the real
// output_file only when translation succeeds. This sidesteps the old
// "clearing output file" defect, where an output_file.clear() inside
// recompile_function_impl merely reset stream flags instead of discarding
// buffered text — leaving a half-written function (signature plus open
// braces, no body) inside shared multi-function output files.
bool N64Recomp::recompile_function(const N64Recomp::Context& context, size_t function_index, std::ostream& output_file, std::span<std::vector<uint32_t>> static_funcs_out, bool tag_reference_relocs) {
    std::ostringstream buffer;
    CGenerator generator{buffer};
    bool ok = recompile_function_impl(generator, context, function_index, buffer, static_funcs_out, tag_reference_relocs);
    if (ok) {
        output_file << buffer.str();
    }
    return ok;
}

bool N64Recomp::recompile_function_custom(Generator& generator, const Context& context, size_t function_index, std::ostream& output_file, std::span<std::vector<uint32_t>> static_funcs_out, bool tag_reference_relocs) {
    return recompile_function_impl(generator, context, function_index, output_file, static_funcs_out, tag_reference_relocs);
}
