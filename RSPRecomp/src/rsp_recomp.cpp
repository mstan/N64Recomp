// RSP microcode -> C source recompiler (mstan N64Recomp fork).
// Licensed under the project's MIT License; see ../../LICENSE.
//
// This translation unit reads a packed RSP text segment out of a ROM,
// decodes it with rabbitizer, and writes a C++ source file whose body
// reproduces the microcode one instruction at a time. The emitted code
// is the contract with librecomp's RSP runtime, so the strings printed
// here are intentionally verbatim.
//
// mstan fork additions layered on top of the base recompiler:
//   - "Path A" persistent RSP general registers that survive across
//     run_task calls, plus per-register COP0 handling that follows a
//     documented HLE model (the matching half lives in librecomp's
//     rsp.cpp).
//   - An always-on hang watchdog: every label emits a PC-trail write
//     and a transition counter check, so a stuck microcode reports its
//     recent PC history instead of spinning silently.
//   - A pre-task hook and an expanded watchdog register dump.
//   - aspMain PC-mapping fix and Ares-bridge state exposure used by the
//     divergence diagnostics.
//
// Copyright (c) 2026 Matthew Stanley
//
// ---------------------------------------------------------------------

#include <optional>
#include <fstream>
#include <array>
#include <vector>
#include <algorithm>
#include <unordered_set>
#include <unordered_map>
#include <cassert>
#include <iostream>
#include <filesystem>
#include "rabbitizer.hpp"
#include "fmt/format.h"
#include "fmt/ostream.h"
#include <toml++/toml.hpp>

using InstrId = rabbitizer::InstrId::UniqueId;
using Cop0Reg = rabbitizer::Registers::Rsp::Cop0;
constexpr size_t instr_size = sizeof(uint32_t);
constexpr uint32_t rsp_mem_mask = 0x1FFF;

// We roll our own operand kinds instead of reusing rabbitizer's: some
// vector ops need the register passed as an array reference while others
// need the bare register index, a distinction rabbitizer doesn't draw.
enum class RspOperand {
    None,
    Vt,
    VtIndex,
    Vd,
    Vs,
    VsIndex,
    De,
    Rt,
    Rs,
    Imm7,
};

std::unordered_map<InstrId, std::array<RspOperand, 3>> vector_operands{
    // Vt, Rs, Imm
    { InstrId::rsp_lbv, {RspOperand::Vt, RspOperand::Rs, RspOperand::Imm7}},
    { InstrId::rsp_ldv, {RspOperand::Vt, RspOperand::Rs, RspOperand::Imm7}},
    { InstrId::rsp_lfv, {RspOperand::Vt, RspOperand::Rs, RspOperand::Imm7}},
    { InstrId::rsp_lhv, {RspOperand::Vt, RspOperand::Rs, RspOperand::Imm7}},
    { InstrId::rsp_llv, {RspOperand::Vt, RspOperand::Rs, RspOperand::Imm7}},
    { InstrId::rsp_lpv, {RspOperand::Vt, RspOperand::Rs, RspOperand::Imm7}},
    { InstrId::rsp_lqv, {RspOperand::Vt, RspOperand::Rs, RspOperand::Imm7}},
    { InstrId::rsp_lrv, {RspOperand::Vt, RspOperand::Rs, RspOperand::Imm7}},
    { InstrId::rsp_lsv, {RspOperand::Vt, RspOperand::Rs, RspOperand::Imm7}},
    { InstrId::rsp_luv, {RspOperand::Vt, RspOperand::Rs, RspOperand::Imm7}},
    // { InstrId::rsp_lwv, {RspOperand::Vt, RspOperand::Rs, RspOperand::Imm7}}, // Not in rabbitizer
    { InstrId::rsp_sbv, {RspOperand::Vt, RspOperand::Rs, RspOperand::Imm7}},
    { InstrId::rsp_sdv, {RspOperand::Vt, RspOperand::Rs, RspOperand::Imm7}},
    { InstrId::rsp_sfv, {RspOperand::Vt, RspOperand::Rs, RspOperand::Imm7}},
    { InstrId::rsp_shv, {RspOperand::Vt, RspOperand::Rs, RspOperand::Imm7}},
    { InstrId::rsp_slv, {RspOperand::Vt, RspOperand::Rs, RspOperand::Imm7}},
    { InstrId::rsp_spv, {RspOperand::Vt, RspOperand::Rs, RspOperand::Imm7}},
    { InstrId::rsp_sqv, {RspOperand::Vt, RspOperand::Rs, RspOperand::Imm7}},
    { InstrId::rsp_srv, {RspOperand::Vt, RspOperand::Rs, RspOperand::Imm7}},
    { InstrId::rsp_ssv, {RspOperand::Vt, RspOperand::Rs, RspOperand::Imm7}},
    { InstrId::rsp_suv, {RspOperand::Vt, RspOperand::Rs, RspOperand::Imm7}},
    { InstrId::rsp_swv, {RspOperand::Vt, RspOperand::Rs, RspOperand::Imm7}},
    { InstrId::rsp_stv, {RspOperand::VtIndex, RspOperand::Rs, RspOperand::Imm7}},
    { InstrId::rsp_ltv, {RspOperand::VtIndex, RspOperand::Rs, RspOperand::Imm7}},

    // Vd, Vs, Vt
    { InstrId::rsp_vabs,    {RspOperand::Vd, RspOperand::Vs, RspOperand::Vt}},
    { InstrId::rsp_vadd,    {RspOperand::Vd, RspOperand::Vs, RspOperand::Vt}},
    { InstrId::rsp_vaddc,   {RspOperand::Vd, RspOperand::Vs, RspOperand::Vt}},
    { InstrId::rsp_vand,    {RspOperand::Vd, RspOperand::Vs, RspOperand::Vt}},
    { InstrId::rsp_vch,     {RspOperand::Vd, RspOperand::Vs, RspOperand::Vt}},
    { InstrId::rsp_vcl,     {RspOperand::Vd, RspOperand::Vs, RspOperand::Vt}},
    { InstrId::rsp_vcr,     {RspOperand::Vd, RspOperand::Vs, RspOperand::Vt}},
    { InstrId::rsp_veq,     {RspOperand::Vd, RspOperand::Vs, RspOperand::Vt}},
    { InstrId::rsp_vge,     {RspOperand::Vd, RspOperand::Vs, RspOperand::Vt}},
    { InstrId::rsp_vlt,     {RspOperand::Vd, RspOperand::Vs, RspOperand::Vt}},
    { InstrId::rsp_vmacf,   {RspOperand::Vd, RspOperand::Vs, RspOperand::Vt}},
    { InstrId::rsp_vmacu,   {RspOperand::Vd, RspOperand::Vs, RspOperand::Vt}},
    { InstrId::rsp_vmadh,   {RspOperand::Vd, RspOperand::Vs, RspOperand::Vt}},
    { InstrId::rsp_vmadl,   {RspOperand::Vd, RspOperand::Vs, RspOperand::Vt}},
    { InstrId::rsp_vmadm,   {RspOperand::Vd, RspOperand::Vs, RspOperand::Vt}},
    { InstrId::rsp_vmadn,   {RspOperand::Vd, RspOperand::Vs, RspOperand::Vt}},
    { InstrId::rsp_vmrg,    {RspOperand::Vd, RspOperand::Vs, RspOperand::Vt}},
    { InstrId::rsp_vmudh,   {RspOperand::Vd, RspOperand::Vs, RspOperand::Vt}},
    { InstrId::rsp_vmudl,   {RspOperand::Vd, RspOperand::Vs, RspOperand::Vt}},
    { InstrId::rsp_vmudm,   {RspOperand::Vd, RspOperand::Vs, RspOperand::Vt}},
    { InstrId::rsp_vmudn,   {RspOperand::Vd, RspOperand::Vs, RspOperand::Vt}},
    { InstrId::rsp_vne,     {RspOperand::Vd, RspOperand::Vs, RspOperand::Vt}},
    { InstrId::rsp_vnor,    {RspOperand::Vd, RspOperand::Vs, RspOperand::Vt}},
    { InstrId::rsp_vnxor,   {RspOperand::Vd, RspOperand::Vs, RspOperand::Vt}},
    { InstrId::rsp_vor,     {RspOperand::Vd, RspOperand::Vs, RspOperand::Vt}},
    { InstrId::rsp_vsub,    {RspOperand::Vd, RspOperand::Vs, RspOperand::Vt}},
    { InstrId::rsp_vsubc,   {RspOperand::Vd, RspOperand::Vs, RspOperand::Vt}},
    { InstrId::rsp_vmulf,   {RspOperand::Vd, RspOperand::Vs, RspOperand::Vt}},
    { InstrId::rsp_vmulu,   {RspOperand::Vd, RspOperand::Vs, RspOperand::Vt}},
    { InstrId::rsp_vmulq,   {RspOperand::Vd, RspOperand::Vs, RspOperand::Vt}},
    { InstrId::rsp_vnand,   {RspOperand::Vd, RspOperand::Vs, RspOperand::Vt}},
    { InstrId::rsp_vxor,    {RspOperand::Vd, RspOperand::Vs, RspOperand::Vt}},
    { InstrId::rsp_vsar,    {RspOperand::Vd, RspOperand::Vs, RspOperand::None}},
    { InstrId::rsp_vmacq,   {RspOperand::Vd, RspOperand::None, RspOperand::None}},
    // { InstrId::rsp_vzero,   {RspOperand::Vd, RspOperand::Vs, RspOperand::Vt}}, // pseudo, never emitted
    { InstrId::rsp_vrndn,   {RspOperand::Vd, RspOperand::VsIndex, RspOperand::Vt}},
    { InstrId::rsp_vrndp,   {RspOperand::Vd, RspOperand::VsIndex, RspOperand::Vt}},

    // Vd, De, Vt
    { InstrId::rsp_vmov,    {RspOperand::Vd, RspOperand::De, RspOperand::Vt}},
    { InstrId::rsp_vrcp,    {RspOperand::Vd, RspOperand::De, RspOperand::Vt}},
    { InstrId::rsp_vrcpl,   {RspOperand::Vd, RspOperand::De, RspOperand::Vt}},
    { InstrId::rsp_vrcph,   {RspOperand::Vd, RspOperand::De, RspOperand::Vt}},
    { InstrId::rsp_vrsq,    {RspOperand::Vd, RspOperand::De, RspOperand::Vt}},
    { InstrId::rsp_vrsql,   {RspOperand::Vd, RspOperand::De, RspOperand::Vt}},
    { InstrId::rsp_vrsqh,   {RspOperand::Vd, RspOperand::De, RspOperand::Vt}},

    // Rt, Vs
    { InstrId::rsp_mfc2,    {RspOperand::Rt, RspOperand::Vs, RspOperand::None}},
    { InstrId::rsp_mtc2,    {RspOperand::Rt, RspOperand::Vs, RspOperand::None}},

    // Nop
    { InstrId::rsp_vnop,    {RspOperand::None, RspOperand::None, RspOperand::None}}
};

// Register $0 is the hardwired zero, so it is referenced by the bare
// name "0"; every other GPR is named "rN", hence the "r" prefix.
std::string_view gpr_ref_prefix(int reg) {
    if (reg != 0) {
        return "r";
    }
    return "";
}

// HLE model for `mfc0` reads. Under high-level emulation DMAs finish
// before the next instruction and there is no real RDP, so the status,
// DMA and semaphore registers all read back as zero. Anything we don't
// model is a hard error rather than a silent guess.
uint32_t cop0_read_value(int cop0_reg) {
    switch (static_cast<Cop0Reg>(cop0_reg)) {
    case Cop0Reg::RSP_COP0_SP_STATUS:
        return 0; // No RSP status flags are ever raised in this model
    case Cop0Reg::RSP_COP0_SP_DMA_FULL:
        return 0; // DMAs are treated as instantaneous
    case Cop0Reg::RSP_COP0_SP_DMA_BUSY:
        return 0; // DMAs are treated as instantaneous
    case Cop0Reg::RSP_COP0_SP_SEMAPHORE:
        return 0; // The semaphore is always considered free
    case Cop0Reg::RSP_COP0_DPC_START:
    case Cop0Reg::RSP_COP0_DPC_END:
    case Cop0Reg::RSP_COP0_DPC_CURRENT:
    case Cop0Reg::RSP_COP0_DPC_STATUS:
    case Cop0Reg::RSP_COP0_DPC_CLOCK:
    case Cop0Reg::RSP_COP0_DPC_BUFBUSY:
    case Cop0Reg::RSP_COP0_DPC_PIPEBUSY:
    case Cop0Reg::RSP_COP0_DPC_TMEM:
        return 0; // Only non-graphics microcodes are recompiled, so zero suffices
    default:
        fmt::print(stderr, "Unhandled mfc0: {}\n", cop0_reg);
        throw std::runtime_error("Unhandled mfc0");
        return 0;
    }
}

// Maps an `mtc0` target register to the runtime macro that should be
// emitted for the write. An empty result means the write is a no-op in
// the HLE model. Unknown registers abort the recompile.
std::string_view cop0_write_action(int cop0_reg) {
    switch (static_cast<Cop0Reg>(cop0_reg)) {
    case Cop0Reg::RSP_COP0_SP_SEMAPHORE:
        return ""; // Semaphore writes have no effect here
    case Cop0Reg::RSP_COP0_SP_STATUS:
        return "WRITE_SP_STATUS";
    case Cop0Reg::RSP_COP0_SP_DRAM_ADDR:
        return "SET_DMA_DRAM";
    case Cop0Reg::RSP_COP0_SP_MEM_ADDR:
        return "SET_DMA_MEM";
    case Cop0Reg::RSP_COP0_SP_RD_LEN:
        return "DO_DMA_READ";
    case Cop0Reg::RSP_COP0_SP_WR_LEN:
        return "DO_DMA_WRITE";
    default:
        fmt::print(stderr, "Unhandled mtc0: {}\n", cop0_reg);
        throw std::runtime_error("Unhandled mtc0");
    }

}

// True when the COP0 write kicks off a DRAM->IMEM/DMEM read, which is the
// trigger an overlay swap watches for.
bool cop0_write_is_dma_read(int cop0_reg) {
    return static_cast<Cop0Reg>(cop0_reg) == Cop0Reg::RSP_COP0_SP_RD_LEN;
}

// Pulls the vector element selector out of a COP2 instruction. The high
// and low element encodings live in different operand fields; return
// nothing for instructions that carry no element.
std::optional<int> decode_vector_element(const rabbitizer::InstructionRsp& instr) {
    if (instr.hasOperand(rabbitizer::OperandType::rsp_vt_elementhigh)) {
        return instr.GetRsp_elementhigh();
    } else if (instr.hasOperand(rabbitizer::OperandType::rsp_vt_elementlow) || instr.hasOperand(rabbitizer::OperandType::rsp_vs_index)) {
        return instr.GetRsp_elementlow();
    }

    return std::nullopt;
}

// A couple of vector ops carry no usable element field, so their emit
// path must skip the templated element argument entirely.
bool vector_op_skips_element(InstrId id) {
    return id == InstrId::rsp_vmacq || id == InstrId::rsp_vnop;
}

struct BranchTargets {
    std::unordered_set<uint32_t> direct_targets;
    std::unordered_set<uint32_t> indirect_targets;
};

BranchTargets collect_branch_targets(const std::vector<rabbitizer::InstructionRsp>& instrs) {
    BranchTargets ret;
    std::unordered_set<int> indirect_jump_regs;

    for (const auto& instr : instrs) {
        InstrId instr_id = instr.getUniqueId();
        if (instr_id == InstrId::rsp_jr || instr_id == InstrId::rsp_jalr) {
            indirect_jump_regs.insert((int)instr.GetO32_rs());
        }
    }

    for (const auto& instr : instrs) {
        InstrId instr_id = instr.getUniqueId();
        if (instr.isJumpWithAddress() || instr.isBranch()) {
            // Set the IMEM region bit (0x1000) on the computed target so it
            // lines up with the L_1XXX labels emitted at instruction
            // boundaries; emit_instruction masks branch references the
            // exact same way.
            ret.direct_targets.insert((instr.getBranchVramGeneric() | 0x1000u) & rsp_mem_mask);
        }
        if (instr.doesLink()) {
            ret.indirect_targets.insert(instr.getVram() + 2 * instr_size);
        }
        // Recognize the `li $reg, imm` (addiu/ori from $zero) idiom that
        // loads a literal IMEM address into a register later used by jr/jalr.
        // Such constants are reachable indirect targets, so register any
        // value that lands inside the IMEM range.
        if ((instr_id == InstrId::rsp_addiu || instr_id == InstrId::rsp_ori) &&
            (int)instr.GetO32_rs() == 0 &&
            indirect_jump_regs.contains((int)instr.GetO32_rt())) {
            uint16_t imm = instr.Get_immediate();
            if (imm >= 0x1000 && imm <= rsp_mem_mask) {
                ret.indirect_targets.insert(imm);
            }
        }
    }
    return ret;
}

struct ResumeTargets {
    std::unordered_set<uint32_t> non_delay_targets;
    std::unordered_set<uint32_t> delay_targets;
};

// A DMA-read `mtc0` can trigger an overlay swap, after which execution must
// resume at the very instruction that issued it. Record every such site (and
// flag the ones sitting in a delay slot) so the function emitter can plant the
// matching resume labels.
void collect_resume_targets(const std::vector<rabbitizer::InstructionRsp>& instrs, ResumeTargets& targets) {
    bool is_delay_slot = false;
    for (const auto& instr : instrs) {
        InstrId instr_id = instr.getUniqueId();
        int rd = (int)instr.GetO32_rd();

        if (instr_id == InstrId::rsp_mtc0 && cop0_write_is_dma_read(rd)) {
            uint32_t vram = instr.getVram();

            targets.non_delay_targets.insert(vram);

            if (is_delay_slot) {
                targets.delay_targets.insert(vram);
            }
        }

        is_delay_slot = instr.hasDelaySlot();
    }
}

bool emit_instruction(size_t instr_index, const std::vector<rabbitizer::InstructionRsp>& instructions, std::ofstream& output_file, const BranchTargets& branch_targets, const std::unordered_set<uint32_t>& unsupported_instructions, const ResumeTargets& resume_targets, bool has_overlays, bool indent, bool in_delay_slot) {
    const auto& instr = instructions[instr_index];

    uint32_t instr_vram = instr.getVram();
    InstrId instr_id = instr.getUniqueId();

    // When an instruction is being duplicated into a delay slot we are
    // re-emitting it, so don't repeat its label.
    if (!in_delay_slot) {
        // Emit a label here if this PC is a branch/jump destination.
        if (branch_targets.direct_targets.contains(instr_vram) || branch_targets.indirect_targets.contains(instr_vram)) {
            fmt::print(output_file, "L_{:04X}:\n", instr_vram);
            // Watchdog tick on every label, i.e. once per basic-block
            // entry: stash this PC into the `pc_trail` ring and bump
            // watchdog_count, bailing out with RspExitReason::Watchdog
            // once the count crosses 100M transitions (the microcode is
            // wedged).
            //
            // This is roughly five cheap instructions per block; across a
            // ~50ms audio frame that is well under a millisecond, so it
            // stays compiled in unconditionally. A future speed-critical
            // ucode could gate these emits behind a compile-time #define.
            //
            // This follows the global always-on ring-buffer rule: nothing
            // is "armed" — the trail records continuously and the runtime
            // reads the last 32 entries backward when the watchdog fires.
            fmt::print(output_file,
                "    ctx->pc_trail[ctx->pc_trail_idx & 31] = 0x{0:04X};\n"
                "    ctx->pc_trail_idx++;\n"
                "    if (++ctx->watchdog_count > 100000000ULL) {{\n"
                "        fprintf(stderr, \"[rsp watchdog] hung at PC 0x{0:04X} after %llu transitions; PC trail (oldest..newest):\\n\", (unsigned long long)ctx->watchdog_count);\n"
                "        for (uint32_t i = 0; i < 32; i++) {{\n"
                "            uint32_t pos = (ctx->pc_trail_idx + i) & 31;\n"
                "            fprintf(stderr, \"  [%2u] PC=0x%04X\\n\", i, ctx->pc_trail[pos]);\n"
                "        }}\n"
                "        fprintf(stderr, \"[rsp watchdog] gprs: r1=%08X r2=%08X r3=%08X r25=%08X r26=%08X r27=%08X r28=%08X r29=%08X r30=%08X r31=%08X jt=%08X dma_mem=%08X dma_dram=%08X\\n\",\n"
                "            ctx->r1, ctx->r2, ctx->r3, ctx->r25, ctx->r26, ctx->r27, ctx->r28, ctx->r29, ctx->r30, ctx->r31, ctx->jump_target, ctx->dma_mem_address, ctx->dma_dram_address);\n"
                "        return RspExitReason::Watchdog;\n"
                "    }}\n",
                instr_vram);
        }
    }

    // Force the computed target into the canonical L_1XXX form: OR in the
    // IMEM region bit (0x1000) and then mask to the 13-bit IMEM range. The
    // indirect-jump switch and the label declarations both encode PCs this
    // way, so the references must agree. Skipping the OR would let a branch
    // whose PC wraps below 0x1000 (e.g. an aspMain `beq` with a big negative
    // immediate aimed at an rspboot helper around IMEM[0x44]) emit a
    // `goto L_0044` with no matching label; the OR turns it into L_1044.
    uint16_t branch_target = (instr.getBranchVramGeneric() | 0x1000u) & rsp_mem_mask;

    // Precede the generated code with the disassembled source instruction
    // as a comment, resolving the label/target for branches and jumps.
    if (instr.isBranch() || instr_id == InstrId::rsp_j) {
        fmt::print(output_file, "    // {}\n", instr.disassemble(0, fmt::format("L_{:04X}", branch_target)));
    } else if (instr_id == InstrId::rsp_jal) {
        fmt::print(output_file, "    // {}\n", instr.disassemble(0, fmt::format("0x{:04X}", branch_target)));
    } else {
        fmt::print(output_file, "    // {}\n", instr.disassemble(0));
    }

    auto print_indent = [&]() {
        fmt::print(output_file, "    ");
    };

    auto print_line = [&]<typename... Ts>(fmt::format_string<Ts...> fmt_str, Ts&& ...args) {
        print_indent();
        fmt::print(output_file, fmt_str, std::forward<Ts>(args)...);
        fmt::print(output_file, ";\n");
    };

    auto print_branch_condition = [&]<typename... Ts>(fmt::format_string<Ts...> fmt_str, Ts&& ...args) {
        fmt::print(output_file, fmt_str, std::forward<Ts>(args)...);
        fmt::print(output_file, " ");
    };

    auto print_unconditional_branch = [&]<typename... Ts>(fmt::format_string<Ts...> fmt_str, Ts&& ...args) {
        if (instr_index < instructions.size() - 1) {
            uint32_t next_vram = instr_vram + 4;
            emit_instruction(instr_index + 1, instructions, output_file, branch_targets, unsupported_instructions, resume_targets, has_overlays, false, true);
        }
        print_indent();
        fmt::print(output_file, fmt_str, std::forward<Ts>(args)...);
        fmt::print(output_file, ";\n");
    };

    auto print_branch = [&]<typename... Ts>(fmt::format_string<Ts...> fmt_str, Ts&& ...args) {
        fmt::print(output_file, "{{\n    ");
        if (instr_index < instructions.size() - 1) {
            uint32_t next_vram = instr_vram + 4;
            emit_instruction(instr_index + 1, instructions, output_file, branch_targets, unsupported_instructions, resume_targets, has_overlays, true, true);
        }
        fmt::print(output_file, "        ");
        fmt::print(output_file, fmt_str, std::forward<Ts>(args)...);
        fmt::print(output_file, ";\n    }}\n");
    };

    if (indent) {
        print_indent();
    }

    // Config can flag specific PCs as unsupported; emit an early return there.
    if (unsupported_instructions.contains(instr_vram)) {
        print_line("return RspExitReason::Unsupported", instr_vram);
        if (indent) {
            print_indent();
        }
    }

    int rd = (int)instr.GetO32_rd();
    int rs = (int)instr.GetO32_rs();
    int base = rs;
    int rt = (int)instr.GetO32_rt();
    int sa = (int)instr.Get_sa();

    int fd = (int)instr.GetO32_fd();
    int fs = (int)instr.GetO32_fs();
    int ft = (int)instr.GetO32_ft();

    uint16_t imm = instr.Get_immediate();

    std::string imm_unsigned_text = fmt::format("{:#X}", imm);
    std::string imm_signed_text = fmt::format("{:#X}", (int16_t)imm);

    auto rsp_element = decode_vector_element(instr);

    // Vector (COP2) ops are looked up in the operand table and lowered to a
    // call on the rsp object, with each operand formatted per its kind.
    auto operand_find_it = vector_operands.find(instr_id);
    if (operand_find_it != vector_operands.end()) {
        const auto& operands = operand_find_it->second;
        int vd = (int)instr.GetRsp_vd();
        int vs = (int)instr.GetRsp_vs();
        int vt = (int)instr.GetRsp_vt();
        std::string args_text = "";
        for (RspOperand operand : operands) {
            switch (operand) {
                case RspOperand::Vt:
                    args_text += fmt::format("rsp.vpu.r[{}], ", vt);
                    break;
                case RspOperand::VtIndex:
                    args_text += fmt::format("{}, ", vt);
                    break;
                case RspOperand::Vd:
                    args_text += fmt::format("rsp.vpu.r[{}], ", vd);
                    break;
                case RspOperand::Vs:
                    args_text += fmt::format("rsp.vpu.r[{}], ", vs);
                    break;
                case RspOperand::VsIndex:
                    args_text += fmt::format("{}, ", vs);
                    break;
                case RspOperand::De:
                    args_text += fmt::format("{}, ", instr.GetRsp_de() & 7);
                    break;
                case RspOperand::Rt:
                    args_text += fmt::format("{}{}, ", gpr_ref_prefix(rt), rt);
                    break;
                case RspOperand::Rs:
                    args_text += fmt::format("{}{}, ", gpr_ref_prefix(rs), rs);
                    break;
                case RspOperand::Imm7:
                    // 7-bit immediate, sign-extended via a shift up-and-back
                    args_text += fmt::format("{:#X}, ", ((int8_t)(imm << 1)) >> 1);
                    break;
                case RspOperand::None:
                    break;
            }
        }
        // Each operand appended a ", "; drop the dangling separator.
        if (args_text.size() > 0) {
            args_text = args_text.substr(0, args_text.size() - 2);
        }
        // The emitted call uses the mnemonic upper-cased (e.g. vadd -> VADD).
        std::string upper_mnemonic = "";
        std::string mnemonic = instr.getOpcodeName();
        upper_mnemonic.reserve(mnemonic.size() + 1);
        for (char c : mnemonic) {
            upper_mnemonic += std::toupper(c);
        }
        if (vector_op_skips_element(instr_id)) {
            print_line("rsp.{}({})", upper_mnemonic, args_text);
        } else {
            print_line("rsp.{}<{}>({})", upper_mnemonic, rsp_element.value(), args_text);
        }
    }
    // Everything else (scalar/COP0/control flow) is lowered inline here.
    else {
        switch (instr_id) {
        case InstrId::rsp_nop:
            fmt::print(output_file, "\n");
            break;
            // Arithmetic / logic
        case InstrId::rsp_lui:
            print_line("{}{} = S32(U32({}) << 16)", gpr_ref_prefix(rt), rt, imm_unsigned_text);
            break;
        case InstrId::rsp_add:
        case InstrId::rsp_addu:
            if (rd == 0) {
                fmt::print(output_file, "\n");
                break;
            }
            print_line("{}{} = RSP_ADD32({}{}, {}{})", gpr_ref_prefix(rd), rd, gpr_ref_prefix(rs), rs, gpr_ref_prefix(rt), rt);
            break;
        case InstrId::rsp_negu: // pseudo instruction for subu x, 0, y
        case InstrId::rsp_sub:
        case InstrId::rsp_subu:
            print_line("{}{} = RSP_SUB32({}{}, {}{})", gpr_ref_prefix(rd), rd, gpr_ref_prefix(rs), rs, gpr_ref_prefix(rt), rt);
            break;
        case InstrId::rsp_addi:
        case InstrId::rsp_addiu:
            print_line("{}{} = RSP_ADD32({}{}, {})", gpr_ref_prefix(rt), rt, gpr_ref_prefix(rs), rs, imm_signed_text);
            break;
        case InstrId::rsp_and:
            if (rd == 0) {
                fmt::print(output_file, "\n");
                break;
            }
            print_line("{}{} = {}{} & {}{}", gpr_ref_prefix(rd), rd, gpr_ref_prefix(rs), rs, gpr_ref_prefix(rt), rt);
            break;
        case InstrId::rsp_andi:
            print_line("{}{} = {}{} & {}", gpr_ref_prefix(rt), rt, gpr_ref_prefix(rs), rs, imm_unsigned_text);
            break;
        case InstrId::rsp_or:
            print_line("{}{} = {}{} | {}{}", gpr_ref_prefix(rd), rd, gpr_ref_prefix(rs), rs, gpr_ref_prefix(rt), rt);
            break;
        case InstrId::rsp_ori:
            print_line("{}{} = {}{} | {}", gpr_ref_prefix(rt), rt, gpr_ref_prefix(rs), rs, imm_unsigned_text);
            break;
        case InstrId::rsp_nor:
            print_line("{}{} = ~({}{} | {}{})", gpr_ref_prefix(rd), rd, gpr_ref_prefix(rs), rs, gpr_ref_prefix(rt), rt);
            break;
        case InstrId::rsp_xor:
            print_line("{}{} = {}{} ^ {}{}", gpr_ref_prefix(rd), rd, gpr_ref_prefix(rs), rs, gpr_ref_prefix(rt), rt);
            break;
        case InstrId::rsp_xori:
            print_line("{}{} = {}{} ^ {}", gpr_ref_prefix(rt), rt, gpr_ref_prefix(rs), rs, imm_unsigned_text);
            break;
        case InstrId::rsp_sll:
            print_line("{}{} = S32(U32({}{}) << {})", gpr_ref_prefix(rd), rd, gpr_ref_prefix(rt), rt, sa);
            break;
        case InstrId::rsp_sllv:
            print_line("{}{} = S32(U32({}{}) << ({}{} & 31))", gpr_ref_prefix(rd), rd, gpr_ref_prefix(rt), rt, gpr_ref_prefix(rs), rs);
            break;
        case InstrId::rsp_sra:
            print_line("{}{} = S32(RSP_SIGNED({}{}) >> {})", gpr_ref_prefix(rd), rd, gpr_ref_prefix(rt), rt, sa);
            break;
        case InstrId::rsp_srav:
            print_line("{}{} = S32(RSP_SIGNED({}{}) >> ({}{} & 31))", gpr_ref_prefix(rd), rd, gpr_ref_prefix(rt), rt, gpr_ref_prefix(rs), rs);
            break;
        case InstrId::rsp_srl:
            print_line("{}{} = S32(U32({}{}) >> {})", gpr_ref_prefix(rd), rd, gpr_ref_prefix(rt), rt, sa);
            break;
        case InstrId::rsp_srlv:
            print_line("{}{} = S32(U32({}{}) >> ({}{} & 31))", gpr_ref_prefix(rd), rd, gpr_ref_prefix(rt), rt, gpr_ref_prefix(rs), rs);
            break;
        case InstrId::rsp_slt:
            print_line("{}{} = RSP_SIGNED({}{}) < RSP_SIGNED({}{}) ? 1 : 0", gpr_ref_prefix(rd), rd, gpr_ref_prefix(rs), rs, gpr_ref_prefix(rt), rt);
            break;
        case InstrId::rsp_slti:
            print_line("{}{} = RSP_SIGNED({}{}) < {} ? 1 : 0", gpr_ref_prefix(rt), rt, gpr_ref_prefix(rs), rs, imm_signed_text);
            break;
        case InstrId::rsp_sltu:
            print_line("{}{} = {}{} < {}{} ? 1 : 0", gpr_ref_prefix(rd), rd, gpr_ref_prefix(rs), rs, gpr_ref_prefix(rt), rt);
            break;
        case InstrId::rsp_sltiu:
            print_line("{}{} = {}{} < {} ? 1 : 0", gpr_ref_prefix(rt), rt, gpr_ref_prefix(rs), rs, imm_signed_text);
            break;
            // Loads (no 64-bit ld on the RSP)
        case InstrId::rsp_lw:
            print_line("{}{} = RSP_MEM_W_LOAD({}, {}{})", gpr_ref_prefix(rt), rt, imm_signed_text, gpr_ref_prefix(base), base);
            break;
        case InstrId::rsp_lh:
            print_line("{}{} = RSP_MEM_H_LOAD({}, {}{})", gpr_ref_prefix(rt), rt, imm_signed_text, gpr_ref_prefix(base), base);
            break;
        case InstrId::rsp_lb:
            print_line("{}{} = RSP_MEM_B({}, {}{})", gpr_ref_prefix(rt), rt, imm_signed_text, gpr_ref_prefix(base), base);
            break;
        case InstrId::rsp_lhu:
            print_line("{}{} = RSP_MEM_HU_LOAD({}, {}{})", gpr_ref_prefix(rt), rt, imm_signed_text, gpr_ref_prefix(base), base);
            break;
        case InstrId::rsp_lbu:
            print_line("{}{} = RSP_MEM_BU({}, {}{})", gpr_ref_prefix(rt), rt, imm_signed_text, gpr_ref_prefix(base), base);
            break;
            // Stores
        case InstrId::rsp_sw:
            print_line("RSP_MEM_W_STORE({}, {}{}, {}{})", imm_signed_text, gpr_ref_prefix(base), base, gpr_ref_prefix(rt), rt);
            break;
        case InstrId::rsp_sh:
            print_line("RSP_MEM_H_STORE({}, {}{}, {}{})", imm_signed_text, gpr_ref_prefix(base), base, gpr_ref_prefix(rt), rt);
            break;
        case InstrId::rsp_sb:
            print_line("RSP_MEM_B({}, {}{}) = {}{}", imm_signed_text, gpr_ref_prefix(base), base, gpr_ref_prefix(rt), rt);
            break;
            // Branches
        case InstrId::rsp_j:
        case InstrId::rsp_b:
            print_unconditional_branch("goto L_{:04X}", branch_target);
            break;
        case InstrId::rsp_jal:
            print_line("{}{} = 0x{:04X}", gpr_ref_prefix(31), 31, instr_vram + 2 * instr_size);
            print_unconditional_branch("goto L_{:04X}", branch_target);
            break;
        case InstrId::rsp_jr:
            print_line("jump_target = {}{}", gpr_ref_prefix(rs), rs);
            print_line("debug_file = __FILE__; debug_line = __LINE__");
            print_unconditional_branch("goto do_indirect_jump");
            break;
        case InstrId::rsp_jalr:
            print_line("jump_target = {}{}; {}{} = 0x{:8X}", gpr_ref_prefix(rs), rs, gpr_ref_prefix(rd), rd, instr_vram + 2 * instr_size);
            print_line("debug_file = __FILE__; debug_line = __LINE__");
            print_unconditional_branch("goto do_indirect_jump");
            break;
        case InstrId::rsp_bne:
            print_indent();
            print_branch_condition("if ({}{} != {}{})", gpr_ref_prefix(rs), rs, gpr_ref_prefix(rt), rt);
            print_branch("goto L_{:04X}", branch_target);
            break;
        case InstrId::rsp_beq:
            print_indent();
            print_branch_condition("if ({}{} == {}{})", gpr_ref_prefix(rs), rs, gpr_ref_prefix(rt), rt);
            print_branch("goto L_{:04X}", branch_target);
            break;
        case InstrId::rsp_bgez:
            print_indent();
            print_branch_condition("if (RSP_SIGNED({}{}) >= 0)", gpr_ref_prefix(rs), rs);
            print_branch("goto L_{:04X}", branch_target);
            break;
        case InstrId::rsp_bgtz:
            print_indent();
            print_branch_condition("if (RSP_SIGNED({}{}) > 0)", gpr_ref_prefix(rs), rs);
            print_branch("goto L_{:04X}", branch_target);
            break;
        case InstrId::rsp_blez:
            print_indent();
            print_branch_condition("if (RSP_SIGNED({}{}) <= 0)", gpr_ref_prefix(rs), rs);
            print_branch("goto L_{:04X}", branch_target);
            break;
        case InstrId::rsp_bltz:
            print_indent();
            print_branch_condition("if (RSP_SIGNED({}{}) < 0)", gpr_ref_prefix(rs), rs);
            print_branch("goto L_{:04X}", branch_target);
            break;
        case InstrId::rsp_bgezal:
            print_indent();
            print_branch_condition("if (RSP_SIGNED({}{}) >= 0)", gpr_ref_prefix(rs), rs);
            fmt::print(output_file, "{{\n");
            fmt::print(output_file, "        {}{} = 0x{:04X};\n", gpr_ref_prefix(31), 31, instr_vram + 2 * instr_size);
            if (instr_index < instructions.size() - 1) {
                emit_instruction(instr_index + 1, instructions, output_file, branch_targets, unsupported_instructions, resume_targets, has_overlays, true, true);
            }
            fmt::print(output_file, "        goto L_{:04X};\n", branch_target);
            fmt::print(output_file, "    }}\n");
            break;
        case InstrId::rsp_bltzal:
            print_indent();
            print_branch_condition("if (RSP_SIGNED({}{}) < 0)", gpr_ref_prefix(rs), rs);
            fmt::print(output_file, "{{\n");
            fmt::print(output_file, "        {}{} = 0x{:04X};\n", gpr_ref_prefix(31), 31, instr_vram + 2 * instr_size);
            if (instr_index < instructions.size() - 1) {
                emit_instruction(instr_index + 1, instructions, output_file, branch_targets, unsupported_instructions, resume_targets, has_overlays, true, true);
            }
            fmt::print(output_file, "        goto L_{:04X};\n", branch_target);
            fmt::print(output_file, "    }}\n");
            break;
        case InstrId::rsp_break:
            print_line("return RspExitReason::Broke", instr_vram);
            break;
        case InstrId::rsp_mfc0:
            print_line("{}{} = {}", gpr_ref_prefix(rt), rt, cop0_read_value(rd));
            break;
        case InstrId::rsp_mtc0:
            {
                std::string_view write_action = cop0_write_action(rd);
                if (has_overlays && cop0_write_is_dma_read(rd)) {
                    // A DMA read into IMEM means new code is being paged in,
                    // so divert to the overlay-swap path (remembering the
                    // resume PC and whether we're in a delay slot).
                    fmt::print(output_file,
                        "    if (dma_mem_address & 0x1000) {{\n"
                        "        ctx->resume_address = 0x{:04X};\n"
                        "        ctx->resume_delay = {};\n"
                        "        goto do_overlay_swap;\n"
                        "    }}\n",
                        instr_vram, in_delay_slot ? "true" : "false");
                }
                if (!write_action.empty()) {
                    print_line("{}({}{})", write_action, gpr_ref_prefix(rt), rt);
                }
                break;
            }
        default:
            fmt::print(stderr, "Unhandled instruction: {}\n", instr.getOpcodeName());
            assert(false);
            return false;
        }
    }

    // Drop the resume label (if any) that a post-swap re-entry jumps to,
    // choosing the delay-slot variant when appropriate.
    if (in_delay_slot) {
        if (resume_targets.delay_targets.contains(instr_vram)) {
            fmt::print(output_file, "R_{:04X}_delay:\n", instr_vram);
        }
    } else {
        if (resume_targets.non_delay_targets.contains(instr_vram)) {
            fmt::print(output_file, "R_{:04X}:\n", instr_vram);
        }
    }

    return true;
}

void emit_indirect_jump_table(std::ofstream& output_file, const BranchTargets& branch_targets, const std::string& output_function_name) {
    fmt::print(output_file,
        "do_indirect_jump:\n"
        "    switch ((jump_target | 0x1000) & {:#X}) {{ \n", rsp_mem_mask);

    // Build the dispatch case list from both target sets. Direct branch
    // labels are obviously valid computed destinations, and so are the
    // indirect ones — some ucodes fake a call with `j helper; addiu $ra,
    // $zero, return_pc` rather than a real `jal`, and collect_branch_targets
    // records those literal return PCs as indirect labels.
    std::vector<uint32_t> jump_targets;
    jump_targets.reserve(branch_targets.direct_targets.size() + branch_targets.indirect_targets.size());
    for (uint32_t branch_target : branch_targets.direct_targets) {
        jump_targets.push_back(branch_target);
    }
    for (uint32_t branch_target : branch_targets.indirect_targets) {
        if (!branch_targets.direct_targets.contains(branch_target)) {
            jump_targets.push_back(branch_target);
        }
    }
    std::sort(jump_targets.begin(), jump_targets.end());

    for (uint32_t branch_target: jump_targets) {
        fmt::print(output_file, "        case 0x{0:04X}: goto L_{0:04X};\n", branch_target);
    }
    fmt::print(output_file,
        "    }}\n"
        "    fprintf(stderr, \"Unhandled jump target 0x%04X in microcode {}, coming from [%s:%d]\\n\", jump_target, debug_file, debug_line);\n"
        "    fprintf(stderr, \"PC trail (oldest..newest):\\n\");\n"
        "    for (uint32_t i = 0; i < 32; i++) {{\n"
        "        uint32_t pos = (ctx->pc_trail_idx + i) & 31;\n"
        "        fprintf(stderr, \"  [%2u] PC=0x%04X\\n\", i, ctx->pc_trail[pos]);\n"
        "    }}\n"
        "    fprintf(stderr, \"Register dump: r0  = %08X r1  = %08X r2  = %08X r3  = %08X r4  = %08X r5  = %08X r6  = %08X r7  = %08X\\n\"\n"
        "           \"               r8  = %08X r9  = %08X r10 = %08X r11 = %08X r12 = %08X r13 = %08X r14 = %08X r15 = %08X\\n\"\n"
        "           \"               r16 = %08X r17 = %08X r18 = %08X r19 = %08X r20 = %08X r21 = %08X r22 = %08X r23 = %08X\\n\"\n"
        "           \"               r24 = %08X r25 = %08X r26 = %08X r27 = %08X r28 = %08X r29 = %08X r30 = %08X r31 = %08X\\n\",\n"
        "           0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12, r13, r14, r15, r16,\n"
        "           r17, r18, r19, r20, r21, r22, r23, r24, r25, r26, r27, r28, r29, r30, r31);\n"
        "    fflush(stderr);\n"
        "    return RspExitReason::UnhandledJumpTarget;\n", output_function_name);
}

void emit_overlay_swap_return(std::ofstream& output_file) {
    // No state needs to be flushed before returning: emit_recompiled_function emits
    // the GPRs, dma_*, jump_target and rsp locals as C++ references into
    // *ctx, so every write has already gone straight into the context.
    fmt::print(output_file,
        "do_overlay_swap:\n"
        "    return RspExitReason::SwapOverlay;\n");
}

#ifdef _MSC_VER
inline uint32_t byteswap(uint32_t val) {
    return _byteswap_ulong(val);
}
#else
constexpr uint32_t byteswap(uint32_t val) {
    return __builtin_bswap32(val);
}
#endif

struct RSPRecompilerOverlayConfig {
    size_t offset;
    size_t size;
};

struct RSPRecompilerOverlaySlotConfig {
    size_t text_address;
    std::vector<RSPRecompilerOverlayConfig> overlays;
};

struct RSPRecompilerConfig {
    size_t text_offset;
    size_t text_size;
    size_t text_address;
    std::filesystem::path rom_file_path;
    std::filesystem::path output_file_path;
    std::string output_function_name;
    std::vector<uint32_t> extra_indirect_branch_targets;
    std::unordered_set<uint32_t> unsupported_instructions;
    std::vector<RSPRecompilerOverlaySlotConfig> overlay_slots;
};

std::filesystem::path join_relative_path(const std::filesystem::path& parent, const std::filesystem::path& child) {
    if (!child.empty()) {
        return parent / child;
    }
    return child;
}

template <typename T>
std::vector<T> toml_array_to_vector(const toml::array* array) {
    std::vector<T> ret;

    // Size the vector up front for the whole toml array.
    ret.reserve(array->size());
    array->for_each([&ret](auto&& el) {
        if constexpr (toml::is_integer<decltype(el)>) {
            ret.push_back(*el);
        }
    });

    return ret;
}

template <typename T>
std::unordered_set<T> toml_array_to_set(const toml::array* array) {
    std::unordered_set<T> ret;

    array->for_each([&ret](auto&& el) {
        if constexpr (toml::is_integer<decltype(el)>) {
            ret.insert(*el);
        }
    });

    return ret;
}

bool load_config(const std::filesystem::path& config_path, RSPRecompilerConfig& out) {
    RSPRecompilerConfig ret{};

    try {
        const toml::table config_data = toml::parse_file(config_path.u8string());
        std::filesystem::path basedir = std::filesystem::path{ config_path }.parent_path();

        std::optional<uint32_t> text_offset = config_data["text_offset"].value<uint32_t>();
        if (text_offset.has_value()) {
            ret.text_offset = text_offset.value();
        }
        else {
            throw toml::parse_error("Missing text_offset in config file", config_data.source());
        }

        std::optional<uint32_t> text_size = config_data["text_size"].value<uint32_t>();
        if (text_size.has_value()) {
            ret.text_size = text_size.value();
        }
        else {
            throw toml::parse_error("Missing text_size in config file", config_data.source());
        }

        std::optional<uint32_t> text_address = config_data["text_address"].value<uint32_t>();
        if (text_address.has_value()) {
            ret.text_address = text_address.value();
        }
        else {
            throw toml::parse_error("Missing text_address in config file", config_data.source());
        }

        std::optional<std::string> rom_file_path = config_data["rom_file_path"].value<std::string>();
        if (rom_file_path.has_value()) {
            ret.rom_file_path = join_relative_path(basedir, rom_file_path.value());
        }
        else {
            throw toml::parse_error("Missing rom_file_path in config file", config_data.source());
        }

        std::optional<std::string> output_file_path = config_data["output_file_path"].value<std::string>();
        if (output_file_path.has_value()) {
            ret.output_file_path = join_relative_path(basedir, output_file_path.value());
        }
        else {
            throw toml::parse_error("Missing output_file_path in config file", config_data.source());
        }

        std::optional<std::string> output_function_name = config_data["output_function_name"].value<std::string>();
        if (output_function_name.has_value()) {
            ret.output_function_name = output_function_name.value();
        }
        else {
            throw toml::parse_error("Missing output_function_name in config file", config_data.source());
        }

        // Extra indirect branch targets (optional)
        const toml::node_view branch_targets_data = config_data["extra_indirect_branch_targets"];
        if (branch_targets_data.is_array()) {
            const toml::array* branch_targets_array = branch_targets_data.as_array();
            ret.extra_indirect_branch_targets = toml_array_to_vector<uint32_t>(branch_targets_array);
        }

        // Unsupported_instructions (optional)
        const toml::node_view unsupported_instructions_data = config_data["unsupported_instructions"];
        if (unsupported_instructions_data.is_array()) {
            const toml::array* unsupported_instructions_array = unsupported_instructions_data.as_array();
            ret.unsupported_instructions = toml_array_to_set<uint32_t>(unsupported_instructions_array);
        }

        // Overlay slots (optional)
        const toml::node_view overlay_slots = config_data["overlay_slots"];
        if (overlay_slots.is_array()) {
            const toml::array* overlay_slots_array = overlay_slots.as_array();

            int slot_idx = 0;
            overlay_slots_array->for_each([&](toml::table slot){
                RSPRecompilerOverlaySlotConfig slot_config;

                std::optional<uint32_t> text_address = slot["text_address"].value<uint32_t>();
                if (text_address.has_value()) {
                    slot_config.text_address = text_address.value();
                }
                else {
                    throw toml::parse_error(
                        fmt::format("Missing text_address in config file at overlay slot {}", slot_idx).c_str(), 
                        config_data.source());
                }

                // Overlays per slot
                const toml::node_view overlays = slot["overlays"];
                if (overlays.is_array()) {
                    const toml::array* overlay_array = overlays.as_array();

                    int overlay_idx = 0;
                    overlay_array->for_each([&](toml::table overlay){
                        RSPRecompilerOverlayConfig overlay_config;
                        
                        std::optional<uint32_t> offset = overlay["offset"].value<uint32_t>();
                        if (offset.has_value()) {
                            overlay_config.offset = offset.value();
                        }
                        else {
                            throw toml::parse_error(
                                fmt::format("Missing offset in config file at overlay slot {} overlay {}", slot_idx, overlay_idx).c_str(), 
                                config_data.source());
                        }

                        std::optional<uint32_t> size = overlay["size"].value<uint32_t>();
                        if (size.has_value()) {
                            overlay_config.size = size.value();

                            if ((size.value() % sizeof(uint32_t)) != 0) {
                                throw toml::parse_error(
                                    fmt::format("Overlay size must be a multiple of {} in config file at overlay slot {} overlay {}", sizeof(uint32_t), slot_idx, overlay_idx).c_str(), 
                                    config_data.source());
                            }
                        }
                        else {
                            throw toml::parse_error(
                                fmt::format("Missing size in config file at overlay slot {} overlay {}", slot_idx, overlay_idx).c_str(), 
                                config_data.source());
                        }

                        slot_config.overlays.push_back(overlay_config);
                        overlay_idx++;
                    });
                }
                else {
                    throw toml::parse_error(
                        fmt::format("Missing overlays in config file at overlay slot {}", slot_idx).c_str(), 
                        config_data.source());
                }

                ret.overlay_slots.push_back(slot_config);
                slot_idx++;
            });
        }

    }
    catch (const toml::parse_error& err) {
        std::cerr << "Syntax error parsing toml: " << *err.source().path << " (" << err.source().begin <<  "):\n" << err.description() << std::endl;
        return false;
    }

    out = ret;
    return true;
}

struct FunctionPermutation {
    std::vector<rabbitizer::InstructionRsp> instrs;
    std::vector<uint32_t> permutation;
};

struct Permutation {
    std::vector<uint32_t> instr_words;
    std::vector<uint32_t> permutation;
};

struct Overlay {
    std::vector<uint32_t> instr_words;
};

struct OverlaySlot {
    uint32_t offset;
    std::vector<Overlay> overlays;
};

// Odometer-style increment over a mixed-radix counter: bump the last digit,
// carrying into earlier slots when a slot reaches its option count. Returns
// false once the counter rolls all the way over (all permutations visited).
bool advance_overlay_counter(const std::vector<uint32_t>& option_lengths, std::vector<uint32_t>& current) {
    current[current.size() - 1] += 1;

    size_t i = current.size() - 1;
    while (current[i] == option_lengths[i]) {
        current[i] = 0;
        if (i == 0) {
            return false;
        }

        current[i - 1] += 1;
        i--;
    }

    return true;
}

// Enumerate every combination of overlay choices across the slots. For each
// combination, start from the base text and patch each slot's chosen overlay
// words into place, producing one fully-resolved instruction image.
void expand_permutations(const std::vector<uint32_t>& base_words, const std::vector<OverlaySlot>& overlay_slots, std::vector<Permutation>& permutations) {
    auto current = std::vector<uint32_t>(overlay_slots.size(), 0);
    auto slot_options = std::vector<uint32_t>(overlay_slots.size(), 0);

    for (size_t i = 0; i < overlay_slots.size(); i++) {
        slot_options[i] = overlay_slots[i].overlays.size();
    }

    do {
        Permutation permutation = {
            .instr_words = std::vector<uint32_t>(base_words),
            .permutation = std::vector<uint32_t>(current)
        };

        for (size_t i = 0; i < overlay_slots.size(); i++) {
            const OverlaySlot &slot = overlay_slots[i];
            const Overlay &overlay = slot.overlays[current[i]];

            uint32_t word_offset = slot.offset / sizeof(uint32_t);

            size_t size_needed = word_offset + overlay.instr_words.size();
            if (permutation.instr_words.size() < size_needed) {
                permutation.instr_words.reserve(size_needed);
            }

            std::copy(overlay.instr_words.begin(), overlay.instr_words.end(), permutation.instr_words.data() + word_offset);
        }

        permutations.push_back(permutation);
    } while (advance_overlay_counter(slot_options, current));
}

std::string permutation_suffix(const std::vector<uint32_t> permutation) {
    std::string str = "";

    for (uint32_t opt : permutation) {
        str += std::to_string(opt);
    }

    return str;
}

void emit_overlay_dispatcher(const std::string& function_name, std::ofstream& output_file, const std::vector<FunctionPermutation>& permutations, const RSPRecompilerConfig& config) {
    // Forward-declare the permutation func type and one prototype per body.
    fmt::print(output_file,
        "#include <map>\n"
        "#include <vector>\n\n"
        "using RspUcodePermutationFunc = RspExitReason(uint8_t* rdram, RspContext* ctx);\n\n"
        "RspExitReason {}(uint8_t* rdram, RspContext* ctx);\n",
        config.output_function_name + "_initial");

    for (const auto& permutation : permutations) {
        fmt::print(output_file, "RspExitReason {}(uint8_t* rdram, RspContext* ctx);\n",
            config.output_function_name + permutation_suffix(permutation.permutation));
    }
    fmt::print(output_file, "\n");

    // Lookup table: IMEM address of a slot -> that slot's index.
    fmt::print(output_file,
        "static const std::map<uint32_t, uint32_t> imemToSlot = {{\n");
    for (size_t i = 0; i < config.overlay_slots.size(); i++) {
        const RSPRecompilerOverlaySlotConfig& slot = config.overlay_slots[i];

        uint32_t imemAddress = slot.text_address & rsp_mem_mask;
        fmt::print(output_file, "    {{ 0x{:04X}, {} }},\n",
            imemAddress, i);
    }
    fmt::print(output_file, "}};\n\n");

    // Per slot, a lookup table: ucode offset -> overlay index within the slot.
    fmt::print(output_file,
        "static const std::vector<std::map<uint32_t, uint32_t>> offsetToOverlay = {{\n");
    for (const auto& slot : config.overlay_slots) {
        fmt::print(output_file, "    {{\n");
        for (size_t i = 0; i < slot.overlays.size(); i++) {
            const RSPRecompilerOverlayConfig& overlay = slot.overlays[i];

            fmt::print(output_file, "        {{ 0x{:04X}, {} }},\n",
                overlay.offset, i);
        }
        fmt::print(output_file, "    }},\n");
    }
    fmt::print(output_file, "}};\n\n");

    // The array of permutation function pointers, indexed by combination.
    fmt::print(output_file,
        "static RspUcodePermutationFunc* permutations[] = {{\n");
    for (const auto& permutation : permutations) {
        fmt::print(output_file, "    {},\n",
            config.output_function_name + permutation_suffix(permutation.permutation));
    }
    fmt::print(output_file, "}};\n\n");

    // Public entry point. It keeps a static thread_local RspContext alive
    // so general registers carry over between run_task calls — on real
    // hardware rspboot only rewrites $1/$2/$3/$4/$7 and the rest is left as
    // the previous task ended it. emit_recompiled_function() uses the same trick for
    // the no-overlay path.
    fmt::print(output_file,
        "RspExitReason {}(uint8_t* rdram, uint32_t ucode_addr) {{\n"
        "    static thread_local RspContext ctx{{}};\n",
        config.output_function_name);
    
    std::string slots_init_str = "";
    for (size_t i = 0; i < config.overlay_slots.size(); i++) {
        if (i > 0) {
            slots_init_str += ", ";
        }

        slots_init_str += "0";
    }

    fmt::print(output_file, "    uint32_t slots[] = {{{}}};\n\n",
        slots_init_str);

    fmt::print(output_file, "    RspExitReason exitReason = {}(rdram, &ctx);\n\n",
        config.output_function_name + "_initial");
    
    fmt::print(output_file, "");

    std::string perm_index_str = "";
    for (size_t i = 0; i < config.overlay_slots.size(); i++) {
        if (i > 0) {
            perm_index_str += " + ";
        }

        uint32_t multiplier = 1;
        for (size_t k = i + 1; k < config.overlay_slots.size(); k++) {
            multiplier *= config.overlay_slots[k].overlays.size();
        }

        perm_index_str += fmt::format("slots[{}] * {}", i, multiplier);
    }
    
    fmt::print(output_file,
        "    while (exitReason == RspExitReason::SwapOverlay) {{\n"
        "        uint32_t slot = imemToSlot.at(ctx.dma_mem_address);\n"
        "        uint32_t overlay = offsetToOverlay.at(slot).at(ctx.dma_dram_address - ucode_addr);\n"
        "        slots[slot] = overlay;\n"
        "\n"
        "        RspUcodePermutationFunc* permutationFunc = permutations[{}];\n"
        "        exitReason = permutationFunc(rdram, &ctx);\n"
        "    }}\n\n"
        "    return exitReason;\n"
        "}}\n\n",
        perm_index_str);
}

void emit_recompiled_function(const std::string& function_name, std::ofstream& output_file, const std::vector<rabbitizer::InstructionRsp>& instrs, const RSPRecompilerConfig& config, const ResumeTargets& resume_targets, bool is_permutation, bool is_initial) {
    // Collect indirect jump targets (return addresses for linked jumps)
    BranchTargets branch_targets = collect_branch_targets(instrs);

    // Fold in any indirect targets the config supplies explicitly; these
    // cover destinations (jump tables, etc.) that can't be spotted in code.
    for (uint32_t target : config.extra_indirect_branch_targets) {
        branch_targets.indirect_targets.insert(target);
    }

    // Emit the function body. There are two shapes, both taking RspContext*:
    //
    //   is_permutation == true  : an overlay permutation invoked by the
    //                             swap wrapper with a persistent ctx; it may
    //                             be entered at a resume target.
    //
    //   is_permutation == false : the no-overlay case (e.g. Stadium's
    //                             aspMain). Here we emit the body as an
    //                             `_impl(rdram, ctx)` function and pair it
    //                             with a legacy-ABI wrapper `(rdram,
    //                             ucode_addr)` that holds a static
    //                             thread_local RspContext so GPRs survive
    //                             between run_task calls — again mirroring
    //                             rspboot, which only writes $1/$2/$3/$4/$7.
    //
    // The GPR / dma_* / jump_target / rsp names are emitted as C++
    // references bound to *ctx, so assigning through them writes straight
    // into the context. No path (normal return, SwapOverlay,
    // UnhandledJumpTarget, ...) needs an explicit save-back.
    std::string impl_function_name = is_permutation
        ? function_name                      // permutation/initial: name as given
        : (function_name + "_impl");         // no-overlay: wrap with _impl

    fmt::print(output_file,
        "RspExitReason {}(uint8_t* rdram, RspContext* ctx) {{\n"
        "    uint32_t&                 r1 = ctx->r1;   uint32_t&  r2 = ctx->r2;   uint32_t&  r3 = ctx->r3;   uint32_t&  r4 = ctx->r4;   uint32_t&  r5 = ctx->r5;   uint32_t&  r6 = ctx->r6;   uint32_t&  r7 = ctx->r7;\n"
        "    uint32_t&  r8 = ctx->r8;  uint32_t&  r9 = ctx->r9;   uint32_t& r10 = ctx->r10; uint32_t& r11 = ctx->r11; uint32_t& r12 = ctx->r12; uint32_t& r13 = ctx->r13; uint32_t& r14 = ctx->r14; uint32_t& r15 = ctx->r15;\n"
        "    uint32_t& r16 = ctx->r16; uint32_t& r17 = ctx->r17; uint32_t& r18 = ctx->r18; uint32_t& r19 = ctx->r19; uint32_t& r20 = ctx->r20; uint32_t& r21 = ctx->r21; uint32_t& r22 = ctx->r22; uint32_t& r23 = ctx->r23;\n"
        "    uint32_t& r24 = ctx->r24; uint32_t& r25 = ctx->r25; uint32_t& r26 = ctx->r26; uint32_t& r27 = ctx->r27; uint32_t& r28 = ctx->r28; uint32_t& r29 = ctx->r29; uint32_t& r30 = ctx->r30; uint32_t& r31 = ctx->r31;\n"
        "    uint32_t& dma_mem_address = ctx->dma_mem_address; uint32_t& dma_dram_address = ctx->dma_dram_address; uint32_t& jump_target = ctx->jump_target;\n"
        "    const char * debug_file = NULL; int debug_line = 0;\n"
        "    RSP& rsp = ctx->rsp;\n", impl_function_name);

    // Only permutations need resume dispatch: on re-entry after a
    // SwapOverlay round-trip, jump to the PC that triggered the swap. The
    // initial call (is_initial) is the task's first entry, so it has no
    // pending resume and skips this block.
    if (is_permutation && !is_initial) {
        fmt::print(output_file,
            "    if (ctx->resume_delay) {{\n"
            "        switch (ctx->resume_address) {{\n");

        for (uint32_t address : resume_targets.delay_targets) {
            fmt::print(output_file, "            case 0x{0:04X}: goto R_{0:04X}_delay;\n",
                address);
        }

        fmt::print(output_file,
            "        }}\n"
            "    }} else {{\n"
            "        switch (ctx->resume_address) {{\n");

        for (uint32_t address : resume_targets.non_delay_targets) {
            fmt::print(output_file, "            case 0x{0:04X}: goto R_{0:04X};\n",
                address);
        }

        fmt::print(output_file,
            "        }}\n"
            "    }}\n"
            "    printf(\"Unhandled resume target 0x%04X (delay slot: %d) in microcode {}\\n\", ctx->resume_address, ctx->resume_delay);\n"
            "    return RspExitReason::UnhandledResumeTarget;\n",
            config.output_function_name);
    }

    // Per rspboot, $1 is reloaded with 0xFC0 on every entry; the remaining
    // GPRs keep their prior-task values, which already live in *ctx via the
    // reference bindings above.
    fmt::print(output_file, "    r1 = 0xFC0;\n");
    // Clear the watchdog counter for this run. The PC trail is deliberately
    // left intact: a previous task's final PCs are useful context if this
    // run goes wrong.
    fmt::print(output_file, "    ctx->watchdog_count = 0;\n");
    // Field note on Stadium's aspMain hang (watchdog trail, 2026-04-27):
    // the dispatcher at L_1048 indexes a handler table by DMEM[$29] and
    // `jr`s to the result. At first entry $29 is 0 (Path A's persistent ctx
    // starts zeroed). DMEM[0..0xF7F] is ucode_data DMA'd in by the runtime,
    // whose first 32 bytes are the handler table, so index 0 sends control
    // to handler[0] = PC 0x10EC — the DMA-trigger stub (`jr $ra; mtc0 r3,
    // SP_RD_LEN`). That returns to $31 = 0x1038 (the point just after the
    // initial `jal L_1120` on the L_102C boot path), spins on SP_DMA_BUSY
    // (always 0 under HLE), and re-enters the dispatcher with $29 still 0:
    // an infinite loop.
    //
    // Forcing $29 isn't enough on its own: even pointed at a real command
    // block, the first DMA loads nothing because dma_mem_address /
    // dma_dram_address are still uninitialized when L_10EC runs from the
    // L_1120 path (L_1120 never issues SET_DMA_MEM/DRAM — it assumes the
    // caller already did). Real hardware leaves SP_MEM_ADDR / SP_DRAM_ADDR
    // holding rspboot's last DMA (the ucode_data load), so aspMain's opening
    // dispatch must rely on a command that re-DMAs from a known offset.
    // Pinning that down needs a closer look at stock libultra aspMain, or a
    // side-by-side with a known-good audio task.
    //
    // The watchdog and PC trail make any fix's effect obvious: once the
    // dispatcher starts landing on handlers other than 0x10EC, it's moving.
    // Write each instruction
    for (size_t instr_index = 0; instr_index < instrs.size(); instr_index++) {
        emit_instruction(instr_index, instrs, output_file, branch_targets, config.unsupported_instructions, resume_targets, is_permutation, false, false);
    }

    // Terminate instruction code with a return to indicate that the microcode has run past its end
    fmt::print(output_file, "    return RspExitReason::ImemOverrun;\n");

    // Write the section containing the indirect jump table
    emit_indirect_jump_table(output_file, branch_targets, config.output_function_name);

    // Write routine for returning for an overlay swap
    if (is_permutation) {
        emit_overlay_swap_return(output_file);
    }

    // End the impl function
    fmt::print(output_file, "}}\n");

    // No-overlay case: also emit the legacy-ABI wrapper. The runtime calls
    // ucodes through rsp.hpp's RspUcodeFunc typedef — signature `(rdram,
    // ucode_addr)` — so this keeps that interface unchanged. The wrapper
    // holds a static thread_local RspContext to carry GPRs across run_task
    // calls. Per-ucode storage is right for the usual "same ucode invoked
    // repeatedly" pattern; a game relying on GPR leakage between *different*
    // ucodes would need a runtime-owned shared context, which belongs in
    // librecomp rather than this recompiler.
    if (!is_permutation) {
        fmt::print(output_file,
            "\n"
            "RspExitReason {0}(uint8_t* rdram, [[maybe_unused]] uint32_t ucode_addr) {{\n"
            "    static thread_local RspContext persistent_ctx{{}};\n"
            "    // Pre-task hook: if a runtime registered a hook keyed by\n"
            "    // this ucode's name, call it here. Lets game-specific code\n"
            "    // replicate parts of rspboot's setup that the static\n"
            "    // recompilation can't infer (initial GPRs, DMA-engine\n"
            "    // residue, pre-loaded command data in DMEM). Inline\n"
            "    // null-check by the std::unordered_map lookup — typical\n"
            "    // cost is one branch when no hook is registered.\n"
            "    recomp::rsp::run_pre_task_hook(rdram, &persistent_ctx, \"{0}\", ucode_addr);\n"
            "    return {0}_impl(rdram, &persistent_ctx);\n"
            "}}\n",
            function_name);
    }
}

int main(int argc, const char** argv) {
    if (argc != 2) {
        fmt::print("Usage: {} [config file]\n", argv[0]);
        std::exit(EXIT_SUCCESS);
    }

    RSPRecompilerConfig config;
    if (!load_config(std::filesystem::path{argv[1]}, config)) {
        fmt::print("Failed to parse config file {}\n", argv[0]);
        std::exit(EXIT_FAILURE);
    }

    std::vector<uint32_t> instr_words{};
    std::vector<OverlaySlot> overlay_slots{};
    instr_words.resize(config.text_size / sizeof(uint32_t));
    {
        std::ifstream rom_file{ config.rom_file_path, std::ios_base::binary };

        if (!rom_file.good()) {
            fmt::print(stderr, "Failed to open rom file\n");
            return EXIT_FAILURE;
        }

        rom_file.seekg(config.text_offset);
        rom_file.read(reinterpret_cast<char*>(instr_words.data()), config.text_size);

        for (const RSPRecompilerOverlaySlotConfig &slot_config : config.overlay_slots) {
            OverlaySlot slot{};
            slot.offset = (slot_config.text_address - config.text_address) & rsp_mem_mask;

            for (const RSPRecompilerOverlayConfig &overlay_config : slot_config.overlays) {
                Overlay overlay{};
                overlay.instr_words.resize(overlay_config.size / sizeof(uint32_t));

                rom_file.seekg(config.text_offset + overlay_config.offset);
                rom_file.read(reinterpret_cast<char*>(overlay.instr_words.data()), overlay_config.size);

                slot.overlays.push_back(overlay);
            }

            overlay_slots.push_back(slot);
        }
    }

    // Expand every overlay combination into its own instruction image.
    std::vector<Permutation> permutations{};
    if (!overlay_slots.empty()) {
        expand_permutations(instr_words, overlay_slots, permutations);
    }

    // Turn off the rabbitizer pseudo-ops we don't want decoded as such.
    RabbitizerConfig_Cfg.pseudos.pseudoMove = false;
    RabbitizerConfig_Cfg.pseudos.pseudoBeqz = false;
    RabbitizerConfig_Cfg.pseudos.pseudoBnez = false;
    RabbitizerConfig_Cfg.pseudos.pseudoNot = false;

    // Decode the raw text words into rabbitizer instructions, assigning each
    // its IMEM-relative vram.
    std::vector<rabbitizer::InstructionRsp> instrs{};
    instrs.reserve(instr_words.size());
    uint32_t vram = config.text_address & rsp_mem_mask;
    for (uint32_t instr_word : instr_words) {
        const rabbitizer::InstructionRsp& instr = instrs.emplace_back(byteswap(instr_word), vram);
        vram += instr_size;
    }

    std::vector<FunctionPermutation> func_permutations{};
    func_permutations.reserve(permutations.size());
    for (const Permutation& permutation : permutations) {
        FunctionPermutation func = {
            .permutation = std::vector<uint32_t>(permutation.permutation)
        };

        func.instrs.reserve(permutation.instr_words.size());
        uint32_t vram = config.text_address & rsp_mem_mask;
        for (uint32_t instr_word : permutation.instr_words) {
            const rabbitizer::InstructionRsp& instr = func.instrs.emplace_back(byteswap(instr_word), vram);
            vram += instr_size;
        }

        func_permutations.emplace_back(func);
    }

    // Gather the union of overlay-swap resume targets across every permutation.
    ResumeTargets resume_targets{};
    for (const FunctionPermutation& permutation : func_permutations) {
        collect_resume_targets(permutation.instrs, resume_targets);
    }

    // Create the output file (and its directory) and write the header includes.
    std::filesystem::create_directories(std::filesystem::path{ config.output_file_path }.parent_path());
    std::ofstream output_file(config.output_file_path);
    fmt::print(output_file,
        "#include \"librecomp/rsp.hpp\"\n"
        "#include \"librecomp/rsp_vu_impl.hpp\"\n");

    // Emit the recompiled function(s): a single function with no overlays,
    // otherwise the swap dispatcher plus the initial and per-permutation bodies.
    if (overlay_slots.empty()) {
        emit_recompiled_function(config.output_function_name, output_file, instrs, config, resume_targets, false, false);
    } else {
        emit_overlay_dispatcher(config.output_function_name, output_file, func_permutations, config);
        emit_recompiled_function(config.output_function_name + "_initial", output_file, instrs, config, ResumeTargets{}, true, true);

        for (const auto& permutation : func_permutations) {
            emit_recompiled_function(config.output_function_name + permutation_suffix(permutation.permutation), 
                output_file, permutation.instrs, config, resume_targets, true, false);
        }
    }

    return 0;
}
