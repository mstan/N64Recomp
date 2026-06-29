#include <cassert>
#include <fstream>
#include <unordered_map>
#include <cmath>

#include "fmt/format.h"
#include "fmt/ostream.h"

#include "recompiler/live_recompiler.h"
#include "recomp.h"

#include "sljitLir.h"

// This translation unit implements the Generator interface against sljit, emitting
// native host machine code at runtime rather than C source. Each Generator hook turns
// one decoded MIPS operation into a short sequence of sljit IR ops; sljit then lowers
// that IR to the host ISA when the function is finalized.

// Rewritable jump targets are stashed in pointer-sized slots, so the host pointer width
// has to be at least as wide as sljit's word type.
static_assert(sizeof(void*) >= sizeof(sljit_uw), "`void*` must be able to hold a `sljit_uw` value for rewritable jumps!");

// Bias applied to guest addresses so that a guest pointer can index directly off the
// host rdram base register (see the per-function prologue, which subtracts this once).
constexpr uint64_t rdram_offset = 0xFFFFFFFF80000000ULL;

void N64Recomp::live_recompiler_init() {
    RabbitizerConfig_Cfg.pseudos.pseudoMove = false;
    RabbitizerConfig_Cfg.pseudos.pseudoBeqz = false;
    RabbitizerConfig_Cfg.pseudos.pseudoBnez = false;
    RabbitizerConfig_Cfg.pseudos.pseudoNot = false;
    RabbitizerConfig_Cfg.pseudos.pseudoBal = false;
}

// Fixed assignment of guest state to sljit's saved/scratch registers. The saved
// registers (S0-S4) persist across the calls we emit, so the hot guest state lives
// there; the scratch registers (R0-R3) are reused freely as working space.
namespace Registers {
    constexpr int rdram = SLJIT_S0; // holds the rdram base, already biased by -rdram_offset
    constexpr int ctx = SLJIT_S1;   // holds the recomp_context pointer
    constexpr int c1cs = SLJIT_S2;  // holds the COP1 condition (FP compare) bit
    constexpr int hi = SLJIT_S3;    // holds the HI multiply/divide register
    constexpr int lo = SLJIT_S4;    // holds the LO multiply/divide register
    constexpr int temp_reg1 = SLJIT_R0;
    constexpr int temp_reg2 = SLJIT_R1;
    constexpr int temp_reg3 = SLJIT_R2;
    constexpr int temp_reg4 = SLJIT_R3;
}

// A call to another recompiled function in the same batch. The target label isn't known
// until that function has been emitted, so the jump is recorded and patched in finish().
struct InnerCall {
    size_t target_func_index;
    sljit_jump* jump;
};

struct ReferenceSymbolCall {
    N64Recomp::SymbolReference reference;
    sljit_jump* jump;
};

// A bounds-check failure exit for a switch/jump-table. Records what's needed to report the
// out-of-range case (the jr instruction's vram and the table's vram) once the shared error
// trampoline is emitted at the end of the function.
struct SwitchErrorJump {
    uint32_t instr_vram;
    uint32_t jtbl_vram;
    sljit_jump* jump;
};

// Scratch state carried across the emission of a single batch of functions. Most of these
// are "to be resolved later" lists: sljit can't link a jump to a label that hasn't been
// emitted yet, so we stash the jumps/labels here and stitch them together in finish().
struct N64Recomp::LiveGeneratorContext {
    std::string function_name;
    std::unordered_map<std::string, sljit_label*> labels;
    std::unordered_map<std::string, std::vector<sljit_jump*>> pending_jumps;
    std::vector<sljit_label*> func_labels;
    std::vector<InnerCall> inner_calls;
    std::vector<std::vector<std::string>> switch_jump_labels;
    // See LiveGeneratorOutput::jump_tables for info. Contains sljit labels so they can be linked after recompilation.
    std::vector<std::pair<std::vector<sljit_label*>, std::unique_ptr<void*[]>>> unlinked_jump_tables;
    // Jump tables for the current function being recompiled.
    std::vector<std::unique_ptr<void*[]>> pending_jump_tables;
    // See LiveGeneratorOutput::reference_symbol_jumps for info.
    std::vector<std::pair<ReferenceJumpDetails, sljit_jump*>> reference_symbol_jumps;
    // See LiveGeneratorOutput::import_jumps_by_index for info.
    std::unordered_multimap<size_t, sljit_jump*> import_jumps_by_index;
    std::vector<SwitchErrorJump> switch_error_jumps;
    sljit_jump* cur_branch_jump;
};

N64Recomp::LiveGenerator::LiveGenerator(size_t num_funcs, const LiveGeneratorInputs& inputs) : inputs(inputs) {
    compiler = sljit_create_compiler(nullptr);
    context = std::make_unique<LiveGeneratorContext>();
    context->func_labels.resize(num_funcs);
    errored = false;
}

N64Recomp::LiveGenerator::~LiveGenerator() {
    if (compiler != nullptr) {
        sljit_free_compiler(compiler);
        compiler = nullptr;
    }
}

N64Recomp::LiveGeneratorOutput N64Recomp::LiveGenerator::finish() {
    LiveGeneratorOutput ret{};
    if (errored) {
        ret.good = false;
        return ret;
    }
    
    ret.good = true;

    // Resolve every deferred call to another function in this batch now that all of their
    // entry labels exist.
    for (const InnerCall& call : context->inner_calls) {
        sljit_label* target_func_label = context->func_labels[call.target_func_index];

        // If the callee never got recompiled there's no label to point at, so the whole
        // batch is unusable.
        if (target_func_label == nullptr) {
            return { };
        }

        sljit_set_label(call.jump, target_func_label);
    }

    // Emit a single shared trampoline that reports out-of-range switch cases, then wire every
    // bounds-check failure jump to it.
    if (!context->switch_error_jumps.empty()) {
        // The handler needs the function name as a C string; copy it into a heap buffer that
        // the output owns so it stays alive for as long as the generated code does.
        char* func_name = new char[context->function_name.size() + 1];
        memcpy(func_name, context->function_name.c_str(), context->function_name.size());
        func_name[context->function_name.size()] = '\x00';
        ret.string_literals.emplace_back(func_name);

        std::vector<sljit_jump*> switch_error_return_jumps{};
        switch_error_return_jumps.resize(context->switch_error_jumps.size());

        // One landing pad per failed bounds check: report the error, then fall through to a
        // shared return.
        for (size_t i = 0; i < context->switch_error_jumps.size(); i++) {
            const auto& cur_error_jump = context->switch_error_jumps[i];

            // Place a label here and retarget the failure jump at it.
            sljit_set_label(cur_error_jump.jump, sljit_emit_label(compiler));

            // Marshal the three arguments: function name, the jr vram, and the table vram.
            sljit_emit_op1(compiler, SLJIT_MOV, SLJIT_R0, 0, SLJIT_IMM, sljit_sw(func_name));
            sljit_emit_op1(compiler, SLJIT_MOV32, SLJIT_R1, 0, SLJIT_IMM, sljit_sw(cur_error_jump.instr_vram));
            sljit_emit_op1(compiler, SLJIT_MOV32, SLJIT_R2, 0, SLJIT_IMM, sljit_sw(cur_error_jump.jtbl_vram));

            // Invoke the host-side switch_error reporter.
            sljit_emit_icall(compiler, SLJIT_CALL, SLJIT_ARGS3V(P, 32, 32), SLJIT_IMM, sljit_sw(inputs.switch_error));

            // Branch to the common return below.
            switch_error_return_jumps[i] = sljit_emit_jump(compiler, SLJIT_JUMP);
        }

        // The shared return that every landing pad funnels into.
        sljit_label* return_label = sljit_emit_label(compiler);
        sljit_emit_return_void(compiler);

        // Point all of the per-pad return branches at it.
        for (sljit_jump* cur_jump : switch_error_return_jumps) {
            sljit_set_label(cur_jump, return_label);
        }
    }
    context->switch_error_jumps.clear();

    // Lower the accumulated IR to host machine code and record its size.
    ret.code = sljit_generate_code(compiler, 0, NULL);
    ret.code_size = sljit_get_generated_code_size(compiler);
    ret.functions.resize(context->func_labels.size());

    // Now that the code exists, turn each entry label into a callable function pointer.
    for (size_t func_index = 0; func_index < ret.functions.size(); func_index++) {
        sljit_label* func_label = context->func_labels[func_index];

        // Functions that were skipped have a null label and are left as null pointers.
        if (func_label != nullptr) {
            ret.functions[func_index] = reinterpret_cast<recomp_func_t*>(sljit_get_label_addr(func_label));
        }
    }
    context->func_labels.clear();

    // Hand back the machine-code address of each reference-symbol call site so the loader can
    // patch in the real target once it's known.
    ret.reference_symbol_jumps.resize(context->reference_symbol_jumps.size());
    for (size_t jump_index = 0; jump_index < context->reference_symbol_jumps.size(); jump_index++) {
        ReferenceJumpDetails& details = context->reference_symbol_jumps[jump_index].first;
        sljit_jump* jump = context->reference_symbol_jumps[jump_index].second;

        ret.reference_symbol_jumps[jump_index].first = details;
        ret.reference_symbol_jumps[jump_index].second = reinterpret_cast<void*>(jump->addr);
    }
    context->reference_symbol_jumps.clear();

    // Same idea for import call sites, keyed by import index so multiple sites can share a target.
    ret.import_jumps_by_index.reserve(context->import_jumps_by_index.size());
    for (auto& [jump_index, jump] : context->import_jumps_by_index) {
        ret.import_jumps_by_index.emplace(jump_index, reinterpret_cast<void*>(jump->addr));
    }
    context->import_jumps_by_index.clear();

    // Resolve each jump table's case labels into concrete code addresses and move the finished
    // table into the output.
    for (auto& [labels, jump_table] : context->unlinked_jump_tables) {
        for (size_t entry_index = 0; entry_index < labels.size(); entry_index++) {
            sljit_label* cur_label = labels[entry_index];
            jump_table[entry_index] = reinterpret_cast<void*>(sljit_get_label_addr(cur_label));
        }
        ret.jump_tables.emplace_back(std::move(jump_table));
    }
    context->unlinked_jump_tables.clear();

    ret.executable_offset = sljit_get_executable_offset(compiler);

    sljit_free_compiler(compiler);
    compiler = nullptr;
    errored = false;

    return ret;
}

N64Recomp::LiveGeneratorOutput::~LiveGeneratorOutput() {
    if (code != nullptr) {
        sljit_free_code(code, nullptr);
        code = nullptr;
    }
}

size_t N64Recomp::LiveGeneratorOutput::num_reference_symbol_jumps() const {
    return reference_symbol_jumps.size();
}

void N64Recomp::LiveGeneratorOutput::set_reference_symbol_jump(size_t jump_index, recomp_func_t* func) {
    const auto& jump_entry = reference_symbol_jumps[jump_index];
    sljit_set_jump_addr(reinterpret_cast<sljit_uw>(jump_entry.second), reinterpret_cast<sljit_uw>(func), executable_offset);
}

N64Recomp::ReferenceJumpDetails N64Recomp::LiveGeneratorOutput::get_reference_symbol_jump_details(size_t jump_index) {
    return reference_symbol_jumps[jump_index].first;
}

void N64Recomp::LiveGeneratorOutput::populate_import_symbol_jumps(size_t import_index, recomp_func_t* func) {
    auto find_range = import_jumps_by_index.equal_range(import_index);
    for (auto it = find_range.first; it != find_range.second; ++it) {
        sljit_set_jump_addr(reinterpret_cast<sljit_uw>(it->second), reinterpret_cast<sljit_uw>(func), executable_offset);
    }
}

// The following helpers compute the byte offset of a given guest register inside
// recomp_context. They're paired with SLJIT_MEM1(Registers::ctx) to read/write guest state.

constexpr int get_gpr_context_offset(int gpr_index) {
    return offsetof(recomp_context, r0) + sizeof(recomp_context::r0) * gpr_index;
}

constexpr int get_fpr_single_context_offset(int fpr_index) {
    return offsetof(recomp_context, f0.fl) + sizeof(recomp_context::f0) * fpr_index;
}

constexpr int get_fpr_double_context_offset(int fpr_index) {
    return offsetof(recomp_context, f0.d) + sizeof(recomp_context::f0) * fpr_index;
}

// True for the operand kinds that name the low 32 bits of an FPR (the "u32l" view).
constexpr bool is_fpr_u32l(N64Recomp::Operand operand) {
    return
        operand == N64Recomp::Operand::FdU32L ||
        operand == N64Recomp::Operand::FsU32L ||
        operand == N64Recomp::Operand::FtU32L;
    return false;
}

// Produce the operand/offset pair addressing the low word of an FPR. Even-numbered FPRs live
// inline in the context, but odd ones are stored in the separate f_odd array (indirected
// through a pointer), so an extra load of that pointer is emitted when needed.
constexpr void get_fpr_u32l_context_offset(int fpr_index, sljit_compiler* compiler, int odd_float_address_register, sljit_sw& out, sljit_sw& outw) {
    if (fpr_index & 1) {
        assert(compiler != nullptr);
        // Fetch the ctx->f_odd base pointer into the supplied address register.
        sljit_emit_op1(compiler, SLJIT_MOV_P, odd_float_address_register, 0, SLJIT_MEM1(Registers::ctx), offsetof(recomp_context, f_odd));
        // sljit_emit_op0(compiler, SLJIT_BREAKPOINT);
        out = SLJIT_MEM1(odd_float_address_register);
        // Index it by ((fpr_index - 1) * 2) elements of f_odd.
        outw = ((fpr_index - 1) * 2) * sizeof(*recomp_context::f_odd);
    }
    else {
        out = SLJIT_MEM1(Registers::ctx);
        outw = offsetof(recomp_context, f0.u32l) + sizeof(recomp_context::f0) * fpr_index;
    }
}

constexpr int get_fpr_u64_context_offset(int fpr_index) {
    return offsetof(recomp_context, f0.u64) + sizeof(recomp_context::f0) * fpr_index;
}

// Resolve a GPR to an sljit operand. $zero is folded to an immediate 0 instead of a memory
// access, which both matches MIPS semantics and avoids a pointless load.
void get_gpr_values(int gpr, sljit_sw& out, sljit_sw& outw) {
    if (gpr == 0) {
        out = SLJIT_IMM;
        outw = 0;
    }
    else {
        out = SLJIT_MEM1(Registers::ctx);
        outw = get_gpr_context_offset(gpr);
    }
}

// Translate a decoded operand into the sljit (operand, offset) pair that names its storage:
// an immediate, one of the saved guest-state registers, or a slot inside recomp_context.
// Returns false for operand kinds that can't be addressed directly (the high-word FPR views).
bool get_operand_values(N64Recomp::Operand operand, const N64Recomp::InstructionContext& context, sljit_sw& out, sljit_sw& outw,
    sljit_compiler* compiler, int odd_float_address_register
)
{
    using namespace N64Recomp;

    switch (operand) {
        case Operand::Rd:
            get_gpr_values(context.rd, out, outw);
            break;
        case Operand::Rs:
            get_gpr_values(context.rs, out, outw);
            break;
        case Operand::Rt:
            get_gpr_values(context.rt, out, outw);
            break;
        case Operand::Fd:
            out = SLJIT_MEM1(Registers::ctx);
            outw = get_fpr_single_context_offset(context.fd);
            break;
        case Operand::Fs:
            out = SLJIT_MEM1(Registers::ctx);
            outw = get_fpr_single_context_offset(context.fs);
            break;
        case Operand::Ft:
            out = SLJIT_MEM1(Registers::ctx);
            outw = get_fpr_single_context_offset(context.ft);
            break;
        case Operand::FdDouble:
            out = SLJIT_MEM1(Registers::ctx);
            outw = get_fpr_double_context_offset(context.fd);
            break;
        case Operand::FsDouble:
            out = SLJIT_MEM1(Registers::ctx);
            outw = get_fpr_double_context_offset(context.fs);
            break;
        case Operand::FtDouble:
            out = SLJIT_MEM1(Registers::ctx);
            outw = get_fpr_double_context_offset(context.ft);
            break;
        case Operand::FdU32L:
            get_fpr_u32l_context_offset(context.fd, compiler, odd_float_address_register, out, outw);
            break;
        case Operand::FsU32L:
            get_fpr_u32l_context_offset(context.fs, compiler, odd_float_address_register, out, outw);
            break;
        case Operand::FtU32L:
            get_fpr_u32l_context_offset(context.ft, compiler, odd_float_address_register, out, outw);
            break;
        case Operand::FdU32H:
            assert(false);
            return false;
        case Operand::FsU32H:
            assert(false);
            return false;
        case Operand::FtU32H:
            assert(false);
            return false;
        case Operand::FdU64:
            out = SLJIT_MEM1(Registers::ctx);
            outw = get_fpr_u64_context_offset(context.fd);
            break;
        case Operand::FsU64:
            out = SLJIT_MEM1(Registers::ctx);
            outw = get_fpr_u64_context_offset(context.fs);
            break;
        case Operand::FtU64:
            out = SLJIT_MEM1(Registers::ctx);
            outw = get_fpr_u64_context_offset(context.ft);
            break;
        case Operand::ImmU16:
            out = SLJIT_IMM;
            outw = (sljit_sw)(uint16_t)context.imm16;
            break;
        case Operand::ImmS16:
            out = SLJIT_IMM;
            outw = (sljit_sw)(int16_t)context.imm16;
            break;
        case Operand::Sa:
            out = SLJIT_IMM;
            outw = context.sa;
            break;
        case Operand::Sa32:
            out = SLJIT_IMM;
            outw = context.sa + 32;
            break;
        case Operand::Cop1cs:
            out = Registers::c1cs;
            outw = 0;
            break;
        case Operand::Hi:
            out = Registers::hi;
            outw = 0;
            break;
        case Operand::Lo:
            out = Registers::lo;
            outw = 0;
            break;
        case Operand::Zero:
            out = SLJIT_IMM;
            outw = 0;
            break;
    }
    return true;
}

// Detects writes whose destination GPR resolves to $zero, which are no-ops on MIPS and can
// simply be dropped.
bool outputs_to_zero(N64Recomp::Operand output, const N64Recomp::InstructionContext& ctx) {
    if (output == N64Recomp::Operand::Rd && ctx.rd == 0) {
        return true;
    }
    if (output == N64Recomp::Operand::Rt && ctx.rt == 0) {
        return true;
    }
    if (output == N64Recomp::Operand::Rs && ctx.rs == 0) {
        return true;
    }
    return false;
}

void N64Recomp::LiveGenerator::process_binary_op(const BinaryOp& op, const InstructionContext& ctx) const {
    // A write to $zero has no effect, so emit nothing.
    if (outputs_to_zero(op.output, ctx)) {
        return;
    }

    // The low-word FPR view is never valid as an input to a binary op.
    if (is_fpr_u32l(op.operands.operands[0]) || is_fpr_u32l(op.operands.operands[1])) {
        assert(false);
        errored = true;
        return;
    }

    // The only binary op allowed to write the low-word FPR view is lwc1, modeled here as an LW.
    if (is_fpr_u32l(op.output) && op.type != BinaryOpType::LW) {
        assert(false);
        errored = true;
        return;
    }

    sljit_sw dst;
    sljit_sw dstw;
    sljit_sw src1;
    sljit_sw src1w;
    sljit_sw src2;
    sljit_sw src2w;
    bool output_good = get_operand_values(op.output, ctx, dst, dstw, compiler, Registers::temp_reg2);
    bool input0_good = get_operand_values(op.operands.operands[0], ctx, src1, src1w, nullptr, 0);
    bool input1_good = get_operand_values(op.operands.operands[1], ctx, src2, src2w, nullptr, 0);

    if (!output_good || !input0_good || !input1_good) {
        assert(false);
        errored = true;
        return;
    }

    // When the instruction carries a relocation, resolve it and redirect the second source
    // (the immediate) at the relocated value instead.
    if (ctx.reloc_type != RelocType::R_MIPS_NONE) {
        // Binary ops only ever carry the LO16 half of an address.
        if (ctx.reloc_type != RelocType::R_MIPS_LO16) {
            assert(false);
            errored = true;
            return;
        }
        // The relocation must land on the immediate operand.
        if (src2 != SLJIT_IMM) {
            assert(false);
            errored = true;
            return;
        }
        // Relocated immediates are only meaningful for loads and address additions.
        switch (op.type) {
            case BinaryOpType::LD:
            case BinaryOpType::LW:
            case BinaryOpType::LWU:
            case BinaryOpType::LH:
            case BinaryOpType::LHU:
            case BinaryOpType::LB:
            case BinaryOpType::LBU:
            case BinaryOpType::LDL:
            case BinaryOpType::LDR:
            case BinaryOpType::LWL:
            case BinaryOpType::LWR:
            case BinaryOpType::Add64:
            case BinaryOpType::Add32:
                break;
            default:
                // No other instruction may carry a relocation here.
                assert(false);
                errored = true;
                return;
        }
        // Compute the full relocated address into temp1.
        load_relocated_address(ctx, Registers::temp_reg1);
        // Keep just the sign-extended low 16 bits, which is what the LO16 immediate represents.
        sljit_emit_op1(compiler, SLJIT_MOV_S16, Registers::temp_reg1, 0, Registers::temp_reg1, 0);
        // Feed that register in as src2 in place of the original immediate.
        src2 = Registers::temp_reg1;
        src2w = 0;
    }

    // TODO validate that the unary ops are valid for the current binary op.
    if (op.operands.operand_operations[0] != UnaryOpType::None &&
        op.operands.operand_operations[0] != UnaryOpType::ToU64 &&
        op.operands.operand_operations[0] != UnaryOpType::ToS64 &&
        op.operands.operand_operations[0] != UnaryOpType::ToU32)
    {
        assert(false);
        errored = true;
        return;
    }
    
    if (op.operands.operand_operations[1] != UnaryOpType::None &&
        op.operands.operand_operations[1] != UnaryOpType::ToU64 &&
        op.operands.operand_operations[1] != UnaryOpType::ToS64 &&
        op.operands.operand_operations[1] != UnaryOpType::Mask5 && // Only for 32-bit shifts
        op.operands.operand_operations[1] != UnaryOpType::Mask6) // Only for 64-bit shifts
    {
        assert(false);
        errored = true;
        return;
    }

    // ToS64 on the first operand marks the comparison as signed; anything else is unsigned.
    bool cmp_unsigned = op.operands.operand_operations[0] != UnaryOpType::ToS64;

    // Common tail for 32-bit ALU results: MIPS keeps 32-bit values sign-extended into the
    // full 64-bit register, so widen temp1 before writing it back.
    auto store_sext32 = [dst, dstw, this]() {
        sljit_emit_op1(this->compiler, SLJIT_MOV_S32, Registers::temp_reg1, 0, Registers::temp_reg1, 0);
        sljit_emit_op1(this->compiler, SLJIT_MOV_P, dst, dstw, Registers::temp_reg1, 0);
    };

    // 32-bit ALU op: compute into temp1, then sign-extend and store.
    auto emit_alu32 = [src1, src1w, src2, src2w, this, &store_sext32](sljit_s32 op) {
        sljit_emit_op2(this->compiler, op, Registers::temp_reg1, 0, src1, src1w, src2, src2w);
        store_sext32();
    };

    // 64-bit ALU op: write straight to the destination, no extension needed.
    auto emit_alu64 = [dst, dstw, src1, src1w, src2, src2w, this](sljit_s32 op) {
        sljit_emit_op2(this->compiler, op, dst, dstw, src1, src1w, src2, src2w);
    };

    // Two-input floating-point op.
    auto emit_falu = [dst, dstw, src1, src1w, src2, src2w, this](sljit_s32 op) {
        sljit_emit_fop2(this->compiler, op, dst, dstw, src1, src1w, src2, src2w);
    };

    // Aligned guest load. `op` selects the width and sign/zero extension; `address_xor`
    // applies the endianness byte-swap for sub-word accesses.
    auto emit_load = [dst, dstw, src1, src1w, src2, src2w, this](sljit_s32 op, int address_xor) {
        // TODO 0 immediate optimization.

        // Form the effective guest address (base + offset) in temp1.
        sljit_emit_op2(compiler, SLJIT_ADD, Registers::temp_reg1, 0, src1, src1w, src2, src2w);

        if (address_xor != 0) {
            // Apply the endianness xor to the address.
            sljit_emit_op2(compiler, SLJIT_XOR, Registers::temp_reg1, 0, Registers::temp_reg1, 0, SLJIT_IMM, address_xor);
        }

        // Read from rdram[address] using the chosen width/extension op into temp1.
        sljit_emit_op1(compiler, op, Registers::temp_reg1, 0, SLJIT_MEM2(Registers::rdram, Registers::temp_reg1), 0);

        // Write the loaded value to the destination.
        sljit_emit_op1(compiler, SLJIT_MOV, dst, dstw, Registers::temp_reg1, 0);
    };

    // Integer set-on-comparison (slt and friends). Performs the comparison via a flag-setting
    // subtract and materializes the resulting condition flag into the destination.
    auto emit_icmp = [cmp_unsigned, dst, dstw, src1, src1w, src2, src2w, this](sljit_s32 op_unsigned, sljit_s32 op_signed) {
        // Choose the signed or unsigned variant of the condition.
        sljit_s32 op = cmp_unsigned ? op_unsigned : op_signed;

        // Equality/zero conditions need the zero flag; the ordering conditions need their own.
        sljit_s32 flags;
        if (op <= SLJIT_NOT_ZERO) {
            flags = SLJIT_SET_Z;
        } else
        {
            flags = SLJIT_SET(op);
        }

        // Subtract purely for its side-effect flags (result discarded).
        sljit_emit_op2u(compiler, SLJIT_SUB | flags, src1, src1w, src2, src2w);

        // Latch the resulting condition into the destination as a 0/1 value.
        sljit_emit_op_flags(compiler, SLJIT_MOV, dst, dstw, op);
    };

    // Floating-point set-on-comparison. The compare goes through fop1 with the left operand
    // as its first argument, then the condition flag is moved into the destination.
    auto emit_fcmp = [dst, dstw, src1, src1w, src2, src2w, this](sljit_s32 flag_op, sljit_s32 set_op, bool double_precision) {
        // Combine the flag request with the float-compare op of the right precision.
        sljit_s32 compare_op = set_op | (double_precision ? SLJIT_CMP_F64 : SLJIT_CMP_F32);

        sljit_emit_fop1(compiler, compare_op, src1, src1w, src2, src2w);

        sljit_emit_op_flags(compiler, SLJIT_MOV, dst, dstw, flag_op);
    };

    // Unaligned load (lwl/lwr/ldl/ldr). Reads the aligned word containing the address, then
    // merges the requested bytes into the existing destination value using a shift+mask, so
    // partial loads leave the untouched bytes intact. `left` picks the lwl/ldl vs lwr/ldr
    // direction; `doubleword` selects 64-bit vs 32-bit.
    auto emit_unaligned_load = [dst, dstw, src1, src1w, src2, src2w, this](bool left, bool doubleword) {
        // TODO 0 immediate optimization.

        // Shift direction used for both the mask and the loaded value.
        sljit_sw shift_op = left ? SLJIT_SHL : SLJIT_LSHR;
        // Width of the access in bytes.
        sljit_sw word_size = doubleword ? 8 : 4;

        // addr = base + offset, into temp1.
        sljit_emit_op2(compiler, SLJIT_ADD, Registers::temp_reg1, 0, src1, src1w, src2, src2w);

        // misalignment = addr & (word_size - 1), into temp2.
        sljit_emit_op2(compiler, SLJIT_AND, Registers::temp_reg2, 0, Registers::temp_reg1, 0, SLJIT_IMM, word_size - 1);

        // addr = addr & ~(word_size - 1) (align down), back into temp1.
        sljit_emit_op2(compiler, SLJIT_AND, Registers::temp_reg1, 0, Registers::temp_reg1, 0, SLJIT_IMM, ~(word_size - 1));

        // loaded_value = *addr, into temp1.
        if (doubleword) {
            // Swap the two halves of the doubleword back into guest order with a 32-bit rotate.
            sljit_emit_op2(compiler, SLJIT_ROTL, Registers::temp_reg1, 0, SLJIT_MEM2(Registers::rdram, Registers::temp_reg1), 0, SLJIT_IMM, 32);
        }
        else {
            // 32-bit word, sign-extended via MOV_S32.
            sljit_emit_op1(compiler, SLJIT_MOV_S32, Registers::temp_reg1, 0, SLJIT_MEM2(Registers::rdram, Registers::temp_reg1), 0);
        }

        // For a right load, mirror the misalignment: misalignment = word_size - 1 - misalignment.
        if (!left) {
            sljit_emit_op2(compiler, SLJIT_SUB, Registers::temp_reg2, 0, SLJIT_IMM, word_size - 1, Registers::temp_reg2, 0);
        }

        // misalignment_shift = misalignment * 8 (bytes to bits), into temp2.
        sljit_emit_op2(compiler, SLJIT_SHL, Registers::temp_reg2, 0, Registers::temp_reg2, 0, SLJIT_IMM, 3);

        // misalignment_mask = word(-1) shifted by misalignment_shift, into temp3 (32-bit shift for words).
        sljit_emit_op2(compiler, doubleword ? shift_op : (shift_op | SLJIT_32),
            Registers::temp_reg3, 0,
            SLJIT_IMM, doubleword ? uint64_t(-1) : uint32_t(-1),
            Registers::temp_reg2, 0);

        if (!doubleword) {
            // Widen the 32-bit mask to 64 bits with sign extension.
            sljit_emit_op1(compiler, SLJIT_MOV_S32, Registers::temp_reg3, 0, Registers::temp_reg3, 0);
        }

        // Shift the loaded value into place (temp1 <<= / >>= misalignment_shift).
        sljit_emit_op2(compiler, shift_op, Registers::temp_reg1, 0, Registers::temp_reg1, 0, Registers::temp_reg2, 0);

        if (left && !doubleword) {
            // A left word load needs the shifted result re-sign-extended.
            sljit_emit_op1(compiler, SLJIT_MOV_S32, Registers::temp_reg1, 0, Registers::temp_reg1, 0);
        }

        // Keep only the freshly-loaded bytes: loaded_value &= misalignment_mask.
        sljit_emit_op2(compiler, SLJIT_AND, Registers::temp_reg1, 0, Registers::temp_reg1, 0, Registers::temp_reg3, 0);

        // Flip the mask so it selects the preserved bytes instead: misalignment_mask = ~misalignment_mask.
        sljit_emit_op2(compiler, SLJIT_XOR, Registers::temp_reg3, 0, Registers::temp_reg3, 0, SLJIT_IMM, sljit_sw(-1));

        // Keep the untouched bytes of the prior destination value: masked_value = dst & misalignment_mask.
        sljit_emit_op2(compiler, SLJIT_AND, Registers::temp_reg3, 0, dst, dstw, Registers::temp_reg3, 0);

        // out = masked_value | loaded_value.
        sljit_emit_op2(compiler, SLJIT_OR, dst, dstw, Registers::temp_reg3, 0, Registers::temp_reg1, 0);
    };

    switch (op.type) {
        // Addition/subtraction
        case BinaryOpType::Add32:
            emit_alu32(SLJIT_ADD32);
            break;
        case BinaryOpType::Sub32:
            emit_alu32(SLJIT_SUB32);
            break;
        case BinaryOpType::Add64:
            emit_alu64(SLJIT_ADD);
            break;
        case BinaryOpType::Sub64:
            emit_alu64(SLJIT_SUB);
            break;

        // Float arithmetic
        case BinaryOpType::AddFloat:
            emit_falu(SLJIT_ADD_F32);
            break;
        case BinaryOpType::AddDouble:
            emit_falu(SLJIT_ADD_F64);
            break;
        case BinaryOpType::SubFloat:
            emit_falu(SLJIT_SUB_F32);
            break;
        case BinaryOpType::SubDouble:
            emit_falu(SLJIT_SUB_F64);
            break;
        case BinaryOpType::MulFloat:
            emit_falu(SLJIT_MUL_F32);
            break;
        case BinaryOpType::MulDouble:
            emit_falu(SLJIT_MUL_F64);
            break;
        case BinaryOpType::DivFloat:
            emit_falu(SLJIT_DIV_F32);
            break;
        case BinaryOpType::DivDouble:
            emit_falu(SLJIT_DIV_F64);
            break;

        // Bitwise
        case BinaryOpType::And64:
            emit_alu64(SLJIT_AND);
            break;
        case BinaryOpType::Or64:
            emit_alu64(SLJIT_OR);
            break;
        case BinaryOpType::Nor64:
            // NOR = NOT(a OR b): or the inputs into temp1, then xor with all-ones into the destination.
            sljit_emit_op2(this->compiler, SLJIT_OR, Registers::temp_reg1, 0, src1, src1w, src2, src2w);
            sljit_emit_op2(this->compiler, SLJIT_XOR, dst, dstw, Registers::temp_reg1, 0, SLJIT_IMM, sljit_sw(-1));
            break;
        case BinaryOpType::Xor64:
            emit_alu64(SLJIT_XOR);
            break;
        case BinaryOpType::Sll32:
            // TODO only mask if the second input's op is Mask5.
            emit_alu32(SLJIT_MSHL32);
            break;
        case BinaryOpType::Sll64:
            // TODO only mask if the second input's op is Mask6.
            emit_alu64(SLJIT_MSHL);
            break;
        case BinaryOpType::Srl32:
            // TODO only mask if the second input's op is Mask5.
            emit_alu32(SLJIT_MLSHR32);
            break;
        case BinaryOpType::Srl64:
            // TODO only mask if the second input's op is Mask6.
            emit_alu64(SLJIT_MLSHR);
            break;
        case BinaryOpType::Sra32:
            // The N64 doesn't truncate the operand to 32 bits before an sra, so the upper half of
            // the register leaks into the result. Reproduce that by masking the shift amount to 5
            // bits and doing a full 64-bit arithmetic shift rather than a 32-bit one.
            // TODO only mask if the second input's op is Mask5.
            sljit_emit_op2(this->compiler, SLJIT_AND32, Registers::temp_reg1, 0, src2, src2w, SLJIT_IMM, 0b11111);
            sljit_emit_op2(this->compiler, SLJIT_MASHR, Registers::temp_reg1, 0, src1, src1w, Registers::temp_reg1, 0);
            store_sext32();
            break;
        case BinaryOpType::Sra64:
            // TODO only mask if the second input's op is Mask6.
            emit_alu64(SLJIT_MASHR);
            break;

        // Comparisons
        case BinaryOpType::Equal:
            emit_icmp(SLJIT_EQUAL, SLJIT_EQUAL);
            break;
        case BinaryOpType::NotEqual:
            emit_icmp(SLJIT_NOT_EQUAL, SLJIT_NOT_EQUAL);
            break;
        case BinaryOpType::Less:
            emit_icmp(SLJIT_LESS, SLJIT_SIG_LESS);
            break;
        case BinaryOpType::LessEq:
            emit_icmp(SLJIT_LESS_EQUAL, SLJIT_SIG_LESS_EQUAL);
            break;
        case BinaryOpType::Greater:
            emit_icmp(SLJIT_GREATER, SLJIT_SIG_GREATER);
            break;
        case BinaryOpType::GreaterEq:
            emit_icmp(SLJIT_GREATER_EQUAL, SLJIT_SIG_GREATER_EQUAL);
            break;
        case BinaryOpType::EqualFloat:
            emit_fcmp(SLJIT_F_EQUAL, SLJIT_SET_F_EQUAL, false);
            break;
        case BinaryOpType::LessFloat:
            emit_fcmp(SLJIT_F_LESS, SLJIT_SET_F_LESS, false);
            break;
        case BinaryOpType::LessEqFloat:
            emit_fcmp(SLJIT_F_LESS_EQUAL, SLJIT_SET_F_LESS_EQUAL, false);
            break;
        case BinaryOpType::EqualDouble:
            emit_fcmp(SLJIT_F_EQUAL, SLJIT_SET_F_EQUAL, true);
            break;
        case BinaryOpType::LessDouble:
            emit_fcmp(SLJIT_F_LESS, SLJIT_SET_F_LESS, true);
            break;
        case BinaryOpType::LessEqDouble:
            emit_fcmp(SLJIT_F_LESS_EQUAL, SLJIT_SET_F_LESS_EQUAL, true);
            break;
        case BinaryOpType::False:
            // Constant-false comparison: just store 0.
            sljit_emit_op1(compiler, SLJIT_MOV, dst, dstw, SLJIT_IMM, 0);
            break;

        // Loads
        case BinaryOpType::LD:
            // Effective address = base + offset, into temp1.
            sljit_emit_op2(compiler, SLJIT_ADD, Registers::temp_reg1, 0, src1, src1w, src2, src2w);

            // Read the doubleword from rdram and rotate by 32 to restore guest word order.
            sljit_emit_op2(compiler, SLJIT_ROTL, Registers::temp_reg1, 0, SLJIT_MEM2(Registers::rdram, Registers::temp_reg1), 0, SLJIT_IMM, 32);

            // Store it to the destination.
            sljit_emit_op1(compiler, SLJIT_MOV, dst, dstw, Registers::temp_reg1, 0);
            break;
        case BinaryOpType::LW:
            emit_load(SLJIT_MOV_S32, 0);
            break;
        case BinaryOpType::LWU:
            emit_load(SLJIT_MOV_U32, 0);
            break;
        case BinaryOpType::LH:
            emit_load(SLJIT_MOV_S16, 2);
            break;
        case BinaryOpType::LHU:
            emit_load(SLJIT_MOV_U16, 2);
            break;
        case BinaryOpType::LB:
            emit_load(SLJIT_MOV_S8, 3);
            break;
        case BinaryOpType::LBU:
            emit_load(SLJIT_MOV_U8, 3);
            break;
        case BinaryOpType::LDL:
            emit_unaligned_load(true, true);
            break;
        case BinaryOpType::LDR:
            emit_unaligned_load(false, true);
            break;
        case BinaryOpType::LWL:
            emit_unaligned_load(true, false);
            break;
        case BinaryOpType::LWR:
            emit_unaligned_load(false, false);
            break;
        default:
            assert(false);
            errored = true;
            return;
    }
}

// Host-side helpers invoked by the generated code for the FP convert-to-integer instructions
// that sljit doesn't model directly. ROUND.* should really round-half-to-even, but roundeven
// only arrived in C23 and isn't available here, so lround (half-away-from-zero) is used instead.
// TODO switch to banker's rounding once roundeven is usable.
int32_t do_round_w_s(float num) {
    return lroundf(num);
}

int32_t do_round_w_d(double num) {
    return lround(num);
}

int64_t do_round_l_s(float num) {
    return llroundf(num);
}

int64_t do_round_l_d(double num) {
    return llround(num);
}

int32_t do_ceil_w_s(float num) {
    return (int32_t)ceilf(num);
}

int32_t do_ceil_w_d(double num) {
    return (int32_t)ceil(num);
}

int64_t do_ceil_l_s(float num) {
    return (int64_t)ceilf(num);
}

int64_t do_ceil_l_d(double num) {
    return (int64_t)ceil(num);
}

int32_t do_floor_w_s(float num) {
    return (int32_t)floorf(num);
}

int32_t do_floor_w_d(double num) {
    return (int32_t)floor(num);
}

int64_t do_floor_l_s(float num) {
    return (int64_t)floorf(num);
}

int64_t do_floor_l_d(double num) {
    return (int64_t)floor(num);
}

void N64Recomp::LiveGenerator::load_relocated_address(const InstructionContext& ctx, int reg) const {
    // A relocation resolves to "the runtime base of some section" plus a fixed offset within it.
    // The section base is looked up at runtime out of either the reference or local section
    // address table, so grab a pointer to the right table slot.
    int32_t* section_addr_ptr = (ctx.reloc_tag_as_reference ? inputs.reference_section_addresses : inputs.local_section_addresses) + ctx.reloc_section_index;

    // Read the (32-bit) section base into the target register.
    sljit_emit_op1(compiler, SLJIT_MOV_S32, reg, 0, SLJIT_MEM0(), sljit_sw(section_addr_ptr));

    // Add the in-section offset, skipping the add entirely when it's zero.
    if (ctx.reloc_target_section_offset != 0) {
        sljit_emit_op2(compiler, SLJIT_ADD, reg, 0, reg, 0, SLJIT_IMM, ctx.reloc_target_section_offset);
    }
}

void N64Recomp::LiveGenerator::process_unary_op(const UnaryOp& op, const InstructionContext& ctx) const {
    // A write to $zero has no effect, so emit nothing.
    if (outputs_to_zero(op.output, ctx)) {
        return;
    }

    // The low-word FPR view may appear on one side of a unary op but not on both at once.
    if (is_fpr_u32l(op.input) && is_fpr_u32l(op.output)) {
        assert(false);
        errored = true;
        return;
    }

    sljit_sw dst;
    sljit_sw dstw;
    sljit_sw src;
    sljit_sw srcw;
    bool output_good = get_operand_values(op.output, ctx, dst, dstw, compiler, Registers::temp_reg3);
    bool input_good = get_operand_values(op.input, ctx, src, srcw, compiler, Registers::temp_reg3);

    if (!output_good || !input_good) {
        assert(false);
        errored = true;
        return;
    }

    // A relocation on a unary op is the HI16 half of a lui; handle it specially and return early.
    if (ctx.reloc_type != RelocType::R_MIPS_NONE) {
        // Only a lui taking an immediate can be relocated this way.
        if (op.operation != UnaryOpType::Lui || op.input != Operand::ImmU16) {
            assert(false);
            errored = true;
            return;
        }
        // And the relocation must be the HI16 half.
        if (ctx.reloc_type != RelocType::R_MIPS_HI16) {
            assert(false);
            errored = true;
            return;
        }
        // Resolve the full 32-bit address into temp1.
        load_relocated_address(ctx, Registers::temp_reg1);

        // For a HI16 lui, the lui immediate is (a - (int16_t)a) >> 16 where a is that address.
        // Because the high and low shifts cancel and the low 16 bits end up zero, the register we
        // want is simply (int32_t)(a - (int16_t)a). Compute it directly:

        // temp2 = sign-extended low 16 bits of the address.
        sljit_emit_op1(compiler, SLJIT_MOV_S16, Registers::temp_reg2, 0, Registers::temp_reg1, 0);

        // dst = address - temp2, leaving the HI16-aligned value.
        sljit_emit_op2(compiler, SLJIT_SUB, dst, dstw, Registers::temp_reg1, 0, Registers::temp_reg2, 0);
        return;
    }

    sljit_s32 jit_op = SLJIT_BREAKPOINT;

    // float_op routes the operation through fop1 below; func_float_op means one of the helper
    // lambdas already emitted everything (a host function call) and there's nothing left to do.
    bool float_op = false;
    bool func_float_op = false;

    // The lambdas below all follow the same shape: move the source into FR0 / an argument
    // register, call a host C function, and move its return value into the destination. The
    // suffix names the C signature, e.g. emit_l_from_s_func calls "int64_t f(float)".

    auto emit_s_func = [this, src, srcw, dst, dstw, &func_float_op](float (*func)(float)) {
        func_float_op = true;

        sljit_emit_fop1(compiler, SLJIT_MOV_F32, SLJIT_FR0, 0, src, srcw);
        sljit_emit_icall(compiler, SLJIT_CALL, SLJIT_ARGS1(F32, F32), SLJIT_IMM, sljit_sw(func));
        sljit_emit_fop1(compiler, SLJIT_MOV_F32, dst, dstw, SLJIT_RETURN_FREG, 0);
    };

    auto emit_d_func = [this, src, srcw, dst, dstw, &func_float_op](double (*func)(double)) {
        func_float_op = true;

        sljit_emit_fop1(compiler, SLJIT_MOV_F64, SLJIT_FR0, 0, src, srcw);
        sljit_emit_icall(compiler, SLJIT_CALL, SLJIT_ARGS1(F64, F64), SLJIT_IMM, sljit_sw(func));
        sljit_emit_fop1(compiler, SLJIT_MOV_F64, dst, dstw, SLJIT_RETURN_FREG, 0);
    };

    auto emit_l_from_s_func = [this, src, srcw, dst, dstw, &func_float_op](int64_t (*func)(float)) {
        func_float_op = true;

        sljit_emit_fop1(compiler, SLJIT_MOV_F32, SLJIT_FR0, 0, src, srcw);
        sljit_emit_icall(compiler, SLJIT_CALL, SLJIT_ARGS1(P, F32), SLJIT_IMM, sljit_sw(func));
        sljit_emit_op1(compiler, SLJIT_MOV, dst, dstw, SLJIT_RETURN_REG, 0);
    };

    auto emit_w_from_s_func = [this, src, srcw, dst, dstw, &func_float_op](int32_t (*func)(float)) {
        func_float_op = true;

        sljit_emit_fop1(compiler, SLJIT_MOV_F32, SLJIT_FR0, 0, src, srcw);
        sljit_emit_icall(compiler, SLJIT_CALL, SLJIT_ARGS1(32, F32), SLJIT_IMM, sljit_sw(func));
        sljit_emit_op1(compiler, SLJIT_MOV_S32, dst, dstw, SLJIT_RETURN_REG, 0);
    };

    auto emit_l_from_d_func = [this, src, srcw, dst, dstw, &func_float_op](int64_t (*func)(double)) {
        func_float_op = true;

        sljit_emit_fop1(compiler, SLJIT_MOV_F64, SLJIT_FR0, 0, src, srcw);
        sljit_emit_icall(compiler, SLJIT_CALL, SLJIT_ARGS1(P, F64), SLJIT_IMM, sljit_sw(func));
        sljit_emit_op1(compiler, SLJIT_MOV, dst, dstw, SLJIT_RETURN_REG, 0);
    };

    auto emit_w_from_d_func = [this, src, srcw, dst, dstw, &func_float_op](int32_t (*func)(double)) {
        func_float_op = true;

        sljit_emit_fop1(compiler, SLJIT_MOV_F64, SLJIT_FR0, 0, src, srcw);
        sljit_emit_icall(compiler, SLJIT_CALL, SLJIT_ARGS1(32, F64), SLJIT_IMM, sljit_sw(func));
        sljit_emit_op1(compiler, SLJIT_MOV_S32, dst, dstw, SLJIT_RETURN_REG, 0);
    };

    switch (op.operation) {
        case UnaryOpType::Lui:
            if (src != SLJIT_IMM) {
                assert(false);
                errored = true;
                break;
            }
            src = SLJIT_IMM;
            srcw = (sljit_sw)(int32_t)(srcw << 16);
            jit_op = SLJIT_MOV;
            break;
        case UnaryOpType::NegateFloat:
            jit_op = SLJIT_NEG_F32;
            float_op = true;
            break;
        case UnaryOpType::NegateDouble:
            jit_op = SLJIT_NEG_F64;
            float_op = true;
            break;
        case UnaryOpType::AbsFloat:
            jit_op = SLJIT_ABS_F32;
            float_op = true;
            break;
        case UnaryOpType::AbsDouble:
            jit_op = SLJIT_ABS_F64;
            float_op = true;
            break;
        case UnaryOpType::SqrtFloat:
            emit_s_func(sqrtf);
            break;
        case UnaryOpType::SqrtDouble:
            emit_d_func(sqrt);
            break;
        case UnaryOpType::ConvertSFromW:
            jit_op = SLJIT_CONV_F32_FROM_S32;
            float_op = true;
            break;
        case UnaryOpType::ConvertWFromS:
            emit_w_from_s_func(do_cvt_w_s);
            break;
        case UnaryOpType::ConvertDFromW:
            jit_op = SLJIT_CONV_F64_FROM_S32;
            float_op = true;
            break;
        case UnaryOpType::ConvertWFromD:
            emit_w_from_d_func(do_cvt_w_d);
            break;
        case UnaryOpType::ConvertDFromS:
            jit_op = SLJIT_CONV_F64_FROM_F32;
            float_op = true;
            break;
        case UnaryOpType::ConvertSFromD:
            // CVT.S.D honors the current rounding mode, and so does SLJIT_CONV_F32_FROM_F64.
            jit_op = SLJIT_CONV_F32_FROM_F64;
            float_op = true;
            break;
        case UnaryOpType::ConvertDFromL:
            jit_op = SLJIT_CONV_F64_FROM_SW;
            float_op = true;
            break;
        case UnaryOpType::ConvertLFromD:
            emit_l_from_d_func(do_cvt_l_d);
            break;
        case UnaryOpType::ConvertSFromL:
            jit_op = SLJIT_CONV_F32_FROM_SW;
            float_op = true;
            break;
        case UnaryOpType::ConvertLFromS:
            emit_l_from_s_func(do_cvt_l_s);
            break;
        case UnaryOpType::TruncateWFromS:
            // TRUNC.W.S truncates toward zero, matching SLJIT_CONV_S32_FROM_F32.
            jit_op = SLJIT_CONV_S32_FROM_F32;
            float_op = true;
            break;
        case UnaryOpType::TruncateWFromD:
            // TRUNC.W.D truncates toward zero, matching SLJIT_CONV_S32_FROM_F64.
            jit_op = SLJIT_CONV_S32_FROM_F64;
            float_op = true;
            break;
        case UnaryOpType::TruncateLFromS:
            // TRUNC.L.S truncates toward zero, matching SLJIT_CONV_SW_FROM_F32.
            jit_op = SLJIT_CONV_SW_FROM_F32;
            float_op = true;
            break;
        case UnaryOpType::TruncateLFromD:
            // TRUNC.L.D truncates toward zero, matching SLJIT_CONV_SW_FROM_F64.
            jit_op = SLJIT_CONV_SW_FROM_F64;
            float_op = true;
            break;
        case UnaryOpType::RoundWFromS:
            emit_w_from_s_func(do_round_w_s);
            break;
        case UnaryOpType::RoundWFromD:
            emit_w_from_d_func(do_round_w_d);
            break;
        case UnaryOpType::RoundLFromS:
            emit_l_from_s_func(do_round_l_s);
            break;
        case UnaryOpType::RoundLFromD:
            emit_l_from_d_func(do_round_l_d);
            break;
        case UnaryOpType::CeilWFromS:
            emit_w_from_s_func(do_ceil_w_s);
            break;
        case UnaryOpType::CeilWFromD:
            emit_w_from_d_func(do_ceil_w_d);
            break;
        case UnaryOpType::CeilLFromS:
            emit_l_from_s_func(do_ceil_l_s);
            break;
        case UnaryOpType::CeilLFromD:
            emit_l_from_d_func(do_ceil_l_d);
            break;
        case UnaryOpType::FloorWFromS:
            emit_w_from_s_func(do_floor_w_s);
            break;
        case UnaryOpType::FloorWFromD:
            emit_w_from_d_func(do_floor_w_d);
            break;
        case UnaryOpType::FloorLFromS:
            emit_l_from_s_func(do_floor_l_s);
            break;
        case UnaryOpType::FloorLFromD:
            emit_l_from_d_func(do_floor_l_d);
            break;
        case UnaryOpType::None:
            // A plain move; narrow to 32 bits only when the destination is the low-word FPR view.
            if (is_fpr_u32l(op.output)) {
                jit_op = SLJIT_MOV32;
            }
            else {
                jit_op = SLJIT_MOV;
            }
            break;
        case UnaryOpType::ToS32:
        case UnaryOpType::ToInt32:
            // SLJIT_MOV_32 skips the sign extension when writing directly to memory, so route the
            // value through a register (forcing the extension) and use that register as the source.
            sljit_emit_op1(compiler, SLJIT_MOV_S32, Registers::temp_reg1, 0, src, srcw);
            src = Registers::temp_reg1;
            srcw = 0;
            jit_op = SLJIT_MOV;
            break;
        // These conversions only exist as operand modifiers, never as a standalone unary op.
        case UnaryOpType::ToU32:
        case UnaryOpType::ToS64:
        case UnaryOpType::ToU64:
        case UnaryOpType::Mask5:
        case UnaryOpType::Mask6:
            assert(false && "Unsupported unary op");
            errored = true;
            return;
    }

    // Three emission paths: a helper lambda already did the work, a single fop1 for sljit-native
    // float ops, or a single op1 for the integer/move cases.
    if (func_float_op) {
        // Already handled by the lambda.
    }
    else if (float_op) {
        sljit_emit_fop1(compiler, jit_op, dst, dstw, src, srcw);
    }
    else {
        sljit_emit_op1(compiler, jit_op, dst, dstw, src, srcw);
    }
}

void N64Recomp::LiveGenerator::process_store_op(const StoreOp& op, const InstructionContext& ctx) const {
    sljit_sw src;
    sljit_sw srcw;
    sljit_sw imm = (sljit_sw)(int16_t)ctx.imm16;

    get_operand_values(op.value_input, ctx, src, srcw, compiler, Registers::temp_reg2);

    // Stores can only carry the LO16 half of an address relocation.
    if (ctx.reloc_type != RelocType::R_MIPS_NONE && ctx.reloc_type != RelocType::R_MIPS_LO16) {
        assert(false);
        errored = true;
        return;
    }

    if (ctx.reloc_type == RelocType::R_MIPS_LO16) {
        // Resolve the relocated address into temp1.
        load_relocated_address(ctx, Registers::temp_reg1);
        // Reduce it to the sign-extended low 16 bits (the LO16 immediate).
        sljit_emit_op1(compiler, SLJIT_MOV_S16, Registers::temp_reg1, 0, Registers::temp_reg1, 0);
        // Effective address = base register (rs) + that LO16 value.
        sljit_emit_op2(compiler, SLJIT_ADD, Registers::temp_reg1, 0, Registers::temp_reg1, 0, SLJIT_MEM1(Registers::ctx), get_gpr_context_offset(ctx.rs));
    }
    else {
        // TODO 0 immediate optimization.

        // Effective address = base register (rs) + signed immediate, into temp1.
        sljit_emit_op2(compiler, SLJIT_ADD, Registers::temp_reg1, 0, SLJIT_MEM1(Registers::ctx), get_gpr_context_offset(ctx.rs), SLJIT_IMM, imm);
    }

    // Unaligned store (swl/swr/sdl/sdr). The read-modify-write counterpart of the unaligned
    // load: read the aligned word, splice in the relevant bytes of the source register, and
    // write it back. temp1 already holds the (unaligned) effective address on entry.
    auto emit_unaligned_store = [src, srcw, this](bool left, bool doubleword) {
        // Shift direction for both the source value and the byte mask.
        sljit_sw shift_op = left ? SLJIT_LSHR : SLJIT_SHL;
        // Access width in bytes.
        sljit_sw word_size = doubleword ? 8 : 4;

        // misalignment = addr & (word_size - 1), into temp2.
        sljit_emit_op2(compiler, SLJIT_AND, Registers::temp_reg2, 0, Registers::temp_reg1, 0, SLJIT_IMM, word_size - 1);

        // addr = addr & ~(word_size - 1) (align down), back into temp1.
        sljit_emit_op2(compiler, SLJIT_AND, Registers::temp_reg1, 0, Registers::temp_reg1, 0, SLJIT_IMM, ~(word_size - 1));

        // Read the existing aligned word into temp3 (this is the value we'll merge into).
        if (doubleword) {
            // Rotate by 32 to bring the doubleword into guest order.
            sljit_emit_op2(compiler, SLJIT_ROTL, Registers::temp_reg3, 0, SLJIT_MEM2(Registers::rdram, Registers::temp_reg1), 0, SLJIT_IMM, 32);
        }
        else {
            // 32-bit word, sign-extended.
            sljit_emit_op1(compiler, SLJIT_MOV_S32, Registers::temp_reg3, 0, SLJIT_MEM2(Registers::rdram, Registers::temp_reg1), 0);
        }

        // Right stores mirror the misalignment: misalignment = word_size - 1 - misalignment.
        if (!left) {
            sljit_emit_op2(compiler, SLJIT_SUB, Registers::temp_reg2, 0, SLJIT_IMM, word_size - 1, Registers::temp_reg2, 0);
        }

        // misalignment_shift = misalignment * 8, into temp2.
        sljit_emit_op2(compiler, SLJIT_SHL, Registers::temp_reg2, 0, Registers::temp_reg2, 0, SLJIT_IMM, 3);

        // Shift the source value into position: temp4 = src shifted by misalignment_shift.
        sljit_emit_op2(compiler, shift_op, Registers::temp_reg4, 0, src, srcw, Registers::temp_reg2, 0);

        // misalignment_mask = word(-1) shifted by misalignment_shift, into temp2 (32-bit shift for words).
        sljit_emit_op2(compiler, doubleword ? shift_op : (shift_op | SLJIT_32),
            Registers::temp_reg2, 0,
            SLJIT_IMM, doubleword ? uint64_t(-1) : uint32_t(-1),
            Registers::temp_reg2, 0);

        // Keep only the bytes the store actually writes: temp4 &= misalignment_mask.
        sljit_emit_op2(compiler, SLJIT_AND, Registers::temp_reg4, 0, Registers::temp_reg4, 0, Registers::temp_reg2, 0);

        // Flip the mask to select the preserved bytes: misalignment_mask = ~misalignment_mask.
        sljit_emit_op2(compiler, SLJIT_XOR, Registers::temp_reg2, 0, Registers::temp_reg2, 0, SLJIT_IMM, sljit_sw(-1));

        // Keep the untouched bytes of the existing word: temp3 &= misalignment_mask.
        sljit_emit_op2(compiler, SLJIT_AND, Registers::temp_reg3, 0, Registers::temp_reg3, 0, Registers::temp_reg2, 0);

        // Merge the two halves and write the result back to rdram.
        if (doubleword) {
            // Combine in temp4 first, then rotate back into memory word order.
            sljit_emit_op2(compiler, SLJIT_OR, Registers::temp_reg4, 0, Registers::temp_reg4, 0, Registers::temp_reg3, 0);
            sljit_emit_op2(compiler, SLJIT_ROTL, SLJIT_MEM2(Registers::rdram, Registers::temp_reg1), 0, Registers::temp_reg4, 0, SLJIT_IMM, 32);
        }
        else {
            sljit_emit_op2(compiler, SLJIT_OR32, SLJIT_MEM2(Registers::rdram, Registers::temp_reg1), 0, Registers::temp_reg4, 0, Registers::temp_reg3, 0);
        }
    };

    switch (op.type) {
        case StoreOpType::SD:
        case StoreOpType::SDC1:
            // Store the doubleword, rotating by 32 to put it in memory word order.
            sljit_emit_op2(compiler, SLJIT_ROTL, SLJIT_MEM2(Registers::rdram, Registers::temp_reg1), 0, src, srcw, SLJIT_IMM, 32);
            break;
        case StoreOpType::SDL:
            emit_unaligned_store(true, true);
            break;
        case StoreOpType::SDR:
            emit_unaligned_store(false, true);
            break;
        case StoreOpType::SW:
        case StoreOpType::SWC1:
            // Store the low 32 bits at rdram[address].
            sljit_emit_op1(compiler, SLJIT_MOV_U32, SLJIT_MEM2(Registers::rdram, Registers::temp_reg1), 0, src, srcw);
            break;
        case StoreOpType::SWL:
            emit_unaligned_store(true, false);
            break;
        case StoreOpType::SWR:
            emit_unaligned_store(false, false);
            break;
        case StoreOpType::SH:
            // Apply the halfword endianness xor (2) to the address.
            sljit_emit_op2(compiler, SLJIT_XOR, Registers::temp_reg1, 0, Registers::temp_reg1, 0, SLJIT_IMM, 2);
            // Store the low 16 bits at rdram[address].
            sljit_emit_op1(compiler, SLJIT_MOV_U16, SLJIT_MEM2(Registers::rdram, Registers::temp_reg1), 0, src, srcw);
            break;
        case StoreOpType::SB:
            // Apply the byte endianness xor (3) to the address.
            sljit_emit_op2(compiler, SLJIT_XOR, Registers::temp_reg1, 0, Registers::temp_reg1, 0, SLJIT_IMM, 3);
            // Store the low 8 bits at rdram[address].
            sljit_emit_op1(compiler, SLJIT_MOV_U8, SLJIT_MEM2(Registers::rdram, Registers::temp_reg1), 0, src, srcw);
            break;
    }
}

void N64Recomp::LiveGenerator::emit_function_start(const std::string& function_name, size_t func_index) const {
    context->function_name = function_name;
    context->func_labels[func_index] = sljit_emit_label(compiler);
    // sljit_emit_op0(compiler, SLJIT_BREAKPOINT);
    // Prologue: (rdram, ctx) in -> reserve the saved/float registers used to hold guest state.
    sljit_emit_enter(compiler, 0, SLJIT_ARGS2V(P, P), 4 | SLJIT_ENTER_FLOAT(1), 5 | SLJIT_ENTER_FLOAT(0), 0);
    // Pre-bias the rdram base once so guest addresses can index it directly for the rest of the function.
    sljit_emit_op2(compiler, SLJIT_SUB, Registers::rdram, 0, Registers::rdram, 0, SLJIT_IMM, rdram_offset);

    // If an entry hook is registered for this function, call it before running the body.
    auto find_hook_it = inputs.entry_func_hooks.find(func_index);
    if (find_hook_it != inputs.entry_func_hooks.end()) {
        // Hand the hook the unbiased rdram pointer and ctx in R0/R1.
        sljit_emit_op2(compiler, SLJIT_ADD, SLJIT_R0, 0, Registers::rdram, 0, SLJIT_IMM, rdram_offset);
        sljit_emit_op1(compiler, SLJIT_MOV, SLJIT_R1, 0, Registers::ctx, 0);
        // R2 carries the hook index.
        sljit_emit_op1(compiler, SLJIT_MOV, SLJIT_R2, 0, SLJIT_IMM, find_hook_it->second);
        sljit_emit_icall(compiler, SLJIT_CALL, SLJIT_ARGS3V(P, P, W), SLJIT_IMM, sljit_sw(inputs.run_hook));
    }
}

void N64Recomp::LiveGenerator::emit_function_end() const {
    // Every goto should have found its label by now; a leftover means malformed input.
    if (!context->pending_jumps.empty()) {
        assert(false);
        errored = true;
    }

    // Resolve each switch's case names to labels and hand the table off to the unlinked list, which
    // finish() later converts to concrete addresses.
    bool invalid_switch = false;
    for (size_t switch_index = 0; switch_index < context->switch_jump_labels.size(); switch_index++) {
        const std::vector<std::string>& cur_labels = context->switch_jump_labels[switch_index];
        std::vector<sljit_label*> cur_label_addrs{};
        cur_label_addrs.resize(cur_labels.size());
        for (size_t case_index = 0; case_index < cur_labels.size(); case_index++) {
            // Look the case label up in this function's label map.
            auto find_it = context->labels.find(cur_labels[case_index]);
            if (find_it == context->labels.end()) {
                // A missing label means the switch is malformed. Note it and bail out of this loop,
                // but keep going so the per-function pending state still gets cleared below.
                invalid_switch = true;
                break;
            }
            cur_label_addrs[case_index] = find_it->second;
        }
        context->unlinked_jump_tables.emplace_back(
            std::make_pair<std::vector<sljit_label*>, std::unique_ptr<void*[]>>(
                std::move(cur_label_addrs),
                std::move(context->pending_jump_tables[switch_index])
            )
        );
    }
    context->switch_jump_labels.clear();
    context->pending_jump_tables.clear();

    // Drop this function's labels so a later function can't accidentally branch into it.
    context->labels.clear();

    if (invalid_switch) {
        assert(false);
        errored = true;
    }
}

void N64Recomp::LiveGenerator::emit_function_call_lookup(uint32_t addr, const std::set<uint32_t>&, uint32_t) const {
    // A call to a constant guest address: pass the address to get_function in R0.
    sljit_emit_op1(compiler, SLJIT_MOV32, SLJIT_R0, 0, SLJIT_IMM, int32_t(addr));

    // get_function(addr) returns the host function pointer.
    sljit_emit_icall(compiler, SLJIT_CALL, SLJIT_ARGS1(P, 32), SLJIT_IMM, sljit_sw(inputs.get_function));

    // Stash that pointer in R3, since R0/R1 are about to be reused for the call's arguments.
    sljit_emit_op1(compiler, SLJIT_MOV, SLJIT_R3, 0, SLJIT_RETURN_REG, 0);

    // Set up the (rdram, ctx) arguments.
    sljit_emit_op2(compiler, SLJIT_ADD, SLJIT_R0, 0, Registers::rdram, 0, SLJIT_IMM, rdram_offset);
    sljit_emit_op1(compiler, SLJIT_MOV, SLJIT_R1, 0, Registers::ctx, 0);

    // Indirectly call through the looked-up pointer.
    sljit_emit_icall(compiler, SLJIT_CALL, SLJIT_ARGS2V(P, P), SLJIT_R3, 0);
}

void N64Recomp::LiveGenerator::emit_function_call_by_register(int reg, const std::set<uint32_t>&, uint32_t) const {
    // A call through a register: feed that register's guest value to get_function in R0.
    sljit_emit_op1(compiler, SLJIT_MOV32, SLJIT_R0, 0, SLJIT_MEM1(Registers::ctx), get_gpr_context_offset(reg));

    // get_function(target) returns the host function pointer.
    sljit_emit_icall(compiler, SLJIT_CALL, SLJIT_ARGS1(P, 32), SLJIT_IMM, sljit_sw(inputs.get_function));

    // Preserve the returned pointer in R3 across the argument setup.
    sljit_emit_op1(compiler, SLJIT_MOV, SLJIT_R3, 0, SLJIT_RETURN_REG, 0);

    // Set up the (rdram, ctx) arguments.
    sljit_emit_op2(compiler, SLJIT_ADD, SLJIT_R0, 0, Registers::rdram, 0, SLJIT_IMM, rdram_offset);
    sljit_emit_op1(compiler, SLJIT_MOV, SLJIT_R1, 0, Registers::ctx, 0);

    // Indirectly call through the looked-up pointer.
    sljit_emit_icall(compiler, SLJIT_CALL, SLJIT_ARGS2V(P, P), SLJIT_R3, 0);
}

void N64Recomp::LiveGenerator::emit_function_call_reference_symbol(const Context&, uint16_t section_index, size_t symbol_index, uint32_t target_section_offset, const std::set<uint32_t>&, uint32_t) const {
    (void)symbol_index;

    // The (rdram, ctx) arguments.
    sljit_emit_op2(compiler, SLJIT_ADD, SLJIT_R0, 0, Registers::rdram, 0, SLJIT_IMM, rdram_offset);
    sljit_emit_op1(compiler, SLJIT_MOV, SLJIT_R1, 0, Registers::ctx, 0);
    // sljit_emit_op0(compiler, SLJIT_BREAKPOINT);
    // Emit a rewritable call; its real target isn't known until the symbol is bound, so record the
    // jump now and let the loader patch it later.
    sljit_jump* call_jump = sljit_emit_call(compiler, SLJIT_CALL | SLJIT_REWRITABLE_JUMP, SLJIT_ARGS2V(P, P));
    // Park a sentinel target for now (overwritten during reference/import jump population). Imports
    // and reference symbols are tracked in different containers and use distinct sentinels.
    if (section_index == N64Recomp::SectionImport) {
        sljit_set_target(call_jump, sljit_uw(-1));
        context->import_jumps_by_index.emplace(symbol_index, call_jump);
    }
    else {
        sljit_set_target(call_jump, sljit_uw(-2));
        context->reference_symbol_jumps.emplace_back(std::make_pair(
            ReferenceJumpDetails{
                .section = section_index,
                .section_offset = target_section_offset
            },
            call_jump
        ));
    }
}

void N64Recomp::LiveGenerator::emit_function_call(const Context&, size_t function_index, const std::set<uint32_t>&, uint32_t) const {
    // The (rdram, ctx) arguments.
    sljit_emit_op2(compiler, SLJIT_ADD, SLJIT_R0, 0, Registers::rdram, 0, SLJIT_IMM, rdram_offset);
    sljit_emit_op1(compiler, SLJIT_MOV, SLJIT_R1, 0, Registers::ctx, 0);
    // Direct call to another function in this batch; remember the jump so finish() can bind it to
    // that function's entry label once it exists.
    sljit_jump* call_jump = sljit_emit_call(compiler, SLJIT_CALL, SLJIT_ARGS2V(P, P));
    context->inner_calls.emplace_back(InnerCall{ .target_func_index = function_index, .jump = call_jump });
}

void N64Recomp::LiveGenerator::emit_named_function_call(const std::string& function_name, const std::set<uint32_t>&, uint32_t) const {
    // Calling by name is a static-recompilation-only path; the live backend has no use for it.
    assert(false);
    errored = true;
}

void N64Recomp::LiveGenerator::emit_goto(const std::string& target) const {
    sljit_jump* jump = sljit_emit_jump(compiler, SLJIT_JUMP);
    // Bind immediately if the target label has already been emitted (a backward branch)...
    auto find_it = context->labels.find(target);
    if (find_it != context->labels.end()) {
        sljit_set_label(jump, find_it->second);
    }
    // ...otherwise it's a forward branch, so defer it until emit_label sees the target.
    else {
        context->pending_jumps[target].push_back(jump);
    }
}

void N64Recomp::LiveGenerator::emit_label(const std::string& label_name) const {
    sljit_label* label = sljit_emit_label(compiler);

    // Bind any forward branches that were waiting on this label.
    auto find_it = context->pending_jumps.find(label_name);
    if (find_it != context->pending_jumps.end()) {
        for (sljit_jump* jump : find_it->second) {
            sljit_set_label(jump, label);
        }

        // They're resolved now, so drop the pending entry.
        context->pending_jumps.erase(find_it);
    }

    context->labels.emplace(label_name, label);
}

void N64Recomp::LiveGenerator::emit_jtbl_addend_declaration(const JumpTable& jtbl, int reg) const {
    (void)jtbl;
    (void)reg;
    // No-op: emit_switch derives the case index with a subtraction, so there's no addend to declare.
}

void N64Recomp::LiveGenerator::emit_branch_condition(const ConditionalBranchOp& op, const InstructionContext& ctx) const {
    // Only one branch can be in flight at a time; a leftover jump means a missing emit_branch_close.
    if(context->cur_branch_jump != nullptr) {
        assert(false);
        errored = true;
        return;
    }

    // The first operand allows ToS64 (signaling a signed comparison) but no other modifier.
    if(op.operands.operand_operations[0] != UnaryOpType::None && op.operands.operand_operations[0] != UnaryOpType::ToS64) {
        assert(false);
        errored = true;
        return;
    }

    // The second operand allows no modifier at all.
    if (op.operands.operand_operations[1] != UnaryOpType::None) {
        assert(false);
        errored = true;
        return;
    }

    // The low-word FPR view can't take part in a branch comparison.
    if (is_fpr_u32l(op.operands.operands[0]) || is_fpr_u32l(op.operands.operands[1])) {
        assert(false);
        errored = true;
        return;
    }

    sljit_s32 condition_type;
    bool cmp_signed = op.operands.operand_operations[0] == UnaryOpType::ToS64;
    // The caller emits the "condition true" body in line right after this, so the jump we create
    // should skip that body, i.e. it fires when the condition is FALSE. Each case below therefore
    // selects the negation of the source comparison.
    switch (op.comparison) {
        case BinaryOpType::Equal:
            condition_type = SLJIT_NOT_EQUAL;
            break;
        case BinaryOpType::NotEqual:
            condition_type = SLJIT_EQUAL;
            break;
        case BinaryOpType::GreaterEq:
            if (cmp_signed) {
                condition_type = SLJIT_SIG_LESS;
            }
            else {
                condition_type = SLJIT_LESS;
            }
            break;
        case BinaryOpType::Greater:
            if (cmp_signed) {
                condition_type = SLJIT_SIG_LESS_EQUAL;
            }
            else {
                condition_type = SLJIT_LESS_EQUAL;
            }
            break;
        case BinaryOpType::LessEq:
            if (cmp_signed) {
                condition_type = SLJIT_SIG_GREATER;
            }
            else {
                condition_type = SLJIT_GREATER;
            }
            break;
        case BinaryOpType::Less:
            if (cmp_signed) {
                condition_type = SLJIT_SIG_GREATER_EQUAL;
            }
            else {
                condition_type = SLJIT_GREATER_EQUAL;
            }
            break;
        default:
            assert(false && "Invalid branch condition comparison operation!");
            errored = true;
            return;
    }
    sljit_sw src1;
    sljit_sw src1w;
    sljit_sw src2;
    sljit_sw src2w;

    get_operand_values(op.operands.operands[0], ctx, src1, src1w, nullptr, 0);
    get_operand_values(op.operands.operands[1], ctx, src2, src2w, nullptr, 0);

    // A conditional branch should never carry a relocation.
    if(ctx.reloc_type != RelocType::R_MIPS_NONE) {
        assert(false);
        errored = true;
        return;
    }

    // Emit the compare-and-branch and hold onto it; emit_branch_close gives it its landing label.
    context->cur_branch_jump = sljit_emit_cmp(compiler, condition_type, src1, src1w, src2, src2w);
}

void N64Recomp::LiveGenerator::emit_branch_close() const {
    // There must be a branch waiting to be closed.
    if(context->cur_branch_jump == nullptr) {
        assert(false);
        errored = true;
        return;
    }

    // Land the deferred branch on a label here (past the condition body) and clear the slot.
    sljit_set_label(context->cur_branch_jump, sljit_emit_label(compiler));
    context->cur_branch_jump = nullptr;
}

void N64Recomp::LiveGenerator::emit_switch(const Context& recompiler_context, const JumpTable& jtbl, int reg) const {
    // Build the case label name for every table entry, deferred for resolution in emit_function_end.
    std::vector<std::string> cur_labels{};
    cur_labels.resize(jtbl.entries.size());
    for (size_t i = 0; i < cur_labels.size(); i++) {
        cur_labels[i] = fmt::format("L_{:08X}", jtbl.entries[i]);
    }
    context->switch_jump_labels.emplace_back(std::move(cur_labels));

    // Allocate the host-side table of code pointers that the generated code will index into.
    std::unique_ptr<void* []> cur_jump_table = std::make_unique<void* []>(jtbl.entries.size());

    /// Codegen

    // The lw that would load the jump target was rewritten into an addiu, so this register holds
    // the *address of the table entry* rather than the target. Pull it into temp1.
    sljit_emit_op1(compiler, SLJIT_MOV, Registers::temp_reg1, 0, SLJIT_MEM1(Registers::ctx), get_gpr_context_offset(reg));
    // Subtract the table's base address to recover the per-case byte offset. The base is sign
    // extended to 64 bits so the whole register participates rather than just its low 32 bits.
    const auto& jtbl_section = recompiler_context.sections[jtbl.section_index];
    if (jtbl_section.relocatable) {
        // A relocatable section means the table base is only known at runtime; resolve it via a
        // throwaway instruction context fed to load_relocated_address.
        InstructionContext dummy_context{};

        // Offset of the table within its section.
        uint32_t section_offset = jtbl.vram - jtbl_section.ram_addr;

        // Map to the section index the runtime relocation tables expect.
        uint16_t reloc_section_index = jtbl.section_index;
        if (!inputs.original_section_indices.empty()) {
            reloc_section_index = inputs.original_section_indices[reloc_section_index];
        }

        // Fill in just the fields load_relocated_address reads, then load the table base into temp2.
        dummy_context.reloc_section_index = reloc_section_index;
        dummy_context.reloc_target_section_offset = section_offset;
        load_relocated_address(dummy_context, Registers::temp_reg2);

        // offset = entry_address - table_base.
        sljit_emit_op2(compiler, SLJIT_SUB, Registers::temp_reg1, 0, Registers::temp_reg1, 0, Registers::temp_reg2, 0);
    }
    else {
        // Non-relocatable: the table base is the constant jtbl.vram.
        sljit_emit_op2(compiler, SLJIT_SUB, Registers::temp_reg1, 0, Registers::temp_reg1, 0, SLJIT_IMM, (sljit_sw)((int32_t)jtbl.vram));
    }

    // Reject out-of-range offsets (>= entries * 4 bytes) by branching to the shared switch-error path.
    sljit_jump* switch_error_jump = sljit_emit_cmp(compiler, SLJIT_GREATER_EQUAL, Registers::temp_reg1, 0, SLJIT_IMM, jtbl.entries.size() * sizeof(uint32_t));
    context->switch_error_jumps.emplace_back(SwitchErrorJump{.instr_vram = jtbl.jr_vram, .jtbl_vram = jtbl.vram, .jump = switch_error_jump});

    // The guest table has 4-byte entries but ours has 8-byte pointers, so double the offset (add to self).
    sljit_emit_op2(compiler, SLJIT_ADD, Registers::temp_reg1, 0, Registers::temp_reg1, 0, Registers::temp_reg1, 0);
    // Put the host table's base address in temp2.
    sljit_emit_op1(compiler, SLJIT_MOV, Registers::temp_reg2, 0, SLJIT_IMM, (sljit_sw)cur_jump_table.get());
    // Load the selected code pointer (table[offset*2]) into temp1.
    sljit_emit_op1(compiler, SLJIT_MOV, Registers::temp_reg1, 0, SLJIT_MEM2(Registers::temp_reg1, Registers::temp_reg2), 0);
    // Tail off to it.
    sljit_emit_ijump(compiler, SLJIT_JUMP, Registers::temp_reg1, 0);

    // Hand the (still unpopulated) table to the pending list; emit_function_end fills in its entries.
    context->pending_jump_tables.emplace_back(std::move(cur_jump_table));
}

void N64Recomp::LiveGenerator::emit_case(int case_index, const std::string& target_label) const {
    (void)case_index;
    (void)target_label;
    // No-op: emit_switch already recorded every case, so there's nothing to do per-case.
}

void N64Recomp::LiveGenerator::emit_switch_error(uint32_t instr_vram, uint32_t jtbl_vram) const {
    (void)instr_vram;
    (void)jtbl_vram;
    // No-op: the bounds-check failure path is set up in emit_switch and finished in finish().
}

void N64Recomp::LiveGenerator::emit_switch_close() const {
    // No-op: emit_switch handles the whole switch in one shot.
}

void N64Recomp::LiveGenerator::emit_return(const Context& context, size_t func_index) const {
    (void)context;

    // If a return hook is registered for this function, call it just before returning.
    auto find_hook_it = inputs.return_func_hooks.find(func_index);
    if (find_hook_it != inputs.return_func_hooks.end()) {
        // Pass the unbiased rdram pointer and ctx in R0/R1.
        sljit_emit_op2(compiler, SLJIT_ADD, SLJIT_R0, 0, Registers::rdram, 0, SLJIT_IMM, rdram_offset);
        sljit_emit_op1(compiler, SLJIT_MOV, SLJIT_R1, 0, Registers::ctx, 0);
        // R2 carries the return-hook index.
        sljit_emit_op1(compiler, SLJIT_MOV, SLJIT_R2, 0, SLJIT_IMM, find_hook_it->second);
        sljit_emit_icall(compiler, SLJIT_CALL, SLJIT_ARGS3V(P, P, W), SLJIT_IMM, sljit_sw(inputs.run_hook));
    }
    sljit_emit_return_void(compiler);
}

void N64Recomp::LiveGenerator::emit_check_fr(int fpr) const {
    (void)fpr;
    // No-op in the live backend.
}

void N64Recomp::LiveGenerator::emit_check_nan(int fpr, bool is_double) const {
    (void)fpr;
    (void)is_double;
    // No-op in the live backend.
}

void N64Recomp::LiveGenerator::emit_cop0_status_read(int reg) const {
    // Reading into $zero is a no-op, so only emit anything for a real destination.
    if (reg != 0) {
        // Pass ctx to the host reader in R0.
        sljit_emit_op1(compiler, SLJIT_MOV, SLJIT_R0, 0, Registers::ctx, 0);

        // value = cop0_status_read(ctx).
        sljit_emit_icall(compiler, SLJIT_CALL, SLJIT_ARGS1V(P), SLJIT_IMM, sljit_sw(inputs.cop0_status_read));

        // Write the returned value to the destination register.
        sljit_emit_op1(compiler, SLJIT_MOV, SLJIT_MEM1(Registers::ctx), get_gpr_context_offset(reg), SLJIT_R0, 0);
    }
}

void N64Recomp::LiveGenerator::emit_cop0_status_write(int reg) const {
    sljit_sw src;
    sljit_sw srcw;
    get_gpr_values(reg, src, srcw);

    // Pass ctx and the source register value as the (ctx, value) arguments.
    sljit_emit_op1(compiler, SLJIT_MOV, SLJIT_R0, 0, Registers::ctx, 0);
    sljit_emit_op1(compiler, SLJIT_MOV, SLJIT_R1, 0, src, srcw);

    // cop0_status_write(ctx, value).
    sljit_emit_icall(compiler, SLJIT_CALL, SLJIT_ARGS2V(P,32), SLJIT_IMM, sljit_sw(inputs.cop0_status_write));
}

void N64Recomp::LiveGenerator::emit_cop1_cs_read(int reg) const {
    // Reading into $zero is a no-op.
    if (reg != 0) {
        sljit_sw dst;
        sljit_sw dstw;
        get_gpr_values(reg, dst, dstw);

        // value = get_cop1_cs().
        sljit_emit_icall(compiler, SLJIT_CALL, SLJIT_ARGS0(32), SLJIT_IMM, sljit_sw(get_cop1_cs));

        // Sign extend the 32-bit result through temp1...
        sljit_emit_op1(compiler, SLJIT_MOV_S32, Registers::temp_reg1, 0, SLJIT_RETURN_REG, 0);

        // ...then store it to the destination register.
        sljit_emit_op1(compiler, SLJIT_MOV, dst, dstw, Registers::temp_reg1, 0);
    }
}

void N64Recomp::LiveGenerator::emit_cop1_cs_write(int reg) const {
    sljit_sw src;
    sljit_sw srcw;
    get_gpr_values(reg, src, srcw);

    // Pass the source register value as the lone argument.
    sljit_emit_op1(compiler, SLJIT_MOV, SLJIT_R0, 0, src, srcw);

    // set_cop1_cs(value).
    sljit_emit_icall(compiler, SLJIT_CALL, SLJIT_ARGS1V(32), SLJIT_IMM, sljit_sw(set_cop1_cs));
}

void N64Recomp::LiveGenerator::emit_muldiv(InstrId instr_id, int reg1, int reg2) const {
    sljit_sw src1;
    sljit_sw src1w;
    sljit_sw src2;
    sljit_sw src2w;
    get_gpr_values(reg1, src1, src1w);
    get_gpr_values(reg2, src2, src2w);

    // 32-bit multiply (mult/multu): produces a 64-bit product split across HI:LO.
    auto emit_mul32 = [src1, src1w, src2, src2w, this](bool is_signed) {
        // Stage the two operands in the LMUL input registers R0/R1.
        if (is_signed) {
            // The N64's signed 32-bit multiply actually behaves like 64 x 35 bits, so the second
            // operand is sign extended to 35 bits rather than 32.
            sljit_emit_op1(compiler, SLJIT_MOV, SLJIT_R0, 0, src1, src1w);

            // Sign-extend to 35 bits: shift left then arithmetic-shift right by (64 - 35).
            sljit_emit_op2(compiler, SLJIT_SHL, SLJIT_R1, 0, src2, src2w, SLJIT_IMM, 64 - 35);
            sljit_emit_op2(compiler, SLJIT_ASHR, SLJIT_R1, 0, SLJIT_R1, 0, SLJIT_IMM, 64 - 35);
        }
        else {
            sljit_emit_op1(compiler, SLJIT_MOV_U32, SLJIT_R0, 0, src1, src1w);
            sljit_emit_op1(compiler, SLJIT_MOV_U32, SLJIT_R1, 0, src2, src2w);
        }

        // Long multiply; the 128-bit result lands in R1:R0.
        sljit_emit_op0(compiler, is_signed ? SLJIT_LMUL_SW : SLJIT_LMUL_UW);

        // Split the low 64 bits of the product into HI (upper word) and LO (lower word), both sign extended.
        sljit_emit_op2(compiler, SLJIT_ASHR, Registers::hi, 0, SLJIT_R0, 0, SLJIT_IMM, 32);
        sljit_emit_op1(compiler, SLJIT_MOV_S32, Registers::lo, 0, SLJIT_R0, 0);
    };

    // 64-bit multiply (dmult/dmultu): the full 128-bit product fills HI:LO.
    auto emit_mul64 = [src1, src1w, src2, src2w, this](bool is_signed) {
        // Stage the operands in R0/R1.
        sljit_emit_op1(compiler, SLJIT_MOV, SLJIT_R0, 0, src1, src1w);
        sljit_emit_op1(compiler, SLJIT_MOV, SLJIT_R1, 0, src2, src2w);

        // Long multiply into R1:R0.
        sljit_emit_op0(compiler, is_signed ? SLJIT_LMUL_SW : SLJIT_LMUL_UW);

        // High half to HI, low half to LO.
        sljit_emit_op1(compiler, SLJIT_MOV, Registers::hi, 0, SLJIT_R1, 0);
        sljit_emit_op1(compiler, SLJIT_MOV, Registers::lo, 0, SLJIT_R0, 0);
    };

    // Divide (div/divu/ddiv/ddivu): quotient to LO, remainder to HI, with the MIPS-defined
    // results for a zero divisor reproduced explicitly.
    auto emit_divmod = [src1, src1w, src2, src2w, this](bool doubleword, bool is_signed) {
        // Select the DIVMOD opcode for the width/signedness. Signed 32-bit division uses the 64-bit
        // signed opcode to mirror the hardware and dodge an overflow trap.
        sljit_sw div_opcode = doubleword ?
            (is_signed ? SLJIT_DIVMOD_SW : SLJIT_DIVMOD_UW) :
            (is_signed ? SLJIT_DIVMOD_SW : SLJIT_DIVMOD_U32);

        // Move opcode used to load the operands at the chosen width/extension.
        sljit_sw load_opcode = doubleword ? SLJIT_MOV :
            (is_signed ? SLJIT_MOV_S32 : SLJIT_MOV_U32);

        // Move opcode used to write the HI/LO results back.
        sljit_sw save_opcode = doubleword ? SLJIT_MOV : SLJIT_MOV_S32;

        // Numerator into R0.
        sljit_emit_op1(compiler, load_opcode, SLJIT_R0, 0, src1, src1w);

        // TODO figure out 32-bit signed division behavior when inputs aren't properly sign extended.
        // if (!doubleword && is_signed) {
        //     // Sign extend to 35 bits by shifting left by 64 - 35 and then shifting right by the same amount.
        //     sljit_emit_op2(compiler, SLJIT_SHL, SLJIT_R1, 0, src2, src2w, SLJIT_IMM, 64 - 35);
        //     sljit_emit_op2(compiler, SLJIT_ASHR, SLJIT_R1, 0, SLJIT_R1, 0, SLJIT_IMM, 64 - 35);
        // }
        // else {
            // Denominator into R1.
            sljit_emit_op1(compiler, load_opcode, SLJIT_R1, 0, src2, src2w);
        // }

        // Guard against the one overflowing case of 64-bit signed division.
        if (doubleword && is_signed) {
            // INT64_MIN / -1 overflows and would trap. To behave like the hardware instead, detect
            // exactly that operand pair and, when it occurs, substitute a denominator of 1.

            // temp3 = numerator ^ INT64_MIN (zero iff numerator == INT64_MIN).
            sljit_emit_op2(compiler, SLJIT_XOR, Registers::temp_reg3, 0, Registers::temp_reg1, 0, SLJIT_IMM, sljit_sw(INT64_MIN));

            // temp4 = ~denominator (zero iff denominator == -1).
            sljit_emit_op2(compiler, SLJIT_XOR, Registers::temp_reg4, 0, Registers::temp_reg2, 0, SLJIT_IMM, sljit_sw(-1));

            // OR them and set the zero flag; the flag is set iff both checks were zero, i.e. the bad pair.
            sljit_emit_op2(compiler, SLJIT_OR | SLJIT_SET_Z, Registers::temp_reg3, 0, Registers::temp_reg3, 0, Registers::temp_reg4, 0);

            // On the zero flag (the bad pair), select 1 into the denominator R1; otherwise keep R1.
            sljit_emit_select(compiler, SLJIT_ZERO, SLJIT_R1, SLJIT_IMM, 1, SLJIT_R1);
        }

        // Divide-by-zero has its own MIPS-defined result, so branch around the actual division when
        // the denominator is 0.
        sljit_jump* jump_skip_division = sljit_emit_cmp(compiler, SLJIT_EQUAL, SLJIT_R1, 0, SLJIT_IMM, 0);// sljit_emit_jump(compiler, SLJIT_ZERO);

        // Normal path: do the division.
        sljit_emit_op0(compiler, div_opcode);

        // DIVMOD leaves the remainder in R1 (-> HI) and the quotient in R0 (-> LO).
        sljit_emit_op1(compiler, save_opcode, Registers::hi, 0, SLJIT_R1, 0);
        sljit_emit_op1(compiler, save_opcode, Registers::lo, 0, SLJIT_R0, 0);

        // Skip over the divide-by-zero handling.
        sljit_jump* jump_to_end = sljit_emit_jump(compiler, SLJIT_JUMP);

        // Divide-by-zero path begins here.
        sljit_label* after_division = sljit_emit_label(compiler);
        sljit_set_label(jump_skip_division, after_division);

        // The remainder is defined as the numerator, so put it in HI.
        sljit_emit_op1(compiler, save_opcode, Registers::hi, 0, SLJIT_R0, 0);

        if (is_signed) {
            // Signed divide-by-zero defines the quotient as the negated signum of the numerator:
            // neg_signum = ((int64_t)(~x) >> (bit width - 1)) | 1.
            sljit_emit_op2(compiler, SLJIT_XOR, Registers::lo, 0, SLJIT_R0, 0, SLJIT_IMM, sljit_sw(-1));
            sljit_emit_op2(compiler, SLJIT_ASHR, Registers::lo, 0, Registers::lo, 0, SLJIT_IMM, 64 - 1);
            sljit_emit_op2(compiler, SLJIT_OR, Registers::lo, 0, Registers::lo, 0, SLJIT_IMM, 1);
        }
        else {
            // Unsigned divide-by-zero defines the quotient as -1 (all ones).
            sljit_emit_op1(compiler, SLJIT_MOV, Registers::lo, 0, SLJIT_IMM, sljit_sw(-1));
        }

        // Common exit; both paths rejoin here.
        sljit_label* end_label = sljit_emit_label(compiler);
        sljit_set_label(jump_to_end, end_label);
    };


    switch (instr_id) {
        case InstrId::cpu_mult:
            emit_mul32(true);
            break;
        case InstrId::cpu_multu:
            emit_mul32(false);
            break;
        case InstrId::cpu_dmult:
            emit_mul64(true);
            break;
        case InstrId::cpu_dmultu:
            emit_mul64(false);
            break;
        case InstrId::cpu_div:
            emit_divmod(false, true);
            break;
        case InstrId::cpu_divu:
            emit_divmod(false, false);
            break;
        case InstrId::cpu_ddiv:
            emit_divmod(true, true);
            break;
        case InstrId::cpu_ddivu:
            emit_divmod(true, false);
            break;
        default:
            assert(false && "Invalid mul/div instruction id!");
            break;
    }
}

void N64Recomp::LiveGenerator::emit_syscall(uint32_t instr_vram) const {
    // (rdram, ctx) arguments.
    sljit_emit_op2(compiler, SLJIT_ADD, SLJIT_R0, 0, Registers::rdram, 0, SLJIT_IMM, rdram_offset);
    sljit_emit_op1(compiler, SLJIT_MOV, SLJIT_R1, 0, Registers::ctx, 0);
    // R2 holds the syscall instruction's vram.
    sljit_emit_op1(compiler, SLJIT_MOV32, SLJIT_R2, 0, SLJIT_IMM, instr_vram);
    // syscall_handler(rdram, ctx, vram).
    sljit_emit_icall(compiler, SLJIT_CALL, SLJIT_ARGS3V(P, P, 32), SLJIT_IMM, sljit_sw(inputs.syscall_handler));
}

void N64Recomp::LiveGenerator::emit_do_break(uint32_t instr_vram) const {
    // R0 holds the break instruction's vram.
    sljit_emit_op1(compiler, SLJIT_MOV32, SLJIT_R0, 0, SLJIT_IMM, instr_vram);
    // do_break(vram).
    sljit_emit_icall(compiler, SLJIT_CALL, SLJIT_ARGS1V(32), SLJIT_IMM, sljit_sw(inputs.do_break));
}

void N64Recomp::LiveGenerator::emit_pause_self() const {
    // Pass the unbiased rdram pointer.
    sljit_emit_op2(compiler, SLJIT_ADD, SLJIT_R0, 0, Registers::rdram, 0, SLJIT_IMM, rdram_offset);
    // pause_self(rdram).
    sljit_emit_icall(compiler, SLJIT_CALL, SLJIT_ARGS1V(P), SLJIT_IMM, sljit_sw(inputs.pause_self));
}

void N64Recomp::LiveGenerator::emit_trigger_event(uint32_t event_index) const {
    // (rdram, ctx) arguments.
    sljit_emit_op2(compiler, SLJIT_ADD, SLJIT_R0, 0, Registers::rdram, 0, SLJIT_IMM, rdram_offset);
    sljit_emit_op1(compiler, SLJIT_MOV, SLJIT_R1, 0, Registers::ctx, 0);
    // R2 holds the event index rebased onto this module's global event range.
    sljit_emit_op1(compiler, SLJIT_MOV32, SLJIT_R2, 0, SLJIT_IMM, event_index + inputs.base_event_index);
    // trigger_event(rdram, ctx, global_event_index).
    sljit_emit_icall(compiler, SLJIT_CALL, SLJIT_ARGS3V(P,P,32), SLJIT_IMM, sljit_sw(inputs.trigger_event));
}

void N64Recomp::LiveGenerator::emit_comment(const std::string& comment) const {
    (void)comment;
    // No-op: comments are only meaningful for the C-source backend.
}

bool N64Recomp::recompile_function_live(LiveGenerator& generator, const Context& context, size_t function_index, std::ostream& output_file, std::span<std::vector<uint32_t>> static_funcs_out, bool tag_reference_relocs) {
    return recompile_function_custom(generator, context, function_index, output_file, static_funcs_out, tag_reference_relocs);
}

N64Recomp::ShimFunction::ShimFunction(recomp_func_ext_t* to_shim, uintptr_t value) {
    sljit_compiler* compiler = sljit_create_compiler(nullptr);

    // A shim is a tiny standalone function: it forwards its two pointer args along with a baked-in
    // third argument to the wrapped function. Open it.
    sljit_label* func_label = sljit_emit_label(compiler);
    sljit_emit_enter(compiler, 0, SLJIT_ARGS2V(P_R, P_R), 3, 0, 0);

    // Supply the captured value as the third argument.
    sljit_emit_op1(compiler, SLJIT_MOV, SLJIT_R2, 0, SLJIT_IMM, sljit_sw(value));

    // Tail-call the wrapped function so it returns directly to this shim's caller.
    sljit_emit_icall(compiler, SLJIT_CALL | SLJIT_CALL_RETURN, SLJIT_ARGS3V(P, P, W), SLJIT_IMM, sljit_sw(to_shim));

    // Lower it and grab the resulting entry pointer.
    code = sljit_generate_code(compiler, 0, nullptr);
    func = reinterpret_cast<recomp_func_t*>(sljit_get_label_addr(func_label));

    // The compiler isn't needed once the code is generated.
    sljit_free_compiler(compiler);
}

N64Recomp::ShimFunction::~ShimFunction() {
    sljit_free_code(code, nullptr);
    code = nullptr;
    func = nullptr;
}
