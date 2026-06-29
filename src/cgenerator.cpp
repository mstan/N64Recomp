#include <array>
#include <cassert>
#include <fstream>
#include <stdexcept>
#include <string_view>
#include <utility>

#include "fmt/format.h"
#include "fmt/ostream.h"

#include "recompiler/generator.h"

// C backend for the recompiler. Each method turns a decoded operation (or a
// control-flow event) into the equivalent C source. The emitted text is the
// contract with the runtime: macro names like ADD32 / MEM_W / RECOMP_FUNC, the
// recomp_context field names, and the function-call/tailcall protocol are all
// defined on the runtime side, so this file reproduces them verbatim. Only the
// surrounding generation logic is ours to shape.

namespace {
    using N64Recomp::BinaryOpType;
    using N64Recomp::UnaryOpType;

    // How a binary operation is spelled in C. An entry can be a call form
    // (func set: "func(a, b)"), an infix operator (infix set: "a op b"), both
    // (func wrapping an infix expression: "func(a op b)"), or neither -- the
    // latter (True/False) is special-cased by the caller.
    struct OpNotation {
        const char* func;
        const char* infix;
    };

    const std::array<OpNotation, static_cast<size_t>(BinaryOpType::COUNT)>& binary_op_notation() {
        static const std::array<OpNotation, static_cast<size_t>(BinaryOpType::COUNT)> table = [] {
            std::array<OpNotation, static_cast<size_t>(BinaryOpType::COUNT)> t{};
            t.fill(OpNotation{ "", "" });
            auto set = [&t](BinaryOpType op, const char* func, const char* infix) {
                t[static_cast<size_t>(op)] = OpNotation{ func, infix };
            };
            // Integer add/subtract. The 32-bit forms go through helper macros
            // that truncate-and-sign-extend; the 64-bit forms are plain infix.
            set(BinaryOpType::Add32,        "ADD32", "");
            set(BinaryOpType::Sub32,        "SUB32", "");
            set(BinaryOpType::Add64,        "",      "+");
            set(BinaryOpType::Sub64,        "",      "-");
            // Floating-point arithmetic.
            set(BinaryOpType::AddFloat,     "",      "+");
            set(BinaryOpType::AddDouble,    "",      "+");
            set(BinaryOpType::SubFloat,     "",      "-");
            set(BinaryOpType::SubDouble,    "",      "-");
            set(BinaryOpType::MulFloat,     "MUL_S", "");
            set(BinaryOpType::MulDouble,    "MUL_D", "");
            set(BinaryOpType::DivFloat,     "DIV_S", "");
            set(BinaryOpType::DivDouble,    "DIV_D", "");
            // Bitwise. nor is the only one needing an outer wrap (~).
            set(BinaryOpType::And64,        "",      "&");
            set(BinaryOpType::Or64,         "",      "|");
            set(BinaryOpType::Nor64,        "~",     "|");
            set(BinaryOpType::Xor64,        "",      "^");
            // Shifts. The 32-bit forms wrap the result in S32 to truncate and
            // sign-extend; the arithmetic part of sra is handled by the operand
            // pre-op, so srl/sra share the same spelling here.
            set(BinaryOpType::Sll32,        "S32",   "<<");
            set(BinaryOpType::Sll64,        "",      "<<");
            set(BinaryOpType::Srl32,        "S32",   ">>");
            set(BinaryOpType::Srl64,        "",      ">>");
            set(BinaryOpType::Sra32,        "S32",   ">>");
            set(BinaryOpType::Sra64,        "",      ">>");
            // Comparisons (integer and float share the same operators).
            set(BinaryOpType::Equal,        "",      "==");
            set(BinaryOpType::NotEqual,     "",      "!=");
            set(BinaryOpType::Less,         "",      "<");
            set(BinaryOpType::LessEq,       "",      "<=");
            set(BinaryOpType::Greater,      "",      ">");
            set(BinaryOpType::GreaterEq,    "",      ">=");
            set(BinaryOpType::EqualFloat,   "",      "==");
            set(BinaryOpType::LessFloat,    "",      "<");
            set(BinaryOpType::LessEqFloat,  "",      "<=");
            set(BinaryOpType::EqualDouble,  "",      "==");
            set(BinaryOpType::LessDouble,   "",      "<");
            set(BinaryOpType::LessEqDouble, "",      "<=");
            // Loads spelled as macros / helper calls.
            set(BinaryOpType::LD,           "LD",     "");
            set(BinaryOpType::LW,           "MEM_W",  "");
            set(BinaryOpType::LWU,          "MEM_WU", "");
            set(BinaryOpType::LH,           "MEM_H",  "");
            set(BinaryOpType::LHU,          "MEM_HU", "");
            set(BinaryOpType::LB,           "MEM_B",  "");
            set(BinaryOpType::LBU,          "MEM_BU", "");
            set(BinaryOpType::LDL,          "do_ldl", "");
            set(BinaryOpType::LDR,          "do_ldr", "");
            set(BinaryOpType::LWL,          "do_lwl", "");
            set(BinaryOpType::LWR,          "do_lwr", "");
            // True/False carry no notation; left as the {"",""} default.
            return t;
        }();
        return table;
    }

    // The prefix/suffix that a unary pre-op wraps around an operand. Applying
    // both uniformly (prefix + operand + suffix) reproduces every case; None
    // and ToU64 are no-ops with empty affixes.
    std::pair<std::string_view, std::string_view> unary_affixes(UnaryOpType op) {
        switch (op) {
            case UnaryOpType::None:           return { "", "" };
            case UnaryOpType::ToS32:          return { "S32(", ")" };
            case UnaryOpType::ToU32:          return { "U32(", ")" };
            case UnaryOpType::ToS64:          return { "SIGNED(", ")" };
            case UnaryOpType::ToU64:          return { "", "" }; // already U64
            case UnaryOpType::Lui:            return { "S32(U32(", ") << 16)" };
            case UnaryOpType::Mask5:          return { "(", " & 31)" };
            case UnaryOpType::Mask6:          return { "(", " & 63)" };
            case UnaryOpType::ToInt32:        return { "(int32_t)", "" };
            case UnaryOpType::NegateFloat:    return { "-", "" };
            case UnaryOpType::NegateDouble:   return { "-", "" };
            case UnaryOpType::AbsFloat:       return { "fabsf(", ")" };
            case UnaryOpType::AbsDouble:      return { "fabs(", ")" };
            case UnaryOpType::SqrtFloat:      return { "sqrtf(", ")" };
            case UnaryOpType::SqrtDouble:     return { "sqrt(", ")" };
            case UnaryOpType::ConvertSFromW:  return { "CVT_S_W(", ")" };
            case UnaryOpType::ConvertWFromS:  return { "CVT_W_S(", ")" };
            case UnaryOpType::ConvertDFromW:  return { "CVT_D_W(", ")" };
            case UnaryOpType::ConvertWFromD:  return { "CVT_W_D(", ")" };
            case UnaryOpType::ConvertDFromS:  return { "CVT_D_S(", ")" };
            case UnaryOpType::ConvertSFromD:  return { "CVT_S_D(", ")" };
            case UnaryOpType::ConvertDFromL:  return { "CVT_D_L(", ")" };
            case UnaryOpType::ConvertLFromD:  return { "CVT_L_D(", ")" };
            case UnaryOpType::ConvertSFromL:  return { "CVT_S_L(", ")" };
            case UnaryOpType::ConvertLFromS:  return { "CVT_L_S(", ")" };
            case UnaryOpType::TruncateWFromS: return { "TRUNC_W_S(", ")" };
            case UnaryOpType::TruncateWFromD: return { "TRUNC_W_D(", ")" };
            case UnaryOpType::TruncateLFromS: return { "TRUNC_L_S(", ")" };
            case UnaryOpType::TruncateLFromD: return { "TRUNC_L_D(", ")" };
            // TODO these four should use banker's rounding, but roundeven is C23 and unavailable here.
            case UnaryOpType::RoundWFromS:    return { "lroundf(", ")" };
            case UnaryOpType::RoundWFromD:    return { "lround(", ")" };
            case UnaryOpType::RoundLFromS:    return { "llroundf(", ")" };
            case UnaryOpType::RoundLFromD:    return { "llround(", ")" };
            case UnaryOpType::CeilWFromS:     return { "S32(ceilf(", "))" };
            case UnaryOpType::CeilWFromD:     return { "S32(ceil(", "))" };
            case UnaryOpType::CeilLFromS:     return { "S64(ceilf(", "))" };
            case UnaryOpType::CeilLFromD:     return { "S64(ceil(", "))" };
            case UnaryOpType::FloorWFromS:    return { "S32(floorf(", "))" };
            case UnaryOpType::FloorWFromD:    return { "S32(floor(", "))" };
            case UnaryOpType::FloorLFromS:    return { "S64(floorf(", "))" };
            case UnaryOpType::FloorLFromD:    return { "S64(floor(", "))" };
        }
        return { "", "" };
    }

    // A GPR reads as the literal 0 when it is $zero, otherwise as the context field.
    std::string gpr_to_string(int gpr_index) {
        if (gpr_index == 0) {
            return "0";
        }
        return fmt::format("ctx->r{}", gpr_index);
    }

    std::string fpr_to_string(int fpr_index) {
        return fmt::format("ctx->f{}.fl", fpr_index);
    }

    std::string fpr_double_to_string(int fpr_index) {
        return fmt::format("ctx->f{}.d", fpr_index);
    }

    // Odd single-precision registers live in the f_odd overlay under mips3
    // float mode; even ones are the low word of the paired double.
    std::string fpr_u32l_to_string(int fpr_index) {
        if (fpr_index & 1) {
            return fmt::format("ctx->f_odd[({} - 1) * 2]", fpr_index);
        }
        return fmt::format("ctx->f{}.u32l", fpr_index);
    }

    std::string fpr_u64_to_string(int fpr_index) {
        return fmt::format("ctx->f{}.u64", fpr_index);
    }

    bool is_zero_gpr_operand(N64Recomp::Operand operand, const N64Recomp::InstructionContext& ctx) {
        switch (operand) {
            case N64Recomp::Operand::Rd: return ctx.rd == 0;
            case N64Recomp::Operand::Rs: return ctx.rs == 0;
            case N64Recomp::Operand::Rt: return ctx.rt == 0;
            default: return false;
        }
    }

    // A HI16/LO16 relocation renders as a RELOC_xI16 macro the runtime resolves
    // once the target section's load address is known; the REF_ prefix selects
    // the reference-symbol variant.
    std::string unsigned_reloc(const N64Recomp::InstructionContext& context) {
        const char* ref_prefix = context.reloc_tag_as_reference ? "REF_" : "";
        switch (context.reloc_type) {
            case N64Recomp::RelocType::R_MIPS_HI16:
                return fmt::format("{}RELOC_HI16({}, {:#X})",
                    ref_prefix, context.reloc_section_index, context.reloc_target_section_offset);
            case N64Recomp::RelocType::R_MIPS_LO16:
                return fmt::format("{}RELOC_LO16({}, {:#X})",
                    ref_prefix, context.reloc_section_index, context.reloc_target_section_offset);
            default:
                throw std::runtime_error(fmt::format("Unexpected reloc type {}\n", static_cast<int>(context.reloc_type)));
        }
    }

    std::string signed_reloc(const N64Recomp::InstructionContext& context) {
        return "(int16_t)" + unsigned_reloc(context);
    }

    // Shared open/close of a function-call frame. Every call site captures the
    // stack pointer and host return target, performs the call, runs tailcall
    // handling, then restores and checks that the callee left $sp intact.
    void emit_call_prologue(std::ostream& output_file) {
        fmt::print(output_file, "{{\n");
        fmt::print(output_file, "    gpr recomp_call_sp = ctx->r29;\n");
        fmt::print(output_file, "    uint32_t recomp_prev_host_return = ctx->host_return_target;\n");
        fmt::print(output_file, "    uint32_t recomp_call_host_return = (uint32_t)ctx->r31;\n");
        fmt::print(output_file, "    ctx->host_return_target = recomp_call_host_return;\n");
    }

    void emit_call_epilogue(std::ostream& output_file) {
        fmt::print(output_file, "    ctx->host_return_target = recomp_prev_host_return;\n");
        fmt::print(output_file, "    if (ctx->r29 != recomp_call_sp) {{ recomp_cf_note(\"call-sp-mismatch\", (uint32_t)recomp_call_sp, recomp_prev_host_return, recomp_call_host_return, ctx); return; }}\n");
        fmt::print(output_file, "}}\n");
    }
}

void N64Recomp::CGenerator::get_operand_string(Operand operand, UnaryOpType operation, const InstructionContext& context, std::string& operand_string) const {
    // First resolve the operand to its C lvalue/expression...
    switch (operand) {
        case Operand::Rd:
            operand_string = gpr_to_string(context.rd);
            break;
        case Operand::Rs:
            operand_string = gpr_to_string(context.rs);
            break;
        case Operand::Rt:
            operand_string = gpr_to_string(context.rt);
            break;
        case Operand::Fd:
            operand_string = fpr_to_string(context.fd);
            break;
        case Operand::Fs:
            operand_string = fpr_to_string(context.fs);
            break;
        case Operand::Ft:
            operand_string = fpr_to_string(context.ft);
            break;
        case Operand::FdDouble:
            operand_string = fpr_double_to_string(context.fd);
            break;
        case Operand::FsDouble:
            operand_string = fpr_double_to_string(context.fs);
            break;
        case Operand::FtDouble:
            operand_string = fpr_double_to_string(context.ft);
            break;
        case Operand::FdU32L:
            operand_string = fpr_u32l_to_string(context.fd);
            break;
        case Operand::FsU32L:
            operand_string = fpr_u32l_to_string(context.fs);
            break;
        case Operand::FtU32L:
            operand_string = fpr_u32l_to_string(context.ft);
            break;
        case Operand::FdU32H:
            assert(false);
            break;
        case Operand::FsU32H:
            assert(false);
            break;
        case Operand::FtU32H:
            assert(false);
            break;
        case Operand::FdU64:
            operand_string = fpr_u64_to_string(context.fd);
            break;
        case Operand::FsU64:
            operand_string = fpr_u64_to_string(context.fs);
            break;
        case Operand::FtU64:
            operand_string = fpr_u64_to_string(context.ft);
            break;
        case Operand::ImmU16:
            if (context.reloc_type != N64Recomp::RelocType::R_MIPS_NONE) {
                operand_string = unsigned_reloc(context);
            }
            else {
                operand_string = fmt::format("{:#X}", context.imm16);
            }
            break;
        case Operand::ImmS16:
            if (context.reloc_type != N64Recomp::RelocType::R_MIPS_NONE) {
                operand_string = signed_reloc(context);
            }
            else {
                operand_string = fmt::format("{:#X}", (int16_t)context.imm16);
            }
            break;
        case Operand::Sa:
            operand_string = std::to_string(context.sa);
            break;
        case Operand::Sa32:
            operand_string = fmt::format("({} + 32)", context.sa);
            break;
        case Operand::Cop1cs:
            operand_string = "c1cs";
            break;
        case Operand::Hi:
            operand_string = "hi";
            break;
        case Operand::Lo:
            operand_string = "lo";
            break;
        case Operand::Zero:
            operand_string = "0";
            break;
    }
    // ...then wrap it in the pre-op's prefix/suffix.
    auto [prefix, suffix] = unary_affixes(operation);
    if (!prefix.empty() || !suffix.empty()) {
        operand_string = std::string(prefix) + operand_string + std::string(suffix);
    }
}

void N64Recomp::CGenerator::get_notation(BinaryOpType op_type, std::string& func_string, std::string& infix_string) const {
    const OpNotation& notation = binary_op_notation()[static_cast<size_t>(op_type)];
    func_string = notation.func;
    infix_string = notation.infix;
}

void N64Recomp::CGenerator::get_binary_expr_string(BinaryOpType type, const BinaryOperands& operands, const InstructionContext& ctx, const std::string& output, std::string& expr_string) const {
    thread_local std::string input_a{};
    thread_local std::string input_b{};
    thread_local std::string func_string{};
    thread_local std::string infix_string{};
    get_operand_string(operands.operands[0], operands.operand_operations[0], ctx, input_a);
    get_operand_string(operands.operands[1], operands.operand_operations[1], ctx, input_b);
    get_notation(type, func_string, infix_string);

    const bool second_is_plain_zero = operands.operands[1] == Operand::Zero && operands.operand_operations[1] == UnaryOpType::None;

    // These first three cases aren't strictly necessary; they exist to match
    // the old recompiler's output (a bare comparison-to-zero / boolean form).
    if (type == BinaryOpType::Less && !(second_is_plain_zero || (operands.operands[0] == Operand::Fs || operands.operands[0] == Operand::FsDouble))) {
        expr_string = fmt::format("{} {} {} ? 1 : 0", input_a, infix_string, input_b);
    }
    else if (type == BinaryOpType::Equal && second_is_plain_zero) {
        expr_string = "!" + input_a;
    }
    else if (type == BinaryOpType::NotEqual && second_is_plain_zero) {
        expr_string = input_a;
    }
    // End parity cases.

    // TODO encode these ops so they don't need special handling. The unaligned
    // word/doubleword loads take rdram and the destination as extra arguments.
    else if (type == BinaryOpType::LWL || type == BinaryOpType::LWR || type == BinaryOpType::LDL || type == BinaryOpType::LDR) {
        expr_string = fmt::format("{}(rdram, {}, {}, {})", func_string, output, input_a, input_b);
    }
    else if (!func_string.empty() && !infix_string.empty()) {
        expr_string = fmt::format("{}({} {} {})", func_string, input_a, infix_string, input_b);
    }
    else if (!func_string.empty()) {
        expr_string = fmt::format("{}({}, {})", func_string, input_a, input_b);
    }
    else if (!infix_string.empty()) {
        expr_string = fmt::format("{} {} {}", input_a, infix_string, input_b);
    }
    else {
        // The only notation-less ops are the constant results.
        if (type == BinaryOpType::True) {
            expr_string = "1";
        }
        else if (type == BinaryOpType::False) {
            expr_string = "0";
        }
        assert(false && "Binary operation must have either a function or infix!");
    }
}

void N64Recomp::CGenerator::emit_function_start(const std::string& function_name, size_t func_index) const {
    (void)func_index;
    fmt::print(output_file,
        "RECOMP_FUNC void {}(uint8_t* rdram, recomp_context* ctx) {{\n"
        // these variables shouldn't need to be preserved across function boundaries, so make them local for more efficient output
        "    uint64_t hi = 0, lo = 0, result = 0;\n"
        "    int c1cs = 0;\n", // cop1 conditional signal
        function_name);
}

void N64Recomp::CGenerator::emit_function_end() const {
    fmt::print(output_file, ";}}\n");
}

void N64Recomp::CGenerator::emit_tailcall_handling(const std::set<uint32_t>& local_labels, uint32_t return_vram) const {
    fmt::print(output_file, "    if (ctx->tailcall_pending) {{\n");
    if (return_vram != 0) {
        fmt::print(output_file, "        if (ctx->tailcall_target == 0x{:08X}u) {{\n", return_vram);
        fmt::print(output_file, "            recomp_cf_note(\"call-return-tailcall\", (uint32_t)recomp_call_sp, recomp_prev_host_return, recomp_call_host_return, ctx);\n");
        fmt::print(output_file, "            ctx->tailcall_pending = 0;\n");
        fmt::print(output_file, "            ctx->tailcall_target = 0;\n");
        fmt::print(output_file, "            ctx->tailcall_func = 0;\n");
        fmt::print(output_file, "            ctx->host_return_target = recomp_prev_host_return;\n");
        fmt::print(output_file, "            if (ctx->r29 != recomp_call_sp) {{ recomp_cf_note(\"call-sp-mismatch\", (uint32_t)recomp_call_sp, recomp_prev_host_return, recomp_call_host_return, ctx); return; }}\n");
        fmt::print(output_file, "            goto L_{:08X};\n", return_vram);
        fmt::print(output_file, "        }}\n");
    }
    if (!local_labels.empty()) {
        fmt::print(output_file, "        if (ctx->tailcall_target != 0) {{\n");
        fmt::print(output_file, "            switch ((uint32_t)ctx->tailcall_target) {{\n");
        for (uint32_t label_vram : local_labels) {
            fmt::print(output_file, "            case 0x{:08X}u:\n", label_vram);
            fmt::print(output_file, "                recomp_cf_note(\"call-local-tailcall\", (uint32_t)recomp_call_sp, recomp_prev_host_return, recomp_call_host_return, ctx);\n");
            fmt::print(output_file, "                ctx->tailcall_pending = 0;\n");
            fmt::print(output_file, "                ctx->tailcall_target = 0;\n");
            fmt::print(output_file, "                ctx->tailcall_func = 0;\n");
            fmt::print(output_file, "                ctx->host_return_target = recomp_prev_host_return;\n");
            fmt::print(output_file, "                if (ctx->r29 != recomp_call_sp) {{ recomp_cf_note(\"call-sp-mismatch\", (uint32_t)recomp_call_sp, recomp_prev_host_return, recomp_call_host_return, ctx); return; }}\n");
            fmt::print(output_file, "                goto L_{:08X};\n", label_vram);
        }
        fmt::print(output_file, "            default: break;\n");
        fmt::print(output_file, "            }}\n");
        fmt::print(output_file, "        }}\n");
    }
    // Depth-bounded tailcall draining for a pending NON-local tailcall (one not
    // already resolved by the return-continuation or local-label handlers above).
    // ctx->tailcall_dispatching is the current nested-trampoline DEPTH.
    //   - Shallow depth: drain locally via recomp_handle_tailcalls. This is
    //     required for finite menu-exit continuations such as register-quit
    //     (ISSUES.md #7): the continuation must run THIS frame's tail (e.g.
    //     main_pool_try_free) and resume, so it cannot be bubbled away.
    //   - Past the threshold, re-entering recomp_handle_tailcalls from large
    //     generated frames can overflow the host stack before an unbounded
    //     guest tailcall loop is identified. Bubble up and let the existing
    //     outer trampoline iterate instead.
    // Keep the limit low enough to be a stack-safety guard while still allowing
    // shallow finite continuations to drain locally.
    fmt::print(output_file, "        if (ctx->tailcall_dispatching >= 64u) {{\n");
    fmt::print(output_file, "            recomp_cf_note(\"call-bubble-dispatch\", (uint32_t)recomp_call_sp, recomp_prev_host_return, recomp_call_host_return, ctx);\n");
    fmt::print(output_file, "            ctx->host_return_target = recomp_prev_host_return;\n");
    fmt::print(output_file, "            return;\n");
    fmt::print(output_file, "        }}\n");
    fmt::print(output_file, "        recomp_handle_tailcalls(rdram, ctx);\n");
    fmt::print(output_file, "    }}\n");
}

void N64Recomp::CGenerator::emit_function_call_lookup(uint32_t addr, const std::set<uint32_t>& local_labels, uint32_t return_vram) const {
    emit_call_prologue(output_file);
    fmt::print(output_file, "    LOOKUP_FUNC(0x{:08X})(rdram, ctx);\n", addr);
    emit_tailcall_handling(local_labels, return_vram);
    emit_call_epilogue(output_file);
}

void N64Recomp::CGenerator::emit_function_call_by_register(int reg, const std::set<uint32_t>& local_labels, uint32_t return_vram) const {
    emit_call_prologue(output_file);
    fmt::print(output_file, "    LOOKUP_FUNC({})(rdram, ctx);\n", gpr_to_string(reg));
    emit_tailcall_handling(local_labels, return_vram);
    emit_call_epilogue(output_file);
}

void N64Recomp::CGenerator::emit_function_call_reference_symbol(const Context& context, uint16_t section_index, size_t symbol_index, uint32_t target_section_offset, const std::set<uint32_t>& local_labels, uint32_t return_vram) const {
    (void)target_section_offset;
    const N64Recomp::ReferenceSymbol& sym = context.get_reference_symbol(section_index, symbol_index);
    emit_call_prologue(output_file);
    fmt::print(output_file, "    {}(rdram, ctx);\n", sym.name);
    emit_tailcall_handling(local_labels, return_vram);
    emit_call_epilogue(output_file);
}

void N64Recomp::CGenerator::emit_function_call(const Context& context, size_t function_index, const std::set<uint32_t>& local_labels, uint32_t return_vram) const {
    emit_call_prologue(output_file);
    fmt::print(output_file, "    {}(rdram, ctx);\n", context.functions[function_index].name);
    emit_tailcall_handling(local_labels, return_vram);
    emit_call_epilogue(output_file);
}

void N64Recomp::CGenerator::emit_named_function_call(const std::string& function_name, const std::set<uint32_t>& local_labels, uint32_t return_vram) const {
    emit_call_prologue(output_file);
    fmt::print(output_file, "    {}(rdram, ctx);\n", function_name);
    emit_tailcall_handling(local_labels, return_vram);
    emit_call_epilogue(output_file);
}

void N64Recomp::CGenerator::emit_goto(const std::string& target) const {
    fmt::print(output_file,
        "    goto {};\n", target);
}

void N64Recomp::CGenerator::emit_label(const std::string& label_name) const {
    fmt::print(output_file,
        "{}:\n", label_name);
}

void N64Recomp::CGenerator::emit_jtbl_addend_declaration(const JumpTable& jtbl, int reg) const {
    std::string jump_variable = fmt::format("jr_addend_{:08X}", jtbl.jr_vram);
    fmt::print(output_file, "gpr {} = {};\n", jump_variable, gpr_to_string(reg));
}

void N64Recomp::CGenerator::emit_branch_condition(const ConditionalBranchOp& op, const InstructionContext& ctx) const {
    // Thread local variables to prevent allocations when possible.
    // TODO these thread locals probably don't actually help right now, so figure out a better way to prevent allocations.
    thread_local std::string expr_string{};
    get_binary_expr_string(op.comparison, op.operands, ctx, "", expr_string);
    fmt::print(output_file, "if ({}) {{\n", expr_string);
}

void N64Recomp::CGenerator::emit_branch_close() const {
    fmt::print(output_file, "}}\n");
}

void N64Recomp::CGenerator::emit_switch_close() const {
    fmt::print(output_file, "}}\n");
}

void N64Recomp::CGenerator::emit_switch(const Context& recompiler_context, const JumpTable& jtbl, int reg) const {
    (void)recompiler_context;
    (void)reg;
    // TODO generate code to subtract the jump table address from the register's value instead.
    // Once that's done, the addend temp can be deleted to simplify the generator interface.
    std::string jump_variable = fmt::format("jr_addend_{:08X}", jtbl.jr_vram);

    fmt::print(output_file, "switch ({} >> 2) {{\n", jump_variable);
}

void N64Recomp::CGenerator::emit_case(int case_index, const std::string& target_label) const {
    fmt::print(output_file, "case {}: goto {}; break;\n", case_index, target_label);
}

void N64Recomp::CGenerator::emit_switch_error(uint32_t instr_vram, uint32_t jtbl_vram) const {
    fmt::print(output_file, "default: switch_error(__func__, 0x{:08X}, 0x{:08X});\n", instr_vram, jtbl_vram);
}

void N64Recomp::CGenerator::emit_return(const Context& context, size_t func_index) const {
    (void)func_index;
    if (context.trace_mode) {
        fmt::print(output_file, "TRACE_RETURN()\n    ");
    }
    fmt::print(output_file, "return;\n");
}

void N64Recomp::CGenerator::emit_check_fr(int fpr) const {
    fmt::print(output_file, "CHECK_FR(ctx, {});\n    ", fpr);
}

void N64Recomp::CGenerator::emit_check_nan(int fpr, bool is_double) const {
    fmt::print(output_file, "NAN_CHECK(ctx->f{}.{}); ", fpr, is_double ? "d" : "fl");
}

void N64Recomp::CGenerator::emit_cop0_status_read(int reg) const {
    fmt::print(output_file, "{} = cop0_status_read(ctx);\n", gpr_to_string(reg));
}

void N64Recomp::CGenerator::emit_cop0_status_write(int reg) const {
    fmt::print(output_file, "cop0_status_write(ctx, {});", gpr_to_string(reg));
}

void N64Recomp::CGenerator::emit_cop1_cs_read(int reg) const {
    fmt::print(output_file, "{} = get_cop1_cs();\n", gpr_to_string(reg));
}

void N64Recomp::CGenerator::emit_cop1_cs_write(int reg) const {
    fmt::print(output_file, "set_cop1_cs({});\n", gpr_to_string(reg));
}

void N64Recomp::CGenerator::emit_muldiv(InstrId instr_id, int reg1, int reg2) const {
    switch (instr_id) {
        case InstrId::cpu_mult:
            fmt::print(output_file, "result = S64(S32({})) * S64(S32({})); lo = S32(result >> 0); hi = S32(result >> 32);\n", gpr_to_string(reg1), gpr_to_string(reg2));
            break;
        case InstrId::cpu_dmult:
            fmt::print(output_file, "DMULT(S64({}), S64({}), &lo, &hi);\n", gpr_to_string(reg1), gpr_to_string(reg2));
            break;
        case InstrId::cpu_multu:
            fmt::print(output_file, "result = U64(U32({})) * U64(U32({})); lo = S32(result >> 0); hi = S32(result >> 32);\n", gpr_to_string(reg1), gpr_to_string(reg2));
            break;
        case InstrId::cpu_dmultu:
            fmt::print(output_file, "DMULTU(U64({}), U64({}), &lo, &hi);\n", gpr_to_string(reg1), gpr_to_string(reg2));
            break;
        case InstrId::cpu_div:
            // Cast to 64-bits before division to prevent artihmetic exception for s32(0x80000000) / -1
            fmt::print(output_file, "lo = S32(S64(S32({0})) / S64(S32({1}))); hi = S32(S64(S32({0})) % S64(S32({1})));\n", gpr_to_string(reg1), gpr_to_string(reg2));
            break;
        case InstrId::cpu_ddiv:
            fmt::print(output_file, "DDIV(S64({}), S64({}), &lo, &hi);\n", gpr_to_string(reg1), gpr_to_string(reg2));
            break;
        case InstrId::cpu_divu:
            fmt::print(output_file, "lo = S32(U32({0}) / U32({1})); hi = S32(U32({0}) % U32({1}));\n", gpr_to_string(reg1), gpr_to_string(reg2));
            break;
        case InstrId::cpu_ddivu:
            fmt::print(output_file, "DDIVU(U64({}), U64({}), &lo, &hi);\n", gpr_to_string(reg1), gpr_to_string(reg2));
            break;
        default:
            assert(false);
            break;
    }
}

void N64Recomp::CGenerator::emit_syscall(uint32_t instr_vram) const {
    fmt::print(output_file, "recomp_syscall_handler(rdram, ctx, 0x{:08X});\n", instr_vram);
}

void N64Recomp::CGenerator::emit_do_break(uint32_t instr_vram) const {
    fmt::print(output_file, "do_break({});\n", instr_vram);
}

void N64Recomp::CGenerator::emit_pause_self() const {
    fmt::print(output_file, "pause_self(rdram);\n");
}

void N64Recomp::CGenerator::emit_trigger_event(uint32_t event_index) const {
    fmt::print(output_file, "recomp_trigger_event(rdram, ctx, base_event_index + {});\n", event_index);
}

void N64Recomp::CGenerator::emit_comment(const std::string& comment) const {
    fmt::print(output_file, "// {}\n", comment);
}

void N64Recomp::CGenerator::process_binary_op(const BinaryOp& op, const InstructionContext& ctx) const {
    // Thread local variables to prevent allocations when possible.
    // TODO these thread locals probably don't actually help right now, so figure out a better way to prevent allocations.
    thread_local std::string output{};
    thread_local std::string expression{};
    if (is_zero_gpr_operand(op.output, ctx)) {
        return;
    }
    get_operand_string(op.output, UnaryOpType::None, ctx, output);
    get_binary_expr_string(op.type, op.operands, ctx, output, expression);
    fmt::print(output_file, "{} = {};\n", output, expression);
}

void N64Recomp::CGenerator::process_unary_op(const UnaryOp& op, const InstructionContext& ctx) const {
    // Thread local variables to prevent allocations when possible.
    // TODO these thread locals probably don't actually help right now, so figure out a better way to prevent allocations.
    thread_local std::string output{};
    thread_local std::string input{};
    if (is_zero_gpr_operand(op.output, ctx)) {
        return;
    }
    get_operand_string(op.output, UnaryOpType::None, ctx, output);
    get_operand_string(op.input, op.operation, ctx, input);
    fmt::print(output_file, "{} = {};\n", output, input);
}

void N64Recomp::CGenerator::process_store_op(const StoreOp& op, const InstructionContext& ctx) const {
    // Thread local variables to prevent allocations when possible.
    // TODO these thread locals probably don't actually help right now, so figure out a better way to prevent allocations.
    thread_local std::string base_str{};
    thread_local std::string imm_str{};
    thread_local std::string value_input{};
    get_operand_string(Operand::Base, UnaryOpType::None, ctx, base_str);
    get_operand_string(Operand::ImmS16, UnaryOpType::None, ctx, imm_str);
    get_operand_string(op.value_input, UnaryOpType::None, ctx, value_input);

    // How the store is spelled: a plain function call, a call that also takes
    // rdram (the unaligned stores), or an assignment through an addressing macro.
    enum class StoreSyntax {
        Func,
        FuncWithRdram,
        Assignment,
    };

    StoreSyntax syntax;
    std::string func_text;

    switch (op.type) {
        case StoreOpType::SD:
            func_text = "SD";
            syntax = StoreSyntax::Func;
            break;
        case StoreOpType::SDL:
            func_text = "do_sdl";
            syntax = StoreSyntax::FuncWithRdram;
            break;
        case StoreOpType::SDR:
            func_text = "do_sdr";
            syntax = StoreSyntax::FuncWithRdram;
            break;
        case StoreOpType::SW:
            func_text = "MEM_W";
            syntax = StoreSyntax::Assignment;
            break;
        case StoreOpType::SWL:
            func_text = "do_swl";
            syntax = StoreSyntax::FuncWithRdram;
            break;
        case StoreOpType::SWR:
            func_text = "do_swr";
            syntax = StoreSyntax::FuncWithRdram;
            break;
        case StoreOpType::SH:
            func_text = "MEM_H";
            syntax = StoreSyntax::Assignment;
            break;
        case StoreOpType::SB:
            func_text = "MEM_B";
            syntax = StoreSyntax::Assignment;
            break;
        case StoreOpType::SDC1:
            func_text = "SD";
            syntax = StoreSyntax::Func;
            break;
        case StoreOpType::SWC1:
            func_text = "MEM_W";
            syntax = StoreSyntax::Assignment;
            break;
        default:
            throw std::runtime_error("Unhandled store op");
    }

    switch (syntax) {
        case StoreSyntax::Func:
            fmt::print(output_file, "{}({}, {}, {});\n", func_text, value_input, imm_str, base_str);
            break;
        case StoreSyntax::FuncWithRdram:
            fmt::print(output_file, "{}(rdram, {}, {}, {});\n", func_text, imm_str, base_str, value_input);
            break;
        case StoreSyntax::Assignment:
            fmt::print(output_file, "{}({}, {}) = {};\n", func_text, imm_str, base_str, value_input);
            break;
    }
}
