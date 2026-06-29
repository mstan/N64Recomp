#include "recompiler/operations.h"

// Decode tables: map each MIPS instruction id the recompiler handles to the
// plain-data operation record the code generator emits from. The records are
// dictated by the instruction set, so the contents here track the MIPS ISA
// rather than any particular implementation. Entries are grouped by shape
// (unary / binary / conditional branch / store) and, within binary, by family.

namespace N64Recomp {
namespace {
    // Assemble a BinaryOperands record. Each of the two source operands may
    // carry a pre-op that is applied to it before the binary operation runs
    // (e.g. sign/zero extension, or masking a shift amount). Defaulting both
    // pre-ops to None keeps the common "use the operands as-is" case terse.
    constexpr BinaryOperands ops(Operand lhs, Operand rhs,
                                 UnaryOpType lhs_pre = UnaryOpType::None,
                                 UnaryOpType rhs_pre = UnaryOpType::None) {
        return BinaryOperands{ { lhs_pre, rhs_pre }, { lhs, rhs } };
    }
}

    const std::unordered_map<InstrId, UnaryOp> unary_ops {
        // hi/lo and GPR<->FPR moves.
        { InstrId::cpu_lui,   { UnaryOpType::Lui,     Operand::Rt,     Operand::ImmU16 } },
        { InstrId::cpu_mthi,  { UnaryOpType::None,    Operand::Hi,     Operand::Rs } },
        { InstrId::cpu_mtlo,  { UnaryOpType::None,    Operand::Lo,     Operand::Rs } },
        { InstrId::cpu_mfhi,  { UnaryOpType::None,    Operand::Rd,     Operand::Hi } },
        { InstrId::cpu_mflo,  { UnaryOpType::None,    Operand::Rd,     Operand::Lo } },
        { InstrId::cpu_mtc1,  { UnaryOpType::None,    Operand::FsU32L, Operand::Rt } },
        { InstrId::cpu_mfc1,  { UnaryOpType::ToInt32, Operand::Rt,     Operand::FsU32L } },
        { InstrId::cpu_dmtc1, { UnaryOpType::None,    Operand::FsU64,  Operand::Rt } },
        { InstrId::cpu_dmfc1, { UnaryOpType::None,    Operand::Rt,     Operand::FsU64 } },
        // Single/double moves and sign/abs/sqrt. mov checks FR; the rest also
        // check the operand for NaN.
        { InstrId::cpu_mov_s,  { UnaryOpType::None,         Operand::Fd,       Operand::Fs,       true } },
        { InstrId::cpu_mov_d,  { UnaryOpType::None,         Operand::FdDouble, Operand::FsDouble, true } },
        { InstrId::cpu_neg_s,  { UnaryOpType::NegateFloat,  Operand::Fd,       Operand::Fs,       true, true } },
        { InstrId::cpu_neg_d,  { UnaryOpType::NegateDouble, Operand::FdDouble, Operand::FsDouble, true, true } },
        { InstrId::cpu_abs_s,  { UnaryOpType::AbsFloat,     Operand::Fd,       Operand::Fs,       true, true } },
        { InstrId::cpu_abs_d,  { UnaryOpType::AbsDouble,    Operand::FdDouble, Operand::FsDouble, true, true } },
        { InstrId::cpu_sqrt_s, { UnaryOpType::SqrtFloat,    Operand::Fd,       Operand::Fs,       true, true } },
        { InstrId::cpu_sqrt_d, { UnaryOpType::SqrtDouble,   Operand::FdDouble, Operand::FsDouble, true, true } },
        // Format conversions: cvt.<dst>.<src>.
        { InstrId::cpu_cvt_s_w, { UnaryOpType::ConvertSFromW, Operand::Fd,       Operand::FsU32L,   true } },
        { InstrId::cpu_cvt_w_s, { UnaryOpType::ConvertWFromS, Operand::FdU32L,   Operand::Fs,       true } },
        { InstrId::cpu_cvt_d_w, { UnaryOpType::ConvertDFromW, Operand::FdDouble, Operand::FsU32L,   true } },
        { InstrId::cpu_cvt_w_d, { UnaryOpType::ConvertWFromD, Operand::FdU32L,   Operand::FsDouble, true } },
        { InstrId::cpu_cvt_d_s, { UnaryOpType::ConvertDFromS, Operand::FdDouble, Operand::Fs,       true, true } },
        { InstrId::cpu_cvt_s_d, { UnaryOpType::ConvertSFromD, Operand::Fd,       Operand::FsDouble, true, true } },
        { InstrId::cpu_cvt_d_l, { UnaryOpType::ConvertDFromL, Operand::FdDouble, Operand::FsU64,    true } },
        { InstrId::cpu_cvt_l_d, { UnaryOpType::ConvertLFromD, Operand::FdU64,    Operand::FsDouble, true, true } },
        { InstrId::cpu_cvt_s_l, { UnaryOpType::ConvertSFromL, Operand::Fd,       Operand::FsU64,    true } },
        { InstrId::cpu_cvt_l_s, { UnaryOpType::ConvertLFromS, Operand::FdU64,    Operand::Fs,       true, true } },
        // Float->int with explicit rounding mode (trunc/round/ceil/floor).
        { InstrId::cpu_trunc_w_s, { UnaryOpType::TruncateWFromS, Operand::FdU32L, Operand::Fs,       true } },
        { InstrId::cpu_trunc_w_d, { UnaryOpType::TruncateWFromD, Operand::FdU32L, Operand::FsDouble, true } },
        { InstrId::cpu_round_w_s, { UnaryOpType::RoundWFromS,    Operand::FdU32L, Operand::Fs,       true } },
        { InstrId::cpu_round_w_d, { UnaryOpType::RoundWFromD,    Operand::FdU32L, Operand::FsDouble, true } },
        { InstrId::cpu_ceil_w_s,  { UnaryOpType::CeilWFromS,     Operand::FdU32L, Operand::Fs,       true } },
        { InstrId::cpu_ceil_w_d,  { UnaryOpType::CeilWFromD,     Operand::FdU32L, Operand::FsDouble, true } },
        { InstrId::cpu_floor_w_s, { UnaryOpType::FloorWFromS,    Operand::FdU32L, Operand::Fs,       true } },
        { InstrId::cpu_floor_w_d, { UnaryOpType::FloorWFromD,    Operand::FdU32L, Operand::FsDouble, true } },
    };

    // TODO fix usage of check_nan
    const std::unordered_map<InstrId, BinaryOp> binary_ops {
        // Integer add/subtract (register). negu is the assembler's subu pseudo-op.
        { InstrId::cpu_addu,  { BinaryOpType::Add32, Operand::Rd, ops(Operand::Rs, Operand::Rt) } },
        { InstrId::cpu_add,   { BinaryOpType::Add32, Operand::Rd, ops(Operand::Rs, Operand::Rt) } },
        { InstrId::cpu_negu,  { BinaryOpType::Sub32, Operand::Rd, ops(Operand::Rs, Operand::Rt) } },
        { InstrId::cpu_subu,  { BinaryOpType::Sub32, Operand::Rd, ops(Operand::Rs, Operand::Rt) } },
        { InstrId::cpu_sub,   { BinaryOpType::Sub32, Operand::Rd, ops(Operand::Rs, Operand::Rt) } },
        { InstrId::cpu_daddu, { BinaryOpType::Add64, Operand::Rd, ops(Operand::Rs, Operand::Rt) } },
        { InstrId::cpu_dadd,  { BinaryOpType::Add64, Operand::Rd, ops(Operand::Rs, Operand::Rt) } },
        { InstrId::cpu_dsubu, { BinaryOpType::Sub64, Operand::Rd, ops(Operand::Rs, Operand::Rt) } },
        { InstrId::cpu_dsub,  { BinaryOpType::Sub64, Operand::Rd, ops(Operand::Rs, Operand::Rt) } },
        // Integer add (immediate).
        { InstrId::cpu_addi,   { BinaryOpType::Add32, Operand::Rt, ops(Operand::Rs, Operand::ImmS16) } },
        { InstrId::cpu_addiu,  { BinaryOpType::Add32, Operand::Rt, ops(Operand::Rs, Operand::ImmS16) } },
        { InstrId::cpu_daddi,  { BinaryOpType::Add64, Operand::Rt, ops(Operand::Rs, Operand::ImmS16) } },
        { InstrId::cpu_daddiu, { BinaryOpType::Add64, Operand::Rt, ops(Operand::Rs, Operand::ImmS16) } },
        // Bitwise (register).
        { InstrId::cpu_and, { BinaryOpType::And64, Operand::Rd, ops(Operand::Rs, Operand::Rt) } },
        { InstrId::cpu_or,  { BinaryOpType::Or64,  Operand::Rd, ops(Operand::Rs, Operand::Rt) } },
        { InstrId::cpu_nor, { BinaryOpType::Nor64, Operand::Rd, ops(Operand::Rs, Operand::Rt) } },
        { InstrId::cpu_xor, { BinaryOpType::Xor64, Operand::Rd, ops(Operand::Rs, Operand::Rt) } },
        // Bitwise (immediate, zero-extended).
        { InstrId::cpu_andi, { BinaryOpType::And64, Operand::Rt, ops(Operand::Rs, Operand::ImmU16) } },
        { InstrId::cpu_ori,  { BinaryOpType::Or64,  Operand::Rt, ops(Operand::Rs, Operand::ImmU16) } },
        { InstrId::cpu_xori, { BinaryOpType::Xor64, Operand::Rt, ops(Operand::Rs, Operand::ImmU16) } },
        // Variable shifts: shift amount comes from Rs, masked to 5 (32-bit) or
        // 6 (64-bit) bits. Right shifts pre-coerce the value being shifted.
        { InstrId::cpu_sllv,  { BinaryOpType::Sll32, Operand::Rd, ops(Operand::Rt, Operand::Rs, UnaryOpType::None,  UnaryOpType::Mask5) } },
        { InstrId::cpu_dsllv, { BinaryOpType::Sll64, Operand::Rd, ops(Operand::Rt, Operand::Rs, UnaryOpType::None,  UnaryOpType::Mask6) } },
        { InstrId::cpu_srlv,  { BinaryOpType::Srl32, Operand::Rd, ops(Operand::Rt, Operand::Rs, UnaryOpType::ToU32, UnaryOpType::Mask5) } },
        { InstrId::cpu_dsrlv, { BinaryOpType::Srl64, Operand::Rd, ops(Operand::Rt, Operand::Rs, UnaryOpType::ToU64, UnaryOpType::Mask6) } },
        // Hardware quirk: the 32-bit arithmetic right shift does not mask the
        // value to 32 bits first, so upper-half bits bleed into the low half;
        // ToS64 reproduces that.
        { InstrId::cpu_srav,  { BinaryOpType::Sra32, Operand::Rd, ops(Operand::Rt, Operand::Rs, UnaryOpType::ToS64, UnaryOpType::Mask5) } },
        { InstrId::cpu_dsrav, { BinaryOpType::Sra64, Operand::Rd, ops(Operand::Rt, Operand::Rs, UnaryOpType::ToS64, UnaryOpType::Mask6) } },
        // Immediate shifts. The *32 variants add 32 to the shift amount.
        { InstrId::cpu_sll,    { BinaryOpType::Sll32, Operand::Rd, ops(Operand::Rt, Operand::Sa,   UnaryOpType::None,  UnaryOpType::None) } },
        { InstrId::cpu_dsll,   { BinaryOpType::Sll64, Operand::Rd, ops(Operand::Rt, Operand::Sa,   UnaryOpType::None,  UnaryOpType::None) } },
        { InstrId::cpu_dsll32, { BinaryOpType::Sll64, Operand::Rd, ops(Operand::Rt, Operand::Sa32, UnaryOpType::None,  UnaryOpType::None) } },
        { InstrId::cpu_srl,    { BinaryOpType::Srl32, Operand::Rd, ops(Operand::Rt, Operand::Sa,   UnaryOpType::ToU32, UnaryOpType::None) } },
        { InstrId::cpu_dsrl,   { BinaryOpType::Srl64, Operand::Rd, ops(Operand::Rt, Operand::Sa,   UnaryOpType::ToU64, UnaryOpType::None) } },
        { InstrId::cpu_dsrl32, { BinaryOpType::Srl64, Operand::Rd, ops(Operand::Rt, Operand::Sa32, UnaryOpType::ToU64, UnaryOpType::None) } },
        // Same hardware quirk as srav applies to the immediate arithmetic shift.
        { InstrId::cpu_sra,    { BinaryOpType::Sra32, Operand::Rd, ops(Operand::Rt, Operand::Sa,   UnaryOpType::ToS64, UnaryOpType::None) } },
        { InstrId::cpu_dsra,   { BinaryOpType::Sra64, Operand::Rd, ops(Operand::Rt, Operand::Sa,   UnaryOpType::ToS64, UnaryOpType::None) } },
        { InstrId::cpu_dsra32, { BinaryOpType::Sra64, Operand::Rd, ops(Operand::Rt, Operand::Sa32, UnaryOpType::ToS64, UnaryOpType::None) } },
        // Set-less-than: signed (slt/slti) coerces to S64, unsigned to U64.
        { InstrId::cpu_slt,   { BinaryOpType::Less, Operand::Rd, ops(Operand::Rs, Operand::Rt,     UnaryOpType::ToS64, UnaryOpType::ToS64) } },
        { InstrId::cpu_sltu,  { BinaryOpType::Less, Operand::Rd, ops(Operand::Rs, Operand::Rt,     UnaryOpType::ToU64, UnaryOpType::ToU64) } },
        { InstrId::cpu_slti,  { BinaryOpType::Less, Operand::Rt, ops(Operand::Rs, Operand::ImmS16, UnaryOpType::ToS64, UnaryOpType::None) } },
        { InstrId::cpu_sltiu, { BinaryOpType::Less, Operand::Rt, ops(Operand::Rs, Operand::ImmS16, UnaryOpType::ToU64, UnaryOpType::None) } },
        // Floating-point arithmetic (check FR and NaN).
        { InstrId::cpu_add_s, { BinaryOpType::AddFloat,  Operand::Fd,       ops(Operand::Fs, Operand::Ft),             true, true } },
        { InstrId::cpu_add_d, { BinaryOpType::AddDouble, Operand::FdDouble, ops(Operand::FsDouble, Operand::FtDouble), true, true } },
        { InstrId::cpu_sub_s, { BinaryOpType::SubFloat,  Operand::Fd,       ops(Operand::Fs, Operand::Ft),             true, true } },
        { InstrId::cpu_sub_d, { BinaryOpType::SubDouble, Operand::FdDouble, ops(Operand::FsDouble, Operand::FtDouble), true, true } },
        { InstrId::cpu_mul_s, { BinaryOpType::MulFloat,  Operand::Fd,       ops(Operand::Fs, Operand::Ft),             true, true } },
        { InstrId::cpu_mul_d, { BinaryOpType::MulDouble, Operand::FdDouble, ops(Operand::FsDouble, Operand::FtDouble), true, true } },
        { InstrId::cpu_div_s, { BinaryOpType::DivFloat,  Operand::Fd,       ops(Operand::Fs, Operand::Ft),             true, true } },
        { InstrId::cpu_div_d, { BinaryOpType::DivDouble, Operand::FdDouble, ops(Operand::FsDouble, Operand::FtDouble), true, true } },
        // Float compares set the cop1 condition signal. TODO investigate
        // ordered/unordered and default values.
        //  Single, ordered.
        { InstrId::cpu_c_f_s,   { BinaryOpType::False,       Operand::Cop1cs, ops(Operand::Fs, Operand::Ft), true } },
        { InstrId::cpu_c_eq_s,  { BinaryOpType::EqualFloat,  Operand::Cop1cs, ops(Operand::Fs, Operand::Ft), true } },
        { InstrId::cpu_c_olt_s, { BinaryOpType::LessFloat,   Operand::Cop1cs, ops(Operand::Fs, Operand::Ft), true } },
        { InstrId::cpu_c_ole_s, { BinaryOpType::LessEqFloat, Operand::Cop1cs, ops(Operand::Fs, Operand::Ft), true } },
        { InstrId::cpu_c_sf_s,  { BinaryOpType::False,       Operand::Cop1cs, ops(Operand::Fs, Operand::Ft), true } },
        { InstrId::cpu_c_seq_s, { BinaryOpType::EqualFloat,  Operand::Cop1cs, ops(Operand::Fs, Operand::Ft), true } },
        { InstrId::cpu_c_lt_s,  { BinaryOpType::LessFloat,   Operand::Cop1cs, ops(Operand::Fs, Operand::Ft), true } },
        { InstrId::cpu_c_le_s,  { BinaryOpType::LessEqFloat, Operand::Cop1cs, ops(Operand::Fs, Operand::Ft), true } },
        //  Single, unordered.
        { InstrId::cpu_c_un_s,   { BinaryOpType::False,       Operand::Cop1cs, ops(Operand::Fs, Operand::Ft), true } },
        { InstrId::cpu_c_ueq_s,  { BinaryOpType::EqualFloat,  Operand::Cop1cs, ops(Operand::Fs, Operand::Ft), true } },
        { InstrId::cpu_c_ult_s,  { BinaryOpType::LessFloat,   Operand::Cop1cs, ops(Operand::Fs, Operand::Ft), true } },
        { InstrId::cpu_c_ule_s,  { BinaryOpType::LessEqFloat, Operand::Cop1cs, ops(Operand::Fs, Operand::Ft), true } },
        { InstrId::cpu_c_ngle_s, { BinaryOpType::False,       Operand::Cop1cs, ops(Operand::Fs, Operand::Ft), true } },
        { InstrId::cpu_c_ngl_s,  { BinaryOpType::EqualFloat,  Operand::Cop1cs, ops(Operand::Fs, Operand::Ft), true } },
        { InstrId::cpu_c_nge_s,  { BinaryOpType::LessFloat,   Operand::Cop1cs, ops(Operand::Fs, Operand::Ft), true } },
        { InstrId::cpu_c_ngt_s,  { BinaryOpType::LessEqFloat, Operand::Cop1cs, ops(Operand::Fs, Operand::Ft), true } },
        //  Double, ordered.
        { InstrId::cpu_c_f_d,   { BinaryOpType::False,        Operand::Cop1cs, ops(Operand::FsDouble, Operand::FtDouble), true } },
        { InstrId::cpu_c_eq_d,  { BinaryOpType::EqualDouble,  Operand::Cop1cs, ops(Operand::FsDouble, Operand::FtDouble), true } },
        { InstrId::cpu_c_olt_d, { BinaryOpType::LessDouble,   Operand::Cop1cs, ops(Operand::FsDouble, Operand::FtDouble), true } },
        { InstrId::cpu_c_ole_d, { BinaryOpType::LessEqDouble, Operand::Cop1cs, ops(Operand::FsDouble, Operand::FtDouble), true } },
        /* TODO rename to c_sf_d when fixed in rabbitizer */
        { InstrId::cpu_c_df_d,  { BinaryOpType::False,        Operand::Cop1cs, ops(Operand::FsDouble, Operand::FtDouble), true } },
        /* TODO rename to c_seq_d when fixed in rabbitizer */
        { InstrId::cpu_c_deq_d, { BinaryOpType::EqualDouble,  Operand::Cop1cs, ops(Operand::FsDouble, Operand::FtDouble), true } },
        { InstrId::cpu_c_lt_d,  { BinaryOpType::LessDouble,   Operand::Cop1cs, ops(Operand::FsDouble, Operand::FtDouble), true } },
        { InstrId::cpu_c_le_d,  { BinaryOpType::LessEqDouble, Operand::Cop1cs, ops(Operand::FsDouble, Operand::FtDouble), true } },
        //  Double, unordered.
        { InstrId::cpu_c_un_d,   { BinaryOpType::False,        Operand::Cop1cs, ops(Operand::FsDouble, Operand::FtDouble), true } },
        { InstrId::cpu_c_ueq_d,  { BinaryOpType::EqualDouble,  Operand::Cop1cs, ops(Operand::FsDouble, Operand::FtDouble), true } },
        { InstrId::cpu_c_ult_d,  { BinaryOpType::LessDouble,   Operand::Cop1cs, ops(Operand::FsDouble, Operand::FtDouble), true } },
        { InstrId::cpu_c_ule_d,  { BinaryOpType::LessEqDouble, Operand::Cop1cs, ops(Operand::FsDouble, Operand::FtDouble), true } },
        { InstrId::cpu_c_ngle_d, { BinaryOpType::False,        Operand::Cop1cs, ops(Operand::FsDouble, Operand::FtDouble), true } },
        { InstrId::cpu_c_ngl_d,  { BinaryOpType::EqualDouble,  Operand::Cop1cs, ops(Operand::FsDouble, Operand::FtDouble), true } },
        { InstrId::cpu_c_nge_d,  { BinaryOpType::LessDouble,   Operand::Cop1cs, ops(Operand::FsDouble, Operand::FtDouble), true } },
        { InstrId::cpu_c_ngt_d,  { BinaryOpType::LessEqDouble, Operand::Cop1cs, ops(Operand::FsDouble, Operand::FtDouble), true } },
        // Loads: result = mem[base + signed imm]. lwc1/ldc1 land in FPRs; ldc1
        // additionally checks FR.
        { InstrId::cpu_ld,   { BinaryOpType::LD,  Operand::Rt,     ops(Operand::Base, Operand::ImmS16) } },
        { InstrId::cpu_lw,   { BinaryOpType::LW,  Operand::Rt,     ops(Operand::Base, Operand::ImmS16) } },
        { InstrId::cpu_lwu,  { BinaryOpType::LWU, Operand::Rt,     ops(Operand::Base, Operand::ImmS16) } },
        { InstrId::cpu_lh,   { BinaryOpType::LH,  Operand::Rt,     ops(Operand::Base, Operand::ImmS16) } },
        { InstrId::cpu_lhu,  { BinaryOpType::LHU, Operand::Rt,     ops(Operand::Base, Operand::ImmS16) } },
        { InstrId::cpu_lb,   { BinaryOpType::LB,  Operand::Rt,     ops(Operand::Base, Operand::ImmS16) } },
        { InstrId::cpu_lbu,  { BinaryOpType::LBU, Operand::Rt,     ops(Operand::Base, Operand::ImmS16) } },
        { InstrId::cpu_ldl,  { BinaryOpType::LDL, Operand::Rt,     ops(Operand::Base, Operand::ImmS16) } },
        { InstrId::cpu_ldr,  { BinaryOpType::LDR, Operand::Rt,     ops(Operand::Base, Operand::ImmS16) } },
        { InstrId::cpu_lwl,  { BinaryOpType::LWL, Operand::Rt,     ops(Operand::Base, Operand::ImmS16) } },
        { InstrId::cpu_lwr,  { BinaryOpType::LWR, Operand::Rt,     ops(Operand::Base, Operand::ImmS16) } },
        { InstrId::cpu_lwc1, { BinaryOpType::LW,  Operand::FtU32L, ops(Operand::Base, Operand::ImmS16) } },
        { InstrId::cpu_ldc1, { BinaryOpType::LD,  Operand::FtU64,  ops(Operand::Base, Operand::ImmS16), true } },
    };

    const std::unordered_map<InstrId, ConditionalBranchOp> conditional_branch_ops {
        // Two-register equality branches; the *l variants are "likely".
        { InstrId::cpu_beq,  { BinaryOpType::Equal,    ops(Operand::Rs, Operand::Rt), false, false } },
        { InstrId::cpu_beql, { BinaryOpType::Equal,    ops(Operand::Rs, Operand::Rt), false, true } },
        { InstrId::cpu_bne,  { BinaryOpType::NotEqual, ops(Operand::Rs, Operand::Rt), false, false } },
        { InstrId::cpu_bnel, { BinaryOpType::NotEqual, ops(Operand::Rs, Operand::Rt), false, true } },
        // Compare-against-zero branches (sign-extend the register first).
        { InstrId::cpu_bgez,  { BinaryOpType::GreaterEq, ops(Operand::Rs, Operand::Zero, UnaryOpType::ToS64), false, false } },
        { InstrId::cpu_bgezl, { BinaryOpType::GreaterEq, ops(Operand::Rs, Operand::Zero, UnaryOpType::ToS64), false, true } },
        { InstrId::cpu_bgtz,  { BinaryOpType::Greater,   ops(Operand::Rs, Operand::Zero, UnaryOpType::ToS64), false, false } },
        { InstrId::cpu_bgtzl, { BinaryOpType::Greater,   ops(Operand::Rs, Operand::Zero, UnaryOpType::ToS64), false, true } },
        { InstrId::cpu_blez,  { BinaryOpType::LessEq,    ops(Operand::Rs, Operand::Zero, UnaryOpType::ToS64), false, false } },
        { InstrId::cpu_blezl, { BinaryOpType::LessEq,    ops(Operand::Rs, Operand::Zero, UnaryOpType::ToS64), false, true } },
        { InstrId::cpu_bltz,  { BinaryOpType::Less,      ops(Operand::Rs, Operand::Zero, UnaryOpType::ToS64), false, false } },
        { InstrId::cpu_bltzl, { BinaryOpType::Less,      ops(Operand::Rs, Operand::Zero, UnaryOpType::ToS64), false, true } },
        // Linking compare-against-zero branches (bgezal/bltzal and *l).
        { InstrId::cpu_bgezal,  { BinaryOpType::GreaterEq, ops(Operand::Rs, Operand::Zero, UnaryOpType::ToS64), true, false } },
        { InstrId::cpu_bgezall, { BinaryOpType::GreaterEq, ops(Operand::Rs, Operand::Zero, UnaryOpType::ToS64), true, true } },
        { InstrId::cpu_bltzal,  { BinaryOpType::Less,      ops(Operand::Rs, Operand::Zero, UnaryOpType::ToS64), true, false } },
        { InstrId::cpu_bltzall, { BinaryOpType::Less,      ops(Operand::Rs, Operand::Zero, UnaryOpType::ToS64), true, true } },
        // Branch on cop1 condition signal. bc1f tests "equal to zero" (false),
        // bc1t tests "not equal to zero" (true).
        { InstrId::cpu_bc1f,  { BinaryOpType::Equal,    ops(Operand::Cop1cs, Operand::Zero), false, false } },
        { InstrId::cpu_bc1fl, { BinaryOpType::Equal,    ops(Operand::Cop1cs, Operand::Zero), false, true } },
        { InstrId::cpu_bc1t,  { BinaryOpType::NotEqual, ops(Operand::Cop1cs, Operand::Zero), false, false } },
        { InstrId::cpu_bc1tl, { BinaryOpType::NotEqual, ops(Operand::Cop1cs, Operand::Zero), false, true } },
    };

    const std::unordered_map<InstrId, StoreOp> store_ops {
        { InstrId::cpu_sd,   { StoreOpType::SD,   Operand::Rt } },
        { InstrId::cpu_sdl,  { StoreOpType::SDL,  Operand::Rt } },
        { InstrId::cpu_sdr,  { StoreOpType::SDR,  Operand::Rt } },
        { InstrId::cpu_sw,   { StoreOpType::SW,   Operand::Rt } },
        { InstrId::cpu_swl,  { StoreOpType::SWL,  Operand::Rt } },
        { InstrId::cpu_swr,  { StoreOpType::SWR,  Operand::Rt } },
        { InstrId::cpu_sh,   { StoreOpType::SH,   Operand::Rt } },
        { InstrId::cpu_sb,   { StoreOpType::SB,   Operand::Rt } },
        { InstrId::cpu_sdc1, { StoreOpType::SDC1, Operand::FtU64 } },
        { InstrId::cpu_swc1, { StoreOpType::SWC1, Operand::FtU32L } },
    };
}
