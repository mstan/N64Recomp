#ifndef N64RECOMP_OPERATIONS_H
#define N64RECOMP_OPERATIONS_H

#include <unordered_map>

#include "rabbitizer.hpp"

// Intermediate representation for the MIPS instructions the recompiler knows
// how to translate. Each decoded instruction is classified into one of four
// shapes -- unary, binary, conditional branch, or store -- and described by a
// small plain-data record. The code generator consumes those records; it never
// looks at the raw instruction again. The lookup tables that map a decoded
// instruction id to its record live in operations.cpp.

namespace N64Recomp {
    using InstrId = rabbitizer::InstrId::UniqueId;
    using Cop0Reg = rabbitizer::Registers::Cpu::Cop0;

    // Width/variant of a store instruction. Names mirror the MIPS mnemonics
    // (store doubleword / word / halfword / byte, the unaligned LWL-style
    // variants, and the two coprocessor-1 stores).
    enum class StoreOpType {
        SD,
        SDL,
        SDR,
        SW,
        SWL,
        SWR,
        SH,
        SB,
        SDC1,
        SWC1
    };

    // A transform applied to a single value. Covers the integer width/sign
    // coercions, the immediate-shift helper (Lui), the shift-amount masks, and
    // the full set of coprocessor-1 sign/abs/sqrt and convert/round/trunc/
    // ceil/floor operations.
    enum class UnaryOpType {
        None,
        ToS32,
        ToU32,
        ToS64,
        ToU64,
        Lui,
        Mask5,   // Mask the value to its low 5 bits (32-bit shift amount).
        Mask6,   // Mask the value to its low 6 bits (64-bit shift amount).
        ToInt32, // Equivalent to ToS32; kept distinct only to match legacy codegen output.
        NegateFloat,
        NegateDouble,
        AbsFloat,
        AbsDouble,
        SqrtFloat,
        SqrtDouble,
        ConvertSFromW,
        ConvertWFromS,
        ConvertDFromW,
        ConvertWFromD,
        ConvertDFromS,
        ConvertSFromD,
        ConvertDFromL,
        ConvertLFromD,
        ConvertSFromL,
        ConvertLFromS,
        TruncateWFromS,
        TruncateWFromD,
        TruncateLFromS,
        TruncateLFromD,
        RoundWFromS,
        RoundWFromD,
        RoundLFromS,
        RoundLFromD,
        CeilWFromS,
        CeilWFromD,
        CeilLFromS,
        CeilLFromD,
        FloorWFromS,
        FloorWFromD,
        FloorLFromS,
        FloorLFromD
    };

    // A two-input operation. Besides the obvious arithmetic/logic/compare cases
    // this also encodes loads (the address is computed as base + immediate) and
    // the two constant results True/False used by the float compare encodings.
    enum class BinaryOpType {
        // Integer add/subtract, 32- and 64-bit.
        Add32,
        Sub32,
        Add64,
        Sub64,
        // Floating-point arithmetic.
        AddFloat,
        AddDouble,
        SubFloat,
        SubDouble,
        MulFloat,
        MulDouble,
        DivFloat,
        DivDouble,
        // Bitwise and shifts.
        And64,
        Or64,
        Nor64,
        Xor64,
        Sll32,
        Sll64,
        Srl32,
        Srl64,
        Sra32,
        Sra64,
        // Integer and floating-point comparisons.
        Equal,
        NotEqual,
        Less,
        LessEq,
        Greater,
        GreaterEq,
        EqualFloat,
        LessFloat,
        LessEqFloat,
        EqualDouble,
        LessDouble,
        LessEqDouble,
        // Loads (result = mem[base + imm]).
        LD,
        LW,
        LWU,
        LH,
        LHU,
        LB,
        LBU,
        LDL,
        LDR,
        LWL,
        LWR,
        // Constant results.
        True,
        False,

        COUNT,
    };

    // Where an operand comes from. GPRs (Rd/Rs/Rt), FPRs in their various
    // interpretations (single, double, and the raw 32-/64-bit views that the
    // mips3 float mode behavior cares about), the two immediate widths, shift
    // amounts, the cop1 condition signal, hi/lo, and the hardwired zero.
    enum class Operand {
        Rd, // GPR
        Rs, // GPR
        Rt, // GPR
        Fd, // FPR
        Fs, // FPR
        Ft, // FPR
        FdDouble, // Double float in fd FPR
        FsDouble, // Double float in fs FPR
        FtDouble, // Double float in ft FPR
        // Raw low 32-bit values of FPRs with handling for mips3 float mode behavior
        FdU32L,
        FsU32L,
        FtU32L,
        // Raw high 32-bit values of FPRs with handling for mips3 float mode behavior
        FdU32H,
        FsU32H,
        FtU32H,
        // Raw 64-bit values of FPRs
        FdU64,
        FsU64,
        FtU64,
        ImmU16, // 16-bit immediate, unsigned
        ImmS16, // 16-bit immediate, signed
        Sa, // Shift amount
        Sa32, // Shift amount plus 32
        Cop1cs, // Coprocessor 1 Condition Signal
        Hi,
        Lo,
        Zero,

        Base = Rs, // Alias for Rs for loads
    };

    struct StoreOp {
        StoreOpType type;
        Operand value_input;
    };

    struct UnaryOp {
        UnaryOpType operation;
        Operand output;
        Operand input;
        // Whether the FR bit needs to be checked for odd float registers for this instruction.
        bool check_fr = false;
        // Whether the input need to be checked for being NaN.
        bool check_nan = false;
    };

    struct BinaryOperands {
        // Operation to apply to each operand before applying the binary operation to them.
        UnaryOpType operand_operations[2];
        // The source of the input operands.
        Operand operands[2];
    };

    struct BinaryOp {
        // The type of binary operation this represents.
        BinaryOpType type;
        // The output operand.
        Operand output;
        // The input operands.
        BinaryOperands operands;
        // Whether the FR bit needs to be checked for odd float registers for this instruction.
        bool check_fr = false;
        // Whether the inputs need to be checked for being NaN.
        bool check_nan = false;
    };

    struct ConditionalBranchOp {
        // The type of binary operation to use for this compare
        BinaryOpType comparison;
        // The input operands.
        BinaryOperands operands;
        // Whether this jump should link for returns.
        bool link;
        // Whether this jump has "likely" behavior (doesn't execute the delay slot if skipped).
        bool likely;
    };

    extern const std::unordered_map<InstrId, UnaryOp> unary_ops;
    extern const std::unordered_map<InstrId, BinaryOp> binary_ops;
    extern const std::unordered_map<InstrId, ConditionalBranchOp> conditional_branch_ops;
    extern const std::unordered_map<InstrId, StoreOp> store_ops;
}

#endif
