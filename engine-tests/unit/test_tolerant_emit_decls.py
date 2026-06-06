"""
Tier-1: tolerant-emit declarations and emit-site presence.

The tolerant-emit machinery (commits 512191b / ba044e3) is the engine's
ONLY acceptable fallback for instructions/branches the recompiler can't
translate at compile time. It must:

  (a) declare loud-abort runtime hooks in include/recomp.h
  (b) emit calls to those hooks from src/recompilation.cpp
  (c) keep (a) and (b) in lockstep — stale decls or unbacked emit
      sites are both bugs

All six hooks are load-bearing. There is no "store the bits in flat
storage and trust the game won't notice" fallback for any unmodeled
behavior, including unmodeled COP0 registers — that would be a stub.
"""
from __future__ import annotations

import pathlib
import re

REPO = pathlib.Path(__file__).resolve().parents[2]
HEADER = REPO / 'include' / 'recomp.h'
RECOMP_CPP = REPO / 'src' / 'recompilation.cpp'

# Hooks that MUST be both declared in the header AND actively emitted
# from recompilation.cpp.
ACTIVE_HOOKS = [
    'recomp_unhandled_branch',
    'recomp_unhandled_call',
    'recomp_unhandled_jalr',
    'recomp_unhandled_cop0_read',
    'recomp_unhandled_cop0_write',
    'recomp_unhandled_instruction',
]


def test_header_declares_all_active_hooks():
    header = HEADER.read_text(encoding='utf-8')
    missing = [h for h in ACTIVE_HOOKS if h not in header]
    assert not missing, f'include/recomp.h missing tolerant-emit decls: {missing}'


def test_recompilation_emits_all_active_hooks():
    src = RECOMP_CPP.read_text(encoding='utf-8')
    missing = [h for h in ACTIVE_HOOKS if h not in src]
    assert not missing, (
        f'src/recompilation.cpp does not emit calls to: {missing}. '
        'Tolerant-emit was either removed or replaced with a silent '
        'storage path; the engine would be dropping untranslatable '
        'instructions without a runtime abort.'
    )


def test_no_unknown_recomp_unhandled_emit_sites():
    """
    Inverse direction: every recomp_unhandled_* identifier emitted by
    recompilation.cpp must be declared in recomp.h. Catches typos and
    drift where a new emit site lands without the matching decl.
    """
    src = RECOMP_CPP.read_text(encoding='utf-8')
    header = HEADER.read_text(encoding='utf-8')

    emitted = set(re.findall(r'recomp_unhandled_[a-z0-9_]+', src))
    undeclared = sorted(h for h in emitted if h not in header)
    assert not undeclared, (
        f'src/recompilation.cpp emits calls to undeclared hooks: '
        f'{undeclared}. Add decls in include/recomp.h.'
    )


def test_cop0_dispatch_is_per_register_not_default_fallback():
    """
    The cop0 dispatch in recompilation.cpp must enumerate registers
    explicitly:
      - Status (12)             → dedicated helper
      - Reserved (21..25, 31)   → loud abort
      - Everything else         → ctx->cop0_regs[reg] storage

    There must be no `default:` arm that catches "all unhandled
    registers" with a single behavior — that's the silent-fallback
    anti-pattern. Each register's behavior must be a deliberate
    decision documented in include/recomp.h's cop0_regs[] comment.

    This test guards against:
      1. A `default:` arm reappearing in the cop0 switch
      2. cop0_regs[] being removed (the HLE-correct storage model)
      3. The reserved-register abort being weakened
    """
    header = HEADER.read_text(encoding='utf-8')
    src = RECOMP_CPP.read_text(encoding='utf-8')

    # cop0_regs[] storage IS the documented HLE model for the
    # storage-acceptable register set. Removing it = removing the model.
    assert 'cop0_regs[32]' in header, (
        'cop0_regs[32] removed from recomp_context. The HLE storage '
        'model for non-side-effecting cop0 regs (TLB, cache tags, '
        'watch, EPC, etc.) is documented as correct semantics, not '
        'a stub. See the doc-comment on cop0_regs[] in recomp.h.'
    )
    assert 'ctx->cop0_regs[' in src, (
        'recompilation.cpp no longer emits ctx->cop0_regs[] for the '
        'storage path. Per-register dispatch should route the '
        'storage-acceptable registers to cop0_regs[].'
    )

    # No default: arm in the cop0 mfc0/mtc0 dispatch — every register
    # must be a deliberate decision.
    cop0_block_match = re.search(
        r'case InstrId::cpu_mfc0:.*?case InstrId::cpu_mtc0:.*?case InstrId::cpu_add:',
        src, re.DOTALL,
    )
    assert cop0_block_match, 'cannot locate cop0 dispatch block'
    cop0_block = cop0_block_match.group(0)
    assert 'default:' not in cop0_block, (
        'cop0 dispatch contains a default: arm. Each register must '
        'be a deliberate decision (Status / reserved-abort / storage), '
        'not a catch-all fallback. Remove the default and enumerate.'
    )

    # Reserved registers (21..25 inclusive, 31) must still route to
    # the loud-abort path. The dispatch checks "reg_index >= 21 && <= 25"
    # plus "reg_index == 31".
    assert 'reg_index >= 21 && reg_index <= 25' in src, (
        'reserved-register guard for cop0 21..25 missing or weakened. '
        'These registers are reserved on real hardware; access should '
        'remain a loud abort.'
    )
    assert 'reg_index == 31' in src, (
        'reserved-register guard for cop0 31 missing. Access to this '
        'reserved register should remain a loud abort.'
    )


# Re-import re for the test above (top-level import is shadowed by
# function locals in this module's other tests).
import re
