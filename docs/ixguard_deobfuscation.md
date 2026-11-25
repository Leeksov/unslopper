# iXGuard value analysis and diagnostics

This extends the stack-jump-table work with independently applied MBA rules,
one audited FNV predicate recipe, bounded offline syscall slicing, and
structured per-function diagnostics. Target instructions are not patched.

## MBA

`ixguard_mba.cpp` runs independently of dispatcher recovery. It recognizes
`2*(a|b)-(a^b)`, `(a|b)+(a&b)`, and `(a^b)+2*(a&b)` as `a+b`.
Operands must have equal widths; calls and indirect/faulting loads are
rejected. Global value references must carry matching SSA value numbers;
file values are never substituted by this pass. Z3 checks the identities
for all 8/16/32/64-bit inputs.

The pre-existing rule `a-(~b-1) -> a+b` was incorrect by two. It now matches
the correct `a-(~b+1) -> a+b` form, with a regression counterexample for the
former rule.

## Hash predicates: explicit analysis snapshot

The first recipe covers SNBMobile helper RVA `0x193E78`, with exact helper
bytes in `ixguard_fnv_recipe.inc`, and seed RVA `0x2425FE8` equal to
`0xC8DBA56F43099739`. These are checked again before each transformation.
Under that fixed seed, the helper computes FNV-1a over eight little-endian
bytes of `(uint64_t(flag)<<32)|salt`. Its original ARM64 instructions were
executed in an isolated Unicorn instance on 264 input pairs, including
arbitrary 32-bit flags and salts. No host/target API is executed.

At a comparison, folding additionally requires a syntactically/reaching-
definition proven boolean first argument, constant salt, and two distinct
hash outputs. Other inputs, modified code/seed and unknown domains remain
untouched. The nonboolean hash call in StatusBar is intentionally retained.

Because the seed is writable, the recipe is **OFF by default**. Action 20
enables the explicitly conditional fixed-seed analysis view; action 21
restores the literal view. Neither action patches data or proves runtime
immutability. Affected cached pseudocode is invalidated. The installation
leaves this mode OFF; both views are exported by the integration harness.

## Syscalls and the carry-flag correction

`tools/ixguard_analysis.py syscalls BINARY OUTPUT` performs bounded backward
ARM64 register slices within a control-flow region. Each result records the
original instruction window, dependency instructions, exact data bytes read,
and any X0/X1 arguments it could resolve. Calls, unsupported definitions,
unbacked memory and caller-selected inputs cause an explicit unresolved result.

For the SNBMobile fixture, 225 of 666 SVC candidates resolve under file-data
assumptions; 441 remain unresolved. All 225 dependency slices were replayed
at their original PCs using original instructions with three randomized
initial register files (675 matching executions). No SVC is executed. This
checks the slice evaluator, not runtime immutability or complete reachability.

`apply_ixguard_syscalls.py` checks input identity/base, full instruction
windows, SVC bytes and data reads before appending any comments. Comments
label file-snapshot assumptions and preserve user annotations.

Number/name reference: Apple XNU 10002.61.3
[BSD syscall table](https://github.com/apple-oss-distributions/xnu/blob/xnu-10002.61.3/bsd/kern/syscalls.master)
and [Mach trap table](https://github.com/apple-oss-distributions/xnu/blob/xnu-10002.61.3/osfmk/kern/syscall_sw.c).
Names are hints; recorded instruction/data evidence remains authoritative.

An additional correctness issue was found in the earlier decompilation:
Hex-Rays' ARM `mac_syscall` helper did not define carry, so the preceding
dispatcher's range-check CF could incorrectly determine a syscall error
branch after unflattening. `svc_flags.cpp` now records that hidden output at
GENERATED maturity, before optimization. Pseudocode uses the abstract
intrinsics `__unslop_darwin_svc` and `__unslop_darwin_svc_carry` (one capture per
SVC); these are analysis notation, not real imported functions. X0 remains
the syscall return value. This supersedes the earlier StatusBar pseudocode
where the failure predicate was incorrectly reduced to a constant.

## Diagnostics and tests

Plugin action 4 prints JSON records prefixed with `[unslop-report]`: function
EA, stack recovery outcome, original cases/context count, new MBA changes,
hash matches/folds and last candidate reason, CFG changes, verifier errors,
and number of SVC carry captures. The original per-function fields reset
when the function is freshly decompiled. Hash candidate counts
cover multiple maturities, not unique source call sites.
`edges` remains the latest decompilation's verified CFG rewrite count.
`observed_edges` is the largest verified count seen for one decompilation of
that function during the current plugin session; `observed_changed` is one
when that count is positive. These additional fields survive a fresh F5
that produces zero edits, and repeated F5 does not add the same edits again.
They describe plugin activity, not unique recovered source edges or proof of
semantic equivalence. Plugin reset clears them.

Tests:

- `tests/test_ixguard_analysis.py`: bitvector proofs, partial-byte negatives,
  literal/caller-selected/branch-boundary slices, annotation preflight refusal.
- `tests/ixguard_deobfuscation.py`: five full-CFF fixtures in literal and
  snapshot modes, repeated decompilation, retained syscall/effect anchors,
  exactly one carry capture per SVC, changed seed/code refusal, mode restoration.
- `tests/ixguard_unflatten.py`: eleven-function earlier regression plus the
  unknown-initial-state refusal test.

The literal view still contains encrypted API tables, data decoders, other
hash schemes and residual algebra. This is not a whole-binary deobfuscation
claim and no device bypass was installed by this work.
