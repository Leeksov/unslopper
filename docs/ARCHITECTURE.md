# Unslopper architecture

This document describes how the plugin is put together, the design decisions
behind it, and how to extend it. For *what* each protector does and current
coverage, see [coverage_matrix.md](coverage_matrix.md).

---

## 1. Execution model

Unslopper is a Hex-Rays **block optimizer** (`optblock_t`), not a standalone
analysis. It hooks into decompilation and mutates the *microcode* — the SSA-ish
IR Hex-Rays builds between disassembly and pseudocode — so that the decompiler's
own structurer turns the result into clean `if`/`while`.

```
 disasm ──► gen microcode ──► [ MMAT_LOCOPT ] ──► [ MMAT_GLBOPT1/2 ] ──► ctree ──► pseudocode
                                    │                     │
                                    └──────── Unslopper ─────┘
                          (runs once per (function, maturity))
```

Running at multiple maturities matters: the register/legacy rewrite is only
valid at `LOCOPT` (it would corrupt more-optimized microcode → INTERR), while
the emulated D-810-style path needs the later `GLBOPT` maturities so the
structurer re-forms loops *after* we unflatten. `plugin.cpp::func()` gates each
path to its safe maturity.

---

## 2. Per-function pipeline

`UnslopperOptblock::func(mblock_t*)` is invoked per block, but the work is
whole-function, so it dedups on `(entry_ea, maturity)` and runs this once:

```
func(blk)
 │
 ├─ (opt-in) svc annotation layer .............. passes/svc_resolver
 │      X16 syscall selectors, comment-only, never mutates the CFG
 │
 ├─ opaque / MBA layer (always-on) ............. passes/opaque_mba
 │      self-proving: S-box chains, affine round-trips, opaque-square,
 │      MBA-sub, + the Hikari MBA ruleset (passes/mba_simplify).
 │      Needs NO dispatcher → cleans makeOpaque / Arxan handlers.
 │
 ├─ run_pipeline(mba) ......................... CFF recovery (see §3)
 │      returns 0 (+ definitely_not_cff) when there is no dispatcher
 │
 ├─ if (no CFF change AND no opaque change) ─► return, cache not_cff
 │
 ├─ mba->verify(true)  ........................ EXACTLY ONE strict verify
 │      on failure: mark (func,maturity) skip, never emit broken microcode
 │
 └─ report + return (changes + opaque_changes)
```

Two independent wins can happen in the same function: a flattened *and*
opaqued function is both deflattened and folded, under a single verify.

### Negative caching

Three sets on the optimizer keep re-decompiles cheap and safe:

- `done` — `(func,maturity)` already processed (dedup).
- `not_cff` — no dispatcher / rejected by the pre-filter (skip instantly).
- `skip` — produced microcode that failed `verify()` (never re-attempted).

---

## 3. CFF recovery engine (`src/core`)

```
run_pipeline(mba)
 │
 ├─ pre-filter: qty bounds, max-predecessor count, opcode signatures
 │              (one O(instructions) pass; rejects non-CFF cheaply)
 │
 ├─ build_reg_const_map(mba) .................. microcode_utils
 │      shared register→constant map, built ONCE and threaded through
 │
 ├─ detect_dispatcher(mba, regmap) ............ dispatcher
 │      strategy 1 max-preds · 2 jump-table · 3 state-var · 4 emulated-BST
 │
 ├─ profile = first all_profiles()[i].detect(mba, regmap)
 │      profile->configure(mba, di, regmap)  refines DispatcherInfo
 │
 ├─ resolve state→block map .................... state_resolver + history_tracker
 │      local propagation → forward dataflow → dispatcher-tree walk / emulation
 │
 ├─ rewrite_cfg(mba, di, profile) ............. cfg_rewriter (+ block_dup)
 │      retarget flattened gotos to real successors; D-810 multi-pass
 │      (single-value, conditional split, duplication, nop-stores, prune)
 │
 └─ profile->post_process(mba, changes) ....... family-specific cleanup
```

`DispatcherInfo` (`unslop_types.h`) is the record passed between these stages:
the state variable (register or memory slot), the dispatcher blocks, the
`state→block` map, BST pivots, and — for XOR-keyed BST dispatchers — the
selector transform (`state ^ key + add`) recovered by emulating the tree once
per candidate state.

---

## 4. Profiles (`src/profiles`)

A `Profile` teaches the generic engine one protector's specifics. The interface
(`profile.h`) is deliberately small:

```cpp
struct Profile {
  const char *name();  ProfileKind kind();
  bool detect(mba, regmap);                 // cheap structural match
  bool configure(mba, DispatcherInfo*, regmap);  // refine the dispatcher
  uint64_t transform_state(uint64_t raw);   // e.g. DexProtector (raw^key)+add
  int post_process(mba, changes);           // opaque preds, MBA, ...
};
```

Profiles are tried in **detection-priority order** (`all_profiles()`): specific
families first, generic OLLVM last so it does not shadow the others. Detection
is structural — magic-constant comparisons, register pools, EOR+ADD selectors,
jump-table shape — never a name or a hash.

The opaque/MBA layer is intentionally **not** a profile: it is family-agnostic
and must run even when no profile matches (FairPlay/Arxan handlers have no
dispatcher).

---

## 5. Transformation passes (`src/passes`)

| Pass | Role | Gate |
|---|---|---|
| `opaque_mba` | self-proving makeOpaque/MBA folding + Hikari ruleset | always-on |
| `mba_simplify` | MBA identities, affine reduction, opaque-pred elimination | called by opaque_mba + CFF post-process |
| `svc_resolver` | X16 syscall selector resolution (microcode) | opt-in `UNSLOP_SVC` |
| `fairplay_dispatch` | walk the FairPlay VM LUT → define/name 44,700 handlers | action (arg 10) |
| `anti_decompiler` | indirect-jump / anti-decompiler shielding | CFF path |
| `semantic_diffusion` | volatile-slot round-trip folding | CFF path |
| `virtual_call` | synthetic-vtable devirtualization | CFF path |

### Why "self-proving"

The always-on layer runs on *every* decompiled function, so a false rewrite
would silently corrupt unrelated code. Every rule therefore carries its own
proof and fires only when it holds:

- **S-box chain** `x ^ outer[inner[x]^c]` — both tables are read from the IDB,
  checked to be 256-byte permutations, and the chain is verified constant for
  **all 256** inputs before folding. No hard-coded table addresses.
- **Affine round-trip** `(x·a+b)·a⁻¹+rb → x` — the modular inverse is checked
  (`a·a⁻¹ ≡ 1`, `b·a⁻¹+rb ≡ 0` mod 2ⁿ); the constants come from the code.
- **Opaque-square** `(x·x)%4 ∈ {0,1}` — an always-true residue, folded to 1.
- **MBA-sub** `(x^~c)+((2x)&~(2c+1))+1 → x−c` — shape- and mask-checked.

If a proof does not hold, the instruction is left untouched.

---

## 6. INTERR-safety invariants

An INTERR aborts the whole IDA session, so correctness is a hard constraint:

1. **One strict `verify(true)` per function**, after all edits; on failure the
   function is marked `skip` and the original microcode is emitted.
2. **No CFG surgery the structurer can't digest** — goto-collapse and
   block-removal at GLBOPT are disabled; Unslopper rewrites edges and lets
   Hex-Rays' DCE remove now-dead blocks.
3. **Every mutation is exception-guarded** — a throwing pass leaves the function
   untouched rather than half-rewritten.
4. **Size cap** (`UNSLOP_MAX_BLOCKS`) keeps pathological functions off IDA's
   single UI thread.

---

## 7. Extending Unslopper

### Add a protector profile

1. Create `src/profiles/<name>.cpp` implementing `Profile`.
2. Add a factory `Profile *make_<name>();` to `profile.h` and push it (in
   priority order) inside `all_profiles()` in `plugin.cpp`.
3. Add its source to `CMakeLists.txt` and a `ProfileKind` to `unslop_types.h`.

### Add an always-on microcode rule

1. Add a `try_<rule>(minsn_t*)` matcher to `passes/opaque_mba.cpp` that returns
   `true` only when the identity is *proven*, and rewrites in place.
2. Chain it in `OpaqueVisitor::visit_minsn`.

### Add a one-shot action

Extend `plugin_ctx_t::run(arg)` with a new arg and call your pass (see arg `10`,
the FairPlay VM LUT resolver, for the pattern).

Flat includes (`#include "foo.h"`) resolve across `core/`, `passes/`, and
`profiles/` via `target_include_directories` in `CMakeLists.txt`, so a new file
never needs `../` prefixes.

---

## 8. Offline appliers (`tools/`)

Some obfuscation is better undone at the disassembly level than in microcode:
Hex-Rays folds the syscall/dispatch slices out of the IR, so a microcode pass
sees nothing. Those live as standalone, headless-verified IDAPython scripts
(`apply_svc_map.py`, `apply_dispatch_map.py`, `apply_appdome_trampolines.py`,
`unslop_vm_lift.py`). They read a JSON evidence map and annotate the database;
each was validated by a real headless apply + read-back run. This split is
deliberate — the plugin does what microcode does well, the appliers do what
disassembly does well.
