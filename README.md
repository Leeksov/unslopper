# Unslopper

**A unified Hex-Rays microcode deobfuscator for commercial mobile protectors.**

Unslopper is an IDA Pro 9.4 plugin that removes control-flow
flattening (CFF), collapses opaque/MBA algebra, and resolves obfuscated
dispatch across several commercial iOS/Android hardening products — from one
codebase, behind a single `F5`.

It replaces a drawer of per-protector scripts with one plugin: a generic CFF
recovery engine plus pluggable **profiles** that teach it each protector's
dispatcher shape, and a family-agnostic **opaque/MBA layer** that runs on every
function regardless of flattening.

---

## Supported protectors

| Family | Obfuscation | Unslopper handling | Status |
|---|---|---|---|
| **OLLVM / Hikari** | magic-constant CFF (scramble32 states) | `profiles/ollvm` + core | ✅ verified |
| **BShield** | 64-bit stack-state equality-chain CFF | `core/stack_jtbl` context planner | [verified on six CFF functions](docs/bshield_cff.md) |
| **Promon SHIELD** | BST CFF + register pools + opaque predicates | `profiles/promon` | ✅ verified |
| **DexProtector** | XOR+ADD state-transform CFF | `profiles/dexprotector` | ✅ verified |
| **Guardsquare (MVG / iXGuard / BitGuard)** | jump-table CFF + X16 syscalls + BLR dispatch | `profiles/mvg` + appliers | ✅ verified |
| **Apple FairPlay (`makeOpaque`)** | S-box chains, affine/MBA, opaque preds, VM LUT | `passes/opaque_mba` + `passes/fairplay_dispatch` | ✅ verified |
| **Apple CoreALD 4.1** | state-dependent S-box chains around indirect dispatch | `tools/coreald_sbox.py`, `tools/coreald_pac_scan.py` + `passes/coreald_sbox` | [37 F5 folds; all 16 export transfers traced to PAC table entries](docs/coreald_pac.md) |
| **Arxan-class** | MBA computed branches and hidden reachability | `passes/arxan_branches` + `passes/opaque_mba` | [C++ F5 recovery tested on three TMX libraries](docs/arxan_branch_analysis.md)¹ |

¹ The native pass resolves exact, locally proven ARM64 branch patterns. It does
not disable integrity or debugger checks, and does not claim full protector
removal. Per-family limits remain in [coverage_matrix.md](docs/coverage_matrix.md).

---

## How it works

Unslopper installs a block-level microcode optimizer (`optblock_t`) that fires
once per function at Hex-Rays' local- and global-optimization maturities, so its
edits are re-structured into clean `if`/`while` by the decompiler afterwards.

Two independent layers run per function:

1. **CFF recovery** (`src/core`) — detect the flattening dispatcher, resolve the
   state→block map, and retarget the flattened gotos to their real successors.
   A **profile** refines this for the detected protector family.
2. **Opaque / MBA simplification** (`src/passes/opaque_mba`) — a *self-proving*
   pass that folds S-box chains, affine round-trips, opaque predicates, and MBA
   spellings back to their canonical form. It needs **no dispatcher**, so it
   cleans non-flattened (`makeOpaque`, Arxan) handlers too.

Every rewrite is proven before it is applied (verified permutation tables,
modular-inverse checks, always-true residues), and each function is
strict-`verify()`-ed before emission — a deobfuscator must never hand Hex-Rays
corrupt microcode (that aborts IDA with an INTERR). Across all verified runs:
**0 INTERR**.

---

## Build

Requires the IDA SDK 9.4, CMake 3.25+, Ninja and a C++17 toolchain.
Supports macOS, Windows and Linux, each on x64 and ARM64.

```sh
export IDASDK=/path/to/ida-sdk          # or place it at ../../tools/idasdk/ida-sdk
cmake -S . -B build -G Ninja
ninja -C build
# → build/unslopper.dylib (SDK root and its src/ directory are both accepted)
```

### GitHub Actions builds

[Build plugin](https://github.com/Leeksov/unslopper/actions/workflows/build.yml)
builds all six OS/architecture combinations on pushes to `main`, pull requests,
and manual dispatch. Download the matching `unslopper-ida94-<os>-<arch>` artifact
from a successful run and unpack its ZIP. The plugin is in `package/plugins/`.
Select the architecture of your **IDA installation**, regardless of the binary
being analyzed. macOS uses `.dylib`, Windows `.dll`, and Linux `.so`.

Tags matching `v*` publish all six archives and `SHA256SUMS.txt` to GitHub Releases
only after the builds and reference tests pass. The public IDA SDK is pinned to
commit `2a9143f2f4abd7f54fe20d1e40fb68391d19c4cb` (9.4); no IDA license or
proprietary sample binaries are needed in CI. Builds use native hosted runners
([runner labels](https://docs.github.com/en/actions/reference/runners/github-hosted-runners)).
Linux artifacts are built on Ubuntu 24.04. CI checks compilation and offline
regressions; loading the plugin and running F5 requires a compatible licensed
IDA/Hex-Rays installation and is not exercised by this workflow.

## Install

Symlink (or copy) the built plugin into IDA's user plugin directory:

```sh
ln -sf "$(pwd)/build/unslopper.dylib" ~/.idapro/plugins/unslopper.dylib
```

Check that the link target exists (`test -f ~/.idapro/plugins/unslopper.dylib`).
A broken symlink silently leaves the optimizer unavailable. If the SDK tree
has moved, copy the built library to a stable location such as
`build/unslopper.dylib` and point the link there.

For an already open database, verify the load directly in IDAPython:

```python
import ida_loader
plugin = ida_loader.load_plugin("/absolute/path/to/unslopper.dylib")
assert plugin is not None, "Unslopper did not load"
ida_loader.run_plugin(plugin, 2)
```

The run callback returns `True` for a successful action (older builds returned
`False`). The optimizer installs itself when a database opens; press **F5**.
The dedup caches are reset on `hxe_microcode` for each fresh decompilation, so
repeated F5 exports and type changes retain the same simplifications.

## Usage

The iXGuard value-analysis update adds independent MBA folds, syscall carry
modeling and per-function diagnostics (action `4`). The audited FNV analysis
snapshot is explicit: action `20` enables it, `21` disables it; default OFF.
See [iXGuard analysis and validation](docs/ixguard_deobfuscation.md).

The stack-state jump-table pass now handles the SNBMobile iXGuard fixtures
with shared state-store tails and partial-width boolean assignments. See
[the algorithm and regression results](docs/ixguard_stack_jtbl.md).
Set `UNSLOP_NO_STACK_JTBL=1` to disable only this pass for diagnosis.

- **F5** on any function — flattening and opaque algebra are removed inline.
- **Toggle / status** via the plugin (`Edit ▸ Plugins ▸ Unslopper`, or
  `load_and_run_plugin("unslopper", arg)`):

  | arg | action |
  |---|---|
  | `1` / `2` | disable / enable the optimizer |
  | `3` | print status (functions deflattened, edges, errors) |
  | `10` | **FairPlay**: resolve the VM dispatch handler LUT (one-shot) |

### Environment switches

| Variable | Effect |
|---|---|
| `UNSLOP_NO_ARXAN=1` | disable native Arxan reachability/branch recovery |
| `UNSLOP_NO_OPAQUE=1` | disable the opaque/MBA layer (CFF recovery only) |
| `UNSLOP_MAX_BLOCKS=N` | skip functions with more than N microcode blocks (default 4000) |
| `UNSLOP_SVC=1` | enable the (opt-in, unreliable) microcode syscall fold |
| `UNSLOP_FP_LUT_START/END=0x…` | override the FairPlay VM LUT bounds for other builds |
| `UNSLOP_LOG=0..5`, `UNSLOP_LOG_FILE=…`, `UNSLOP_ONLY_EA=0x…` | diagnostics |

### Automatic C++ Arxan branch recovery

Arxan-pattern recovery runs directly in `unslopper.dylib` during flowchart and
microcode generation. Press F5; no Python importer or annotation step is required.
The pass resolves proven local branches and includes their existing target blocks
in reachability without modifying IDB bytes or xrefs. Python is used only for
independent testing. See [algorithm and measured TMX results](docs/arxan_branch_analysis.md).

### CoreALD byte-dispatch cleanup

For CoreALD's state-dependent S-box chains, run `tools/coreald_sbox.py` in IDA
with the cursor in an export wrapper. Dry-run is the default. Use the `apply`
argument to add proof comments; with the plugin enabled, F5 folds each verified
terminal `AND Wn,Wn,#0xff` into its proven constant. The analyzer checks the
original straight-line ARM64 register flow and both read-only 256-byte tables,
including indirect table bases encoded as shared-cache rebases. The plugin
rechecks the tables, pointer slots, and a fingerprint of the original
instructions before changing GENERATED microcode. It never patches the Mach-O.
This covers 37 sites in all 16 tested iOS 26.0.1 CoreALD exports and **does not resolve** its dynamic
pointer tables or the asset-encryption algorithm. See [scope and test evidence](docs/coreald_sbox.md).

`tools/coreald_pac_scan.py` audits all 16 export `BRAA`/`BLRAA` sites and
reports their pointer-table candidates. Chomper reproduced all 17 branch
register values with synthetic state; a device memory snapshot confirmed
all 17 PAC-signed entries and modifiers at that time. The table is writable,
so the report does not add static CFG edges. See
[authenticated transfer evidence](docs/coreald_pac.md).
The helper's crypt-session calls and 32 KiB chunk descriptor are documented
in [the license-chunk path](docs/coreald_chunk_path.md).

### Offline appliers

Some annotations are more reliable at the disassembly level than in microcode
(Hex-Rays folds syscall/dispatch slices out). These ship as standalone,
headless-verified scripts in [`tools/`](tools/):

- `apply_svc_map.py` — annotate MVG/BitGuard X16 syscalls (1028 sites)
- `apply_dispatch_map.py` — annotate MVG RASP BLR dispatch (596 sites)
- `apply_appdome_trampolines.py` — name AppDome import trampolines (65,535 stubs)
- `deslop_vm_lift.py` — runtime-assisted OLLVM-22 VM devirtualizer
- `coreald_sbox.py` — prove and annotate CoreALD byte-dispatch constants
- `coreald_pac.py` — audit authenticated indirect-transfer candidates
- `coreald_pac_scan.py` — trace all 16 CoreALD export transfers
- `coreald_chomper_probe.py` — emulate export prefixes to transfer sites

---

## Layout

```
unslopper/
├── src/
│   ├── plugin.cpp            # entry: optblock pipeline + toggle/actions
│   ├── unslop_types.h        # ProfileKind, DispatcherInfo, StateTransition
│   ├── profile.h             # Profile interface + registry
│   ├── unslop_log.*          # leveled diagnostics
│   ├── core/                 # CFF recovery engine
│   │   ├── dispatcher.*      #   dispatcher detection (max-pred/jtbl/BST)
│   │   ├── state_resolver.*  #   state-value resolution
│   │   ├── history_tracker.* #   backward state emulation
│   │   ├── block_dup.*       #   block duplication / successor rewiring
│   │   ├── cfg_rewriter.*    #   safe CFG edge rewriting
│   │   └── microcode_utils.* #   shared mop/minsn helpers
│   ├── passes/               # microcode transformation passes
│   │   ├── opaque_mba.*      #   self-proving makeOpaque/MBA layer (always-on)
│   │   ├── mba_simplify.*    #   Hikari MBA identity ruleset
│   │   ├── svc_resolver.*    #   X16 syscall resolution
│   │   ├── fairplay_dispatch.*  # FairPlay VM LUT resolver (action 10)
│   │   ├── coreald_sbox.*       # verified CoreALD byte-dispatch folds
│   │   ├── anti_decompiler.* #   indirect-jump / anti-decompiler passes
│   │   ├── semantic_diffusion.* # volatile-slot round-trip folding
│   │   └── virtual_call.*    #   synthetic-vtable devirtualization
│   └── profiles/             # per-protector detect + configure
│       ├── ollvm.cpp  promon.cpp  dexprotector.cpp  mvg.cpp
├── tools/                    # offline, headless-verified appliers
├── tests/                    # headless harnesses + characterization scripts
├── docs/                     # architecture, specs, reference material
│   ├── ARCHITECTURE.md       # design & data flow (start here to hack on it)
│   ├── coverage_matrix.md    # per-family status & honest limits
│   └── reference/            # external reference (d-810, HexRaysDeob)
└── CMakeLists.txt
```

See **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)** for the pipeline, design
rationale, and how to add a new protector profile or pass.

---

## Scope & ethics

Unslopper is a research tool for **authorized** reverse engineering, security
analysis, and interoperability work on binaries you have the right to analyze.
It reads and annotates static databases; it does not bypass DRM, defeat
licensing, or aid piracy.

### Analyst-verified internal jumps

For an indirect jump independently proven to be an unconditional internal edge,
add a non-repeatable comment exactly `UNSLOPPER_VERIFIED_JUMP: 0xTARGET` and
one matching user code-jump xref in IDA. Unslopper restores the branch at the
`hxe_microcode` event, before local optimization can turn it into a misleading
indirect tail call. The target must be an existing block in the same function.
Missing, conflicting, malformed, or external annotations are ignored.

The marker is an analyst assertion, not a proof inferred from pointer contents:
do not apply it to a conditional/multitarget jump or a runtime-mutable target.
This pass does not patch machine bytes. `tests/verified_jump.py` exercises
positive/negative gates and repeated decompilation on the pinned MVG example.
