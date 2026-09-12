# Automatic C++ Arxan-pattern branch recovery

Arxan-pattern recovery now runs inside `unslopper.dylib` when a function is
decompiled. No Python analysis/import step, comment marker, or user-added xref
is required. Python under `tests/` provides an independent reference and test
harnesses; it is not a runtime dependency of the plugin.

## Native pipeline

- `src/passes/arxan_patterns.*` is an SDK-independent C++ matcher for exact ARM64
  instruction patterns. It reads instructions through bounded callbacks and
  does not contain sample-specific addresses.
- `src/passes/arxan_branches.*` integrates the matcher with Hex-Rays. During
  `hxe_flowchart_ea`, it adds proven target blocks to the mutable reachability
  set, following existing CFG successors. It only includes blocks already
  present in the flowchart and owned by the current function.
- During `hxe_microcode` / `MMAT_GENERATED`, eligible indirect jumps become
  direct microcode gotos. Subsequent Hex-Rays stages build and optimize the CFG.
- The existing generic CFF/MBA passes run afterwards.

The early reachability step matters: many destinations exist in IDA's flowchart
but are omitted from generated microcode because an unresolved BR made them
appear unreachable. A GENERATED-only pass could recognize a branch yet have
no destination block to use. The native implementation handles that prerequisite
without changing machine bytes, comments, xrefs, or function boundaries.

Set `UNSLOP_NO_ARXAN=1` before decompilation to disable both native stages for
comparison. Plugin action `4` prints additional `[unslop-arxan]` diagnostics:
`reachable_added`, `matched`, `changed`, `ownership_rejected`, `entry_rejected`,
and `missing_block`, and `verified`. The native rewrite is strict-verified after
preoptimization; a verification failure aborts that decompilation.

## Accepted patterns and gates

1. **Stored zero + address arithmetic:** matching 64-bit STR/LDR or STUR/LDUR
   through SP/FP, followed by an ADR destination, optionally a read-only signed
   relative word, and `(address XOR 0) + 2*(address AND 0)`. A pointer in X8 is
   accepted only when an immediately preceding ADD/SUB-immediate derives it
   from SP or FP. General pointer stores and mutable literal reads are rejected.
2. **Multiply by one:** MOV X8,1; ADR X9,target; MUL X8,X9,X8; BR X8.
3. **Cancelling offset:** ADR X9,target; subtract X11; a known direct edge skips
   a decoy subtraction; add X11; BR X9. Balanced SP adjustments are preserved.

The proof slice and destination must have the same current IDA function owner.
Known incoming code references from outside the slice into its middle reject
the rewrite, as do conflicting user jump references. Destinations must be
aligned and inside the executable segment. Unsupported cases remain unchanged.

These are local instruction proofs, not vendor detection or whole-program
proofs. Unknown indirect entry paths, asynchronous modification, fragmented
function bounds, and other protector variants are not established by a match.
`__ETC,__PII` is layout evidence, not permission to rewrite arbitrary code.
Integrity checks, debugger checks, syscalls, and failure handlers are not disabled.

## Validation on the three additional bet365 frameworks

A fresh C++ plugin was built against IDA SDK 9.4. Each sample was loaded from
its original binary into an isolated IDA database. No Python annotation importer
was called. Twenty eligible functions per library were selected at evenly spaced
positions in the sorted function list, with a 12,000-byte size cap.

The harness compares disabled Unslopper, existing passes with native Arxan
recovery disabled, and the full native pipeline. The table below isolates the
new pass against existing passes:

| Sample | Functions tested | JUMPOUT: existing passes → native | Native edges recovered | Additional reachable blocks |
|---|---:|---:|---:|---:|
| TMXBehavioSec | 20 | 20 → 1 | 63 | 455 |
| TMXProfilingConnections | 20 | 23 → 3 | 65 | 386 |
| TMXAuthentication | 20 | 17 → 0 | 39 | 127 |

All three runs completed without new decompilation failures and without changing
machine bytes. These are representative function tests, not coverage of every
function in those SDKs. Lower JUMPOUT counts measure recovery of visible flow;
they do not establish complete semantic equivalence of the final pseudocode.

### Repeat decompilation and type inference

Exposing previously unreachable code can cause Hex-Rays to infer additional
callee types. Initial tests observed `_QWORD*`/`__int64*` changes and expanded
inferred prototypes between first and second exports. The harness therefore
records `initial_native` and allows one native type-inference pass before
comparing `native` with `repeated`. Those subsequent texts matched in all three
libraries. TMXAuthentication also showed type propagation with the pre-existing
passes alone (`core_repeat_matches=false`); this is preserved in the evidence.
The plugin does not force prototypes or suppress these differences.

Full per-function metrics, plugin hashes and native diagnostics are in
[evidence/arxan_native_summary.json](evidence/arxan_native_summary.json) and the
three `*_arxan_native.json` files beside it.

## Matcher coverage and independent instruction checks

| Sample | Zero-mask patterns | Cancelling offsets | Multiply one | Total local matches |
|---|---:|---:|---:|---:|
| NianticLabsPlugin, Pokemon GO 0.415.2 | 8,878 | 6,223 | 6,031 | 21,132 |
| TMXProfiling | 943 | 737 | 708 | 2,388 |
| TMXBehavioSec | 928 | 488 | 544 | 1,960 |
| TMXProfilingConnections | 156 | 123 | 127 | 406 |
| TMXAuthentication | 201 | 152 | 149 | 502 |

C++ discovery matched the independent Python reference exactly on Niantic and
the three newly tested TMX frameworks. Original-versus-direct-branch ARM64
execution matched for 63,396 Niantic comparisons and respectively 5,880, 1,218,
and 1,506 comparisons on the three TMX libraries. Each local match is exercised
with three initial register states; registers, SP and NZCV are compared.
Niantic's new C++ F5 pipeline has not been exercised by this three-library run.

Broader syntactic scans find more sites, because they also count general-pointer
zero stores that this implementation deliberately does not treat as proofs.
Full hashes are in [arxan_samples.json](evidence/arxan_samples.json). No target
binaries or IDA databases are committed.

## Reproducing tests

The C++ matcher can be built and tested without an IDA SDK:

```sh
c++ -std=c++17 -Wall -Wextra -Werror -I src/passes \
  tests/arxan_native_patterns.cpp src/passes/arxan_patterns.cpp \
  -o build/arxan_native_patterns
build/arxan_native_patterns
python3 -m unittest discover -s tests -p 'test_*.py' -v
```

Independent sample checks (the differential harness requires Unicorn):

```sh
python3 tests/arxan_reference.py /path/to/binary --output report.json
python3 tests/arxan_differential.py /path/to/binary report.json differential.json
python3 tests/arxan_native_parity.py build/arxan_native_patterns /path/to/binary parity.json
```

For the full F5 comparison, build the plugin using the repository's normal CMake
instructions, use an isolated IDA user directory with no older Unslopper plugin,
and run the harness against an analysis copy:

```sh
idat -A -S"tests/arxan_native_ida.py report.json native.json /path/to/unslopper.dylib 20" copy.i64
```

The harness writes metrics and local pseudocode snapshots next to `native.json`.
Do not publish those snapshots when the target is proprietary. They are not
needed to use the C++ plugin.

Complete protector removal, automatic repair of fragmented IDBs, live application
behavior, and removal of integrity machinery are not claimed.
