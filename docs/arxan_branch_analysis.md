# Checked Arxan-pattern branch import

This update adds address-independent discovery of three ARM64 branch patterns
observed in NianticLabsPlugin and four TMX frameworks. It feeds the existing
`verified_jump` microcode pass. It does not patch machine instructions or disable
integrity checks, debugger checks, syscalls, or exception handlers.

## Pipeline

1. `tools/arxan_analysis.py` reads a thin, decrypted ARM64 Mach-O and derives
   `__text`, segment permissions, and optional `LC_FUNCTION_STARTS` bounds.
2. It recognizes exact local instruction families and records source bytes,
   target, pattern, and any read-only literal needed by the proof.
3. `tools/apply_arxan_branches.py` re-derives every match from the current IDB
   before making changes. Its default operation is a read-only plan.
4. Explicit import writes an `UNSLOPPER_VERIFIED_JUMP` comment and a matching
   user jump xref. Existing Unslopper handling turns eligible generated
   microcode indirect jumps into gotos before local optimization.

The importer requires all instructions in the proof and its target to have the
same current IDA function owner. It rejects known incoming edges into the middle
of the proof from outside the slice. Existing comments and conflicting jump
xrefs are preserved by skipping the site. Function-boundary repair is outside
this update: a split function can prevent an otherwise valid local match from
being imported.

## Patterns and proof boundaries

- **Stored zero + address arithmetic:** matching 64-bit STR/LDR or STUR/LDUR
  through SP/FP, followed by a constant ADR destination, optionally a read-only
  signed relative word, and `(address XOR 0) + 2*(address AND 0)`. A pointer in X8
  is accepted only when the immediately preceding ADD/SUB-immediate derives it
  from SP or FP. General pointer stores are deliberately rejected.
- **Multiply by one:** MOV X8,1; ADR X9,target; MUL X8,X9,X8; BR X8.
- **Cancelling offset:** ADR X9,target; subtract X11; a known edge skips a decoy
  subtraction; add X11; BR X9. The balanced SP adjustments remain intact.

These are local execution proofs, not a general Arxan signature or whole-program
proof. Unknown indirect entry paths, asynchronous modification, and other
protector variants are not established by a match. `__ETC,__PII` is reported as
layout evidence, not treated as permission to rewrite arbitrary code.

The Mach-O reader translates VM addresses through segment file offsets. This
matters for Niantic: `__PII` has VM address `0xcc0000`, but file offset `0xb98000`.
The tools reject encrypted input, malformed command bounds, mutable literals,
external targets, changed proof bytes, duplicate records, and edited targets.

## Usage

Offline discovery needs only the Python standard library:

```sh
python3 tools/arxan_analysis.py /path/to/NianticLabsPlugin --output report.json
```

Inside IDAPython, with this repository's `tools/` directory on `sys.path`:

```python
import json
from apply_arxan_branches import apply

with open('/path/to/report.json') as stream:
    report = json.load(stream)

plan = apply(report)  # Read-only
print(len(plan['accepted']), len(plan['skipped']))
result = apply(report, commit=True)  # Comments and user jump xrefs only
```

Use an analysis copy. Enable Unslopper and decompile with F5. The existing
microcode pass still checks that the destination is an actual block in the same
function; an annotation alone does not guarantee a change in the pseudocode.
Rebased IDBs require a report matching the current base; rebasing is not inferred.

## Sample results

These counts are accepted local patterns, before IDA ownership/xref gates:

| Sample | Stored zero | Cancelling offset | Multiply one | Total |
|---|---:|---:|---:|---:|
| NianticLabsPlugin, Pokemon GO 0.415.2 | 8,878 | 6,223 | 6,031 | 21,132 |
| TMXProfiling | 943 | 737 | 708 | 2,388 |
| TMXBehavioSec | 928 | 488 | 544 | 1,960 |
| TMXProfilingConnections | 156 | 123 | 127 | 406 |
| TMXAuthentication | 201 | 152 | 149 | 502 |

A broader syntactic scan counted 22,784 Niantic matches. The importer deliberately
accepts fewer because it requires a stack-derived zero-store address and
read-only literals. Broader pattern counts are not rewrite authorization.

Full sample hashes and counts: [arxan_samples.json](evidence/arxan_samples.json).
No target binaries or full disassembly databases are included.

## Validation

- Twenty sample-independent positive/negative unit tests cover instruction
  patterns, mutable literals, general-pointer stores, external destinations,
  changed reports, competing xrefs, comments, function ownership, encryption,
  and VM/file-offset differences.
- Original versus direct-branch ARM64 execution matched for **all 21,132 Niantic
  records**, three initial register states each: **63,396 comparisons**. This
  checks registers, SP, and NZCV at the local destination, not whole functions.
- On an analysis copy of the Niantic IDB, **6,112** records were eligible;
  **15,020** were skipped because function ownership was missing or differed.
- Three eligible functions were exercised with an existing local Unslopper
  build. Repeat decompilation metrics matched, and machine bytes were unchanged.
  At `0x69d8`, JUMPOUT count fell from 1 to 0. At `0x45e0`, lines fell from 62
  to 58. At `0x6b58`, the selected annotation did not change these metrics.
- This is a Python tooling change; it does not add or rebuild a C++ pass.

Evidence: [local differential test](evidence/niantic_arxan_differential.json),
[IDA annotation/decompilation test](evidence/niantic_arxan_annotations.json).

```sh
python3 -m unittest discover -s tests -p 'test_arxan_analysis.py' -v
# Requires Unicorn:
python3 tests/arxan_differential.py /path/to/binary report.json differential.json
# IDA analysis-copy harness; pass a built Unslopper plugin as the final argument:
idat -A -S"tests/arxan_annotations.py report.json ida-result.json /path/to/unslopper.dylib" copy.i64
```

Complete protector removal, automatic repair of fragmented IDBs, live application
behavior, and removal of the integrity machinery are not claimed.
