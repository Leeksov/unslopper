# CoreALD byte-dispatch constant recovery

## Scope

The tested sample is the arm64e `CoreALD` 4.1.0 image from iOS 26.0.1,
SHA-256 `247842d90546265eb6ced34fa18d83bc3d2eaaa3d4c1e79bb2cd3aab0e91f24f`.
Control Ultimate Edition 1.354 requires iOS 26.1, so this result has **not**
been transferred to its minimum OS build. No CoreALD sample is committed here.

CoreALD's export wrappers calculate an index from mutable global state, pass
its low byte through two site-specific permutation tables, and use the result
to select data or an authenticated indirect transfer. Hex-Rays sometimes
duplicates the source expression, including mutable global loads. The existing
`opaque_mba` pass correctly refuses to treat those duplicated expressions as
the same pure value. Removing its side-effect guard would be unsound.

The new analyzer proves the relationship from the **original native register
slice** instead. It requires an uninterrupted sequence in which a source `Wn`
is masked to one byte, one table result passes through a byte XOR and a second
table, and that result is XORed back into the same unchanged `Wn` before
`AND Wn,Wn,#0xff`. It rejects outside control-flow entries, source clobbers,
writable or non-permutation tables, ambiguous matches, and changed bytes.
Table bases may come from direct `ADRL` references or from read-only dyld
shared-cache rebase slots. For the latter, the analyzer decodes the observed
34-bit runtime offset from the iOS 26.0.1 cache base, checks the effective
table address and includes the original pointer-slot bytes in its fingerprint.
For all 256 possible source bytes it checks:

```text
x ^ outer[inner[x] ^ c] == K
```

Only after the equation has one constant result `K` does `apply` write a
`UNSLOPPER_COREALD_SBOX` comment at the final `AND`. The comment carries the
instruction-window, table, and optional pointer-slot addresses plus an FNV-1a
change fingerprint over code, tables, and slot bytes.
FNV is a snapshot check, **not** a cryptographic attestation. The C++ pass
rechecks the native `AND`, code ownership, read-only table contents, all 256
inputs, and the fingerprint before replacing one 32-bit `m_and` in Hex-Rays'
GENERATED microcode with `m_mov #K`. No instruction bytes, IDA xrefs, or CFG
edges are changed. The pass requires exactly one matching `m_and` at that EA.

## Use in IDA

1. Build and load `unslopper` as usual.
2. Put the cursor inside a CoreALD export wrapper and run
   [`tools/coreald_sbox.py`](../tools/coreald_sbox.py) from IDA's **File → Script
   file**. It reports proven sites without modifying the database.
3. Run the same script with `apply` in batch mode to add proof comments, or
   call its `analyze_site(IDAImage(), ea).marker()` result from IDAPython for a
   site you have reviewed. Redecode with F5 while the plugin is enabled.

The batch form is:

```text
idat -A -S"/path/to/coreald_sbox.py 0xENTRY[,0xENTRY...] apply exit" CoreALD.i64
```

Only `apply` creates comments. `exit` asks the IDA batch process to quit.

## Evidence across every export

The isolated IDA 9.4 test compared three phases: plugin disabled, existing
plugin enabled with no CoreALD proof comments, and plugin enabled with verified
comments. The second and third columns below isolate the **new** pass from
the existing Unslopper rules.

| Export | Proven folds | Existing plugin F5 lines | With CoreALD proofs |
| --- | ---: | ---: | ---: |
| `_adMedklO` | 2 | 50 | 38 |
| `_OZpDoyky` | 3 | 48 | 38 |
| `_FbLnABIk` | 0 | 8 | 8 |
| `_qENIaLkr` | 3 | 38 | 38 |
| `_xrPnDyPw` | 3 | 49 | 39 |
| `_QSIlMWCo` | 1 | 50 | 40 |
| `_niaOacKH` | 3 | 75 | 65 |
| `_g4Bksweo` | 2 | 57 | 57 |
| `_SljH37Yp` | 2 | 52 | 35 |
| `_WJUddQgY` | 3 | 58 | 48 |
| `_cdHFeFDJ` | 2 | 41 | 41 |
| `_TBQFRWlW` | 1 | 52 | 42 |
| `_fyzGzQHg` | 3 | 59 | 49 |
| `_jYWQDEvI` | 3 | 47 | 38 |
| `_CWeMQvFE` | 3 | 59 | 47 |
| `_bmXjyxfx` | 3 | 52 | 42 |
| **Total** | **37** | **795** | **665** |

The 37 verified folds occur in 15 of 16 exports; 12 F5 texts changed. The
unmarked plugin alone reduced the combined 16-export output from 1,069 to 795
lines, so those earlier changes are **not** attributed to this pass. The new
pass reduced it from 795 to 665 lines. Every marked site was checked for the
expected `m_mov` in GENERATED microcode. The test found no newly failing
exports, rejected a tampered fingerprint, reproduced identical marked output
on repeat, and found no changed Mach-O bytes. See the machine-readable
[all-export result](evidence/coreald_all_exports_26_0_1.json) and the
[IDA harness](../tests/coreald_all_exports_ida.py). Eight synthetic
positive/negative analyzer tests pass.

Six more `AND Wn,Wn,#0xff` sites in these exports were intentionally left
unmarked: `0x242777978`, `0x2427b456c`, `0x2428b0174`, `0x242510f1c`,
`0x242856d74`, and `0x242784378`. Some reuse table-base registers across
intervening state updates; another changes temporary registers between the
two table reads. The current native slice matcher cannot prove these under
its straight-line register and pointer-slot conditions. It does not replace
them based on visual similarity.

This is a **partial deobfuscation**. CoreALD's mutable pointer tables and
authenticated `BRAA`/`BLRAA` successors remain unresolved. The pass does not
name the cipher, recover a license key, or decrypt an asset pack. Mapping a
CoreALD export to the Background Assets `decryptChunk` call requires separate
evidence from the runtime or correctly rebased chained fixups.
