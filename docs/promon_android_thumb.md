# Promon Android ARM32 audit (Valu 10.5.3)

This is a **read-only** audit for the corrected ARM32 ELF from Valu
`com.efgh.customer` 10.5.3. It does not deflatten or modify an IDB. The input
SHA-256 must be
`776e99e7b60bf9803f7ed59afc46907e6a3e8d3c9a198a9b4ec101675d0406b0`.
The original APK library and intermediate code-only ELF are deliberately
rejected; the audited input includes constructor-decoded data as well as the
seven table-listed code chunks.

Run plugin action `40` with `UNSLOP_PROMON_THUMB_AUDIT=1`. The action checks the
input hash, 32-bit ARM processor, Thumb `T=1` at each site, exact native-byte
fingerprints, at least 20 incoming code references to each hub, and a verified
constant-state predecessor edge. It prints the result to IDA's output window.
It also fingerprints an encoded indirect-call helper and one producer. It
changes no bytes, types, function boundaries, xrefs, microcode, or CFG edges.

| Function | Hub | Incoming code refs | Example state backedge | Evidence |
|---|---:|---:|---|---|
| `0x4655EC` | `0x465654` | 42 | `0x466504`: `R0=0x18555161; B.W hub` | `R0` selector, `CMP` tree, 690 IDA BB |
| `0x1FA036` | `0x1F92EA` | 132 | `0x1FA1D8`: `R0=0x32094048; B.W hub` | `R0` selector, `CMP` tree, 610 IDA BB; multi-chunk function |

These are control-flow-flattening candidates with strong local structural
evidence. A high predecessor count alone is insufficient: `0x2B4AFC` has 4,000
IDA blocks but maximum indegree 3; `0x2DE6D2` has 1,945 blocks and indegree 3;
`0x2428B8` reaches indegree 13 but does not pass this audit's threshold. The
old Promon profile models a different ARM64 register-pool BST shape and must
not be assumed to recover these ARM32 graphs.

The helper at `0x451E40` XORs two descriptor words before an indirect `BLX`;
`0x4657E8` writes one `(target ^ key, key)` pair. The audit reports their
byte-anchored presence only. It neither resolves every call target nor folds
the return-value masks in adjacent wrappers.

Two local arithmetic sequences at `0x470598–0x4705B2` and
`0x470D20–0x470D60` both compute final `R3 = input R3 - 1` modulo `2^32`
(proved as bit-vector identities). They are **not rewritten**: intermediate
flags, register writes and liveness need a separate proof at every site. The
first successor overwrites flags before its comparison; this observation does
not justify a universal replacement rule.

Validation: `python3 tests/test_promon_thumb_audit.py /absolute/path/to/the/ELF`
checks the audited input hash, four byte windows, Thumb state writes and
branches, and comparison instructions. Live IDA read-only checks confirmed
`T=1`, 42/132 incoming code references, and both predecessor branches. The
C++ plugin build requires an IDA SDK, and the full optimizer requires a
matching Hex-Rays interface. The Python test does not substitute for a
compiled plugin smoke test.

If the plugin was built with an older Hex-Rays interface than the installed
decompiler, setting `UNSLOP_PROMON_THUMB_AUDIT=1` before IDA starts enables an
**audit-only** plugin context. It accepts action `40` and installs no optimizer,
Hex-Rays callback or microcode handler. Other actions and F5 transformations
remain unavailable in that context; use a matching SDK for the full plugin.
In the validated setup, the supplied SDK advertised Hex-Rays broadcast version
`5` while the installed IDA 9.5 decompiler answered version `6`. The compiled
audit-only context loaded through IDA MCP, reported both hubs and the encoded
call anchor, and rejected action `3`; without the environment gate it did not
load. This smoke test verifies the diagnostic action, not the legacy optimizer.

When the C++ plugin cannot be built, the matching read-only IDAPython fallback
is `tools/promon_thumb_audit.py`. Explicitly run it in the corrected ELF's IDA
database with IDA's Script file action or a configured IDA tool. It uses the same
sample, architecture, Thumb, native-byte and xref gates as action `40`. This
fallback is an audit, not a CFG transformation or a substitute for a future
compiled-plugin validation.
