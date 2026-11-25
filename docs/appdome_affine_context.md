# Affine jump-table context recovery (experimental)

**Current status: experimental and opt-in.** Set `UNSLOP_AFFINE_CONTEXT=1`
before starting IDA to enable this path. A final-maturity microcode audit of
all 35 edited functions found three differences that required manual
classification; they are described below. The audit supports a bounded result
on one exact image, not all-path equivalence or complete CFF removal.

Unslopper can analyze an Appdome-marked ARM64 `libloader` whose SHA-256 is
`aa4ba77dc142c944b64fdbd8d3fb83a38b7e7200b13cb79422dc9da88cf10970`.
The observed protection has a 32-bit state register and a jump-table selector
such as `xdu(w9 - constant)`. Some dispatchers also copy registers and update
the state before the branch. A direct predecessor-to-case edge would skip those
instructions, so the ordinary jump-table rewriter declines these functions.

The context path recognizes an exact `m_xdu(m_add/sub(raw32, immediate32))` selector
and builds a bounded graph of `(original block, known state facts)` contexts.
Each context clones the **complete** original block; a dispatcher clone keeps
every pre-branch instruction and replaces only its proven `m_jtbl` target with
a direct edge. Unrelated switches keep their case tables, remapped to context
targets. Calls or unknown external effects invalidate state facts, and an
unmapped or unknown selector rejects the entire rewrite. A primary table with
more than 128 cases is skipped before the context trial; the context graph is
also capped at 2,048 nodes and twelve times the original block count.

The proposed graph is emitted first into a detached serialized microcode
array. The plugin verifies it, asks Hex-Rays to optimize through **GLBOPT2**,
and rejects a failure, early STOP, or reachable selected dispatcher. Only then
does it replay the same edit in the live array. This preflight does **not**
certify GLBOPT3, local-variable allocation, or final F5. It is necessary:
`mba->verify(true)` alone accepted a graph for `0x24A28` that later raised
`INTERR 50342`. With the downstream trial, that function stays unchanged and
F5 succeeds on the tested image.

## Bounded evaluation

Using IDA/Hex-Rays 9.5.0.261026, 188 functions classified as strong affine
switch candidates were decompiled on a disposable copy of this exact image.
All 188 decompiled with the opt-in path; no live INTERR was observed. The
plugin reported edits in **35 distinct functions**:

An earlier uncapped probe had one bulk-only F5 failure at `0x25CA34`
(172 cases), followed by successful singleton retests. The final probe's
128-case cap skips that function before context construction; it and the
250-case `0xD68E8` remained unchanged on repeated F5. The exact trigger of
the earlier failure was not isolated, so the cap and finite successful batch
are not a universal guarantee.

| Result among edited functions | Count |
|---|---:|
| No remaining `goto` or `switch` in F5 | 9 |
| Fewer `goto` or `switch`, with no increase in either | 25 |
| Fewer lines and `goto`, but one additional ordinary `switch` | 1 |

The other 153 candidates had no reported edge rewrite. All 35 edited
functions produced the same `goto` and `switch` counts on a second F5.
An initial GLBOPT1 origin comparison was insufficient because it can precede
the rewrite. A second audit inspected each actual final `cfunc.mba` after OFF
and ON F5. Calls, indirect calls, memory stores and external effects had
identical recursive opcode/source-address multisets in 32 of 35 functions.
The other three were resolved with additional destination and CFG checks:

- `0x2C2E50`: `m_stx` at `0x2C2F50` becomes a one-byte local-array assignment
  at the same EA. Both forms write the same stack slot (`[xsp+B6h]`), with the
  high byte of the same loaded halfword; the local buffer is passed to the
  subsequent call.
- `0x97138`: the missing `m_call` at `0x971D0` is the synthetic default
  `abort()` of the primary 32-case CFF switch. The context planner maps every
  reachable selector state to cases 0–31 in its bounded model and removes
  that default. The application-call origins remain equal.
- `0xB9C5C`: stores at `0xB9F2C` and `0xBA4E4` each appear twice in ON
  microcode because context specialization copies them into the two mutually
  exclusive successors of a conditional block. The same write expression
  runs once along either selected path.

These checks do not prove equivalent behavior for every possible input or
another Appdome build. The mode remains opt-in.

Representative measurements:

| Function | F5 without plugin | F5 with opt-in context path |
|---|---|---|
| `0x691DC` | 73 lines, 5 `goto`, 1 `switch` | 28 lines, 0 `goto`, 0 `switch` |
| `0x2BD47C` | 92 lines, 5 `goto`, 1 `switch` | 42 lines, 0 `goto`, 0 `switch` |
| `0x1140B4` | 92 lines, 5 `goto`, 1 `switch` | 40 lines, 0 `goto`, 0 `switch` |
| `0xC2EF8` | 100 lines, 5 `goto`, 1 `switch` | 47 lines, 2 `goto`, 0 `switch` |
| `0x24A28` | 863 lines, 86 `goto`, 2 `switch` | unchanged; downstream trial rejects it |

These are sample-specific results. They do not establish recovery of all CFF
functions in `libloader`, let alone all Appdome variants. The remaining
non-stub functions and other CFF forms require separate coverage and behavior
checks. The context mode is intentionally opt-in while that work continues.
`tests/appdome_affine_context_ida.py` provides a sample-hash-gated manual
OFF/ON/repeated-F5 regression on a disposable IDB; the binary is not in this
repository.
