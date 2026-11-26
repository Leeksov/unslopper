# Affine jump-table context recovery (experimental)

**Current status: experimental and opt-in.** Set `UNSLOP_AFFINE_CONTEXT=1`
before starting IDA to enable this path. The first bounded trial edited 35 of
188 strong affine candidates; a later full non-trampoline scan found 92
affine-context completions. Both trials concern one exact image. Neither
establishes all-path equivalence or complete CFF removal.

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
functions in `libloader`, let alone all Appdome variants. The full inventory
and F5 comparison below cover the remaining non-trampoline functions, while
other CFF forms and behavior on all paths remain unproved. The context mode
remains opt-in.
`tests/appdome_affine_context_ida.py` provides a sample-hash-gated manual
OFF/ON/repeated-F5 regression on a disposable IDB; the binary is not in this
repository.

## Full non-trampoline scan

The later opt-in scan used the same ARM64 image identified above and
IDA/Hex-Rays 9.5.0.261026. An inventory found **76,263 IDA-defined
functions**. Structural and byte-template checks identified **65,535 uniform
88-byte resolver trampolines**; they were not each F5-decompiled. The
remaining **10,728 functions were all attempted** with the combined plugin
(build SHA-256
`1c39dca771c302f567d0f750ce9e13040aa05889efddda6e096c9c25fdc0650d`)
and `UNSLOP_AFFINE_CONTEXT=1`, in 314 bounded batches. The OFF comparison used
the same image.

| Full-scan measure | Result |
|---|---:|
| ON F5 successes / attempts | 10,711 / 10,728 |
| ON F5 failures matching OFF failures | 17 / 17 |
| ON-only F5 failures | 0 |
| Plugin internal errors after every batch | 0 |
| Functions touched by all plugin passes | 1,000 |
| Edges reported changed by all plugin passes | 9,427 |
| Affine-context completions (`stack.reason=complete`) | 92 |
| Affine completions inside / outside the original 188-candidate set | 36 / 56 |

The 1,000 touched functions and 9,427 edges include **all** enabled passes;
they are not counts of affine-context rewrites. The 188-candidate classifier
was a strong-affine heuristic, not a complete inventory: 56 context
completions lay outside it. F5 success only means Hex-Rays produced
pseudocode, and the plugin's edge counter is a diagnostic, not an independent
proof that the transformed machine code has equivalent behavior.

At final `cfunc.mba` maturity 8, an OFF/ON effect audit reviewed **53
high-tier action-4 deltas, 5 small-switch context completions, and 10 other
complex context completions**, including all 56 affine completions outside
the initial candidate set. Recursive call, indirect call, store, and external
effect origins were compared, with repeat ON F5. Most audited multisets
matched. The exceptions required individual review: `0x13E374` and
`0x252694` lost synthetic default abort calls after their bounded selector
cases were mapped; `0x1B65B8` copied one native store into mutually exclusive
successors. A selected trial on this experimental build recorded an F5
readability regression at `0x33BE68` (86 lines / 0 `goto` to 186 lines / 1
`goto`) and a different final-MBA representation of 24 bytes of local stack
zeroing. That observation belongs to this trial; it is not an established
regression in the current public plugin. In a later paired control using fresh
copies of the same saved IDB, IDA 9.5 and the v1.6.0 macOS ARM64 release build,
OFF and ON F5 at `0x33BE68` were byte-identical on both the first and a forced
repeat decompilation: 183 lines, 1 `goto`, SHA-256
`3bb114fd7c378b85fa455ce14ad94cb1e6ba62b240daa68466d1d41f6b4d4f1a`.
The discrepancy could reflect a build or IDB state difference; the saved
experimental trial does not isolate its cause.

The SDK does not expose a supported atomic swap or rollback of a live MBA.
The detached preflight reaches GLBOPT2, then the accepted edit is replayed in
the live array; the preflight cannot certify GLBOPT3 or final F5. A previous
uncapped trial produced a bulk-only `INTERR 50342` at `0x25CA34`; the current
128-case cap excludes it. The full-scan observations apply only to this exact
sample and tested build. **They do not show that all CFF has been decrypted or
prove all-path equivalence.**
