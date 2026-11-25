# Emulated CFG rewrite postcondition

The emulated dispatcher rewriter has a cheap, non-mutating feasibility check. A check can predict that every father will resolve and still leave a real path into the dispatcher after block splitting. The old implementation could then emit a partly rewritten CFG that passed Hex-Rays' structural verifier but made F5 less readable.

The rewriter now serializes the current microcode into a detached trial MBA, applies the complete rewrite there, runs strict `verify(true)`, and traverses the final successor graph from the entry. It commits to the live MBA only if **every designated dispatcher block is unreachable**. Unreachable self-cycles are allowed; any surviving goto, fallthrough, or indirect path to a dispatcher rejects the trial without changing the live graph. Explicit `UNSLOP_NO_GUARD=1` remains a diagnostic override and should not be used as a normal recovery setting.

## Evidence and limits

- In `libloader` (ARM64 Mach-O, SHA-256 `aa4ba77dc142c944b64fdbd8d3fb83a38b7e7200b13cb79422dc9da88cf10970`), `0x252E74` previously reported 29 rewritten edges but left five predecessors of the dispatcher. On a fresh disposable IDB, F5 changed from 4 to 21 `goto` statements. The new trial rejects this rewrite; repeated F5 keeps 4 `goto` statements and reports zero committed edges.
- `0x22CCE8` likewise remains unchanged instead of exposing additional gotos. This deliberately suppresses some partial visual gains too: `0x256058` stays flattened because its dispatcher remains reachable.
- Full removal still works on a tested function: `0x194F4C` went from two switches to zero with 31 committed edge changes. Both direct callee names remained present in the paired listing.

The detached trial and microcode verifier establish graph integrity and dispatcher unreachability. They do **not** prove semantic equivalence for every input or measure all Appdome families. The postcondition is exercised by a standalone CFG fixture with a surviving goto/fallthrough, an unreachable self-cycle, a reachable secondary dispatcher node, and malformed edges.
