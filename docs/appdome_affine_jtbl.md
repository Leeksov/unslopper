# Affine jump-table dispatch: proof boundary

`libloader` (Mach-O ARM64, SHA-256 `aa4ba77dc142c944b64fdbd8d3fb83a38b7e7200b13cb79422dc9da88cf10970`) contains Appdome-related strings and large functions with switch-based control-flow flattening. These strings support an Appdome association; they do not identify a product version or prove which component emitted every function.

In a representative function at `0x24A28`, the dispatcher computes a 32-bit selector from a raw state register:

```text
selector = (raw_state - 0x74A8A924) mod 2^32
switch (selector) { 84 cases; ... }
```

Case blocks install raw constants before returning to the dispatcher. The former jump-table path used zero-based case indices as raw states, so none of those installs could match. The new detector inverts the proven affine transform and retains a raw-state-to-target map only when the map is unique and at least two block-local installs match. It also prevents the Promon comparison-tree profile from reinterpreting a jump-table dispatcher.

## Why this sample stays unchanged

The `0x24A28` jump-table block is not merely a switch. Before the branch it writes several ordinary registers, including the state register after computing the selector. Redirecting a predecessor straight to a case target would skip those writes. The `0x92C04` dispatcher has the same kind of side effects. A clean-looking F5 listing cannot establish that these writes are dead on every rewritten path.

The emulated rewriter now requires a pure dispatcher before accepting any strategy-2 jump-table bridge, including the earlier identity-selector case. For affine selectors, it also requires the temporary selector register to be unused outside the dispatcher. Otherwise the map remains analysis evidence and no CFG edge is changed, even when the legacy mode is enabled. The full-resolution preflight and strict microcode verifier remain mandatory for accepted rewrites.

## Validation and limits

- The public IDA SDK 9.5 build and the standalone affine-map regression pass. The regression covers 84 synthetic cases, 32-bit wraparound, an XOR+ADD inverse, a pure selector shape, and rejection of extra dispatcher instructions or a live-out selector.
- On the side-effectful `libloader` functions studied, the safe result is unchanged F5 output. The map and profile diagnostic do not constitute a successful unflattening.
- No real-world *pure* affine jump-table fixture has yet demonstrated a full CFG rewrite. Behavior across other Appdome builds is unknown.

A future side-effect-preserving approach could clone the complete dispatcher computation for a proven single-state predecessor, then replace only the cloned jump-table terminator. That needs an independent proof that the clone preserves all register and memory effects, and an IDA regression showing that unresolved paths still reach the original dispatcher.
