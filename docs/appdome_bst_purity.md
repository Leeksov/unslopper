# Register-BST dispatch: effect boundary in `libloader`

This audit concerns one ARM64 `libloader` image (SHA-256
`aa4ba77dc142c944b64fdbd8d3fb83a38b7e7200b13cb79422dc9da88cf10970`)
in IDA/Hex-Rays 9.5.0.261026. The 211 comparison-tree candidates came from
saved OFF pseudocode heuristics. They are **not** 211 structurally proven CFF
functions. In that text, 160 show at least eight literal comparisons and two
constant assignments of the same local, which is stronger evidence of a state
machine but still not a microcode proof.

## Why a direct edge can be wrong

The guarded emulated-BST rewriter connects a state-installing father directly
to the selected case block. That edge skips every comparison node on the
original route. The selector comparisons can be skipped once their values are
proven. Other instructions in those nodes cannot be skipped without a proof
that their effects are dead or reproduced on the direct route.

Read-only GLBOPT1 inspection found these shapes:

| Function | Dispatcher evidence | Effect that a direct edge could skip |
|---|---|---|
| `0x387714` | 1,395 microblocks. Max-predecessor block 4 has 375 predecessors, but is a two-move bridge; root block 5 compares `w8` with `0x5F2D84F1`. | Bridge copies `x23→x10`, `x21→x11`; root copies `x11→x21`, `x10→x23`, and `w8→w9` before its branch. |
| `0x4CB25C` | 569 microblocks. Root block 5 has 73 predecessors and compares `w8` with `0x662857DB`. | Root executes two extensions and twelve register-to-stack moves before its branch. |
| `0x49423C` | Root compares `w8` with `0x673E5BF4`. | Root stores `x21` into stack variable `%var_6A8`; later blocks read `%var_6A8`. The current guarded run made zero edge edits here, so this is a rejection rationale, not a demonstrated past wrong rewrite. |
| `0x53F9A0` | Root block 4 is branch-only, but the comparison tree is not. | A reachable internal node saves a value that a later case restores. See the trace below. |

For `0x53F9A0`, a read-only final-MBA inspection found node 710 at EA
`0x543538`: `mov v2.8→v107.8` precedes `jz v9,#0x5882D8EA`. Its fallthrough
reaches node 711, which tests `v9==0x58908706`; the taken path reaches case
1719 at EA `0x548ADC`. That case calls `sub_482D80`, installs the next state,
then executes `mov v107.8→v2.8` before returning to root 4. The saved value
is used on a reachable path. Bypassing node 710 to case 1719 could use a stale
`v107` value. The final MBA contained only these two `v107.8` references.

The new **identity/register-BST** gate therefore requires every comparison
node to contain only NOPs before its terminal branch. It leaves the separate
XOR/ADD selector-transform path unchanged. This is a conservative proof of
which instructions a direct edge skips; it does not make broader claims about
all paths or other Appdome builds.

## Bounded regression

The change was built with the official IDA 9.5 SDK and its C++ test passed.
In a disposable IDA database, all **211/211** comparison-tree candidates
decompiled, with **zero plugin errors**. The plugin reported 12 edges in three
functions: `0x35CE28` (10), `0x3A8AFC` (1), and `0x484BDC` (1). An earlier
build had reported 37 edges in five functions. The new gate also suppresses
`0x49423C` (previously 2) and `0x53F9A0` (previously 23). Every candidate had
the same `goto` and `switch` count as the saved earlier ON audit, including
the two suppressed functions. The comparison uses different disposable IDB
sessions; it is a coverage check, not a controlled semantic equivalence test.

All **188/188** strong affine state-switch controls also decompiled with zero
plugin errors and zero action-4 edge edits. Their `goto` and `switch` counts
matched the saved prior ON audit. This confirms that the register-BST guard did
not alter the tested affine controls; it does not prove the affine path's
semantics.

The large side-effectful trees remain flattened. Recovering them requires a
path-specific rewrite that preserves the pre-branch copies and calls. The IDA
9.5 SDK used here offers no supported atomic swap or rollback of a live
`mba_t`, so block insertion on a detached trial followed by live replay is not
yet a safe default completion method.
