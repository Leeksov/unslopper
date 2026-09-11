# iXGuard stack-state jump-table recovery

`src/core/stack_jtbl.cpp` adds a separate GLBOPT1 pass for jump-table CFF with
a scalar stack selector. It runs before the older comparison-tree pipeline.
It does not require an application hash, hardcoded addresses, or runtime keys.

## Why the previous path kept SNBMobile flattened

The older driver deliberately skips comparison trees with fewer than four
dispatcher blocks. A 35-case jump table occupies one block. Its history
resolver also transports the carrier value but loses intermediate registers
at shared state-store blocks. Raising the duplication budget or disabling the
commit guard does not fix that information loss.

The new pass builds a finite graph of `(original block, relevant constants)`:

1. Find one stack-selector jump table with at least four explicit cases and
   three incoming edges. Preserve default behavior by refusing specialization
   if any reachable selector is unknown or outside the explicit cases.
2. Compute backward scalar demand up to the next dispatch. Application branch
   predicates are not added to demand, and real conditionals are retained.
3. Propagate only demanded register/stack constants. Never read globals from
   the IDB as constants. Calls, indirect stores and opaque assembly invalidate
   facts. Overlapping writes invalidate old facts; masked reads can recover
   known bytes without inventing unknown upper bits.
4. Build the entire context graph before editing. Refuse unsupported exits,
   multiple dispatchers, nonconvergent demand, or excessive growth (4096
   contexts, at most 16 times the input block count; input cap 2000 blocks).
5. Copy original instructions into the context graph and replace proven
   dispatcher edges with direct gotos. No application instruction, RASP test,
   call or trap is manually erased. Conditional fallthrough bridges preserve
   Hex-Rays' physical successor ordering. Let Hex-Rays perform its own DCE.
6. Emit and strictly verify the exact plan on a detached serialized microcode
   snapshot before applying it to the live array. Rejection leaves the live
   array unchanged. The normal plugin verifier also checks the final result.

`UNSLOP_NO_STACK_JTBL=1` disables this pass for diagnosis. Existing CFF/MBA
passes retain their behavior. A zero-case decompilation is evidence of removal
of the selected dispatcher, not a proof of complete deobfuscation of the app.

## Regression fixture

SNBMobile SHA-256:
`a256ae2b4b296f675c268d10dfcd06cfd64b43f6c7f938d95684c223523ea389`.

| Function VA | Original cases | Remaining cases |
|---|---:|---:|
| `0x100221240` | 35 | 0 |
| `0x1000053AC` | 71 | 0 |
| `0x100007F2C` | 40 | 0 |
| `0x100009878` | 36 | 0 |
| `0x10000B984` | 65 | 0 |

Run `tests/ixguard_unflatten.py` with headless IDA 9.4 and a disposable database
copy. The harness exports OFF/ON pseudocode, checks repeatability for eleven
functions, asserts complete dispatcher removal on the five fixtures, retains
crash/call anchors, and checks a simple non-CFF function is unchanged. A
negative test replaces the initial zero state with an unknown register value
in the copy: the dispatcher must remain. Original bytes are restored in a
`finally` block. This is static verification; target code is not executed.

Residual MBA, string decoding, lazy API tables, fragmented functions and
register/BST dispatchers require their own passes. Do not report these five
fixtures as a whole-binary coverage percentage.
