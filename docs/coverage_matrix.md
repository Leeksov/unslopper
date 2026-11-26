# Unslopper coverage matrix

| Obfuscator / pass | Unslopper component | Status |
|---|---|---|
| Hikari CFF (scramble32 states) | profiles/ollvm.cpp + core | done |
| Classic OLLVM (sr-tream, Junod) | profiles/ollvm.cpp | done (same scramble32) |
| Promon SHIELD BST CFF + opaque | profiles/promon.cpp | done |
| Promon Android ARM32 Thumb CFF + encoded calls (Valu 10.5.3) | core/promon_thumb_audit.cpp (action 40) | read-only, hash-gated audit of two hubs; rewrite not validated |
| Appdome-associated affine jump-table CFF | core/dispatcher.cpp + core/jtbl_affine.h; opt-in core/stack_jtbl.cpp context path | [Exact state-map detection](appdome_affine_jtbl.md); [experimental context recovery](appdome_affine_context.md): 92 affine completions in a full F5 scan of 10,728 non-trampoline functions in one `libloader` build (36 within the original 188 strong-affine candidates, 56 outside). All plugin passes together touched 1,000 functions / 9,427 edges. Final-MBA effect deltas were audited in selected functions; all-path equivalence, full CFF removal, and other builds remain unverified. |
| Direct-state register jump-table CFF in `libloader` | core/stack_jtbl.cpp + audit-only plugin context | [Read-only state-map audit](appdome_identity_audit.md): original 502 heuristic candidates had 465 proved maps in two agreeing audit contexts. A signed-label revision on the same exact-SHA IDB audited those 502 plus 27 disjoint high-goto leads: 482/529 proved maps, including all 465 original proofs with identical state-to-target EAs. The 47 remaining rows were 33 unknown selectors, 7 without an identity dispatcher, 5 over the 128-case budget, and 2 with multiple dispatchers. Zero plugin CFG edits; no automatic identity rewrite, all-path equivalence, runtime reachability, or cross-build claim. |
| Appdome-associated register-BST CFF | core/dispatcher.cpp + core/cfg_rewriter.cpp | [Effect-boundary audit](appdome_bst_purity.md): a direct edge is allowed only when every identity-BST comparison node has no pre-branch effects. In one `libloader` image, 211 heuristic candidates all decompiled; 3 received 12 edge edits. Large side-effectful trees remain flattened. |
| DexProtector XOR+ADD CFF | profiles/dexprotector.cpp | done |
| BitGuard / MVG jump-table CFF | profiles/mvg.cpp | done |
| Substitution / MBA (Hikari full set) | mba_simplify.cpp | expand from docs/hikari_mba_rules.md |
| BitGuard SVC/syscall (X16 MBA) | svc_resolver.cpp + tools/apply_svc_map.py | done (offline applier verified) |
| **FairPlay `makeOpaque` (S-box/MBA/affine/opaque)** | **opaque_mba.cpp** | **done — verified on fairplayd.H2 (0 INTERR, _main 59→16)** |
| **FairPlay VM dispatch LUT (52,614 slots)** | **fairplay_dispatch.cpp (run arg 10)** | **done — 52,466 resolved / 44,700 unique, matches inventory** |
| **Arxan/branding-stripped MBA branch obf** | **mba_simplify.cpp + opaque_mba.cpp** | **core covered ((a^b)+2(a&b)→a+b); verifying on NianticLabsPlugin** |
| Arxan constant-target BR + reachability | C++ passes/arxan_branches + arxan_patterns | [60 TMX functions tested; JUMPOUT 60→4 versus existing passes](arxan_branch_analysis.md) |
| Genshin 7.1 relocated table branches | native `profiles/genshin.cpp` + `tools/yuanshen_unflatten_manifest.py` | [four independent functions tested in headless IDA: 10/10, 18/18, 3/3, and 2/2 sites](genshin_unflatten.md); other complete static manifests await IDA ownership |
| Arxan direct syscalls (X16, SVC #0x80) | svc_resolver.cpp (same as MVG) | reuse — same pattern |
| Arxan BRK #1 traps / __PII section | annotation (planned) | annotation, not deobf — pending IDB verify |
| OLLVM-22 BogusControlFlow | mba_simplify::eliminate_opaque_predicates | partial |
| OLLVM-22 Anti-Decompiler (adec) | anti_decompiler.cpp | TODO |
|   - indirectBr trampolines | resolve indirect jmp -> direct | TODO |
|   - aliasConfusion (ptrtoint chains) | fold ptr<->int round-trips | TODO |
|   - deadDecoy / fakeLoop opaque blocks | opaque-pred prune | TODO |
|   - asmGadgets / stackPollution / constLaunder | strip junk | TODO |
| OLLVM-22 Semantic Diffusion (volatile slots) | semantic_diffusion.cpp | TODO |
| OLLVM-22 Anti-Optimization Shield (volatile barriers) | semantic_diffusion.cpp | TODO |
| OLLVM-22 Virtual Call (synthetic vtables) | virtual_call.cpp | TODO |
| OLLVM-22 VM (bytecode virtualization) | unslop_vm_lift.py (standalone) | TODO — runtime-assisted |

## VM devirtualization — honest limits
The OLLVM-22 `vm` pass is a full custom bytecode VM (51 opcodes, 4 typed register
files, per-function opcode permutation, AES-128-CTR or LCG bytecode encryption,
optional per-slot register-value XOR, FNV-1a integrity, RDTSC anti-debug salt
corruption). See docs/ollvm22_vm_spec.md.

Fully-static devirtualization is blocked by:
- AES-128-CTR bytecode (key+nonce in .init_array) and ASLR-mixed LCG -> decrypted
  bytecode only exists at runtime.
- regEncrypt (per-slot value XOR) and salt corruption under anti-debug.

Therefore the lifter is RUNTIME-ASSISTED:
1. Statically locate __vm_engine, the 51 handler BBs, per-fn wrappers, and the 3
   globals (@fn.vm.bytecode / .ophandlers / .callees).
2. Dump the DECRYPTED bytecode + salt + regkey tables at runtime (after .init_array
   ctors run) via debugger/Frida read of the globals.
3. Reverse the opcode permutation from the ophandlers table (ptr -> handler BB ->
   logical VMOp), undo register-index XOR (slot ^ (salt&0xFF)).
4. Decode the ISA (docs/ollvm22_vm_spec.md) and lift bytecode -> C-like pseudocode.
