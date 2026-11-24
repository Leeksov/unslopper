# Genshin 7.1 native table-branch profile

Genshin's 7.1 `libyuanshen.so` contains many local control-flow transfers of
the form `CSEL/CINC/CSINC/CSET → ADRP/ADD → LDR X8,[X8,W9,UXTW/SXTW #3] → BR X8`, plus
fixed relocated pointer loads ending in `BR X8` (with or without an intervening
`ADD` after `ADRP`). A smaller group uses a Boolean index multiplied by a
8–256 byte record stride before `LDR X8,[X8,X9]` (or scaled `X9`) and `BR X8`.
Its index is proven Boolean by a bounded `CSET`, `AND #1`, or one-bit mask
slice. In the audited function
`sub_6A44C1C`, IDA recognized only four entries of a 16-entry table. Hex-Rays
therefore emitted 15 lines and discarded most of the function before the usual
Unslopper `optblock_t` pass could see it. The same failure shape appeared at
`0x6345E50`, where IDA recorded one case for a 22-entry table.

The separate `genshin` profile is a **native prepass** in `src/profiles/`.
It is registered in `all_profiles()` but deliberately skipped by the generic
microcode CFF engine. Actions `30` and `31` inspect or apply one complete
offline-generated manifest. Applying changes only the IDB's final `BR X8`
instruction and its xrefs. All earlier selector and pointer-load instructions
remain in place, preserving their register and flag effects. The ELF is never
patched.

## Prepare and run

Generate a manifest for a fully inventoried unwind range:

```sh
python3 tools/yuanshen_unflatten_manifest.py /path/to/libyuanshen.so 0x6A44C1C /tmp/genshin-6a44c1c.json
```

This generator needs `numpy`, `pyelftools`, and `capstone`. It uses Android's
packed `APS2` relocations to recover the table contents, then verifies the
input hash, every original `BR X8` in the unwind range, the selector's two
constant indices or fixed pointer slot, aligned in-range targets, branch
encoding, and the absence of native direct/table entries into the middle of
a selector slice. It refuses partial coverage.

Build Unslopper with IDA SDK 9.5. In IDA, first disable autoanalysis, open the
matching IDB, and run from the IDAPython console:

```python
import os, ida_loader
os.environ["UNSLOP_GENSHIN_MANIFEST"] = "/tmp/genshin-6a44c1c.json"
ida_loader.load_and_run_plugin("unslopper", 30)  # validate; no IDB edit
ida_loader.load_and_run_plugin("unslopper", 31)  # IDB-only apply
```

Without the environment variable, actions `30`/`31` open a file chooser. The
plugin rechecks the IDB's input SHA-256, complete function ownership and
bounds, original 36-byte instruction contexts, relocated table slots, current
opcodes, incoming/outgoing code xrefs, and coverage of all original `BR X8`
sites **before** applying anything. It rejects a function that IDA has not
fully defined. Refresh F5 and review the result before saving the IDB.

## Evidence and limits

The pinned 7.1 sample has SHA-256
`9d59283b3235ba5afe3f220d952133b9dbad49af6e88da16ae03ff6e3289171e`.
The offline analyzer recovered 24,068 two-way indexed, 41,234 fixed-target,
134 Boolean strided-table, and 18 Boolean-index single-instruction proposals
in `.text`, covering 65,454 of its 67,492 `BR X8` words. These are static
candidates, not a license to patch the whole library. In 2,052 unwind ranges with at least
four `BR X8` words, every such
site has a static proposal; IDA ownership still needs checking. In the three
individually audited unwind ranges, the manifests cover
all BR sites: 10/10 at `0x6A44C1C`, 18/18 at `0x6345BCC`, and 41/41 at
`0x6558024`. A fourth SXTW-heavy range, `0x5DA3C80`, has 208/208 static
proposals, but the copied IDB has not defined its complete function, so the
native profile correctly refused to patch it.

The remaining 2,038 `BR X8` words are outside this local proof: 1,236 have
a relative-switch instruction shape, 264 use an indexed load without a proven
one-edge fallthrough/constant selector, seven use a strided table without a
proven Boolean index, and 531 have other shapes. No rewrite is proposed for
them. Among the 531 miscellaneous sites, 437 are in the early engine portion
of `.text`; sampled examples are callbacks, virtual tail calls, or compiler
switches.
Most `BR X16` sites in `.text` are direct veneers into `il2cpp` or `.plt`,
and sampled `BR X3–X7` sites are dynamic callback/virtual-method tail calls;
they are outside the Genshin profile's scope.

A headless IDA 9.4 run on a disposable, pre-patch copy of the 7.1 IDB
validated 10/10 sites, applied them, and confirmed repeat application made
zero changes. The recovered F5 output grew from 15 to 567 lines with no
`JUMPOUT`; five further F5 runs converged to identical text after the first
post-patch type-refinement pass. An independent second function,
`sub_6345BCC`, recovered 18/18 sites and F5 grew from 37 to 447 lines.
Both tests rejected a tampered late table slot before any patch and produced
stable repeated F5 output. The tests never executed target code.

A third headless copy validated a long-slice strided case at `sub_65DB634`:
3/3 branches recovered, F5 21→54 lines, a tampered manifest rejected, and
stable repeated F5 output. The C++ profile accepts `CBZ/CBNZ X9` only when
the offline proof has shown the retained index is exactly zero or one stride.
A fourth copy tested a Boolean `W9` index at `sub_5FE8EA8`: 2/2 sites
rewritten, F5 71→67 lines, no new `JUMPOUT`, a tampered manifest rejected,
and stable repeated F5. That function already decompiled before the rewrite,
so this is a cleanup case rather than a recovered missing body.

The pointer tables are in writable `.data`. No static evidence proves they
remain unchanged at runtime; this is an IDB analysis view and not a runtime
or executable-binary equivalence claim. A function's next unwind entry is
also only a candidate boundary until IDA defines and owns every target.
