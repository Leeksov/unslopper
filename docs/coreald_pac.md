# CoreALD authenticated indirect transfers

This note concerns the iOS 26.0.1 `CoreALD` sample named in
[the byte-dispatch report](coreald_sbox.md). The sample has 16 exported
functions. Each has one authenticated indirect transfer in its IDA-owned
range: one `BRAA` and 15 `BLRAA`. Nine calls have one indexed pointer-table
load immediately before `BLRAA`; six have two. These instructions
authenticate a pointer with the IA key and the modifier in `X17` before branching or calling. They
are control-flow operations; they do not identify the asset cipher.

The on-disk table entries here use Apple's
`DYLD_CHAINED_PTR_ARM64E_SHARED_CACHE` (format 13) authenticated-rebase
layout. Bits 0–33 give an offset from the shared-cache base (`0x180000000` in
this sample), bits 34–49 give `diversity`, bit 50 is `addrDiv`, bit 51 chooses
the data or instruction key, bits 52–62 link the next fixup, and bit 63 is
`auth`. All three inspected branch entries have `auth=1`, `addrDiv=0`, and
`keyIsData=0`. Their `diversity` equals the immediate loaded into `X17`.

## Audited paths

| Export / site | Native index evidence | On-disk candidate destinations |
| --- | --- | --- |
| `_FbLnABIk` / `BRAA` `0x24252FBA8` | `CSET` from the null checks makes `W8` 0 or 1. `ORR` creates 0 or `0x12`; indexing starts at `0x10A1`. The read-only slot at `0x2790C42E8` points to table base `0x28561CA20`. | `0x24252FBB4` or `0x24252FBAC`; both entries have diversity `0x869D`, matching `X17`. |
| `_CWeMQvFE` / `BLRAA` `0x242B7EF48` | The already verified first byte-permutation result is `0xE8`, so `X12` reads the same table-base slot at index `0xE8 + 0x61 = 0x149`. The final low-byte relation is `x ^ outer[inner[x] ^ 0x88] = 0xC4` for every byte `x`. `ADD W8,#0x56F1,W8,UXTB` therefore selects table index `0x57B5`. | `0x242511324`; the entry has diversity `0xE74D`, matching `X17`. |

The values above are **on-disk candidates**, not proven runtime edges. The
pointer table at `0x28561CA20` is in an IDA segment with read and write
permissions. A runtime store could change an entry before a transfer. The
on-disk fixup also does not by itself prove that pointer authentication
succeeds in a running process. The remaining 14 export transfers have not
been traced to unique destinations; six have an extra indexed table load.
The candidate at `0x242511324` is a 192-byte block that ends in another
`BRAA X0,X17` at `0x2425113E0`. Its target is computed from the call context,
so this first recovered call does not yet expose the chunk-decryption routine.

[`tools/coreald_pac.py`](../tools/coreald_pac.py) checks the native instruction
shapes, the input image SHA-256, the previously verified byte-permutation
proof, the 256-byte relation at the final call, pointer-slot values,
authenticated pointer fields, and executable destination mappings. It
reports the candidates without modifying the IDB. `apply` adds comments
containing destination addresses for manual navigation. It does **not** add
IDA code xrefs or rewrite the original CFG.

```text
idat -A -S"/path/to/coreald_pac.py exit" CoreALD.i64
idat -A -S"/path/to/coreald_pac.py apply exit" CoreALD.i64
```

The isolated IDA 9.4 report and apply runs both completed on a copy of the
database. The report produced the two paths and three candidates above. A
runtime trace or a proof that the pointer table cannot be modified is needed
before converting any candidate into a static CFG edge.
