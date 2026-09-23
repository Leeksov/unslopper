# CoreALD authenticated dispatch

## Scope and pointer format

The tested image is iOS 26.0.1 `CoreALD` 4.1.0, SHA-256
`247842d90546265eb6ced34fa18d83bc3d2eaaa3d4c1e79bb2cd3aab0e91f24f`.
Its 16 exports each have one authenticated indirect transfer in their
IDA-owned range: one `BRAA` and 15 `BLRAA`. Nine calls have one indexed
pointer-table load immediately before `BLRAA`; six have two. These
instructions authenticate control-flow pointers; they are not asset-cipher
instructions.

The on-disk entries use Apple's
`DYLD_CHAINED_PTR_ARM64E_SHARED_CACHE` (format 13) authenticated-rebase
layout. Bits 0–33 are the offset from shared-cache base `0x180000000` in
this image; bits 34–49 are `diversity`; bit 50 is `addrDiv`; bit 51 selects
IA or DA; bits 52–62 link the next fixup; bit 63 indicates authentication.
The inspected branch entries have `auth=1`, `addrDiv=0`, `keyIsData=0`, and
their diversity matches the immediate placed in `X17` before the branch.

## All export candidates

[`coreald_pac_scan.py`](../tools/coreald_pac_scan.py) follows each original
native byte-table slice, verifies its low-byte relationship for all 256
possible inputs, checks register liveness and table access, and evaluates
both indices where there are two levels. All 16 exports select the same
read-only root slot, `0x2790C42E8`, which points to table base
`0x28561CA20`. These are the decoded destinations from the input image:

| Export | Transfer | On-disk destination |
| --- | --- | --- |
| `_adMedklO` | `BLRAA` | `0x24252F794` |
| `_OZpDoyky` | `BLRAA` | `0x24252E50C` |
| `_FbLnABIk` | `BRAA` | `0x24252FBB4` when both arguments are non-null; `0x24252FBAC` otherwise |
| `_qENIaLkr` | `BLRAA` | `0x2428DFA3C` |
| `_xrPnDyPw` | `BLRAA` | `0x24252F794` |
| `_QSIlMWCo` | `BLRAA` | `0x24252E50C` |
| `_niaOacKH` | `BLRAA` | `0x24273AB98` |
| `_g4Bksweo` | `BLRAA` | `0x242856EF0` |
| `_SljH37Yp` | `BLRAA` | `0x24252E50C` |
| `_WJUddQgY` | `BLRAA` | `0x242A6D4A8` |
| `_cdHFeFDJ` | `BLRAA` | `0x242A6C508` |
| `_TBQFRWlW` | `BLRAA` | `0x242848358` |
| `_fyzGzQHg` | `BLRAA` | `0x242511324` |
| `_jYWQDEvI` | `BLRAA` | `0x242EAEF44` |
| `_CWeMQvFE` | `BLRAA` | `0x242511324` |
| `_bmXjyxfx` | `BLRAA` | `0x2428F9EC4` |

There are 17 pointer entries and 13 distinct destinations. The full
per-export site, index, entry, raw fixup, PAC modifier, and result are in the
[static evidence](evidence/coreald_pac_all_exports_26_0_1.json). The script
is read-only by default. `apply` adds comments with destination addresses
for manual navigation, and refuses to annotate if any export is unresolved.
It does not add IDA code xrefs or rewrite the original CFG.

```text
idat -A -S"/path/to/coreald_pac_scan.py exit" CoreALD.i64
idat -A -S"/path/to/coreald_pac_scan.py apply exit" CoreALD.i64
```

[`coreald_pac.py`](../tools/coreald_pac.py) remains a smaller, independent
check of two representative sites. Both scripts require the audited image
SHA-256 and reject changed native shapes or pointer fields.

## Emulator and device checks

Chomper 0.3.8 loaded the image but left its shared-cache chained pointers
as raw on-disk words. The [probe](../tools/coreald_chomper_probe.py) rebased
1,746 unauthenticated read-only slots **in emulator memory only**, provided
a synthetic stack-guard import and arguments, then stopped at each transfer.
All 17 observed target-register values and `X17` modifiers matched the
static report. This validates the index arithmetic under synthetic state;
Chomper did not execute or validate PAC branches. See the
[emulator evidence](evidence/coreald_pac_chomper_26_0_1.json).

The device's running `backgroundassets.user` process had CoreALD loaded.
A read-only Frida snapshot of its table after dyld fixups found all 17
entries pointed to the expected slid code addresses after stripping IA PAC.
Re-signing each stripped address with IA and the associated `X17` modifier
reproduced the stored pointer in 17/17 cases. A modifier changed by one bit
matched in 0/17 cases. See the [live snapshot](evidence/coreald_pac_live_26_0_1.json).
This confirms the table contents and PAC modifiers **at the snapshot time**.
It does not prove that a writable entry can never change or that any export
was invoked by a real asset download during the observation.

## Link to chunk decryption

`ManagedBackgroundAssetsHelper` names a `BADecryptLicenseChunk` function.
Its call at `0x1D1F9AE1C` reaches a shared-cache branch island which, in
the live process, branches to CoreALD export `_FbLnABIk`. The export's
non-null path enters `0x24252FBB4`, whose `BLRAA` table entry at
`0x2856488C0` points to `0x242A66658` with valid modifier `0xCC65` in the
device snapshot. That block ends at `0x242A66740` with `BRAA X9,X17`;
`X9` is derived from the caller-provided context. The context-dependent
branch is the next unresolved edge on the chunk path. Neither the asset
cipher nor a license key has been identified from these transfers.
