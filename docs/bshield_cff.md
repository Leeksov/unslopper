# BShield stack equality CFF

The September 2026 change extends the existing stack context planner to pure
`jz`/`jnz` chains using a 4- or 8-byte stack state. It does not add a protector
brand detector or identify virtual-machine opcodes.

The legacy detector predominantly searched register carriers; the inspected
BShield functions keep 64-bit constants in `mop_S`. Reusing the jump-table
planner preserves full-width values, handles conditional shared store tails and
avoids widening the older 32-bit transformed-BST assumptions.

Detection requires at least four distinct constants and a shared comparison
entry with at least three predecessors. Only otherwise-empty comparison blocks
become dispatcher boundaries. Payload branches and effects remain intact. Calls,
indirect stores and unknown writes invalidate facts. Planning rejects unresolved
selectors or excessive context growth before editing. The exact proposed graph
is verified on a detached serialization before live emission.

The existing `UNSLOP_NO_STACK_JTBL=1` disables this entire stack context engine,
including its equality fallback. The previous jump-table route is unchanged.
No target instruction bytes are modified.

Observed BShield corpus, IDA 9.4.0.260714:

| Function | Lines off | Lines on | Repeated on |
|---|---:|---:|---:|
| `0x3A95B4` | 102 | 61 | 61 |
| `0x28F444` | 89 | 22 | 22 |
| `0x11970` | 136 | 61 | 61 |
| `0x2A233C` | 164 | 29 | 29 |
| `0x2A15A4` | 342 | 99 | 99 |
| `0xC874` | 53 | 13 | 13 |
| `0x4DCC` negative control | 4 | 4 | 4 |

All 21 graphs passed strict microcode verification. BShield fixture and recovery
evidence live in [bshield-research](https://github.com/Leeksov/bshield-research).
`tests/bshield_cff.py` is the repeatable IDAPython corpus harness. This local run
used the existing GUI instance; a separate headless process could not obtain a
license. Structural validity and this small corpus do not establish full
semantic equivalence or a cross-protector regression guarantee.
