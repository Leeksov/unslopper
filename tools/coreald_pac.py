"""Report two audited on-disk CoreALD arm64e authenticated transfers.

Run in IDA on the iOS 26.0.1 CoreALD image. Reporting is read-only; pass
``apply`` to add comments with addresses for manual navigation. The target
table is writable in the IDB, so this does not add misleading static xrefs,
change machine bytes, or replace BRAA/BLRAA instructions.
"""

from __future__ import annotations

from dataclasses import dataclass


CACHE_BASE = 0x180000000
SAMPLE_BRANCHES = (0x24252FBA8, 0x242B7EF48)


@dataclass(frozen=True)
class AuthRebase:
    target: int
    diversity: int
    addr_div: int
    key_is_data: int
    next: int


def decode_shared_cache_auth_rebase(raw: int, cache_base: int = CACHE_BASE) -> AuthRebase | None:
    """Decode format 13 from Apple's mach-o/fixup-chains.h.

    The format has no bind bit. `auth=1` selects the authenticated rebase
    layout; `keyIsData=0` uses IA, while `keyIsData=1` uses DA.
    """
    if raw < 0 or raw >= 1 << 64 or not raw >> 63:
        return None
    return AuthRebase(
        cache_base + (raw & ((1 << 34) - 1)),
        (raw >> 34) & 0xFFFF,
        (raw >> 50) & 1,
        (raw >> 51) & 1,
        (raw >> 52) & 0x7FF,
    )


def decode_shared_cache_rebase(raw: int, cache_base: int = CACHE_BASE) -> int | None:
    if raw < 0 or raw >= 1 << 64 or raw >> 63:
        return None
    if ((raw >> 34) & 0xFF) or ((raw >> 42) & 0x3FF):
        return None
    return cache_base + (raw & ((1 << 34) - 1))


def _assert_native(image, ea: int, mnemonic: str, *operands: str) -> None:
    assert image.mnem(ea) == mnemonic, hex(ea)
    for i, operand in enumerate(operands):
        assert image.operand(ea, i).upper() == operand.upper(), hex(ea)


def _check_entry(image, ea: int, expected_raw: int, modifier: int) -> int:
    assert image.mapped(ea, 8), hex(ea)
    raw = int.from_bytes(image.read(ea, 8), "little")
    assert raw == expected_raw, hex(ea)
    record = decode_shared_cache_auth_rebase(raw)
    assert record is not None and record.diversity == modifier
    assert record.addr_div == 0 and record.key_is_data == 0
    assert image.executable(record.target, 4), hex(record.target)
    return record.target


def analyze_null_dispatch(image) -> tuple[int, ...]:
    """Prove `_FbLnABIk`'s two null-dependent BRAA destinations."""
    site = 0x24252FBA8
    _assert_native(image, 0x24252FB7C, "CMP", "X0", "#0")
    _assert_native(image, 0x24252FB80, "CCMP", "X1", "#0", "#4")
    _assert_native(image, 0x24252FB84, "CSET", "W8", "EQ")
    _assert_native(image, 0x24252FB88, "LSL", "W9", "W8", "#1")
    _assert_native(image, 0x24252FB8C, "ORR", "W8", "W9", "W8,LSL#4")
    _assert_native(image, 0x24252FB90, "MOV", "W9", "#0X10A1")
    _assert_native(image, 0x24252FB94, "ORR", "W9", "W8", "W9")
    _assert_native(image, 0x24252FB98, "ADRP", "X8")
    _assert_native(image, 0x24252FB9C, "LDR", "X8", "[X8,#0X2E8]")
    _assert_native(image, 0x24252FBA0, "LDR", "X9", "[X8,W9,UXTW#3]")
    _assert_native(image, 0x24252FBA4, "MOV", "X17", "#0X869D")
    _assert_native(image, site, "BRAA", "X9", "X17")
    slot = 0x2790C42E8
    assert image.readonly(slot, 8)
    table = decode_shared_cache_rebase(int.from_bytes(image.read(slot, 8), "little"))
    assert table == 0x28561CA20
    # W8 is 0 or 1; (W8 << 1) | (W8 << 4) is 0 or 0x12.
    entries = ((0x10A1, 0x80121A74C252FBB4),
               (0x10B3, 0x80121A74C252FBAC))
    return tuple(_check_entry(image, table + index * 8, raw, 0x869D)
                 for index, raw in entries)


def analyze_sbox_call(image) -> tuple[int, ...]:
    """Prove `_CWeMQvFE`'s final BLRAA through two byte permutations."""
    site = 0x242B7EF48
    _assert_native(image, 0x242B7EDC8, "ADRL", "X10")
    assert image.operand_value(0x242B7EDC8, 1) == 0x2790C38A0
    _assert_native(image, 0x242B7EE6C, "AND", "W12", "W12", "#0XFF")
    _assert_native(image, 0x242B7EE70, "ADD", "W12", "W12", "#0X61")
    _assert_native(image, 0x242B7EE74, "LDR", "X12", "[X10,W12,UXTW#3]")
    assert "QWORD_2790C5880" in image.operand(0x242B7EF10, 1).upper()
    assert "QWORD_2790C4FD0" in image.operand(0x242B7EF24, 1).upper()
    _assert_native(image, 0x242B7EF14, "ADD", "X9", "X9", "W8,UXTB")
    _assert_native(image, 0x242B7EF18, "LDURB", "W9", "[X9,#-0XC]")
    _assert_native(image, 0x242B7EF1C, "MOV", "W11", "#0X88")
    _assert_native(image, 0x242B7EF20, "EOR", "W9", "W9", "W11")
    _assert_native(image, 0x242B7EF28, "ADD", "X9", "X10", "X9")
    _assert_native(image, 0x242B7EF2C, "LDURB", "W9", "[X9,#-0XC]")
    _assert_native(image, 0x242B7EF30, "EOR", "W8", "W9", "W8")
    _assert_native(image, 0x242B7EF34, "MOV", "W9", "#0X56F1")
    _assert_native(image, 0x242B7EF38, "ADD", "W8", "W9", "W8,UXTB")
    _assert_native(image, 0x242B7EF3C, "LDR", "X8", "[X12,W8,UXTW#3]")
    _assert_native(image, 0x242B7EF44, "MOV", "X17", "#0XE74D")
    _assert_native(image, site, "BLRAA", "X8", "X17")
    # Retain the first selected table base and byte source until their uses.
    for ea in range(0x242B7EE78, site, 4):
        assert image.operand(ea, 0).upper() not in {"X12", "W12"}, hex(ea)
    for ea in range(0x242B7EF10, 0x242B7EF30, 4):
        assert image.operand(ea, 0).upper() not in {"X8", "W8"}, hex(ea)

    # Revalidate the earlier low-byte proof, including its native slice and
    # both read-only permutation tables, before trusting the X12 table base.
    import coreald_sbox
    proof = coreald_sbox.analyze_site(coreald_sbox.IDAImage(), 0x242B7EE6C)
    assert proof is not None and proof.constant == 0xE8
    assert image.operand_value(0x242B7EF1C, 1) == 0x88
    for slot, expected in ((0x2790C5880, 0x243018D3C),
                           (0x2790C4FD0, 0x243018E3C)):
        assert image.readonly(slot, 8)
        assert decode_shared_cache_rebase(
            int.from_bytes(image.read(slot, 8), "little")) == expected
    inner = image.read(0x243018D30, 256)
    outer = image.read(0x243018E30, 256)
    assert len(inner) == len(outer) == 256
    values = {x ^ outer[inner[x] ^ 0x88] for x in range(256)}
    assert values == {0xC4}

    slot = 0x2790C38A0 + (0xE8 + 0x61) * 8
    assert slot == 0x2790C42E8 and image.readonly(slot, 8)
    table = decode_shared_cache_rebase(int.from_bytes(image.read(slot, 8), "little"))
    assert table == 0x28561CA20
    index = 0x56F1 + 0xC4
    target = _check_entry(image, table + index * 8,
                          0x80139D34C2511324, 0xE74D)
    return (target,)


class IDAImage:
    def __init__(self):
        import ida_bytes
        import ida_segment
        import idc
        self.bytes, self.segments, self.idc = ida_bytes, ida_segment, idc

    def mnem(self, ea):
        return self.idc.print_insn_mnem(ea).upper()

    def operand(self, ea, index):
        return self.idc.print_operand(ea, index) or ""

    def operand_value(self, ea, index):
        return self.idc.get_operand_value(ea, index)

    def read(self, ea, size):
        return self.bytes.get_bytes(ea, size) or b""

    def readonly(self, ea, size):
        seg = self.segments.getseg(ea)
        return bool(seg and ea + size <= seg.end_ea
                    and not (seg.perm & self.segments.SEGPERM_WRITE))

    def mapped(self, ea, size):
        seg = self.segments.getseg(ea)
        return bool(seg and ea + size <= seg.end_ea)

    def executable(self, ea, size):
        seg = self.segments.getseg(ea)
        return bool(seg and ea + size <= seg.end_ea
                    and (seg.perm & self.segments.SEGPERM_EXEC))


def main():
    import ida_nalt
    import idc
    assert ida_nalt.retrieve_input_file_sha256().hex() == (
        "247842d90546265eb6ced34fa18d83bc3d2eaaa3d4c1e79bb2cd3aab0e91f24f")
    image = IDAImage()
    results = ((SAMPLE_BRANCHES[0], analyze_null_dispatch(image)),
               (SAMPLE_BRANCHES[1], analyze_sbox_call(image)))
    apply = "apply" in idc.ARGV[1:]
    for site, targets in results:
        print(f"COREALD_PAC branch=0x{site:x} on_disk_candidates={','.join(hex(t) for t in targets)}")
        if not apply:
            continue
        note = "UNSLOPPER_COREALD_PAC: writable-table on-disk candidates " + ", ".join(
            hex(t) for t in targets)
        current = idc.get_cmt(site, False) or ""
        if note not in current.splitlines():
            idc.set_cmt(site, current + ("\n" if current else "") + note, False)
    print(f"COREALD_PAC sites={len(results)} apply={apply}")


if __name__ == "__main__":
    main()
    import idc
    if "exit" in idc.ARGV[1:]:
        import ida_pro
        ida_pro.qexit(0)
