"""Prove and annotate CoreALD's byte-permutation constant slices in IDA.

Usage from IDA: File > Script file, with current cursor inside a function.
For batch mode: idat -A -S"tools/coreald_sbox.py 0xENTRY[,0xENTRY...] apply" image

The script never patches machine bytes. ``apply`` writes a proof marker at the
terminal AND instruction for Unslopper's GENERATED-microcode pass.
"""

from __future__ import annotations

from dataclasses import dataclass
import re


MASK64 = (1 << 64) - 1
MARKER = "UNSLOPPER_COREALD_SBOX:"
REGISTER = re.compile(r"^[WX](\d+)$")
INNER_INDEX = re.compile(r"^\[(X\d+),(X\d+)\]$")
OUTER_INDEX = re.compile(r"^\[(X\d+),(W\d+),UXTW\]$")
UNSCALED_BYTE = re.compile(r"^\[(X\d+),#-(0X[0-9A-F]+|[0-9]+)\]$")
SLOT_REFERENCE = re.compile(r"QWORD_([0-9A-F]+)")
CACHE_BASE = 0x180000000


def fnv64(parts: list[bytes]) -> int:
    value = 0xCBF29CE484222325
    for part in parts:
        for byte in part:
            value = ((value ^ byte) * 0x100000001B3) & MASK64
    return value


def proof_hash(start: int, site: int, inner: int, outer: int,
               xor_byte: int, constant: int, code: bytes,
               inner_table: bytes, outer_table: bytes,
               inner_slot: int = 0, outer_slot: int = 0,
               inner_slot_bytes: bytes = b"", outer_slot_bytes: bytes = b"") -> int:
    metadata = b"".join(v.to_bytes(8, "little") for v in
                        (start, site, inner, outer, xor_byte, constant,
                         inner_slot, outer_slot))
    return fnv64([code, inner_table, outer_table, inner_slot_bytes,
                  outer_slot_bytes, metadata])


@dataclass(frozen=True)
class Proof:
    start: int
    site: int
    inner: int
    outer: int
    xor_byte: int
    constant: int
    fingerprint: int
    inner_slot: int = 0
    outer_slot: int = 0

    def marker(self) -> str:
        return (f"{MARKER} 0x{self.start:x} 0x{self.inner:x} "
                f"0x{self.outer:x} 0x{self.xor_byte:x} "
                f"0x{self.constant:x} 0x{self.inner_slot:x} "
                f"0x{self.outer_slot:x} 0x{self.fingerprint:016x}")


def _same_register(a: str, b: str) -> bool:
    ma, mb = REGISTER.fullmatch(a), REGISTER.fullmatch(b)
    return bool(ma and mb and ma.group(1) == mb.group(1))


def _candidates(image, begin: int, end: int, predicate):
    return [ea for ea in range(begin & ~3, end, 4) if predicate(ea)]


def _finish_proof(image, start: int, site: int, inner: int, outer: int,
                  xor_byte: int, inner_slot: int = 0,
                  outer_slot: int = 0) -> Proof | None:
    if not image.readonly(inner, 256) or not image.readonly(outer, 256):
        return None
    t1, t2 = image.read(inner, 256), image.read(outer, 256)
    if len(t1) != 256 or len(t2) != 256 or len(set(t1)) != 256 or len(set(t2)) != 256:
        return None
    constants = {x ^ t2[t1[x] ^ xor_byte] for x in range(256)}
    if len(constants) != 1:
        return None
    constant = constants.pop()
    code = image.read(start, site + 4 - start)
    if len(code) != site + 4 - start:
        return None
    if (inner_slot and not image.readonly(inner_slot, 8)
            or outer_slot and not image.readonly(outer_slot, 8)):
        return None
    slot1 = image.read(inner_slot, 8) if inner_slot else b""
    slot2 = image.read(outer_slot, 8) if outer_slot else b""
    if inner_slot and len(slot1) != 8 or outer_slot and len(slot2) != 8:
        return None
    fingerprint = proof_hash(start, site, inner, outer, xor_byte,
                             constant, code, t1, t2,
                             inner_slot, outer_slot, slot1, slot2)
    return Proof(start, site, inner, outer, xor_byte, constant, fingerprint,
                 inner_slot, outer_slot)


def _decode_shared_cache_slot(image, slot: int) -> int | None:
    if not image.readonly(slot, 8):
        return None
    data = image.read(slot, 8)
    if len(data) != 8:
        return None
    raw = int.from_bytes(data, "little")
    # DYLD_CHAINED_PTR_ARM64E_SHARED_CACHE unauthenticated rebase:
    # runtimeOffset[33:0], high8[41:34], unused[51:42], next[62:52], auth[63].
    # This build's target tables have high8=0 and cache base 0x180000000.
    if raw >> 63 or (raw >> 34) & 0xFF or (raw >> 42) & 0x3FF:
        return None
    return CACHE_BASE + (raw & ((1 << 34) - 1))


def _slot_load(image, ea: int, base: str) -> int | None:
    if image.mnem(ea) != "LDR" or image.operand(ea, 0).upper() != base:
        return None
    match = SLOT_REFERENCE.search(image.operand(ea, 1).upper())
    if match is None:
        return None
    return int(match.group(1), 16)


def _terminal_xor_temp(image, site: int, state: str) -> str | None:
    if image.mnem(site - 4) != "EOR" or image.operand(site - 4, 0).upper() != state:
        return None
    left, right = (image.operand(site - 4, 1).upper(),
                   image.operand(site - 4, 2).upper())
    temp = right if left == state else left if right == state else ""
    return temp if temp.startswith("W") and temp != state else None


def _analyze_direct_site(image, site: int) -> Proof | None:
    """Match one straight-line native slice and prove its low byte for all 256 inputs.

    The matcher intentionally rejects branches, external entries, repeated
    matches, writable tables, and intervening writes to the source register.
    """
    if image.mnem(site) != "AND" or image.operand(site, 2).upper() != "#0XFF":
        return None
    state = image.operand(site, 0).upper()
    if not state.startswith("W") or image.operand(site, 1).upper() != state:
        return None
    state_x = "X" + state[1:]
    temp = _terminal_xor_temp(image, site, state)
    if temp is None:
        return None
    if image.mnem(site - 8) != "LDRB" or image.operand(site - 8, 0).upper() != temp:
        return None
    outer_match = OUTER_INDEX.fullmatch(image.operand(site - 8, 1).upper())
    if not outer_match or outer_match.group(2) != temp:
        return None
    outer_base = outer_match.group(1)

    eors = _candidates(image, site - 0x30, site - 8, lambda ea:
        image.mnem(ea) == "EOR" and image.operand(ea, 0).upper() == temp
        and image.operand(ea, 1).upper() == temp
        and image.operand(ea, 2).upper().startswith(("W", "#")))
    if len(eors) != 1:
        return None
    xor_ea = eors[0]
    immediate_reg = image.operand(xor_ea, 2).upper()
    if immediate_reg.startswith("#"):
        xor_byte = image.operand_value(xor_ea, 2)
    else:
        movs = _candidates(image, xor_ea - 0x20, xor_ea, lambda ea:
            image.mnem(ea) == "MOV" and image.operand(ea, 0).upper() == immediate_reg
            and image.operand(ea, 1).startswith("#"))
        if len(movs) != 1:
            return None
        xor_byte = image.operand_value(movs[0], 1)
    if not 0 <= xor_byte <= 255:
        return None

    inner_loads = _candidates(image, xor_ea - 0x24, xor_ea, lambda ea:
        image.mnem(ea) == "LDRB" and image.operand(ea, 0).upper() == temp
        and INNER_INDEX.fullmatch(image.operand(ea, 1).upper()) is not None)
    if len(inner_loads) != 1:
        return None
    inner_load = inner_loads[0]
    inner_match = INNER_INDEX.fullmatch(image.operand(inner_load, 1).upper())
    inner_base, index = inner_match.groups()
    pre_ands = _candidates(image, inner_load - 0x1c, inner_load, lambda ea:
        image.mnem(ea) == "AND" and image.operand(ea, 0).upper() == index
        and image.operand(ea, 1).upper() == state_x
        and image.operand(ea, 2).upper() == "#0XFF")
    if len(pre_ands) != 1:
        return None
    pre_mask = pre_ands[0]

    def adrl_for(base: str, begin: int, end: int):
        return _candidates(image, begin, end, lambda ea:
            image.mnem(ea) == "ADRL" and image.operand(ea, 0).upper() == base)

    inner_adrl = adrl_for(inner_base, pre_mask - 0x10, inner_load)
    outer_adrl = adrl_for(outer_base, inner_load + 4, site - 8)
    if len(inner_adrl) != 1 or len(outer_adrl) != 1:
        return None
    start = min(pre_mask, inner_adrl[0])
    if site - start > 0x60 or not image.same_function(start, site):
        return None
    inner, outer = (image.operand_value(inner_adrl[0], 1),
                    image.operand_value(outer_adrl[0], 1))
    # The source W register must remain live from the pre-mask to the final
    # XOR. The byte-table loads, ADRL, and temp operations may not clobber it.
    for ea in range(start + 4, site - 4, 4):
        if not image.same_function(start, ea):
            return None
        mnem = image.mnem(ea)
        if mnem not in {"", "ADRL", "LDRB", "MOV", "EOR", "AND"}:
            return None
        if ea > pre_mask and image.writes_register(ea, state):
            return None
        if image.external_entry(ea, start, site):
            return None
    return _finish_proof(image, start, site, inner, outer, xor_byte)


def _analyze_indirect_site(image, site: int) -> Proof | None:
    """Match the same byte identity when table bases come from cache rebases.

    This accepts only the two observed address forms: direct indexed LDRB or
    ADD followed by a negative-offset LDURB. Cache pointers and their table
    bytes are included in the proof fingerprint.
    """
    if image.mnem(site) != "AND" or image.operand(site, 2).upper() != "#0XFF":
        return None
    state = image.operand(site, 0).upper()
    if not state.startswith("W") or image.operand(site, 1).upper() != state:
        return None
    state_x = "X" + state[1:]
    temp = _terminal_xor_temp(image, site, state)
    if temp is None:
        return None
    temp_x = "X" + temp[1:]
    outer_load = site - 8
    outer_kind = image.mnem(outer_load)
    if outer_kind not in {"LDRB", "LDURB"} or image.operand(outer_load, 0).upper() != temp:
        return None

    outer_add = None
    if outer_kind == "LDRB":
        match = OUTER_INDEX.fullmatch(image.operand(outer_load, 1).upper())
        if not match or match.group(2) != temp:
            return None
        outer_base, outer_displacement = match.group(1), 0
        outer_before = outer_load
    else:
        match = UNSCALED_BYTE.fullmatch(image.operand(outer_load, 1).upper())
        if not match or match.group(1) != temp_x:
            return None
        outer_displacement = -int(match.group(2), 0)
        adds = _candidates(image, outer_load - 0x14, outer_load, lambda ea:
            image.mnem(ea) == "ADD" and image.operand(ea, 0).upper() == temp_x
            and image.operand(ea, 2).upper() == temp_x)
        if len(adds) != 1:
            return None
        outer_add = adds[0]
        outer_base = image.operand(outer_add, 1).upper()
        if not outer_base.startswith("X") or outer_base == state_x:
            return None
        outer_before = outer_add
    outer_slots = [(ea, _slot_load(image, ea, outer_base))
                   for ea in range(outer_before - 0x14, outer_before, 4)]
    outer_slots = [(ea, slot) for ea, slot in outer_slots if slot is not None]
    if len(outer_slots) != 1:
        return None
    outer_slot_ea, outer_slot = outer_slots[0]
    outer_pointer = _decode_shared_cache_slot(image, outer_slot)
    if outer_pointer is None:
        return None
    outer = outer_pointer + outer_displacement

    xors = _candidates(image, site - 0x2c, outer_load, lambda ea:
        image.mnem(ea) == "EOR" and image.operand(ea, 0).upper() == temp
        and image.operand(ea, 1).upper() == temp)
    if len(xors) != 1:
        return None
    xor_ea = xors[0]
    xor_operand = image.operand(xor_ea, 2).upper()
    if xor_operand.startswith("#"):
        xor_byte = image.operand_value(xor_ea, 2)
    elif xor_operand.startswith("W") and xor_operand != temp:
        movs = _candidates(image, xor_ea - 0x18, xor_ea, lambda ea:
            image.mnem(ea) == "MOV" and image.operand(ea, 0).upper() == xor_operand
            and image.operand(ea, 1).startswith("#"))
        if len(movs) != 1:
            return None
        xor_byte = image.operand_value(movs[0], 1)
    else:
        return None
    if not 0 <= xor_byte <= 255:
        return None

    inner_loads = _candidates(image, xor_ea - 0x20, xor_ea, lambda ea:
        image.mnem(ea) in {"LDRB", "LDURB"}
        and image.operand(ea, 0).upper() == temp)
    if len(inner_loads) != 1:
        return None
    inner_load = inner_loads[0]
    inner_kind = image.mnem(inner_load)
    if inner_kind == "LDRB":
        match = INNER_INDEX.fullmatch(image.operand(inner_load, 1).upper())
        if not match:
            return None
        inner_base, index = match.groups()
        pre_masks = _candidates(image, inner_load - 0x14, inner_load, lambda ea:
            image.mnem(ea) == "AND" and image.operand(ea, 0).upper() == index
            and image.operand(ea, 1).upper() == state_x
            and image.operand(ea, 2).upper() == "#0XFF")
        if len(pre_masks) != 1:
            return None
        source_ea = pre_masks[0]
        inner_displacement = 0
        inner_before = inner_load
    else:
        match = UNSCALED_BYTE.fullmatch(image.operand(inner_load, 1).upper())
        if not match or match.group(1) != temp_x:
            return None
        inner_displacement = -int(match.group(2), 0)
        adds = _candidates(image, inner_load - 0x14, inner_load, lambda ea:
            image.mnem(ea) == "ADD" and image.operand(ea, 0).upper() == temp_x
            and image.operand(ea, 2).upper() == state + ",UXTB")
        if len(adds) != 1:
            return None
        source_ea = adds[0]
        inner_base = image.operand(source_ea, 1).upper()
        if not inner_base.startswith("X") or inner_base == state_x:
            return None
        inner_before = source_ea
    inner_slots = [(ea, _slot_load(image, ea, inner_base))
                   for ea in range(inner_before - 0x14, inner_before, 4)]
    inner_slots = [(ea, slot) for ea, slot in inner_slots if slot is not None]
    if len(inner_slots) != 1:
        return None
    inner_slot_ea, inner_slot = inner_slots[0]
    inner_pointer = _decode_shared_cache_slot(image, inner_slot)
    if inner_pointer is None:
        return None
    inner = inner_pointer + inner_displacement
    start = min(source_ea, inner_slot_ea)
    if site - start > 0x60 or not image.same_function(start, site):
        return None
    # Pointer table loads must occur after the source index is prepared and
    # not overwrite the temporary containing the inner table's result.
    if outer_slot_ea <= inner_load or outer_slot_ea >= outer_load:
        return None
    permitted_temp_writes = {inner_load, xor_ea, outer_load}
    if outer_add is not None:
        permitted_temp_writes.add(outer_add)
    for ea in range(start + 4, site - 4, 4):
        if not image.same_function(start, ea):
            return None
        mnem = image.mnem(ea)
        if mnem not in {"", "LDR", "LDRB", "LDURB", "ADD", "AND", "MOV", "EOR"}:
            return None
        if ea > source_ea and image.writes_register(ea, state):
            return None
        if ea > inner_load and image.writes_register(ea, temp) \
                and ea not in permitted_temp_writes:
            return None
        if image.external_entry(ea, start, site):
            return None
    return _finish_proof(image, start, site, inner, outer, xor_byte,
                         inner_slot, outer_slot)


def analyze_site(image, site: int) -> Proof | None:
    return _analyze_direct_site(image, site) or _analyze_indirect_site(image, site)


class IDAImage:
    def __init__(self):
        import ida_bytes
        import ida_funcs
        import ida_segment
        import idautils
        import idc
        self.bytes, self.funcs, self.segments, self.utils, self.idc = (
            ida_bytes, ida_funcs, ida_segment, idautils, idc)

    def mnem(self, ea):
        return self.idc.print_insn_mnem(ea).upper()

    def operand(self, ea, index):
        return self.idc.print_operand(ea, index) or ""

    def operand_value(self, ea, index):
        return self.idc.get_operand_value(ea, index)

    def read(self, ea, size):
        return self.bytes.get_bytes(ea, size) or b""

    def readonly(self, ea, size):
        segment = self.segments.getseg(ea)
        return bool(segment and ea + size <= segment.end_ea
                    and not (segment.perm & self.segments.SEGPERM_WRITE))

    def same_function(self, a, b):
        first, last = self.funcs.get_func(a), self.funcs.get_func(b)
        return bool(first and last and first.start_ea == last.start_ea)

    def writes_register(self, ea, register):
        mnem = self.mnem(ea)
        if not mnem or mnem in {"CMP", "CMN", "TST", "CCMP", "CCMN"}:
            return False
        if mnem.startswith("ST") or mnem.startswith("B") or mnem in {"RET", "NOP"}:
            return False
        return _same_register(self.operand(ea, 0).upper(), register)

    def external_entry(self, ea, start, end):
        return any(not start <= source <= end for source in self.utils.CodeRefsTo(ea, 0))


def main():
    import ida_auto
    import ida_funcs
    import idc
    image = IDAImage()
    ida_auto.auto_wait()
    args = list(idc.ARGV[1:])
    apply = "apply" in args
    misses = "misses" in args
    entries = [int(token, 0) for value in args
               if value not in {"apply", "exit", "misses"}
               for token in value.split(",") if token]
    if not entries:
        current = ida_funcs.get_func(idc.get_screen_ea())
        if current is None:
            raise RuntimeError("Place the cursor in a function or supply an entry EA")
        entries = [current.start_ea]
    found = 0
    for entry in entries:
        function = ida_funcs.get_func(entry)
        if function is None:
            print(f"COREALD_SBOX no function at 0x{entry:x}")
            continue
        for ea in range(function.start_ea, function.end_ea, 4):
            if image.mnem(ea) != "AND":
                continue
            proof = analyze_site(image, ea)
            if proof is None:
                if (misses and image.mnem(ea) == "AND"
                        and image.operand(ea, 0) == image.operand(ea, 1)
                        and image.operand(ea, 2).upper() == "#0XFF"):
                    print(f"COREALD_SBOX_UNKNOWN site=0x{ea:x}")
                continue
            print(f"COREALD_SBOX site=0x{ea:x} constant=0x{proof.constant:02x} "
                  f"inner=0x{proof.inner:x} outer=0x{proof.outer:x} "
                  f"fingerprint=0x{proof.fingerprint:016x}")
            found += 1
            if apply:
                current = idc.get_cmt(ea, False) or ""
                if proof.marker() not in current.splitlines():
                    idc.set_cmt(ea, current + ("\n" if current else "")
                                + proof.marker(), False)
    print(f"COREALD_SBOX total={found} applied={apply}")


if __name__ == "__main__":
    main()
    import idc
    if "exit" in idc.ARGV[1:]:
        import ida_pro
        ida_pro.qexit(0)
