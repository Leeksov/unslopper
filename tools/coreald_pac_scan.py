"""Strict native-slice scan of CoreALD export BRAA/BLRAA table dispatch.

Run on the iOS 26.0.1 IDB. This reports *on-disk* candidates only: the
authenticated dispatch table is writable, and no runtime edge is asserted.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import re

import coreald_pac
import coreald_sbox


EXPORTS = (
    0x242510DFC, 0x242512CC0, 0x24252FB5C, 0x24273B60C,
    0x242747EF0, 0x24277785C, 0x242777C58, 0x2427842A8,
    0x2427B4454, 0x2427DFF50, 0x242856CB8, 0x2428AFFDC,
    0x242A469C0, 0x242A59160, 0x242B7ED44, 0x242DD84EC,
)
SLOT_RE = re.compile(r"QWORD_([0-9A-F]+)")
LDUR_RE = re.compile(r"^\[X\d+,#-(0X[0-9A-F]+|[0-9]+)\]$")
BYTE_BASE_RE = re.compile(r"^\[(X\d+),")
DIRECT_BYTE_RE = re.compile(r"^\[(X\d+),([WX]\d+)(?:,UXTW)?\]$")
INDEX_LOAD_RE = re.compile(r"^\[(X\d+),(W\d+),UXTW#3\]$")


@dataclass(frozen=True)
class Relation:
    source: str
    eor: int
    inner: int
    outer: int
    xor_byte: int
    constant: int
    first_load: int


def _ops(image, ea):
    return tuple(image.operand(ea, i).upper() for i in range(3))


def _last(image, begin, end, predicate):
    return next((ea for ea in range(end - 4, begin - 4, -4)
                 if predicate(ea)), None)


def _last_write(image, begin, end, reg):
    return _last(image, begin, end, lambda ea:
                 image.writes_register(ea, reg))


def _imm_from_source(image, ea, token, begin):
    if token.startswith("#"):
        return image.operand_value(ea, 2)
    mov = _last_write(image, begin, ea, token)
    if (mov is None or image.mnem(mov) != "MOV"
            or not image.operand(mov, 1).startswith("#")):
        raise ValueError("no XOR immediate definition")
    return image.operand_value(mov, 1)


def _table_base(image, load, begin):
    mnem = image.mnem(load)
    operand = image.operand(load, 1).upper()
    if mnem == "LDRB":
        match = BYTE_BASE_RE.match(operand)
        if match is None:
            raise ValueError("unrecognized direct byte load")
        reg = match.group(1)
        writer = _last_write(image, begin, load, reg)
        if writer is None:
            raise ValueError("direct table base has no definition")
        if image.mnem(writer) == "ADRL":
            return image.operand_value(writer, 1)
        if image.mnem(writer) == "LDR":
            slot_match = SLOT_RE.search(image.operand(writer, 1).upper())
            if slot_match is not None:
                slot = int(slot_match.group(1), 16)
                if not image.readonly(slot, 8):
                    raise ValueError("direct table pointer slot writable")
                base = coreald_pac.decode_shared_cache_rebase(
                    int.from_bytes(image.read(slot, 8), "little"))
                if base is not None:
                    return base
        raise ValueError("direct table base has no ADRL or rebase slot")
    if mnem != "LDURB":
        raise ValueError("unsupported byte load")
    match = LDUR_RE.fullmatch(operand)
    if match is None:
        raise ValueError("unsupported unscaled byte load")
    displacement = int(match.group(1), 0)
    slot_load = _last(image, max(begin, load - 0x40), load, lambda ea:
                      image.mnem(ea) == "LDR"
                      and SLOT_RE.search(image.operand(ea, 1).upper()) is not None)
    if slot_load is None:
        raise ValueError("pointer-slot load missing")
    slot = int(SLOT_RE.search(image.operand(slot_load, 1).upper()).group(1), 16)
    loaded_reg = image.operand(slot_load, 0).upper()
    address_reg = BYTE_BASE_RE.match(operand).group(1)
    add = _last_write(image, slot_load + 4, load, address_reg)
    if add is None or image.mnem(add) != "ADD":
        raise ValueError("unscaled byte address has no ADD")
    if loaded_reg not in _ops(image, add)[1:]:
        raise ValueError("pointer slot does not feed byte address")
    if not image.readonly(slot, 8):
        raise ValueError("mutable pointer slot")
    raw = int.from_bytes(image.read(slot, 8), "little")
    base = coreald_pac.decode_shared_cache_rebase(raw)
    if base is None:
        raise ValueError("pointer slot is not an unauthenticated rebase")
    return base - displacement


def _register_number(reg):
    return reg[1:] if re.fullmatch(r"[WX]\d+", reg) else None


def _check_byte_index(image, load, source, outer, begin):
    operand = image.operand(load, 1).upper()
    if image.mnem(load) == "LDRB":
        match = DIRECT_BYTE_RE.fullmatch(operand)
        if match is None:
            raise ValueError("direct byte index shape changed")
        index = match.group(2)
        if outer:
            if _register_number(index) != _register_number(source):
                raise ValueError("outer index is not XOR result")
            return
        writer = _last_write(image, begin, load, index)
        if writer is None or image.mnem(writer) != "AND":
            raise ValueError("inner byte index is not masked")
        _, input_reg, mask = _ops(image, writer)
        if (_register_number(input_reg) != _register_number(source)
                or mask != "#0XFF"):
            raise ValueError("inner index is not source low byte")
        return
    if image.mnem(load) != "LDURB":
        raise ValueError("unexpected byte-load mnemonic")
    address = BYTE_BASE_RE.match(operand)
    if address is None:
        raise ValueError("unscaled byte address changed")
    reg = address.group(1)
    add = _last_write(image, begin, load, reg)
    if add is None or image.mnem(add) != "ADD":
        raise ValueError("unscaled byte index ADD missing")
    dst, left, right = _ops(image, add)
    if outer:
        if _register_number(source) not in (
                _register_number(left), _register_number(right)):
            raise ValueError("outer byte ADD does not use XOR result")
    elif right != source + ",UXTB":
        raise ValueError("inner byte ADD does not use source low byte")


def relation_before(image, eor, begin):
    if image.mnem(eor) != "EOR":
        raise ValueError("terminal XOR missing")
    dst, left, right = _ops(image, eor)
    temp = right if left == dst else left if right == dst else ""
    if not (dst.startswith("W") and temp.startswith("W") and temp != dst):
        raise ValueError("terminal XOR operands changed")
    second = _last(image, max(begin, eor - 0x70), eor, lambda ea:
                   image.mnem(ea) in ("LDRB", "LDURB")
                   and image.operand(ea, 0).upper() == temp)
    if second is None:
        raise ValueError("outer table load missing")
    xor = _last(image, max(begin, second - 0x48), second, lambda ea:
                image.mnem(ea) == "EOR"
                and image.operand(ea, 0).upper() == temp)
    if xor is None:
        raise ValueError("table-byte XOR missing")
    xor_left, xor_right = _ops(image, xor)[1:]
    first = None
    c_token = None
    for inner_reg, constant_reg in ((xor_left, xor_right), (xor_right, xor_left)):
        candidate = _last(image, max(begin, xor - 0x48), xor, lambda ea:
                          image.mnem(ea) in ("LDRB", "LDURB")
                          and image.operand(ea, 0).upper() == inner_reg)
        if candidate is not None:
            first, c_token = candidate, constant_reg
            break
    if first is None:
        raise ValueError("inner table load missing")
    c = _imm_from_source(image, xor, c_token, begin)
    if not 0 <= c <= 255:
        raise ValueError("table-byte XOR is not one byte")
    inner = _table_base(image, first, begin)
    outer = _table_base(image, second, begin)
    _check_byte_index(image, first, dst, False, begin)
    _check_byte_index(image, second, temp, True, first + 4)
    if not image.readonly(inner, 256) or not image.readonly(outer, 256):
        raise ValueError("permutation tables are not read-only")
    t1, t2 = image.read(inner, 256), image.read(outer, 256)
    if len(set(t1)) != 256 or len(set(t2)) != 256:
        raise ValueError("table is not a byte permutation")
    values = {x ^ t2[t1[x] ^ c] for x in range(256)}
    if len(values) != 1:
        raise ValueError("byte relation is not constant")
    # No alternate entry into the native slice and no intervening write to
    # the state register: the table identity must apply to this live value.
    for ea in range(first, eor, 4):
        if image.external_entry(ea, first, eor):
            raise ValueError("external control-flow entry")
        if ea > first and image.writes_register(ea, dst):
            raise ValueError("state register clobbered")
    return Relation(dst, eor, inner, outer, c, values.pop(), first)


def _index_add(image, start, end, index_reg):
    """Find immediate ADD or UXTByte ADD defining a table index."""
    ea = _last_write(image, start, end, index_reg)
    if ea is None or image.mnem(ea) != "ADD":
        raise ValueError("table index has no final ADD")
    dst, left, right = _ops(image, ea)
    if dst != index_reg:
        raise ValueError("index register changed")
    if right.startswith("#") and left == index_reg:
        mask = _last(image, max(start, ea - 8), ea, lambda at:
                     image.mnem(at) == "AND" and image.operand(at, 0).upper() == index_reg
                     and image.operand(at, 2).upper() == "#0XFF")
        if mask is None:
            raise ValueError("selector byte mask missing")
        if mask != ea - 4:
            raise ValueError("selector mask is not adjacent to ADD")
        relation = relation_before(image, mask - 4, start)
        if relation.source != index_reg:
            raise ValueError("selector source changed")
        return relation.constant + image.operand_value(ea, 2), relation
    if right.endswith(",UXTB"):
        source = right.split(",")[0]
        if source != index_reg:
            raise ValueError("final byte source differs")
        mov = _last(image, max(start, ea - 8), ea, lambda at:
                    image.mnem(at) == "MOV" and image.operand(at, 0).upper() == left)
        if mov is None:
            raise ValueError("index base constant missing")
        relation_eor = _last(image, max(start, ea - 0x48), ea, lambda at:
                             image.mnem(at) == "EOR"
                             and image.operand(at, 0).upper() == index_reg
                             and index_reg in _ops(image, at)[1:])
        if relation_eor is None:
            raise ValueError("final byte relation missing")
        relation = relation_before(image, relation_eor, start)
        for at in range(relation_eor + 4, ea, 4):
            if image.writes_register(at, index_reg):
                raise ValueError("index source clobbered after relation")
        return image.operand_value(mov, 1) + relation.constant, relation
    raise ValueError("unsupported index ADD")


def _root_base(image, entry, table_load, reg):
    writer = _last_write(image, entry, table_load, reg)
    if writer is None or image.mnem(writer) != "ADRL":
        raise ValueError("dispatch root has no stable ADRL")
    return image.operand_value(writer, 1)


def analyze_export(image, entry):
    import ida_funcs
    f = ida_funcs.get_func(entry)
    if f is None or f.start_ea != entry:
        raise ValueError("export function missing")
    branches = [ea for ea in range(entry, f.end_ea, 4)
                if image.mnem(ea) in ("BRAA", "BLRAA")]
    if len(branches) != 1:
        raise ValueError("expected exactly one authenticated transfer")
    site = branches[0]
    if image.mnem(site) == "BRAA":
        targets = coreald_pac.analyze_null_dispatch(image)
        return {"export": hex(entry), "site": hex(site), "kind": "BRAA",
                "on_disk_candidates": [hex(t) for t in targets],
                "levels": 1}
    modifier_ea = _last(image, site - 12, site, lambda ea:
                        image.mnem(ea) == "MOV"
                        and image.operand(ea, 0).upper() == "X17")
    if modifier_ea is None:
        raise ValueError("authentication modifier missing")
    for ea in range(modifier_ea + 4, site, 4):
        if image.writes_register(ea, "X17"):
            raise ValueError("authentication modifier clobbered")
    modifier = image.operand_value(modifier_ea, 1)
    # Last two indexed LDRs are either table-base + entry, or entry only.
    indexed = [ea for ea in range(entry, site, 4)
               if image.mnem(ea) == "LDR"
               and INDEX_LOAD_RE.fullmatch(image.operand(ea, 1).upper())]
    final_load = indexed[-1]
    final_reg = image.operand(final_load, 0).upper()
    branch_reg = image.operand(site, 0).upper()
    if final_reg != branch_reg:
        raise ValueError("branch target register changed")
    final_base, final_index = INDEX_LOAD_RE.fullmatch(
        image.operand(final_load, 1).upper()).groups()
    base_load = _last(image, entry, final_load, lambda ea:
                      image.mnem(ea) == "LDR"
                      and image.operand(ea, 0).upper() == final_base
                      and INDEX_LOAD_RE.fullmatch(image.operand(ea, 1).upper()))
    if base_load is None:
        raise ValueError("pointer-table base load missing")
    for ea in range(base_load + 4, final_load, 4):
        if image.writes_register(ea, final_base):
            raise ValueError("pointer-table base clobbered")
    root_reg, selector_reg = INDEX_LOAD_RE.fullmatch(
        image.operand(base_load, 1).upper()).groups()
    # The index may have been calculated long before a two-level final load.
    try:
        selector, selector_relation = _index_add(image, entry, base_load, selector_reg)
    except ValueError as error:
        raise ValueError(f"selector at {base_load:#x}: {error}") from error
    root = _root_base(image, entry, base_load, root_reg)
    if root != 0x2790C38A0:
        raise ValueError("unexpected dispatch root")
    root_slot = root + selector * 8
    if not image.readonly(root_slot, 8):
        raise ValueError("dispatch root slot is writable")
    table = coreald_pac.decode_shared_cache_rebase(
        int.from_bytes(image.read(root_slot, 8), "little"))
    if table is None or not image.mapped(table, 8):
        raise ValueError("root slot does not name a mapped table")
    try:
        final_index_value, final_relation = _index_add(
            image, entry, final_load, final_index)
    except ValueError as error:
        raise ValueError(f"final index at {final_load:#x}: {error}") from error
    entry_ea = table + final_index_value * 8
    if not image.mapped(entry_ea, 8):
        raise ValueError("dispatch entry unmapped")
    raw = int.from_bytes(image.read(entry_ea, 8), "little")
    auth = coreald_pac.decode_shared_cache_auth_rebase(raw)
    if auth is None or auth.diversity != modifier or auth.addr_div or auth.key_is_data:
        raise ValueError("entry pointer authentication fields do not match")
    if not image.executable(auth.target, 4):
        raise ValueError("decoded target is not executable")
    return {"export": hex(entry), "site": hex(site), "kind": "BLRAA",
            "levels": 2 if final_base == branch_reg else 1,
            "selector": hex(selector), "root_slot": hex(root_slot),
            "table": hex(table), "index": hex(final_index_value),
            "entry": hex(entry_ea), "raw": hex(raw),
            "modifier": hex(modifier),
            "selector_relation": {"site": hex(selector_relation.eor),
                                  "constant": hex(selector_relation.constant)},
            "final_relation": {"site": hex(final_relation.eor),
                               "constant": hex(final_relation.constant)},
            "on_disk_candidates": [hex(auth.target)]}


class Image(coreald_sbox.IDAImage):
    def mapped(self, ea, size):
        seg = self.segments.getseg(ea)
        return bool(seg and ea + size <= seg.end_ea)

    def executable(self, ea, size):
        seg = self.segments.getseg(ea)
        return bool(seg and ea + size <= seg.end_ea
                    and (seg.perm & self.segments.SEGPERM_EXEC))


def main():
    import ida_auto
    import ida_nalt
    import idc
    ida_auto.auto_wait()
    if ida_nalt.retrieve_input_file_sha256().hex() != (
            "247842d90546265eb6ced34fa18d83bc3d2eaaa3d4c1e79bb2cd3aab0e91f24f"):
        raise ValueError("different input image")
    image = Image()
    out = []
    for entry in EXPORTS:
        try:
            row = analyze_export(image, entry)
        except (ValueError, AssertionError) as error:
            row = {"export": hex(entry), "error": str(error)}
        out.append(row)
        print("COREALD_PAC_SCAN " + json.dumps(row, sort_keys=True))
    if "apply" in idc.ARGV[1:]:
        if any("error" in row for row in out):
            raise ValueError("refusing partial annotation")
        for row in out:
            site = int(row["site"], 16)
            note = ("UNSLOPPER_COREALD_PAC_SCAN: on-disk candidates "
                    + ", ".join(row["on_disk_candidates"])
                    + "; writable table, runtime unverified")
            current = idc.get_cmt(site, False) or ""
            if note not in current.splitlines():
                if not idc.set_cmt(site, current + ("\n" if current else "") + note, False):
                    raise ValueError(f"failed comment at {site:#x}")
    print("COREALD_PAC_SCAN_TOTAL " + json.dumps({
        "exports": len(out), "resolved": sum("on_disk_candidates" in row for row in out),
        "unresolved": sum("error" in row for row in out)}))
    if "exit" in idc.ARGV[1:]:
        import ida_pro
        ida_pro.qexit(0)


if __name__ == "__main__":
    main()
