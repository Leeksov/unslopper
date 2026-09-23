"""Prove CBZ/CBNZ W9 rewrites for residual Boolean-index BR X8 sites.

A bounded straight-line abstract interpretation keeps only W8/W9 value sets.
It accepts an indexed pointer table only if W9 is proven within {0,1}, both
APS2 entries point into the same unwind range, and exactly one target is the
next instruction. This is a static IDB proposal, not a binary patch or a
claim about runtime table immutability.
"""

import argparse
from collections import Counter

import numpy as np
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM, CS_GRP_CALL, CS_GRP_JUMP, CS_GRP_RET
from capstone.arm64 import ARM64_OP_IMM
from elftools.elf.elffile import ELFFile

from yuanshen_aps2_tables import _packed_relocations, KNOWN_TABLE, KNOWN_TARGETS
from yuanshen_signature_scan import _fde_starts, _pointer_table_base
from yuanshen_unflatten_plan import _sha256, EXPECTED_SHA256, BR_X8


def _value(token, state):
    if token in ("wzr", "xzr"):
        return {0}, None
    if token.startswith("#"):
        return {int(token[1:], 0) & 0xFFFFFFFF}, None
    return state.get(token, (None, None))


def _abstract_boolean(insns):
    state = {"w8": (None, None), "w9": (None, None)}
    for insn in insns:
        if insn.group(CS_GRP_JUMP) or insn.group(CS_GRP_CALL) or insn.group(CS_GRP_RET):
            if not (insn.mnemonic == "b" and insn.operands
                    and insn.operands[-1].type == ARM64_OP_IMM
                    and insn.operands[-1].imm == insn.address + 4):
                state = {"w8": (None, None), "w9": (None, None)}
                continue
        parts = [part.strip() for part in insn.op_str.split(",")]
        writes = {insn.reg_name(reg) for reg in insn.regs_access()[1]}
        destination = parts[0] if parts else ""
        old = dict(state)
        for reg in ("w8", "w9"):
            if reg in writes or "x" + reg[1:] in writes:
                state[reg] = (None, None)
        if destination not in ("w8", "w9", "x8", "x9"):
            continue
        key = "w" + destination[1:]
        if insn.mnemonic == "mov" and len(parts) == 2:
            values, source = _value(parts[1], old)
            if values is not None:
                state[key] = values, min(insn.address, source or insn.address)
        elif insn.mnemonic == "cset" and len(parts) == 2:
            state[key] = {0, 1}, insn.address
        elif insn.mnemonic == "and" and len(parts) == 3 and parts[2] == "#1":
            state[key] = {0, 1}, insn.address
        elif insn.mnemonic == "csel" and len(parts) == 4:
            a, a_start = _value(parts[1], old)
            b, b_start = _value(parts[2], old)
            if a is not None and b is not None:
                state[key] = a | b, min(a_start or insn.address, b_start or insn.address)
        elif insn.mnemonic == "cinc" and len(parts) == 3:
            a, source = _value(parts[1], old)
            if a is not None:
                state[key] = a | {((x + 1) & 0xFFFFFFFF) for x in a}, source or insn.address
        elif insn.mnemonic == "csinc" and len(parts) == 4:
            a, source_a = _value(parts[1], old)
            b, source_b = _value(parts[2], old)
            if a is not None and b is not None:
                state[key] = (a | {((x + 1) & 0xFFFFFFFF) for x in b},
                              min(source_a or insn.address, source_b or insn.address))
    return state["w9"]


def _cb_word(site, target, nonzero):
    if (target - site) % 4:
        raise ValueError("unaligned target")
    delta = (target - site) // 4
    if not -(1 << 18) <= delta < (1 << 18):
        raise ValueError("CB target out of range")
    return (0x35000009 if nonzero else 0x34000009) | ((delta & 0x7FFFF) << 5)


def _scan(path, focus=None, covered=None):
    if _sha256(path) != EXPECTED_SHA256:
        raise ValueError("Input SHA-256 differs from the verified 7.1 sample")
    if covered is None:
        from yuanshen_unflatten_plan import _scan as conditional_scan
        from yuanshen_unflatten_direct_plan import _scan as direct_scan
        from yuanshen_unflatten_strided_plan import _scan as strided_scan
        covered = set()
        for scanner in (conditional_scan, direct_scan, strided_scan):
            _, _, rows, _ = scanner(path, focus)
            covered.update(row["site"] for row in rows)
    with open(path, "rb") as stream:
        elf = ELFFile(stream)
        section = elf.get_section_by_name(".text")
        base = section["sh_addr"]
        words = np.memmap(path, dtype="<u4", mode="r",
                          offset=section["sh_offset"], shape=(section["sh_size"] // 4,))
        starts = _fde_starts(elf)
        br = np.flatnonzero(words == BR_X8)
        br = br[(br >= 5) & ((words[br - 1] == 0xF8695908) |
                             (words[br - 1] == 0xF869D908))]
        disassembler = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        disassembler.detail = True
        requested = {KNOWN_TABLE + 8 * i for i in range(len(KNOWN_TARGETS))}
        proposals = []
        reasons = Counter()
        for raw_index in br:
            index = int(raw_index)
            site = base + 4 * index
            if site in covered:
                continue
            table = _pointer_table_base(words, base, index)
            if table is None:
                reasons["no_table_base"] += 1
                continue
            fde_index = int(np.searchsorted(starts, site, side="right") - 1)
            if not 0 <= fde_index < len(starts) - 1:
                reasons["no_unwind_range"] += 1
                continue
            start, end = int(starts[fde_index]), int(starts[fde_index + 1])
            if focus is not None and start != focus:
                continue
            begin = max(start, site - 640)
            first = (begin - base) // 4
            insns = list(disassembler.disasm(words[first:index - 3].tobytes(), begin))
            if len(insns) != (site - 12 - begin) // 4:
                reasons["decode_failed"] += 1
                continue
            values, slice_start = _abstract_boolean(insns)
            if values is None or not values <= {0, 1} or slice_start is None:
                reasons["boolean_not_proven"] += 1
                continue
            requested.update((table, table + 8))
            proposals.append((site, table, start, end, slice_start, values))
        _, relocations = _packed_relocations(elf.get_section_by_name(".rela.dyn").data(), requested)
        known = tuple(relocations.get(KNOWN_TABLE + 8 * i, (None, None))[1]
                      for i in range(len(KNOWN_TARGETS)))
        if known != KNOWN_TARGETS:
            raise ValueError("APS2 decoder failed known-table cross-check")
        verified = []
        for site, table, start, end, slice_start, values in proposals:
            r0, r1 = relocations.get(table), relocations.get(table + 8)
            if r0 is None or r1 is None or any((info & 0xFFFFFFFF) != 1027 or info >> 32 != 0
                                             for info, _ in (r0, r1)):
                reasons["relocation"] += 1
                continue
            t0, t1 = r0[1], r1[1]
            if not (start <= t0 < end and start <= t1 < end):
                reasons["target_outside_unwind_range"] += 1
                continue
            if t0 == site + 4 and t1 != site + 4:
                target, nonzero = t1, True
            elif t1 == site + 4 and t0 != site + 4:
                target, nonzero = t0, False
            else:
                reasons["no_unique_fallthrough"] += 1
                continue
            try:
                replacement = _cb_word(site, target, nonzero)
            except ValueError:
                reasons["branch_out_of_range"] += 1
                continue
            verified.append({"site": site, "table": table, "target_zero": t0,
                             "target_one": t1, "branch_target": target,
                             "replacement": replacement, "slice_start": slice_start,
                             "fde_start": start, "fde_end": end})
        return len(br), len(proposals), verified, reasons


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary")
    parser.add_argument("--function", type=lambda value: int(value, 0))
    args = parser.parse_args()
    raw, candidates, rows, reasons = _scan(args.binary, args.function)
    print("Indexed BR signatures:", raw)
    print("Boolean W9 candidates:", candidates)
    print("Verified CBZ/CBNZ W9 rewrites:", len(rows))
    print("Skipped:", dict(reasons))
    print("Top ranges:", [(hex(ea), n) for ea, n in Counter(row["fde_start"] for row in rows).most_common(12)])
    if args.function is not None:
        for row in rows:
            print("0x%X: W9 {0,1}, 0→0x%X 1→0x%X, word=0x%08X" %
                  (row["site"], row["target_zero"], row["target_one"], row["replacement"]))
