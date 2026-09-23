"""Prove candidate B.cond rewrites for Yuanshen 7.1 table-dispatched branches.

Read-only. Recognizes ADRP/ADD/LDR/BR X8 with a bounded CSEL, CINC, CSINC,
or CSET selector slice; decodes APS2 relocations; and emits a rewrite only when both targets
belong to the same unwind range and one is the next instruction. The preceding
selector and pointer load are preserved. Runtime table immutability is not
established, so these are proposals for an IDB analysis view only.

Usage: python3 yuanshen_unflatten_plan.py /path/to/libyuanshen.so
       python3 yuanshen_unflatten_plan.py /path/to/libyuanshen.so --function 0x6558024
Requires numpy, pyelftools, and capstone.
"""

import argparse
import hashlib
from collections import Counter

import numpy as np
from capstone import CS_ARCH_ARM64, CS_GRP_CALL, CS_GRP_JUMP, CS_GRP_RET, CS_MODE_ARM, Cs
from capstone.arm64 import ARM64_OP_IMM
from elftools.elf.elffile import ELFFile

from yuanshen_aps2_tables import _packed_relocations, KNOWN_TABLE, KNOWN_TARGETS
from yuanshen_signature_scan import _fde_starts, _pointer_table_base


EXPECTED_SHA256 = "9d59283b3235ba5afe3f220d952133b9dbad49af6e88da16ae03ff6e3289171e"
BR_X8 = 0xD61F0100
LDR_INDEXED_UXTW = 0xF8695908
LDR_INDEXED_SXTW = 0xF869D908
CONDITIONS = {
    "eq": 0, "ne": 1, "hs": 2, "lo": 3,
    "mi": 4, "pl": 5, "vs": 6, "vc": 7,
    "hi": 8, "ls": 9, "ge": 10, "lt": 11,
    "gt": 12, "le": 13,
}


def _sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _mov_constant(instruction, register):
    if instruction.mnemonic != "mov":
        return None
    parts = [part.strip() for part in instruction.op_str.split(",")]
    if len(parts) != 2 or parts[0] != register:
        return None
    if parts[1] == "wzr":
        return 0
    if parts[1].startswith("#"):
        return int(parts[1][1:], 0)
    return None


def _selector(instructions):
    """Return (true index, false index, condition, kind, first defining EA)."""
    last = instructions[-1]
    parts = [part.strip() for part in last.op_str.split(",")]
    if last.mnemonic == "csel" and parts[:3] == ["w9", "w8", "w9"]:
        required = {"w8", "w9"}
        kind = "csel"
        condition = parts[3] if len(parts) == 4 else None
    elif last.mnemonic == "cinc" and parts[:2] == ["w9", "w8"]:
        required = {"w8"}
        kind = "cinc"
        condition = parts[2] if len(parts) == 3 else None
    elif last.mnemonic == "csinc" and parts[:3] == ["w9", "w8", "wzr"]:
        required = {"w8"}
        kind = "csinc"
        condition = parts[3] if len(parts) == 4 else None
    elif last.mnemonic == "cset" and parts[:1] == ["w9"]:
        required = set()
        kind = "cset"
        condition = parts[1] if len(parts) == 2 else None
    else:
        return None
    if condition not in CONDITIONS:
        return None
    if kind == "cset":
        return 1, 0, CONDITIONS[condition], kind, last.address
    constants = {}
    for insn in reversed(instructions[:-1]):
        if insn.group(CS_GRP_JUMP) or insn.group(CS_GRP_CALL) or insn.group(CS_GRP_RET):
            # B to the immediately following instruction is a semantic no-op.
            if not (insn.mnemonic == "b" and insn.operands
                    and insn.operands[-1].type == ARM64_OP_IMM
                    and insn.operands[-1].imm == insn.address + 4):
                return None
        writes = {insn.reg_name(reg) for reg in insn.regs_access()[1]}
        for register in tuple(required):
            if register in writes or "x" + register[1:] in writes:
                value = _mov_constant(insn, register)
                if value is None:
                    return None
                constants[register] = (value, insn.address)
                required.remove(register)
        if not required:
            break
    if required:
        return None
    slice_start = min(ea for _, ea in constants.values())
    if kind == "csel":
        return (constants["w8"][0], constants["w9"][0],
                CONDITIONS[condition], kind, slice_start)
    if kind == "cinc":
        return (constants["w8"][0] + 1, constants["w8"][0],
                CONDITIONS[condition], kind, slice_start)
    return constants["w8"][0], 1, CONDITIONS[condition], kind, slice_start


def _conditional_word(site, target, condition):
    if (target - site) % 4:
        raise ValueError("Unaligned branch target")
    displacement = (target - site) // 4
    if not -(1 << 18) <= displacement < (1 << 18):
        raise ValueError("B.cond target out of range")
    return 0x54000000 | ((displacement & 0x7FFFF) << 5) | condition


def _scan(path, focus=None, diagnostics=None):
    if _sha256(path) != EXPECTED_SHA256:
        raise ValueError("Input SHA-256 differs from the verified 7.1 sample")
    with open(path, "rb") as stream:
        elf = ELFFile(stream)
        section = elf.get_section_by_name(".text")
        section_start = section["sh_addr"]
        words = np.memmap(path, dtype="<u4", mode="r",
                          offset=section["sh_offset"], shape=(section["sh_size"] // 4,))
        fde_starts = _fde_starts(elf)
        indices = np.flatnonzero(words == BR_X8)
        indices = indices[(indices >= 8) &
                          ((words[indices - 1] == LDR_INDEXED_UXTW) |
                           (words[indices - 1] == LDR_INDEXED_SXTW))]
        disassembler = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        disassembler.detail = True
        proposals = []
        reasons = Counter()
        requested = {KNOWN_TABLE + 8 * i for i in range(len(KNOWN_TARGETS))}
        for index in indices:
            index = int(index)
            site = section_start + 4 * index
            table = _pointer_table_base(words, section_start, index)
            if table is None:
                reasons["no_adjacent_table_base"] += 1
                continue
            fde_index = int(np.searchsorted(fde_starts, site, side="right") - 1)
            if not 0 <= fde_index < len(fde_starts) - 1:
                reasons["no_unwind_range"] += 1
                continue
            fde_start = int(fde_starts[fde_index])
            fde_end = int(fde_starts[fde_index + 1])
            if focus is not None and fde_start != focus:
                continue
            prefix_start = max(fde_start, site - 16 - 32 * 4)
            prefix_index = (prefix_start - section_start) // 4
            prefix = words[prefix_index:index - 3].tobytes()
            instructions = list(disassembler.disasm(prefix, prefix_start))
            if len(instructions) != (site - 12 - prefix_start) // 4:
                reasons["selector_decode_failed"] += 1
                continue
            selector = _selector(instructions)
            if selector is None:
                reasons["unsupported_selector"] += 1
                continue
            true_index, false_index, condition, kind, slice_start = selector
            if not 0 <= true_index < 4096 or not 0 <= false_index < 4096:
                reasons["index_out_of_bounds"] += 1
                continue
            requested.update((table + 8 * true_index, table + 8 * false_index))
            proposals.append((site, table, true_index, false_index,
                              condition, kind, slice_start, fde_start, fde_end))

        _, relocations = _packed_relocations(
            elf.get_section_by_name(".rela.dyn").data(), requested)
        known = tuple(relocations.get(KNOWN_TABLE + 8 * i, (None, None))[1]
                      for i in range(len(KNOWN_TARGETS)))
        if known != KNOWN_TARGETS:
            raise ValueError("APS2 decoder failed known-table cross-check")

        verified = []
        for site, table, true_index, false_index, condition, kind, slice_start, start, end in proposals:
            r_true = relocations.get(table + 8 * true_index)
            r_false = relocations.get(table + 8 * false_index)
            if r_true is None or r_false is None:
                reasons["missing_relocation"] += 1
                continue
            if any((info & 0xFFFFFFFF) != 1027 or (info >> 32) != 0
                   for info, _ in (r_true, r_false)):
                reasons["non_relative_relocation"] += 1
                continue
            true_target, false_target = r_true[1], r_false[1]
            if not (start <= true_target < end and start <= false_target < end):
                reasons["target_outside_unwind_range"] += 1
                continue
            fallthrough = site + 4
            if true_target == fallthrough and false_target != fallthrough:
                branch_condition = condition ^ 1
                branch_target = false_target
            elif false_target == fallthrough and true_target != fallthrough:
                branch_condition = condition
                branch_target = true_target
            else:
                reasons["no_unique_fallthrough"] += 1
                if diagnostics is not None:
                    diagnostics.append((site, true_target, false_target))
                continue
            try:
                replacement = _conditional_word(site, branch_target, branch_condition)
            except ValueError:
                reasons["branch_out_of_range"] += 1
                continue
            verified.append({
                "site": site, "table": table, "kind": kind,
                "true_index": true_index, "false_index": false_index,
                "true_target": true_target, "false_target": false_target,
                "condition": condition, "branch_condition": branch_condition,
                "branch_target": branch_target, "replacement": replacement,
                "slice_start": slice_start,
                "fde_start": start, "fde_end": end,
            })
        return len(indices), len(proposals), verified, reasons


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary")
    parser.add_argument("--function", type=lambda value: int(value, 0),
                        help="Show details for this FDE start")
    args = parser.parse_args()
    raw_count, decoded_count, verified, reasons = _scan(args.binary, args.function)
    print("Indexed BR signatures:", raw_count)
    print("Locally decoded selectors:", decoded_count)
    print("Verified single-instruction rewrites:", len(verified))
    print("Skipped:", dict(reasons))
    by_function = Counter(row["fde_start"] for row in verified)
    print("Distinct verified FDE ranges:", len(by_function))
    print("Top ranges:", [(hex(ea), n) for ea, n in by_function.most_common(12)])
    if args.function is not None:
        for row in verified:
            print("0x%X: %s %d/%d -> 0x%X/0x%X; B.cond 0x%X word=0x%08X" % (
                row["site"], row["kind"], row["true_index"], row["false_index"],
                row["true_target"], row["false_target"], row["branch_target"],
                row["replacement"]))
