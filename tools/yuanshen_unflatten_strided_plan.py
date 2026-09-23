"""Prove bounded two-way rewrites for Genshin's strided BR X8 tables.

Recognizes MOV W8,W9; UBFIZ X9,X8,#k,#32; ADRP/ADD; LDR X8,[X8,X9],
or direct one-bit AND/shift variants (including scaled LDR), ending in BR X8.
A bounded straight-line slice must prove the offset is zero or one stride.
APS2 must then resolve slots 0/1 inside one unwind
range with exactly one fallthrough target. The proposed CBZ/CBNZ X9 preserves
all earlier arithmetic and the loaded X8 value. Read-only; no IDB patches.
"""

import argparse
from collections import Counter

import numpy as np
from capstone import CS_ARCH_ARM64, CS_GRP_CALL, CS_GRP_JUMP, CS_GRP_RET, CS_MODE_ARM, Cs
from capstone.arm64 import ARM64_OP_IMM
from elftools.elf.elffile import ELFFile

from yuanshen_aps2_tables import _packed_relocations, KNOWN_TABLE, KNOWN_TARGETS
from yuanshen_signature_scan import _fde_starts, _pointer_table_base
from yuanshen_unflatten_plan import _sha256, EXPECTED_SHA256, BR_X8


LDR_STRIDED = 0xF8696908
LDR_SCALED = 0xF8697908    # LDR X8,[X8,X9,LSL #3]
MOV_W8_W9 = 0x2A0903E8
STRIDES = {
    0xD37C7D09: 16,
    0xD37B7D09: 32,
    0xD37A7D09: 64,
    0xD3797D09: 128,
    0xD3787D09: 256,
}


def _boolean_definition(instructions):
    for insn in reversed(instructions):
        if insn.group(CS_GRP_JUMP) or insn.group(CS_GRP_CALL) or insn.group(CS_GRP_RET):
            if not (insn.mnemonic == "b" and insn.operands
                    and insn.operands[-1].type == ARM64_OP_IMM
                    and insn.operands[-1].imm == insn.address + 4):
                return None
        writes = {insn.reg_name(reg) for reg in insn.regs_access()[1]}
        if not ("w9" in writes or "x9" in writes):
            continue
        parts = [part.strip() for part in insn.op_str.split(",")]
        if insn.mnemonic == "cset" and len(parts) == 2 and parts[0] == "w9":
            return insn.address, "cset"
        if insn.mnemonic == "and" and len(parts) == 3 and parts[0] == "w9" and parts[2] == "#1":
            return insn.address, "and_1"
        return None
    return None


def _cb_word(site, target, nonzero):
    if (target - site) % 4:
        raise ValueError("unaligned target")
    displacement = (target - site) // 4
    if not -(1 << 18) <= displacement < (1 << 18):
        raise ValueError("CB target out of range")
    return (0xB5000009 if nonzero else 0xB4000009) | ((displacement & 0x7FFFF) << 5)


def _scan(path, focus=None):
    if _sha256(path) != EXPECTED_SHA256:
        raise ValueError("Input SHA-256 differs from the verified 7.1 sample")
    with open(path, "rb") as stream:
        elf = ELFFile(stream)
        section = elf.get_section_by_name(".text")
        base = section["sh_addr"]
        words = np.memmap(path, dtype="<u4", mode="r",
                          offset=section["sh_offset"], shape=(section["sh_size"] // 4,))
        starts = _fde_starts(elf)
        indices = np.flatnonzero(words == BR_X8)
        indices = indices[(indices >= 6) &
                          ((words[indices - 1] == LDR_STRIDED) |
                           (words[indices - 1] == LDR_SCALED))]
        disassembler = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        disassembler.detail = True
        candidates = []
        requested = {KNOWN_TABLE + 8 * i for i in range(len(KNOWN_TARGETS))}
        reasons = Counter()
        for raw_index in indices:
            index = int(raw_index)
            site = base + 4 * index
            table = _pointer_table_base(words, base, index)
            if table is None:
                reasons["unsupported_strided_shape"] += 1
                continue
            stride = STRIDES.get(int(words[index - 4]))
            local_kind = None
            local_start = None
            if int(words[index - 1]) == LDR_SCALED:
                if int(words[index - 4]) != 0x92400109:
                    reasons["unsupported_strided_shape"] += 1
                    continue
                stride, local_kind, local_start = 8, "mask_x9_scaled", site - 16
            elif stride is not None and int(words[index - 5]) == MOV_W8_W9:
                local_kind = "ubfiz_boolean"
            else:
                nearby = list(disassembler.disasm(words[index - 5:index - 3].tobytes(), site - 20))
                if len(nearby) == 2:
                    before, offset_insn = nearby
                    parts = [part.strip() for part in offset_insn.op_str.split(",")]
                    if (offset_insn.mnemonic == "and" and len(parts) == 3
                        and parts[:2] == ["x9", "x8"] and parts[2].startswith("#")):
                        mask = int(parts[2][1:], 0)
                        if mask >= 8 and mask & (mask - 1) == 0:
                            stride, local_kind, local_start = mask, "mask_x9", offset_insn.address
                    elif (offset_insn.mnemonic == "lsl" and len(parts) == 3
                          and parts[:2] == ["x9", "x8"] and parts[2].startswith("#")
                          and before.mnemonic == "and"
                          and before.op_str in ("x8, x8, #1", "w8, w8, #1")):
                        shift = int(parts[2][1:], 0)
                        if 3 <= shift <= 10:
                            stride, local_kind, local_start = 1 << shift, "mask_then_shift", before.address
            if stride is None or (local_kind is None and int(words[index - 5]) != MOV_W8_W9):
                reasons["unsupported_strided_shape"] += 1
                continue
            fde_index = int(np.searchsorted(starts, site, side="right") - 1)
            if not 0 <= fde_index < len(starts) - 1:
                reasons["no_unwind_range"] += 1
                continue
            start, end = int(starts[fde_index]), int(starts[fde_index + 1])
            if focus is not None and start != focus:
                continue
            if local_kind in ("mask_x9", "mask_then_shift", "mask_x9_scaled"):
                slice_start, source_kind = local_start, local_kind
            else:
                prefix_start = max(start, site - 20 - 160 * 4)
                prefix_index = (prefix_start - base) // 4
                instructions = list(disassembler.disasm(words[prefix_index:index - 5].tobytes(),
                                                        prefix_start))
                if len(instructions) != (site - 20 - prefix_start) // 4:
                    reasons["slice_decode_failed"] += 1
                    continue
                found = _boolean_definition(instructions)
                if found is None:
                    reasons["boolean_not_proven"] += 1
                    continue
                slice_start, source_kind = found
            requested.update((table, table + stride))
            candidates.append((site, table, stride, start, end, slice_start, source_kind))

        _, relocations = _packed_relocations(elf.get_section_by_name(".rela.dyn").data(), requested)
        known = tuple(relocations.get(KNOWN_TABLE + 8 * i, (None, None))[1]
                      for i in range(len(KNOWN_TARGETS)))
        if known != KNOWN_TARGETS:
            raise ValueError("APS2 decoder failed known-table cross-check")
        verified = []
        for site, table, stride, start, end, slice_start, source_kind in candidates:
            r0 = relocations.get(table)
            r1 = relocations.get(table + stride)
            if r0 is None or r1 is None:
                reasons["missing_relocation"] += 1
                continue
            if any((info & 0xFFFFFFFF) != 1027 or (info >> 32) != 0 for info, _ in (r0, r1)):
                reasons["non_relative_relocation"] += 1
                continue
            t0, t1 = r0[1], r1[1]
            if not (start <= t0 < end and start <= t1 < end):
                reasons["target_outside_unwind_range"] += 1
                continue
            if t0 == site + 4 and t1 != site + 4:
                branch_target, nonzero = t1, True
            elif t1 == site + 4 and t0 != site + 4:
                branch_target, nonzero = t0, False
            else:
                reasons["no_unique_fallthrough"] += 1
                continue
            try:
                replacement = _cb_word(site, branch_target, nonzero)
            except ValueError:
                reasons["branch_out_of_range"] += 1
                continue
            verified.append({"site": site, "table": table, "stride": stride,
                             "target_zero": t0, "target_one": t1,
                             "branch_target": branch_target, "replacement": replacement,
                             "slice_start": slice_start, "source_kind": source_kind,
                             "fde_start": start, "fde_end": end})
        return len(indices), len(candidates), verified, reasons


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary")
    parser.add_argument("--function", type=lambda value: int(value, 0))
    args = parser.parse_args()
    raw_count, decoded_count, verified, reasons = _scan(args.binary, args.function)
    print("Strided BR signatures:", raw_count)
    print("Boolean index proofs:", decoded_count)
    print("Verified CBZ/CBNZ rewrites:", len(verified))
    print("Skipped:", dict(reasons))
    counts = Counter(row["fde_start"] for row in verified)
    print("Distinct verified FDE ranges:", len(counts))
    print("Top ranges:", [(hex(ea), n) for ea, n in counts.most_common(12)])
    if args.function is not None:
        for row in verified:
            print("0x%X: stride %d, %s at 0x%X, 0→0x%X 1→0x%X, word=0x%08X" % (
                row["site"], row["stride"], row["source_kind"], row["slice_start"],
                row["target_zero"], row["target_one"], row["replacement"]))
