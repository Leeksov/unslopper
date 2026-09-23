"""Prove direct B rewrites for Yuanshen 7.1 fixed pointer BR X8 sites.

Read-only. Recognizes ADRP X8; optional ADD X8; LDR X8,[X8,#slot]; intervening
instructions that leave X8 untouched; BR X8. APS2 relocation must resolve
to an aligned target in the same unwind range. Only the final BR would be
replaced, so the original pointer load and its register effect remain.
The table may be runtime-mutable; proposals are for static IDB analysis only.

Usage: python3 yuanshen_unflatten_direct_plan.py /path/to/libyuanshen.so
       python3 yuanshen_unflatten_direct_plan.py /path/to/libyuanshen.so --function 0x6345BCC
Requires numpy, pyelftools, and capstone.
"""

import argparse
from collections import Counter

import numpy as np
from capstone import CS_ARCH_ARM64, CS_GRP_CALL, CS_GRP_JUMP, CS_GRP_RET, CS_MODE_ARM, Cs
from elftools.elf.elffile import ELFFile

from yuanshen_aps2_tables import _packed_relocations, KNOWN_TABLE, KNOWN_TARGETS
from yuanshen_signature_scan import _fde_starts
from yuanshen_unflatten_plan import _sha256, EXPECTED_SHA256, BR_X8


LDR_X8_IMM_MASK = 0xFFC003FF
LDR_X8_IMM_VALUE = 0xF9400108
ADRP_X8_MASK = 0x9F00001F
ADRP_X8_VALUE = 0x90000008
ADD_X8_IMM_MASK = 0xFF8003FF
ADD_X8_IMM_VALUE = 0x91000108


def _adrp_page(word, pc):
    delta = (((word >> 5) & 0x7FFFF) << 2) | ((word >> 29) & 3)
    if delta & (1 << 20):
        delta -= 1 << 21
    return (pc & ~0xFFF) + (delta << 12)


def _branch_word(site, target):
    if (target - site) % 4:
        raise ValueError("Unaligned target")
    delta = (target - site) // 4
    if not -(1 << 25) <= delta < (1 << 25):
        raise ValueError("Unconditional B target out of range")
    return 0x14000000 | (delta & 0x3FFFFFF)


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
        br_indices = np.flatnonzero(words == BR_X8)
        disassembler = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        disassembler.detail = True
        requested = {KNOWN_TABLE + 8 * i for i in range(len(KNOWN_TARGETS))}
        proposals = []
        reasons = Counter()
        for raw_index in br_indices:
            index = int(raw_index)
            site = base + 4 * index
            fde_index = int(np.searchsorted(starts, site, side="right") - 1)
            if not 0 <= fde_index < len(starts) - 1:
                continue
            start, end = int(starts[fde_index]), int(starts[fde_index + 1])
            if focus is not None and start != focus:
                continue
            found = False
            for gap in range(1, 33):
                ldr_index = index - gap
                if ldr_index < 1:
                    break
                if base + 4 * (ldr_index - 2) < start:
                    break
                ldr_word = int(words[ldr_index])
                if ldr_word & LDR_X8_IMM_MASK != LDR_X8_IMM_VALUE:
                    continue
                previous = int(words[ldr_index - 1])
                add_immediate = 0
                if previous & ADRP_X8_MASK == ADRP_X8_VALUE:
                    adrp_index = ldr_index - 1
                elif (previous & ADD_X8_IMM_MASK == ADD_X8_IMM_VALUE
                      and ldr_index >= 2
                      and int(words[ldr_index - 2]) & ADRP_X8_MASK == ADRP_X8_VALUE):
                    adrp_index = ldr_index - 2
                    add_immediate = (previous >> 10) & 0xFFF
                    if previous & (1 << 22):
                        add_immediate <<= 12
                else:
                    continue
                if base + 4 * adrp_index < start:
                    continue
                between = words[ldr_index + 1:index].tobytes()
                instructions = list(disassembler.disasm(between, base + 4 * (ldr_index + 1)))
                if len(instructions) != gap - 1:
                    continue
                if any(insn.group(CS_GRP_JUMP) or insn.group(CS_GRP_CALL)
                       or insn.group(CS_GRP_RET)
                       or any(insn.reg_name(reg) in ("x8", "w8")
                              for reg in insn.regs_access()[1])
                       for insn in instructions):
                    continue
                page = _adrp_page(int(words[adrp_index]), base + 4 * adrp_index)
                slot = page + add_immediate + (((ldr_word >> 10) & 0xFFF) << 3)
                requested.add(slot)
                proposals.append((site, slot, start, end,
                                  base + 4 * adrp_index, base + 4 * ldr_index))
                found = True
                break
            if not found:
                reasons["no_local_fixed_pointer_load"] += 1

        _, relocations = _packed_relocations(
            elf.get_section_by_name(".rela.dyn").data(), requested)
        known = tuple(relocations.get(KNOWN_TABLE + 8 * i, (None, None))[1]
                      for i in range(len(KNOWN_TARGETS)))
        if known != KNOWN_TARGETS:
            raise ValueError("APS2 decoder failed known-table cross-check")
        verified = []
        for site, slot, start, end, adrp_ea, load_ea in proposals:
            relocation = relocations.get(slot)
            if relocation is None:
                reasons["missing_relocation"] += 1
                continue
            info, target = relocation
            if (info & 0xFFFFFFFF) != 1027 or (info >> 32) != 0:
                reasons["non_relative_relocation"] += 1
                continue
            if not start <= target < end:
                reasons["target_outside_unwind_range"] += 1
                continue
            try:
                replacement = _branch_word(site, target)
            except ValueError:
                reasons["branch_out_of_range"] += 1
                continue
            verified.append({"site": site, "slot": slot, "target": target,
                             "replacement": replacement,
                             "adrp_ea": adrp_ea, "load_ea": load_ea,
                             "fde_start": start, "fde_end": end})
        return len(br_indices), len(proposals), verified, reasons


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary")
    parser.add_argument("--function", type=lambda value: int(value, 0),
                        help="Show details for this FDE start")
    args = parser.parse_args()
    raw_count, local_count, verified, reasons = _scan(args.binary, args.function)
    print("BR X8 sites:", raw_count)
    print("Local fixed-pointer loads:", local_count)
    print("Verified direct B rewrites:", len(verified))
    print("Skipped:", dict(reasons))
    by_function = Counter(row["fde_start"] for row in verified)
    print("Distinct verified FDE ranges:", len(by_function))
    print("Top ranges:", [(hex(ea), n) for ea, n in by_function.most_common(12)])
    if args.function is not None:
        for row in verified:
            print("0x%X: slot 0x%X -> B 0x%X word=0x%08X" %
                  (row["site"], row["slot"], row["target"], row["replacement"]))
