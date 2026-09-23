"""Build a proof-gated IDB rewrite manifest for one Yuanshen 7.1 function.

Usage: python3 yuanshen_unflatten_manifest.py libyuanshen.so 0x6345BCC plan.json
Read-only against the ELF; writes only the requested JSON manifest. It refuses
partial BR X8 coverage. The manifest is for static IDA analysis, not an ELF
patch or proof that a writable pointer table is immutable at runtime.
"""

import argparse
import json
from pathlib import Path

import numpy as np
from capstone import Cs, CS_ARCH_ARM64, CS_GRP_CALL, CS_GRP_JUMP, CS_MODE_ARM
from capstone.arm64 import ARM64_OP_IMM
from elftools.elf.elffile import ELFFile

from yuanshen_unflatten_plan import _scan as scan_conditional, EXPECTED_SHA256, BR_X8
from yuanshen_unflatten_direct_plan import _scan as scan_direct
from yuanshen_unflatten_strided_plan import _scan as scan_strided
from yuanshen_unflatten_bool_plan import _scan as scan_boolean_index
from yuanshen_signature_scan import _fde_starts


def build(binary, function_start):
    with open(binary, "rb") as stream:
        elf = ELFFile(stream)
        starts = _fde_starts(elf)
        fde_index = int(np.searchsorted(starts, function_start, side="left"))
        if fde_index >= len(starts) - 1 or int(starts[fde_index]) != function_start:
            raise ValueError("Function start is not an exact FDE start")
        function_end = int(starts[fde_index + 1])
        section = elf.get_section_by_name(".text")
        section_start = section["sh_addr"]
        words = np.memmap(binary, dtype="<u4", mode="r",
                          offset=section["sh_offset"], shape=(section["sh_size"] // 4,))
        if not (section_start <= function_start < function_end <= section_start + section["sh_size"]):
            raise ValueError("FDE is not contained in .text")
        first = (function_start - section_start) // 4
        last = (function_end - section_start) // 4
        raw_br = {section_start + 4 * (first + int(index))
                  for index in np.flatnonzero(words[first:last] == BR_X8)}

        _, _, conditional, _ = scan_conditional(binary, function_start)
        _, _, direct, _ = scan_direct(binary, function_start)
        _, _, strided, _ = scan_strided(binary, function_start)
        covered_before_bool = {row["site"] for row in conditional + direct + strided}
        if covered_before_bool == raw_br:
            boolean_index = []
        else:
            _, _, boolean_index, _ = scan_boolean_index(binary, function_start,
                                                        covered_before_bool)
        resolved = covered_before_bool | {row["site"] for row in boolean_index}
        if len(resolved) != len(conditional) + len(direct) + len(strided) + len(boolean_index):
            raise ValueError("One BR site has conflicting rewrite proposals")
        missing = sorted(raw_br - resolved)
        if missing:
            raise ValueError("Unresolved BR sites: %s" % [hex(ea) for ea in missing])
        if resolved - raw_br:
            raise ValueError("Proposal outside function BR inventory")

        # A branch into the middle of a selector could bypass the constants
        # used by the proof. Check native direct branches and all table targets
        # recovered for this function before emitting the manifest.
        selector_interiors = {ea for row in conditional
                              for ea in range(row["slice_start"] + 4, row["site"], 4)}
        selector_interiors.update(ea for row in direct
                                  for ea in range(row["adrp_ea"] + 4, row["site"], 4))
        selector_interiors.update(ea for row in strided
                                  for ea in range(row["slice_start"] + 4, row["site"], 4))
        selector_interiors.update(ea for row in boolean_index
                                  for ea in range(row["slice_start"] + 4, row["site"], 4))
        disassembler = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        disassembler.detail = True
        instructions = list(disassembler.disasm(words[first:last].tobytes(), function_start))
        direct_entries = {
            insn.operands[-1].imm
            for insn in instructions
            if (insn.group(CS_GRP_JUMP) or insn.group(CS_GRP_CALL))
            and insn.operands and insn.operands[-1].type == ARM64_OP_IMM
        }
        table_entries = {target for row in conditional
                         for target in (row["true_target"], row["false_target"])}
        table_entries.update(row["target"] for row in direct)
        table_entries.update(target for row in strided
                             for target in (row["target_zero"], row["target_one"]))
        table_entries.update(target for row in boolean_index
                             for target in (row["target_zero"], row["target_one"]))
        unexpected_entries = selector_interiors & (direct_entries | table_entries)
        if unexpected_entries:
            raise ValueError("Incoming edges into selector interiors: %s" %
                             [hex(ea) for ea in sorted(unexpected_entries)])

        items = []
        for row in conditional:
            items.append({
                "site": row["site"], "target": row["branch_target"],
                "replacement": row["replacement"], "kind": "conditional",
                "table_slots": [row["table"] + 8 * row["true_index"],
                                row["table"] + 8 * row["false_index"]],
                "table_targets": [row["true_target"], row["false_target"]],
                "selector": row["kind"],
                "slice_start": row["slice_start"],
            })
        for row in direct:
            items.append({
                "site": row["site"], "target": row["target"],
                "replacement": row["replacement"], "kind": "direct",
                "table_slots": [row["slot"]], "table_targets": [row["target"]],
                "selector": "fixed_slot",
                "adrp_ea": row["adrp_ea"], "load_ea": row["load_ea"],
            })
        for row in strided:
            items.append({
                "site": row["site"], "target": row["branch_target"],
                "replacement": row["replacement"], "kind": "strided_bool",
                "table_slots": [row["table"], row["table"] + row["stride"]],
                "table_targets": [row["target_zero"], row["target_one"]],
                "selector": row["source_kind"], "slice_start": row["slice_start"],
                "stride": row["stride"],
            })
        for row in boolean_index:
            items.append({
                "site": row["site"], "target": row["branch_target"],
                "replacement": row["replacement"], "kind": "indexed_bool",
                "table_slots": [row["table"], row["table"] + 8],
                "table_targets": [row["target_zero"], row["target_one"]],
                "selector": "abstract_boolean", "slice_start": row["slice_start"],
            })
        items.sort(key=lambda row: row["site"])
        for item in items:
            index = (item["site"] - section_start) // 4
            item["original_word"] = BR_X8
            context_start = min(item.get("slice_start", item.get("adrp_ea", item["site"])),
                                item["site"] - 32)
            context_index = (context_start - section_start) // 4
            item["original_context_start"] = context_start
            item["original_context_hex"] = words[context_index:index + 1].tobytes().hex()
        return {
            "format": "yuanshen-idb-branch-manifest-v1",
            "binary_sha256": EXPECTED_SHA256,
            "function_start": function_start,
            "function_end": function_end,
            "br_count": len(raw_br),
            "conditional_count": len(conditional),
            "direct_count": len(direct),
            "strided_count": len(strided),
            "boolean_index_count": len(boolean_index),
            "items": items,
            "limitations": [
                "FDE range may not equal IDA function ownership until analysis finishes",
                "Writability of pointer tables means runtime mutation is not excluded",
                "IDA CFG ownership and any missing external incoming edges need validation before applying",
            ],
        }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary")
    parser.add_argument("function", type=lambda value: int(value, 0))
    parser.add_argument("output")
    args = parser.parse_args()
    manifest = build(args.binary, args.function)
    Path(args.output).write_text(json.dumps(manifest, indent=2) + "\n")
    print("0x%X–0x%X: %d/%d BR sites covered (%d conditional, %d direct, %d strided, %d Boolean-index)" % (
        manifest["function_start"], manifest["function_end"],
        len(manifest["items"]), manifest["br_count"],
        manifest["conditional_count"], manifest["direct_count"],
        manifest["strided_count"], manifest["boolean_index_count"]))
    print("Wrote", args.output)
