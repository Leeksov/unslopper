"""Emulate the 16 CoreALD export prefixes up to their BRAA/BLRAA sites.

This is a synthetic-state check of native index arithmetic. Chomper 0.3.8
does not process this image's dyld shared-cache pointer chains, so the probe
rebases unauthenticated read-only slots in emulator memory. It stops before
PAC branch execution and never modifies the input image or a device.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
from pathlib import Path


SAMPLE_SHA256 = "247842d90546265eb6ced34fa18d83bc3d2eaaa3d4c1e79bb2cd3aab0e91f24f"
GUARD_SLOT = 0x278053720
ROOT_TABLE = 0x28561CA20
NULL_DISPATCH = 0x24252FB5C


def main():
    from chomper import Chomper
    from chomper.const import ARCH_ARM64, OS_IOS
    from unicorn import UC_PROT_ALL
    from unicorn.arm64_const import UC_ARM64_REG_X8, UC_ARM64_REG_X9, UC_ARM64_REG_X17
    import lief

    from coreald_pac import decode_shared_cache_rebase

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", type=Path, required=True)
    parser.add_argument("--rootfs", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    if hashlib.sha256(args.image.read_bytes()).hexdigest() != SAMPLE_SHA256:
        raise ValueError("CoreALD image SHA-256 differs from the audited sample")
    report = json.loads(args.report.read_text())
    if report.get("sample_sha256") != SAMPLE_SHA256 or len(report["transfers"]) != 16:
        raise ValueError("report does not describe all 16 audited exports")
    parsed = lief.MachO.parse(str(args.image))
    binary = parsed.at(0) if hasattr(parsed, "at") else parsed
    segments = [(seg.virtual_address, seg.virtual_address + seg.virtual_size)
                for seg in binary.segments]
    data_const = next(seg for seg in binary.segments if seg.name == "__DATA_CONST")

    logging.disable(logging.CRITICAL)
    emu = Chomper(arch=ARCH_ARM64, os_type=OS_IOS,
                  rootfs_path=str(args.rootfs))
    module = emu.load_module(str(args.image), exec_init_array=False,
                             exec_objc_init=False)

    def mapped(static_address):
        return module.base + static_address - module.macho_info.image_base

    # The stack-guard import is outside CoreALD's own Mach-O segments.
    guard = emu.create_buffer(8)
    guard_page = mapped(GUARD_SLOT) & ~0xFFF
    if not any(lo <= guard_page < hi for lo, hi, _ in emu.uc.mem_regions()):
        emu.uc.mem_map(guard_page, 0x1000, UC_PROT_ALL)
    emu.write_pointer(mapped(GUARD_SLOT), guard)
    emu.write_pointer(guard, 0)

    # Chomper leaves format-13 shared-cache rebases as on-disk words. Rebase
    # only slots whose decoded target belongs to this Mach-O's mapped ranges.
    fixed = 0
    for slot in range(data_const.virtual_address,
                      data_const.virtual_address + data_const.virtual_size, 8):
        raw = emu.read_pointer(mapped(slot))
        target = decode_shared_cache_rebase(raw)
        if target is not None and any(lo <= target < hi for lo, hi in segments):
            emu.write_pointer(mapped(slot), mapped(target))
            fixed += 1
    if emu.read_pointer(mapped(0x2790C42E8)) != mapped(ROOT_TABLE):
        raise ValueError("dispatch root slot was not rebased")

    argument = emu.create_buffer(0x1000)
    checks = []
    for row in report["transfers"]:
        site = int(row["site"], 16)
        entry = int(row["export"], 16)
        captured = []
        register = UC_ARM64_REG_X9 if row["kind"] == "BRAA" else UC_ARM64_REG_X8

        def stop_at_transfer(uc, address, size, context):
            captured.append((uc.reg_read(register), uc.reg_read(UC_ARM64_REG_X17)))
            uc.emu_stop()

        emu.add_hook(mapped(site), stop_at_transfer)
        arg_sets = ((0, 0), (argument, argument)) if entry == NULL_DISPATCH else (
            (argument,) * 8,)
        for call_args in arg_sets:
            captured.clear()
            try:
                emu.call_address(mapped(entry), *call_args)
            except Exception as error:
                checks.append({"export": row["export"], "error":
                               f"{type(error).__name__}: {error}"})
                continue
            if len(captured) != 1:
                checks.append({"export": row["export"], "error":
                               "transfer hook was not reached exactly once"})
                continue
            value, modifier = captured[0]
            if entry == NULL_DISPATCH:
                index = 0x10B3 if call_args[0] == 0 else 0x10A1
                expected = emu.read_pointer(mapped(ROOT_TABLE + index * 8))
                expected_modifier = 0x869D
            else:
                expected = int(row["raw"], 16)
                expected_modifier = int(row["modifier"], 16)
            checks.append({"export": row["export"],
                           "args_null": call_args[0] == 0,
                           "value": hex(value), "expected": hex(expected),
                           "modifier": hex(modifier),
                           "match": (value, modifier) == (expected, expected_modifier)})

    output = {"sample_sha256": SAMPLE_SHA256,
              "scope": "synthetic Chomper state; stops before PAC transfer",
              "chomper_readonly_slots_rebased": fixed,
              "checks": checks,
              "matched": sum(check.get("match", False) for check in checks),
              "total": len(checks)}
    if args.output:
        args.output.write_text(json.dumps(output, indent=2) + "\n")
    print(json.dumps({"matched": output["matched"], "total": output["total"],
                      "slots_rebased": fixed}))
    if output["matched"] != 17 or output["total"] != 17:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
