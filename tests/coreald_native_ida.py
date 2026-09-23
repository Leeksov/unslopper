"""Isolated IDA differential check for the marked CoreALD 26.0.1 slices.

IDA args: plugin.dylib result.json
Runs on a copy of the CoreALD IDB. No machine bytes are changed.
"""

import hashlib
import importlib.util
import json
from pathlib import Path

import ida_auto
import ida_bytes
import ida_funcs
import ida_hexrays
import ida_loader
import ida_pro
import idc


ENTRIES = (0x242512CC0, 0x242B7ED44)
EXPECTED = {
    0x242512D3C: 0x45,
    0x242512D84: 0x8D,
    0x242512DF4: 0x69,
    0x242B7EDC0: 0x32,
    0x242B7EE04: 0xB1,
    0x242B7EE6C: 0xE8,
}
TEXT_START, TEXT_SIZE = 0x2424D1000, 0x9F1FB4


def microcode_at(entry, site):
    function = ida_funcs.get_func(entry)
    mba = ida_hexrays.gen_microcode(
        ida_hexrays.mba_ranges_t(function), None, None, 0,
        ida_hexrays.MMAT_GENERATED)
    if mba is None:
        raise RuntimeError(f"No microcode for 0x{entry:x}")
    return [(ins.opcode, ins.dstr())
            for block_no in range(mba.qty)
            for ins in instructions(mba.get_mblock(block_no))
            if ins.ea == site]


def instructions(block):
    ins = block.head
    while ins:
        yield ins
        ins = ins.next


def cfunc(entry):
    ida_hexrays.mark_cfunc_dirty(entry, False)
    result = ida_hexrays.decompile(entry)
    if result is None:
        raise RuntimeError(f"Decompilation failed at 0x{entry:x}")
    return str(result)


def main():
    plugin_path, output = Path(idc.ARGV[1]), Path(idc.ARGV[2])
    ida_auto.auto_wait()
    if not ida_hexrays.init_hexrays_plugin():
        raise RuntimeError("Hex-Rays is unavailable")
    before_bytes = hashlib.sha256(ida_bytes.get_bytes(TEXT_START, TEXT_SIZE)).hexdigest()

    spec = importlib.util.spec_from_file_location(
        "coreald_sbox", Path(__file__).resolve().parents[1] / "tools" / "coreald_sbox.py")
    module = importlib.util.module_from_spec(spec)
    import sys
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    image = module.IDAImage()
    proofs = {}
    for entry in ENTRIES:
        function = ida_funcs.get_func(entry)
        for site in range(function.start_ea, function.end_ea, 4):
            proof = module.analyze_site(image, site)
            if proof is not None:
                proofs[site] = proof
    if {site: p.constant for site, p in proofs.items()} != EXPECTED:
        raise RuntimeError("CoreALD proof coverage changed")

    baseline = {hex(entry): cfunc(entry) for entry in ENTRIES}
    baseline_microcode = {
        hex(site): microcode_at(ENTRIES[0] if site < ENTRIES[1] else ENTRIES[1], site)
        for site in EXPECTED}
    if any(not any(op == ida_hexrays.m_and for op, unused in rows)
           for rows in baseline_microcode.values()):
        raise RuntimeError("Native AND is absent in baseline microcode")

    # A wrong fingerprint must leave the instruction untouched.
    first = min(proofs)
    wrong = proofs[first].marker().rsplit(" ", 1)[0] + " 0x0000000000000000"
    idc.set_cmt(first, wrong, False)
    plugin = ida_loader.load_plugin(str(plugin_path))
    if plugin is None:
        raise RuntimeError("Fresh plugin failed to load")
    ida_loader.run_plugin(plugin, 2)
    negative = microcode_at(ENTRIES[0], first)
    if not any(op == ida_hexrays.m_and for op, unused in negative):
        raise RuntimeError("Tampered proof was accepted")

    for site, proof in proofs.items():
        idc.set_cmt(site, proof.marker(), False)
    ida_hexrays.clear_cached_cfuncs()
    transformed = {hex(entry): cfunc(entry) for entry in ENTRIES}
    transformed_microcode = {
        hex(site): microcode_at(ENTRIES[0] if site < ENTRIES[1] else ENTRIES[1], site)
        for site in EXPECTED}
    for site, rows in transformed_microcode.items():
        constant = EXPECTED[int(site, 16)]
        if any(op == ida_hexrays.m_and for op, unused in rows):
            raise RuntimeError(f"Verified AND remained at {site}")
        if not any(op == ida_hexrays.m_mov and f"#0X{constant:X}" in text.upper()
                   for op, text in rows):
            raise RuntimeError(f"Verified constant missing at {site}")
    repeated = {hex(entry): cfunc(entry) for entry in ENTRIES}
    after_bytes = hashlib.sha256(ida_bytes.get_bytes(TEXT_START, TEXT_SIZE)).hexdigest()
    ida_loader.run_plugin(plugin, 4)

    result = {
        "plugin_sha256": hashlib.sha256(plugin_path.read_bytes()).hexdigest(),
        "proofs": {hex(site): proof.marker() for site, proof in proofs.items()},
        "baseline": {key: {"lines": len(text.splitlines()), "sha256": hashlib.sha256(text.encode()).hexdigest()}
                     for key, text in baseline.items()},
        "transformed": {key: {"lines": len(text.splitlines()), "sha256": hashlib.sha256(text.encode()).hexdigest()}
                        for key, text in transformed.items()},
        "repeated_equal": transformed == repeated,
        "machine_bytes_unchanged": before_bytes == after_bytes,
        "negative_rejected": True,
    }
    output.write_text(json.dumps(result, indent=2) + "\n")
    if transformed != repeated or before_bytes != after_bytes:
        raise RuntimeError("Output instability or modified machine bytes")
    print("COREALD_NATIVE_PASS", len(proofs), "verified folds", flush=True)


try:
    main()
except Exception as error:
    print("COREALD_NATIVE_FAIL", error, flush=True)
    ida_pro.qexit(1)
else:
    ida_pro.qexit(0)
