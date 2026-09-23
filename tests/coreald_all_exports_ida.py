"""Differential CoreALD test for every exported function in an isolated IDB.

IDA args: fresh_plugin.dylib result.json
Requires the analyzed iOS 26.0.1 CoreALD IDB. Does not patch machine bytes.
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
import idautils
import idc


TEXT_START, TEXT_SIZE = 0x2424D1000, 0x9F1FB4


def fingerprint_text(text):
    return {"lines": len(text.splitlines()),
            "sha256": hashlib.sha256(text.encode()).hexdigest()}


def decompile_all(exports, phase):
    ida_hexrays.clear_cached_cfuncs()
    results = {}
    for ea, name in exports:
        try:
            cfunc = ida_hexrays.decompile(ea)
            if cfunc is None:
                raise RuntimeError("no cfunc")
            text = str(cfunc)
            (TEXT_DIR / f"{phase}_{ea:x}.c").write_text(text)
            results[hex(ea)] = {"name": name, **fingerprint_text(text)}
        except Exception as error:
            results[hex(ea)] = {"name": name, "error": type(error).__name__}
    return results


def instructions(block):
    ins = block.head
    while ins:
        yield ins
        ins = ins.next


def microcode_at(entry, site):
    mba = ida_hexrays.gen_microcode(
        ida_hexrays.mba_ranges_t(ida_funcs.get_func(entry)), None, None, 0,
        ida_hexrays.MMAT_GENERATED)
    if mba is None:
        raise RuntimeError(f"No generated microcode at 0x{entry:x}")
    return [(ins.opcode, ins.dstr())
            for block_no in range(mba.qty)
            for ins in instructions(mba.get_mblock(block_no))
            if ins.ea == site]


def main():
    global TEXT_DIR
    plugin_path, output = Path(idc.ARGV[1]), Path(idc.ARGV[2])
    TEXT_DIR = output.with_suffix(".texts")
    TEXT_DIR.mkdir(exist_ok=True)
    ida_auto.auto_wait()
    if not ida_hexrays.init_hexrays_plugin():
        raise RuntimeError("Hex-Rays is unavailable")
    exports = [(ea, name) for unused, ordinal, ea, name in idautils.Entries()]
    if len(exports) != 16:
        raise RuntimeError(f"Expected 16 exports, found {len(exports)}")
    original_bytes = hashlib.sha256(ida_bytes.get_bytes(TEXT_START, TEXT_SIZE)).hexdigest()

    spec = importlib.util.spec_from_file_location(
        "coreald_sbox", Path(__file__).resolve().parents[1] / "tools" / "coreald_sbox.py")
    module = importlib.util.module_from_spec(spec)
    import sys
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    image = module.IDAImage()
    proofs = {}
    owners = {}
    for ea, unused in exports:
        function = ida_funcs.get_func(ea)
        for site in range(function.start_ea, function.end_ea, 4):
            proof = module.analyze_site(image, site)
            if proof is not None:
                proofs[site] = proof
                owners[site] = ea
    if len(proofs) != 37:
        raise RuntimeError(f"Expected 37 native proofs, found {len(proofs)}")

    baseline = decompile_all(exports, "baseline")
    plugin = ida_loader.load_plugin(str(plugin_path))
    if plugin is None:
        raise RuntimeError("Fresh plugin failed to load")
    ida_loader.run_plugin(plugin, 2)
    core_only = decompile_all(exports, "core_only")

    # Rejection control: an explicit but modified proof must not fold.
    first = min(proofs)
    wrong = proofs[first].marker().rsplit(" ", 1)[0] + " 0x0000000000000000"
    idc.set_cmt(first, wrong, False)
    negative = microcode_at(owners[first], first)
    if not any(op == ida_hexrays.m_and for op, unused in negative):
        raise RuntimeError("Tampered proof was accepted")

    for site, proof in proofs.items():
        idc.set_cmt(site, proof.marker(), False)
    decompile_all(exports, "warmup")  # Let Hex-Rays settle types after the new constants.
    marked = decompile_all(exports, "marked")
    repeated = decompile_all(exports, "repeated")

    not_folded = []
    for site, proof in proofs.items():
        rows = microcode_at(owners[site], site)
        token = f"#0X{proof.constant:X}"
        if (any(op == ida_hexrays.m_and for op, unused in rows)
                or not any(op == ida_hexrays.m_mov and token in text.upper()
                           for op, text in rows)):
            not_folded.append(hex(site))
    after_bytes = hashlib.sha256(ida_bytes.get_bytes(TEXT_START, TEXT_SIZE)).hexdigest()
    ida_loader.run_plugin(plugin, 4)

    new_errors = [key for key in core_only
                  if "error" not in core_only[key] and "error" in marked[key]]
    result = {
        "sample": "CoreALD 4.1.0 iOS 26.0.1",
        "plugin_sha256": hashlib.sha256(plugin_path.read_bytes()).hexdigest(),
        "export_count": len(exports),
        "native_proof_count": len(proofs),
        "proofs_per_export": {
            hex(ea): sum(owner == ea for owner in owners.values())
            for ea, unused in exports},
        "baseline": baseline,
        "core_only": core_only,
        "marked": marked,
        "repeated_equal": marked == repeated,
        "negative_rejected": True,
        "not_folded": not_folded,
        "new_errors": new_errors,
        "machine_bytes_unchanged": original_bytes == after_bytes,
    }
    output.write_text(json.dumps(result, indent=2) + "\n")
    if not_folded or new_errors or marked != repeated or original_bytes != after_bytes:
        raise RuntimeError("Fold failure, regression, instability, or byte changes")
    print("COREALD_ALL_EXPORTS_PASS", len(exports), "exports", len(proofs), "folds", flush=True)


try:
    main()
except Exception as error:
    print("COREALD_ALL_EXPORTS_FAIL", error, flush=True)
    ida_pro.qexit(1)
else:
    ida_pro.qexit(0)
