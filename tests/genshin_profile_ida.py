"""Headless IDA regression for the Genshin native profile on a disposable IDB.

IDA args: manifest.json fresh_unslopper.dylib result.json
Set UNSLOP_GENSHIN_MANIFEST to the same manifest and open an IDB copy with -a.
The source ELF is never patched or executed.
"""

import hashlib
import json
import os
from pathlib import Path

import ida_auto
import ida_bytes
import ida_hexrays
import ida_loader
import ida_pro
import idc


def pseudo(ea):
    ida_hexrays.clear_cached_cfuncs()
    cfunc = ida_hexrays.decompile(ea)
    if cfunc is None:
        raise RuntimeError("F5 failed at 0x%X" % ea)
    return str(cfunc)


def main():
    manifest = json.loads(Path(idc.ARGV[1]).read_text())
    plugin_path = idc.ARGV[2]
    output = Path(idc.ARGV[3])
    ida_auto.enable_auto(False)
    if not ida_hexrays.init_hexrays_plugin():
        raise RuntimeError("Hex-Rays unavailable")
    plugin = ida_loader.load_plugin(plugin_path)
    if plugin is None:
        raise RuntimeError("Fresh Genshin build did not load")
    ida_loader.run_plugin(plugin, 1)
    start = manifest["function_start"]
    sites = [row["site"] for row in manifest["items"]]
    original = [ida_bytes.get_dword(ea) for ea in sites]
    if any(word != 0xD61F0100 for word in original):
        raise RuntimeError("Disposable IDB already has Genshin branch patches")
    try:
        before = pseudo(start)
        baseline_error = None
    except Exception as exc:
        before = ""
        baseline_error = str(exc)
    bad = json.loads(json.dumps(manifest))
    bad["items"][-1]["table_slots"][0] += 8
    bad_path = output.with_suffix(".tampered.json")
    bad_path.write_text(json.dumps(bad))
    valid_path = os.environ["UNSLOP_GENSHIN_MANIFEST"]
    try:
        os.environ["UNSLOP_GENSHIN_MANIFEST"] = str(bad_path)
        ida_loader.run_plugin(plugin, 31)
    finally:
        os.environ["UNSLOP_GENSHIN_MANIFEST"] = valid_path
    if [ida_bytes.get_dword(ea) for ea in sites] != original:
        raise RuntimeError("Tampered manifest changed IDB instructions")
    ida_loader.run_plugin(plugin, 30)
    if [ida_bytes.get_dword(ea) for ea in sites] != original:
        raise RuntimeError("Dry-run changed IDB instructions")
    ida_loader.run_plugin(plugin, 31)
    replacements = [row["replacement"] for row in manifest["items"]]
    patched = [ida_bytes.get_dword(ea) for ea in sites]
    if patched != replacements:
        raise RuntimeError("Apply did not produce exact manifest branch words")
    after_runs = [pseudo(start) for _ in range(5)]
    after = after_runs[-1]
    ida_loader.run_plugin(plugin, 31)
    if [ida_bytes.get_dword(ea) for ea in sites] != replacements:
        raise RuntimeError("Repeat apply was not idempotent")
    again = pseudo(start)
    run_hashes = [hashlib.sha256(text.encode()).hexdigest() for text in after_runs]
    run_hashes.append(hashlib.sha256(again.encode()).hexdigest())
    if "JUMPOUT" in after and "JUMPOUT" not in before:
        raise RuntimeError("Genshin profile introduced a JUMPOUT")
    result = {
        "function": hex(start),
        "sites": len(sites),
        "before_lines": len(before.splitlines()),
        "baseline_error": baseline_error,
        "after_lines": len(after.splitlines()),
        "before_jumpouts": before.count("JUMPOUT"),
        "after_jumpouts": after.count("JUMPOUT"),
        "f5_line_growth": len(after.splitlines()) > len(before.splitlines()),
        "repeated_f5_equal": after == again,
        "tampered_manifest_rejected_without_patches": True,
        "f5_hashes": run_hashes,
        "f5_lines": [len(text.splitlines()) for text in after_runs] + [len(again.splitlines())],
        "before_sha256": hashlib.sha256(before.encode()).hexdigest(),
        "after_sha256": hashlib.sha256(after.encode()).hexdigest(),
    }
    output.write_text(json.dumps(result, indent=2) + "\n")
    print("GENSHIN_PROFILE_RESULT", json.dumps(result), flush=True)
    if after != again:
        raise RuntimeError("Repeated F5 output still differs after five refreshes")


try:
    main()
except Exception as exc:
    print("GENSHIN_PROFILE_FAILED", repr(exc), flush=True)
    ida_pro.qexit(1)
else:
    ida_pro.qexit(0)
