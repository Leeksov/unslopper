# Headless IDA harness: decompile CFF-candidate functions and record metrics.
# Run via: idat -A -S"harness.py <out.json>" <binary>
# Reads UNSLOP_FORCE=1 to force-load the plugin (test run); absent = baseline.
import json, os
import idaapi, idautils, idc, ida_funcs, ida_gdl, ida_hexrays, ida_auto, ida_pro, ida_loader

def log(m): print("[harness] %s" % m)

def cff_candidates(limit=12, min_blocks=15, min_preds=5):
    out = []
    for ea in idautils.Functions():
        f = ida_funcs.get_func(ea)
        if not f or (f.end_ea - f.start_ea) < 200:
            continue
        try:
            fc = ida_gdl.FlowChart(f)
        except Exception:
            continue
        nb = 0; mp = 0
        for b in fc:
            nb += 1
            p = sum(1 for _ in b.preds())
            if p > mp: mp = p
        if nb >= min_blocks and mp >= min_preds:
            out.append((ea, nb, mp))
    out.sort(key=lambda x: -x[2])
    return out[:limit]

def metrics(txt):
    if not txt: return {}
    lines = txt.split("\n")
    return {
        "lines": len(lines),
        "gotos": txt.count("goto "),
        "switches": txt.count("switch "),
        "cases": txt.count("case "),
        "whiles": txt.count("while ("),
        "ifs": txt.count("if ("),
    }

def main():
    out_path = idc.ARGV[1] if len(idc.ARGV) > 1 else "/tmp/harness_out.json"
    ida_auto.auto_wait()

    if not ida_hexrays.init_hexrays_plugin():
        json.dump({"error": "no hexrays"}, open(out_path, "w"))
        ida_pro.qexit(2)

    forced = os.environ.get("UNSLOP_FORCE") == "1"
    # The deflat optblock installs itself in the plugin ctor at database open,
    # so if the plugin is present in IDAUSR/plugins it is ALREADY active here.
    # Do NOT call run()/load_and_run_plugin (arg toggles it OFF). Presence alone
    # (test IDAUSR has deflat.dylib; baseline IDAUSR does not) controls it.

    cands = cff_candidates()
    log("%d CFF candidates" % len(cands))
    results = []
    for ea, nb, mp in cands:
        name = ida_funcs.get_func_name(ea) or ("sub_%X" % ea)
        try:
            ida_hexrays.mark_cfunc_dirty(ea, False)
            cf = ida_hexrays.decompile(ea)
            txt = str(cf) if cf else ""
            m = metrics(txt)
        except Exception as e:
            m = {"error": str(e)}
        results.append({"ea": "0x%X" % ea, "name": name,
                        "blocks": nb, "max_preds": mp, "metrics": m})

    json.dump({"forced": forced, "count": len(results), "functions": results},
              open(out_path, "w"), indent=2)
    log("wrote %s" % out_path)
    ida_pro.qexit(0)

main()
