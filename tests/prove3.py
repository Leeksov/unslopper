# Headless before/after proof of the D-810-style full-unflatten upgrade.
# Mid-size CFF candidates (30..200 flowchart blocks, a block with >=5 preds).
# For each: decompile deflat OFF (load_and_run_plugin deflat,1) then ON (,2),
# mark_cfunc_dirty between, capture ON text. Verdict per function:
#   CLEAN   = no while(1)/while(2) dispatcher loop AND no switch with >4 cases
#             AND goto count <= OFF goto
#   RESIDUE = still has a while/switch state machine (wrapping loop OR >4-case switch)
#   PARTIAL = anything else (no state machine, but goto count did not drop to baseline)
# idat -A -S"prove3.py <out.json>" <binary>
import json, idaapi, idautils, idc, ida_funcs, ida_gdl, ida_hexrays, ida_auto, ida_pro

def log(m): print("[prove3] %s" % m)

def candidates(minb=30, maxb=200, minpred=5, take=25):
    r = []
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
        if minb <= nb <= maxb and mp >= minpred:
            r.append((ea, nb, mp))
    # Sort by max-pred descending: the strongest dispatcher signal first.
    r.sort(key=lambda x: (-x[2], x[1]))
    return r[:take]

def decompile_text(ea):
    ida_hexrays.mark_cfunc_dirty(ea, False)
    try:
        return str(ida_hexrays.decompile(ea) or "")
    except Exception:
        return None

def max_switch_cases(text):
    best = 0; idx = 0
    while True:
        s = text.find("switch (", idx)
        if s < 0: break
        b = text.find("{", s)
        if b < 0: break
        depth = 0; i = b; cases = 0; n = len(text)
        while i < n:
            c = text[i]
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    i += 1; break
            elif depth == 1 and text.startswith("case ", i):
                cases += 1
            i += 1
        if cases > best: best = cases
        idx = b + 1
    return best

def has_wrapping_state_machine(text):
    for kw in ("while ( 1 )", "while ( 2 )", "while (1)", "while (2)",
               "while ( 1LL )", "while ( 2LL )"):
        p = text.find(kw)
        while p >= 0:
            b = text.find("{", p)
            if b >= 0:
                depth = 0; i = b; n = len(text); body_end = -1
                while i < n:
                    c = text[i]
                    if c == "{":
                        depth += 1
                    elif c == "}":
                        depth -= 1
                        if depth == 0:
                            body_end = i; break
                    i += 1
                if body_end > b and "switch (" in text[b:body_end]:
                    return True
            p = text.find(kw, p + 1)
    return False

def first_lines(t, n=30):
    return "\n".join(t.split("\n")[:n])

def main():
    out = idc.ARGV[1] if len(idc.ARGV) > 1 else "/tmp/dp.prove3.json"
    only = None
    import os
    oe = os.environ.get("UNSLOP_ONLY_EA")
    if oe:
        try: only = int(oe, 0)
        except Exception: only = None

    ida_auto.auto_wait()
    if not ida_hexrays.init_hexrays_plugin():
        json.dump({"error": "no hexrays", "ran": False}, open(out, "w"))
        ida_pro.qexit(2)

    cs = candidates()
    log("%d mid-size candidates (30..200 blocks, >=5 preds)" % len(cs))

    funcs = []
    clean = residue = partial = 0
    sg_off = sg_on = ss_off = ss_on = 0
    on_texts = {}

    for i, (ea, nb, mp) in enumerate(cs):
        idaapi.load_and_run_plugin("unslopper", 1)   # OFF
        off = decompile_text(ea)
        idaapi.load_and_run_plugin("unslopper", 2)   # ON
        on = decompile_text(ea)
        if off is None or on is None:
            funcs.append({"ea": "0x%X" % ea, "err": "decompile failed"})
            log("%d/%d 0x%X decompile failed" % (i + 1, len(cs), ea))
            continue

        off_g = off.count("goto "); on_g = on.count("goto ")
        off_s = off.count("switch ("); on_s = on.count("switch (")

        wrap = has_wrapping_state_machine(on)
        bigsw = max_switch_cases(on) > 4
        goto_ok = on_g <= off_g

        if not wrap and not bigsw and goto_ok:
            verdict = "clean"; clean += 1
        elif wrap or bigsw:
            verdict = "residue"; residue += 1
        else:
            verdict = "partial"; partial += 1

        sg_off += off_g; sg_on += on_g; ss_off += off_s; ss_on += on_s
        on_texts[ea] = (verdict, on)
        funcs.append({"ea": "0x%X" % ea, "blocks": nb, "maxpred": mp,
                      "off_g": off_g, "on_g": on_g,
                      "off_s": off_s, "on_s": on_s, "verdict": verdict})
        log("%d/%d 0x%X %s g %d->%d s %d->%d cases=%d" %
            (i + 1, len(cs), ea, verdict, off_g, on_g, off_s, on_s,
             max_switch_cases(on)))

    # 3 representative samples: spread across verdicts (clean, partial, residue).
    sample = {}
    picked = []
    for want in ("clean", "partial", "residue"):
        for ea, (v, t) in on_texts.items():
            if v == want and ea not in picked:
                picked.append(ea); break
    for ea, (v, t) in on_texts.items():
        if len(picked) >= 3: break
        if ea not in picked: picked.append(ea)
    for ea in picked[:3]:
        v, t = on_texts[ea]
        sample["0x%X (%s)" % (ea, v)] = first_lines(t, 32)

    result = {
        "ran": True,
        "total": len([f for f in funcs if "err" not in f]),
        "clean_count": clean,
        "partial_count": partial,
        "residue_count": residue,
        "sum_goto": [sg_off, sg_on],
        "sum_switch": [ss_off, ss_on],
        "only_ea": ("0x%X" % only) if only else None,
        "functions": funcs,
        "sample_pseudocode": sample,
    }
    json.dump(result, open(out, "w"), indent=2)
    log("DONE total=%d clean=%d partial=%d residue=%d | goto %d->%d switch %d->%d"
        % (result["total"], clean, partial, residue, sg_off, sg_on, ss_off, ss_on))
    ida_pro.qexit(0)

main()
