# Headless before/after proof of the full-unflatten upgrade.
# For each CFF candidate: decompile with deflat OFF then ON (mark_cfunc_dirty
# between), then run a RESIDUE CHECK on the ON pseudocode text - the real
# success metric is whether the goto count dropped and the dispatcher switch
# (a while(1/2) wrapping a switch, or a >8-case switch on one variable) is gone.
# idat -A -S"prove.py <out.json>" <binary>
import json, idaapi, idautils, idc, ida_funcs, ida_gdl, ida_hexrays, ida_auto, ida_pro

def log(m): print("[prove] %s" % m)

def candidates(maxb=400):
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
        if nb >= 15 and mp >= 5 and nb <= maxb:
            r.append((ea, nb, mp))
    r.sort(key=lambda x: -x[2])
    return r

def decompile_text(ea):
    ida_hexrays.mark_cfunc_dirty(ea, False)
    try:
        return str(ida_hexrays.decompile(ea) or "")
    except Exception as e:
        return None

def max_switch_cases(text):
    # Largest number of `case ` labels inside any single switch{...} body.
    best = 0
    idx = 0
    while True:
        s = text.find("switch (", idx)
        if s < 0:
            break
        b = text.find("{", s)
        if b < 0:
            break
        depth = 0
        i = b
        cases = 0
        n = len(text)
        while i < n:
            c = text[i]
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    i += 1
                    break
            elif depth == 1 and text.startswith("case ", i):
                cases += 1
            i += 1
        if cases > best:
            best = cases
        idx = b + 1
    return best

def has_wrapping_state_machine(text):
    # A while(1)/while(2) loop body that contains a switch = classic dispatcher.
    for kw in ("while ( 1 )", "while ( 2 )", "while (1)", "while (2)",
               "while ( 1LL )", "while ( 2LL )"):
        p = text.find(kw)
        while p >= 0:
            b = text.find("{", p)
            if b >= 0:
                depth = 0
                i = b
                n = len(text)
                body_end = -1
                while i < n:
                    c = text[i]
                    if c == "{":
                        depth += 1
                    elif c == "}":
                        depth -= 1
                        if depth == 0:
                            body_end = i
                            break
                    i += 1
                if body_end > b and "switch (" in text[b:body_end]:
                    return True
            p = text.find(kw, p + 1)
    return False

def main():
    out = idc.ARGV[1] if len(idc.ARGV) > 1 else "/tmp/dp.prove.json"
    ida_auto.auto_wait()
    if not ida_hexrays.init_hexrays_plugin():
        json.dump({"error": "no hexrays", "ran": False}, open(out, "w"))
        ida_pro.qexit(2)

    cs = candidates(400)[:30]
    log("%d candidates (top 30 by max-pred)" % len(cs))

    funcs = []
    clean = residue = partial = 0
    sg_off = sg_on = ss_off = ss_on = 0
    # keep (verdict, ea, on_text) so we can pick 3 representative samples later
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

        off_g = off.count("goto ")
        on_g = on.count("goto ")
        off_s = off.count("switch (")
        on_s = on.count("switch (")

        wrap = has_wrapping_state_machine(on)
        bigsw = max_switch_cases(on) > 8
        goto_dropped = on_g < off_g

        if wrap or bigsw or (not goto_dropped):
            verdict = "residue"; residue += 1
        elif on_s < off_s or on_s == 0:
            verdict = "clean"; clean += 1
        else:
            verdict = "partial"; partial += 1

        sg_off += off_g; sg_on += on_g; ss_off += off_s; ss_on += on_s
        on_texts[ea] = (verdict, on)
        funcs.append({"ea": "0x%X" % ea, "blocks": nb, "maxpred": mp,
                      "off_g": off_g, "on_g": on_g,
                      "off_s": off_s, "on_s": on_s, "verdict": verdict})
        log("%d/%d 0x%X %s g %d->%d s %d->%d" %
            (i + 1, len(cs), ea, verdict, off_g, on_g, off_s, on_s))

    # 3 representative samples: prefer ones that still show a switch/while state
    # machine (the residue a human needs to eyeball), else any.
    def cf_window(t, n=60):
        ls = t.split("\n")
        start = 0
        for idx, l in enumerate(ls):
            if "switch (" in l or "while ( 1 )" in l or "while ( 2 )" in l:
                start = max(0, idx - 2)
                break
        return "\n".join(ls[start:start + n])

    reps = []
    # first, functions where a switch survives (on_s > 0)
    for ea, (v, t) in on_texts.items():
        if len(reps) >= 3: break
        if "switch (" in t and ea not in [r[0] for r in reps]:
            reps.append((ea, t))
    for ea, (v, t) in on_texts.items():
        if len(reps) >= 3: break
        if ea not in [r[0] for r in reps]:
            reps.append((ea, t))

    sample = {}
    for ea, t in reps[:3]:
        sample["0x%X" % ea] = cf_window(t, 60)

    result = {
        "ran": True,
        "total": len([f for f in funcs if "err" not in f]),
        "clean_count": clean,
        "partial_count": partial,
        "residue_count": residue,
        "sum_goto": [sg_off, sg_on],
        "sum_switch": [ss_off, ss_on],
        "functions": funcs,
        "sample_pseudocode": sample,
    }
    json.dump(result, open(out, "w"), indent=2)
    log("DONE total=%d clean=%d partial=%d residue=%d | goto %d->%d switch %d->%d"
        % (result["total"], clean, partial, residue, sg_off, sg_on, ss_off, ss_on))
    ida_pro.qexit(0)

main()
