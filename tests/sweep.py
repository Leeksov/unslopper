# Full-library before/after sweep in ONE headless process (no MCP 15s cap).
# For each CFF candidate: decompile with deflat OFF then ON, record deltas.
# idat -A -S"sweep.py <out.json> <max_blocks>" <binary>
import json, idaapi, idautils, idc, ida_funcs, ida_gdl, ida_hexrays, ida_auto, ida_pro
def log(m): print("[sweep] %s" % m)
def cands(maxb):
    r=[]
    for ea in idautils.Functions():
        f=ida_funcs.get_func(ea)
        if not f or (f.end_ea-f.start_ea)<200: continue
        try: fc=ida_gdl.FlowChart(f)
        except Exception: continue
        nb=0; mp=0
        for b in fc:
            nb+=1; p=sum(1 for _ in b.preds())
            if p>mp: mp=p
        if nb>=15 and mp>=5 and nb<=maxb: r.append((ea,nb,mp))
    r.sort(key=lambda x:-x[2]); return r
def met(ea):
    ida_hexrays.mark_cfunc_dirty(ea, False)
    try: t=str(ida_hexrays.decompile(ea) or "")
    except Exception as e: return {"err":str(e)}
    return {"g":t.count("goto "),"s":t.count("switch "),"L":len(t.split("\n"))}
def main():
    out=idc.ARGV[1] if len(idc.ARGV)>1 else "/tmp/sweep.json"
    maxb=int(idc.ARGV[2]) if len(idc.ARGV)>2 else 500
    ida_auto.auto_wait()
    if not ida_hexrays.init_hexrays_plugin():
        json.dump({"error":"no hexrays"},open(out,"w")); ida_pro.qexit(2)
    cs=cands(maxb); log("%d candidates (blocks<=%d)"%(len(cs),maxb))
    res=[]; ndef=0; sg0=sg1=ss0=ss1=0
    for i,(ea,nb,mp) in enumerate(cs):
        idaapi.load_and_run_plugin("unslopper",1)          # OFF
        b=met(ea)
        idaapi.load_and_run_plugin("unslopper",2)          # ON
        a=met(ea)
        if "err" in b or "err" in a:
            res.append({"ea":"0x%X"%ea,"err":b.get("err") or a.get("err")}); continue
        deflat = a["s"]<b["s"] or a["g"]!=b["g"] or a["L"]!=b["L"]
        if deflat: ndef+=1
        sg0+=b["g"]; sg1+=a["g"]; ss0+=b["s"]; ss1+=a["s"]
        res.append({"ea":"0x%X"%ea,"blocks":nb,"maxpred":mp,
                    "off":b,"on":a,"changed":deflat})
        if i%20==0: log("%d/%d done"%(i,len(cs)))
    json.dump({"count":len(res),"deflattened":ndef,
               "sum_goto":[sg0,sg1],"sum_switch":[ss0,ss1],
               "functions":res}, open(out,"w"), indent=2)
    log("DONE %d funcs, %d changed | switch %d->%d goto %d->%d"%(len(res),ndef,ss0,ss1,sg0,sg1))
    ida_pro.qexit(0)
main()
