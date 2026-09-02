import idautils, ida_funcs, ida_gdl, ida_hexrays, ida_auto, ida_pro, idaapi
ida_auto.auto_wait(); ida_hexrays.init_hexrays_plugin()
idaapi.load_and_run_plugin("unslopper",1)  # OFF - see raw
out=[]
n=0
for ea in idautils.Functions():
    f=ida_funcs.get_func(ea)
    if not f: continue
    sz=f.end_ea-f.start_ea
    if sz<400 or sz>1800: continue
    try: fc=ida_gdl.FlowChart(f); nb=sum(1 for _ in fc)
    except: continue
    if nb<25 or nb>60: continue
    try:
        t=str(ida_hexrays.decompile(ea) or "")
    except: continue
    sw=t.count("switch "); g=t.count("goto ")
    if sw>=1 and (sw>=2 or "while ( 1 )" in t):
        out.append((ea,nb,sw,g)); n+=1
        if n>=12: break
print("REAL CFF small funcs (OFF switch>=1):")
for ea,nb,sw,g in out: print("0x%X blk=%d switch=%d goto=%d"%(ea,nb,sw,g))
ida_pro.qexit(0)
