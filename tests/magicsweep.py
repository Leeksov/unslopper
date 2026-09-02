import idautils, ida_funcs, ida_ua, idc, ida_hexrays, ida_auto, ida_pro, idaapi, json
ida_auto.auto_wait(); ida_hexrays.init_hexrays_plugin()
def magic_states(f):
    c=set(); a=f.start_ea
    while a<f.end_ea:
        mn=idc.print_insn_mnem(a)
        if mn in ("CMP","MOV","MOVK","MOVZ"):
            insn=ida_ua.insn_t()
            if ida_ua.decode_insn(insn,a):
                for o in insn.ops:
                    if o.type==5:
                        v=o.value&0xFFFFFFFF
                        if v>0x1000000 and (v&0xFFFF)!=0: c.add(v)
        a=idc.next_head(a,f.end_ea)
        if a==idc.BADADDR: break
    return len(c)
cands=[]
for ea in idautils.Functions():
    f=ida_funcs.get_func(ea)
    if not f: continue
    sz=f.end_ea-f.start_ea
    if sz<600 or sz>3000: continue
    if magic_states(f)>=5: cands.append(ea)
    if len(cands)>=60: break
def met(ea):
    ida_hexrays.mark_cfunc_dirty(ea,False)
    try: t=str(ida_hexrays.decompile(ea) or "")
    except: return None
    return (t.count("goto "), t.count("switch "), t.count("while ( 1 )"))
res=[]
for ea in cands:
    idaapi.load_and_run_plugin("unslopper",1); b=met(ea)
    idaapi.load_and_run_plugin("unslopper",2); a=met(ea)
    if b and a: res.append((ea,b,a))
sg0=sum(r[1][0] for r in res); sg1=sum(r[2][0] for r in res)
sw0=sum(r[1][1] for r in res); sw1=sum(r[2][1] for r in res)
wl0=sum(1 for r in res if r[1][2]>0); wl1=sum(1 for r in res if r[2][2]>0)
gd=sum(1 for r in res if r[2][0]<r[1][0])
print("MAGIC-CFF sweep: %d funcs | goto %d->%d | switch %d->%d | while(1) funcs %d->%d | goto_down %d"%(
 len(res),sg0,sg1,sw0,sw1,wl0,wl1,gd))
ida_pro.qexit(0)
