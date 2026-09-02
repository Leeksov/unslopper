import idautils, ida_funcs, ida_ua, idc, ida_auto, ida_pro
ida_auto.auto_wait()
hits=[]
for ea in idautils.Functions():
    f=ida_funcs.get_func(ea)
    if not f: continue
    sz=f.end_ea-f.start_ea
    if sz<600 or sz>2500: continue     # small-ish real CFF
    consts=set(); a=f.start_ea
    while a<f.end_ea:
        mn=idc.print_insn_mnem(a)
        if mn in ("CMP","MOV","MOVK","MOVZ"):
            insn=ida_ua.insn_t()
            if ida_ua.decode_insn(insn,a):
                for o in insn.ops:
                    if o.type==5:
                        v=o.value&0xFFFFFFFF
                        if v>0x1000000 and (v&0xFFFF)!=0: consts.add(v)
        a=idc.next_head(a,f.end_ea)
        if a==idc.BADADDR: break
    if 4<=len(consts)<=20: hits.append((ea,sz,len(consts)))
hits.sort(key=lambda x:x[1])
print("small magic-CFF functions:")
for ea,sz,nc in hits[:10]: print("0x%X size=%d magic_states=%d"%(ea,sz,nc))
ida_pro.qexit(0)
