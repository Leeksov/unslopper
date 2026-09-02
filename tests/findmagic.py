import idautils, ida_funcs, ida_gdl, ida_ua, idc, ida_auto, ida_pro
ida_auto.auto_wait()
# TRUE OLLVM CFF signature: a function with >=4 comparisons against DISTINCT
# large random 32-bit constants (> 0x1000000, not round). scramble32 states.
hits=[]; scanned=0
for ea in idautils.Functions():
    f=ida_funcs.get_func(ea)
    if not f: continue
    sz=f.end_ea-f.start_ea
    if sz<300 or sz>20000: continue
    scanned+=1
    consts=set()
    a=f.start_ea
    while a<f.end_ea:
        mn=idc.print_insn_mnem(a)
        if mn in ("CMP","SUBS","MOV","MOVK","MOVZ"):
            insn=ida_ua.insn_t()
            if ida_ua.decode_insn(insn,a):
                for o in insn.ops:
                    if o.type==5:  # immediate
                        v=o.value & 0xFFFFFFFF
                        if v>0x1000000 and (v & 0xFFFF)!=0 and v not in (0xFFFFFFFF,):
                            consts.add(v)
        a=idc.next_head(a,f.end_ea)
        if a==idc.BADADDR: break
    if len(consts)>=4:
        hits.append((ea, sz, len(consts), sorted(consts)[:4]))
hits.sort(key=lambda x:-x[2])
print("functions with >=4 large-random constants (OLLVM CFF signature): %d / %d scanned"%(len(hits),scanned))
for ea,sz,nc,sample in hits[:12]:
    print("0x%X size=%d distinct_magic=%d e.g. %s"%(ea,sz,nc,[hex(c) for c in sample]))
ida_pro.qexit(0)
