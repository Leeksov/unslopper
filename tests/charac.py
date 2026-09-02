import idautils, ida_funcs, ida_gdl, ida_ua, idc, ida_auto, ida_pro
ida_auto.auto_wait()
def magic(f):
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
    return c
hits=[]
for ea in idautils.Functions():
    f=ida_funcs.get_func(ea)
    if not f: continue
    sz=f.end_ea-f.start_ea
    if sz<600 or sz>20000: continue
    m=magic(f)
    if len(m)>=5: hits.append((ea,sz,len(m)))
hits.sort(key=lambda x:-x[2])
print("PROMON: %d functions with magic-constant CFF signature (>=5 states)"%len(hits))
for ea,sz,nc in hits[:6]: print("  0x%X size=%d magic_states=%d"%(ea,sz,nc))
# dispatcher shape of the top one
if hits:
    ea=hits[0][0]; f=ida_funcs.get_func(ea); fc=ida_gdl.FlowChart(f)
    disp=max(fc,key=lambda b:sum(1 for _ in b.preds()))
    print("top 0x%X dispatcher blk 0x%X:"%(ea,disp.start_ea))
    a=disp.start_ea
    for _ in range(6):
        if a>=disp.end_ea: break
        print("   ",idc.GetDisasm(a)); a=idc.next_head(a,disp.end_ea)
    # xor transform present?
    eor=False; a=f.start_ea
    while a<f.end_ea:
        if idc.print_insn_mnem(a)=="EOR": eor=True; break
        a=idc.next_head(a,f.end_ea)
    print("EOR-transform:", eor, "=> class:", "XOR-BST(DexProtector-like)" if eor else "register-magic-BST(AppDome/Promon-like)")
ida_pro.qexit(0)
