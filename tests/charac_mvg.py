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
def has_jtbl(f):
    a=f.start_ea
    while a<f.end_ea:
        mn=idc.print_insn_mnem(a)
        # jump table: BR Xn (register indirect branch) - iXGuard strong_cff
        if mn=="BR": return True
        a=idc.next_head(a,f.end_ea)
        if a==idc.BADADDR: break
    return False
magic_hits=0; jtbl_hits=0; both=0; scanned=0; samples=[]
for ea in idautils.Functions():
    f=ida_funcs.get_func(ea)
    if not f: continue
    sz=f.end_ea-f.start_ea
    if sz<600 or sz>30000: continue
    scanned+=1
    if scanned>8000: break
    m=len(magic(f))
    j=has_jtbl(f)
    if m>=5: magic_hits+=1
    if j: jtbl_hits+=1
    if m>=5 and j: both+=1; 
    if m>=5 and len(samples)<5: samples.append((ea,sz,m,j))
print("MVG/iXGuard: scanned=%d | magic-const CFF=%d | jump-table(BR)=%d | both=%d"%(scanned,magic_hits,jtbl_hits,both))
for ea,sz,m,j in samples:
    print("  0x%X size=%d magic=%d jtbl=%s"%(ea,sz,m,j))
# dispatcher shape of a magic function
if samples:
    ea=samples[0][0]; f=ida_funcs.get_func(ea); fc=ida_gdl.FlowChart(f)
    disp=max(fc,key=lambda b:sum(1 for _ in b.preds()))
    print("top 0x%X dispatcher blk 0x%X (%d preds):"%(ea,disp.start_ea,sum(1 for _ in disp.preds())))
    a=disp.start_ea
    for _ in range(8):
        if a>=disp.end_ea: break
        print("   ",idc.GetDisasm(a)); a=idc.next_head(a,disp.end_ea)
ida_pro.qexit(0)
