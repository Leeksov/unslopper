import idautils, ida_funcs, ida_gdl, ida_hexrays, ida_auto, ida_pro, idaapi, idc
ida_auto.auto_wait(); ida_hexrays.init_hexrays_plugin()
idaapi.load_and_run_plugin("unslopper",1)  # OFF
# CFF signature: a high-pred block that is a LOOP HEADER (reachable from one of
# its own successors) => back-edge => flattening dispatcher. Genuine switches
# have no back-edge to the switch block.
found=[]
n=0
for ea in idautils.Functions():
    f=ida_funcs.get_func(ea)
    if not f: continue
    sz=f.end_ea-f.start_ea
    if sz<400 or sz>4000: continue
    try: fc=ida_gdl.FlowChart(f)
    except: continue
    blocks=list(fc); 
    if len(blocks)<20: continue
    disp=max(blocks,key=lambda b:sum(1 for _ in b.preds()))
    mp=sum(1 for _ in disp.preds())
    if mp<6: continue
    # BFS from disp's successors; if we can reach disp again => back-edge (loop)
    succ0=[s.start_ea for s in disp.succs()]
    seen=set(); stack=list(succ0); loop=False; steps=0
    while stack and steps<4000:
        steps+=1; s=stack.pop()
        if s==disp.start_ea: loop=True; break
        if s in seen: continue
        seen.add(s)
        for b in blocks:
            if b.start_ea==s:
                stack += [x.start_ea for x in b.succs()]; break
    if loop:
        # confirm decompile shows a while-loop dispatcher
        try: t=str(ida_hexrays.decompile(ea) or "")
        except: continue
        if "while ( 1 )" in t or "for ( ; ; )" in t or t.count("goto ")>=8:
            found.append((ea,len(blocks),mp,t.count("switch "),t.count("goto ")))
            n+=1
            if n>=10: break
print("TRUE CFF (loop-back dispatcher) candidates:")
for ea,nb,mp,sw,g in found: print("0x%X blk=%d maxpred=%d switch=%d goto=%d"%(ea,nb,mp,sw,g))
if not found: print("NONE FOUND - appdome may not use classic loop-back CFF in this size range")
ida_pro.qexit(0)
