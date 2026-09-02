import ida_hexrays, ida_auto, ida_pro, idaapi, idc, ida_funcs, json
ida_auto.auto_wait(); ida_hexrays.init_hexrays_plugin()
idaapi.load_and_run_plugin("unslopper",2)
m=json.load(open("<local-svc-map>"))
recs=[r for r in m["records"] if r.get("resolved")][:15]
hit=0; tot=0
for r in recs:
    svc_rva=r.get("svc_rva"); num=r.get("syscall_number")
    if svc_rva is None: continue
    ea=svc_rva  # __TEXT vmaddr=0 so rva==ea
    fn=ida_funcs.get_func(ea)
    if not fn: continue
    tot+=1
    ida_hexrays.mark_cfunc_dirty(fn.start_ea, False)
    try: ida_hexrays.decompile(fn.start_ea)
    except: pass
    c=idc.get_cmt(ea, False) or ""
    ok = "MVG svc" in c
    if ok: hit+=1
    print("svc 0x%X (fn 0x%X) expect=%s -> %s"%(ea,fn.start_ea,num,"ANNOTATED: "+c[:40] if ok else "miss"))
print("COVERAGE: %d/%d annotated"%(hit,tot))
ida_pro.qexit(0)
