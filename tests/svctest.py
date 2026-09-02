import ida_hexrays, ida_auto, ida_pro, idaapi, idc, ida_funcs
ida_auto.auto_wait(); ida_hexrays.init_hexrays_plugin()
idaapi.load_and_run_plugin("unslopper",2)  # ensure active
# decompile the function containing svc @0x76578
fn = ida_funcs.get_func(0x76578)
ea = fn.start_ea if fn else 0x763E8
ida_hexrays.mark_cfunc_dirty(ea, False)
ida_hexrays.decompile(ea)   # triggers svc layer at LOCOPT
c = idc.get_cmt(0x76578, False)
print("svc @0x76578 comment:", repr(c))
ida_pro.qexit(0)
