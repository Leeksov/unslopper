import ida_hexrays, ida_auto, ida_pro, idaapi, idc
ida_auto.auto_wait(); ida_hexrays.init_hexrays_plugin()
idaapi.load_and_run_plugin("unslopper",1)  # OFF
ea=int(idc.ARGV[1],16)
t=str(ida_hexrays.decompile(ea) or "")
print("=====OFF PSEUDOCODE 0x%X====="%ea)
print(t[:1800])
ida_pro.qexit(0)
