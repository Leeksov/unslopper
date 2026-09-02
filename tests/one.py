import idaapi, ida_hexrays, ida_auto, ida_pro, idc
ida_auto.auto_wait(); ida_hexrays.init_hexrays_plugin()
ea=int(idc.ARGV[1],16)
def m():
    ida_hexrays.mark_cfunc_dirty(ea,False)
    return str(ida_hexrays.decompile(ea) or "")
idaapi.load_and_run_plugin("unslopper",1); off=m()
idaapi.load_and_run_plugin("unslopper",2); on=m()
print("OFF goto=%d switch=%d L=%d | ON goto=%d switch=%d L=%d"%(
 off.count("goto "),off.count("switch "),len(off.split(chr(10))),
 on.count("goto "),on.count("switch "),len(on.split(chr(10)))))
print("=====ON PSEUDOCODE (first 40 lines)=====")
print(chr(10).join(on.split(chr(10))[:40]))
ida_pro.qexit(0)
