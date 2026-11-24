"""Apply the offline MVG RASP dynamic-dispatch map to the open IDB as comments.

MVG resolves dlsym'd APIs through a 2888-slot runtime table (RVA 0x1977F90).
The dig (mvg_rasp_dispatch_map.json) resolved 596 direct BLR/BR call sites to
a named slot each. This annotates those call sites at the DISASSEMBLY/evidence
level (rva == ea because __TEXT vmaddr=0). Hex-Rays microcode folds these
indirect slices away, so this evidence-driven annotator is the reliable path.

    idat -A -S"apply_dispatch_map.py [map.json]" mvg.i64
or inside IDA:  exec(open('apply_dispatch_map.py').read())
"""
import json, os, idc
try: from ida_auto import auto_wait; auto_wait()
except Exception: pass

def apply(map_path=None):
    if map_path is None:
        script_dir = os.path.dirname(globals().get("__file__", os.path.join(os.getcwd(), "tools", "apply_dispatch_map.py")))
        for c in (os.environ.get("MVG_DISPATCH_MAP"),
                  os.path.join(script_dir,"..","evidence","mvg_rasp_dispatch_map.json")):
            if not c: continue
            if os.path.exists(c): map_path=c; break
    if map_path is None:
        raise FileNotFoundError("Pass map_path or set MVG_DISPATCH_MAP to the dispatch map JSON path")
    d=json.load(open(map_path))
    base=d.get("image_base",0)  # __TEXT vmaddr=0 -> rva==ea (image_base==0)
    uses=d.get("direct_slot_uses",[])
    n=skip=0
    for r in uses:
        ea=r.get("call_rva")
        name=r.get("dynamic_name")
        slot=r.get("slot_index")
        if ea is None or not name:   # only annotate sites the evidence resolves
            skip+=1; continue
        ea+=base
        kind=r.get("call_kind","")
        idc.set_cmt(ea, "MVG dispatch -> %s (slot %s)%s"%(
            name, slot, " ["+kind+"]" if kind else ""), False)
        n+=1
    print("[apply_dispatch_map] annotated %d dispatch call sites (%d skipped/unresolved) of %d"%(
        n, skip, len(uses)))
    return n

if __name__=="__main__":
    import sys
    apply(sys.argv[1] if len(sys.argv)>1 else None)
    try:
        import ida_pro; ida_pro.qexit(0)
    except Exception: pass
