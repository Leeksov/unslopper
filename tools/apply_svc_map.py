"""Apply the offline MVG/BitGuard syscall map to the open IDB as comments.
This is the RELIABLE syscall resolver: mvg_svc_map.json was produced by the
disassembly-level slice resolver (mvg_svc_resolver.py) and covers 956 constant
sites + 72 dynamic. The in-plugin microcode fold is unreliable (Hex-Rays folds
the svc slice) — use THIS.

    idat -A -S"apply_svc_map.py [map.json]" mvg.i64
or inside IDA:  exec(open('apply_svc_map.py').read())
"""
import json, idc, ida_funcs
try: from ida_auto import auto_wait; auto_wait()
except Exception: pass

def _num(r):
    return r.get("syscall_number", r.get("syscall_number_raw_u32"))

def apply(map_path=None):
    import os
    if map_path is None:
        for c in ("<local-svc-map>",
                  os.path.join(os.path.dirname(__file__),"..","evidence","mvg_svc_map.json")):
            if os.path.exists(c): map_path=c; break
    d=json.load(open(map_path))
    recs=d["records"]; base=0  # __TEXT vmaddr=0 -> rva==ea
    hint={-47:"mach_msg2_trap",-31:"mach_msg_trap",-28:"task_self_trap",-14:"mach_vm_protect_trap",
          5:"open",6:"close",10:"unlink",20:"getpid",73:"munmap",92:"fcntl",138:"utimes",
          159:"unmount",191:"pathconf",197:"mmap",347:"getfsstat64",381:"__mac_syscall"}
    n=nd=0
    for r in recs:
        ea=r.get("svc_rva")
        if ea is None: continue
        ea+=base
        if r.get("resolved"):
            num=_num(r); h=r.get("darwin_name_hint") or hint.get(num,"")
            ns=r.get("namespace","")
            idc.set_cmt(ea, "MVG syscall %s (%s) [%s]"%(num,h,ns), False); n+=1
        else:
            idc.set_cmt(ea, "MVG syscall: dynamic/caller-selected (X16<-runtime)", False); nd+=1
    print("[apply_svc_map] annotated %d resolved + %d dynamic = %d svc sites"%(n,nd,n+nd))
    return n,nd

if __name__=="__main__":
    import sys
    apply(sys.argv[1] if len(sys.argv)>1 else None)
    try:
        import ida_pro; ida_pro.qexit(0)
    except Exception: pass
