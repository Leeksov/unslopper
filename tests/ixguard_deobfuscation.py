"""Headless IDA integration: snapshot hash folding, refusal, MBA and CFF regressions."""
import json
from pathlib import Path
import ida_auto,ida_hexrays,ida_loader,ida_pro,ida_bytes,idc

def main():
    out=Path(idc.ARGV[1]);out.mkdir(parents=True,exist_ok=True)
    ida_auto.auto_wait();assert ida_hexrays.init_hexrays_plugin()
    p=ida_loader.load_plugin('unslopper');assert p
    ida_loader.run_plugin(p,2)
    def decomp(ea):
        ida_hexrays.mark_cfunc_dirty(ea,False)
        c=ida_hexrays.decompile(ea)
        assert c is not None,'decompilation failed'
        return str(c)
    results=[]
    for ea in (0x100221240,0x1000053ac,0x100007f2c,0x100009878,0x10000b984):
        ida_loader.run_plugin(p,21);normal=decomp(ea)
        assert 'switch (' not in normal,hex(ea)+' residual dispatcher'
        assert normal==decomp(ea),'unstable literal view'
        (out/(hex(ea)+'.literal.c')).write_text(normal)
        ida_loader.run_plugin(p,20);snapshot=decomp(ea)
        assert snapshot==decomp(ea),'unstable snapshot view'
        assert 'switch (' not in snapshot
        (out/(hex(ea)+'.snapshot.c')).write_text(snapshot)
        results.append({'ea':hex(ea),'literal_hash_calls':normal.count('sub_100193E78('),
                        'snapshot_hash_calls':snapshot.count('sub_100193E78('),
                        'literal_lines':len(normal.splitlines()),'snapshot_lines':len(snapshot.splitlines()),
                        'stable':True})
        ida_loader.run_plugin(p,4)
        if ea==0x1000053ac:
            assert 'sub_100193E78(' in normal,'missing baseline hash comparison'
            assert snapshot.count('sub_100193E78(')<normal.count('sub_100193E78('),'boolean hash comparison was not folded'
            assert normal.count('__unslop_darwin_svc_carry(')==normal.count('__unslop_darwin_svc('),'SVC carry must be captured once per syscall'
            for anchor in ('__unslop_darwin_svc(', 'sub_1000C455C('):
                assert anchor in snapshot,'side effect removed: '+anchor
        ida_loader.run_plugin(p,4)
    # A changed seed invalidates the audited model even in explicit snapshot mode.
    seed=0x102425fe8;original=ida_bytes.get_qword(seed)
    try:
        ida_bytes.patch_qword(seed,original^1)
        changed=decomp(0x1000053ac)
        assert changed.count('sub_100193E78(')>=2,'changed-seed helper was folded'
        ida_loader.run_plugin(p,4)
        results.append({'test':'changed seed rejects hash model','passed':True})
    finally:ida_bytes.patch_qword(seed,original)
    # The helper code must still match the audited recipe byte-for-byte.
    pc=0x100193e78;original_code=ida_bytes.get_dword(pc)
    try:
        ida_bytes.patch_dword(pc,0xd503201f)
        changed=decomp(0x1000053ac)
        assert changed.count('sub_100193E78(')>=2,'changed-code helper was folded'
        results.append({'test':'changed code rejects hash model','passed':True})
    finally:ida_bytes.patch_dword(pc,original_code)
    ida_loader.run_plugin(p,21)
    results.append({'test':'snapshot disabled restores literal helper call',
                    'passed':'sub_100193E78(' in decomp(0x1000053ac)})
    assert results[-1]['passed']
    (out/'integration.json').write_text(json.dumps(results,indent=2))
    ida_pro.qexit(0)

try:main()
except Exception:
    import traceback
    traceback.print_exc();ida_pro.qexit(1)
