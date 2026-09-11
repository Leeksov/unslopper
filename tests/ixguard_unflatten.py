"""Headless regression: idat -A -S'.../ixguard_unflatten.py OUTDIR' COPY.i64.

Uses only the supplied database copy, never executes target code. The plugin
must be installed in an isolated IDAUSR. Reports fresh OFF/ON/ON decompilation,
semantic anchors and stable repetition; non-CFF controls must remain unchanged.
"""
import json
from pathlib import Path
import ida_auto, ida_hexrays, ida_loader, ida_pro, ida_nalt, ida_bytes, idc

ADDRESSES = [0x100221240, 0x1000053ac, 0x100007410, 0x100007bc0,
             0x100007f2c, 0x100009878, 0x10000b480, 0x10000b984,
             0x10000d30c, 0x100193e78, 0x100179008]
CONTROLS = {0x100179008} # FNV helper legitimately receives existing MBA folds.
FLATTENED = {0x100221240,0x1000053ac,0x100007f2c,0x100009878,0x10000b984}

def text(ea):
    ida_hexrays.mark_cfunc_dirty(ea, False)
    cf = ida_hexrays.decompile(ea)
    if cf is None:
        raise RuntimeError('decompile failed: ' + hex(ea))
    return str(cf)

def metrics(s):
    return dict(lines=len(s.splitlines()), switches=s.count('switch ('),
                cases=s.count('case '), gotos=s.count('goto '))

def main():
    out = Path(idc.ARGV[1]); out.mkdir(parents=True, exist_ok=True)
    ida_auto.auto_wait()
    if not ida_hexrays.init_hexrays_plugin(): raise RuntimeError('no Hex-Rays')
    plugin = ida_loader.load_plugin('unslopper')
    if plugin is None: raise RuntimeError('no Unslopper')
    rows=[]
    for ea in ADDRESSES:
        row={'ea':hex(ea), 'name':idc.get_func_name(ea)}
        try:
            ida_loader.run_plugin(plugin,1); before=text(ea)
            ida_loader.run_plugin(plugin,2); after=text(ea); again=text(ea)
            (out/(hex(ea)+'.before.c')).write_text(before)
            (out/(hex(ea)+'.after.c')).write_text(after)
            row.update(before=metrics(before),after=metrics(after),stable=after==again)
            if not row['stable']:raise AssertionError('unstable repeated decompilation')
            if ea in CONTROLS and before!=after:raise AssertionError('non-CFF control changed')
            if ea in FLATTENED and row['after']['switches']:
                raise AssertionError('residual fixture dispatcher')
            if ea==0x100221240:
                for anchor in ['__break(1u)', 'class_getInstanceMethod',
                               'method_getImplementation', 'objc_msgSend((id)0x9E']:
                    if anchor not in after:raise AssertionError('missing effect: '+anchor)
                if row['after']['switches']:raise AssertionError('residual load dispatcher')
        except Exception as exc:
            row['error']=str(exc)
        rows.append(row)
        print('[ixguard-test]',json.dumps(row))
        (out/'results.json').write_text(json.dumps(rows,indent=2))
    # Negative regression: replace the initial STR WZR state install with
    # STR W0 (unknown call result), only in the disposable test database.
    # A guessed initial state would incorrectly remove this dispatcher.
    ea=0x100221450
    original=ida_bytes.get_dword(ea)
    try:
        if original & 31 != 31:raise AssertionError('unexpected seed instruction')
        ida_bytes.patch_dword(ea,original & ~31)
        ida_loader.run_plugin(plugin,2)
        unknown=text(0x100221240)
        row={'test':'unknown initial state rejects specialization',
             'passed':unknown.count('switch (')==1}
        if not row['passed']:row['error']='unknown selector was specialized'
    except Exception as exc:
        row={'test':'unknown initial state rejects specialization','error':str(exc)}
    finally:
        ida_bytes.patch_dword(ea,original)
        ida_hexrays.mark_cfunc_dirty(0x100221240,False)
    rows.append(row)
    (out/'results.json').write_text(json.dumps(rows,indent=2))
    ida_pro.qexit(1 if any('error' in r for r in rows) else 0)

main()
