"""Validate automatic C++ Arxan recovery on an isolated, unmodified IDB.
IDA args: report.json output.json fresh_plugin.dylib [max_functions=20]
No annotation importer is called. Python only drives the comparison harness.
"""
import hashlib,json,os
from pathlib import Path
import ida_auto,ida_bytes,ida_funcs,ida_hexrays,ida_loader,ida_pro,idc

def main():
    report=json.loads(Path(idc.ARGV[1]).read_text());out=Path(idc.ARGV[2]);plugin_path=Path(idc.ARGV[3])
    count=int(idc.ARGV[4]) if len(idc.ARGV)>4 else 20
    ida_auto.auto_wait()
    if not ida_hexrays.init_hexrays_plugin():raise RuntimeError('No Hex-Rays')
    plugin=ida_loader.load_plugin(str(plugin_path))
    if plugin is None:raise RuntimeError('Fresh plugin did not load')
    lo,hi=[int(x,16) for x in report['text']]
    before=hashlib.sha256(ida_bytes.get_bytes(lo,hi-lo)).hexdigest()
    owners=set()
    for row in report['records']:
        site,target,start=[int(x,16) for x in (row['ea'],row['target'],row['window']['ea'])]
        fn=ida_funcs.get_func(site);a=ida_funcs.get_func(start);b=ida_funcs.get_func(target)
        if fn and a and b and a.start_ea==fn.start_ea==b.start_ea and fn.end_ea-fn.start_ea<=12000:
            owners.add(fn.start_ea)
    owners=sorted(owners)
    if not owners:raise RuntimeError('No eligible functions')
    selected=owners if count<=0 or len(owners)<=count else [owners[i*(len(owners)-1)//(count-1)] for i in range(count)]
    texts=out.with_suffix('.texts');texts.mkdir(exist_ok=True)
    def phase(name,enabled,native):
        if native:os.environ.pop('UNSLOP_NO_ARXAN',None)
        else:os.environ['UNSLOP_NO_ARXAN']='1'
        ida_loader.run_plugin(plugin,2 if enabled else 1)
        ida_hexrays.clear_cached_cfuncs()
        print('ARXAN_NATIVE_PHASE',name,flush=True)
        values={}
        for ea in selected:
            try:
                cf=ida_hexrays.decompile(ea)
                if cf is None:raise RuntimeError('No cfunc')
                text=str(cf)
                (texts/(name+'_'+hex(ea)+'.c')).write_text(text)
                values[hex(ea)]=dict(lines=len(text.splitlines()),gotos=text.count('goto '),
                    jumpouts=text.count('JUMPOUT'),asm_blocks=text.count('__asm'),sha256=hashlib.sha256(text.encode()).hexdigest())
            except Exception as exc:values[hex(ea)]={'error':str(exc)}
        if enabled:ida_loader.run_plugin(plugin,4)
        return values
    baseline=phase('disabled',False,False)
    core=phase('core_only',True,False)
    core_repeat=phase('core_repeat',True,False)
    initial_native=phase('native_initial',True,True)  # Allow IDA to infer types for newly visible code.
    native=phase('native',True,True)
    repeated=phase('native_repeat',True,True)
    after=hashlib.sha256(ida_bytes.get_bytes(lo,hi-lo)).hexdigest()
    regressions=[ea for ea in native if 'error' not in core[ea] and 'error' in native[ea]]
    stable=native==repeated
    result=dict(sample_sha256=report['sha256'],plugin_sha256=hashlib.sha256(plugin_path.read_bytes()).hexdigest(),
        eligible_functions=len(owners),tested_functions=len(selected),baseline=baseline,core_only=core,
        initial_native=initial_native,native=native,repeated=repeated,repeated_matches=stable,core_repeat_matches=core==core_repeat,
        new_failures=regressions,machine_bytes_unchanged=before==after)
    out.write_text(json.dumps(result,indent=2)+'\n')
    if regressions or not stable or before!=after:raise RuntimeError('Regression, unstable decompilation, or changed machine bytes')
    print('C++ Arxan test passed:',len(selected),'functions',flush=True)

try:main()
except Exception as exc:
    print('C++ Arxan test failed:',exc,flush=True)
    ida_pro.qexit(1)
else:ida_pro.qexit(0)
