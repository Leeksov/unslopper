"""IDA harness for an ANALYSIS COPY: plan, annotate, repeat decompilation.
Run: idat -A -S"arxan_annotations.py report.json output.json [plugin.dylib]" copy.i64
"""
import hashlib,json,sys
from pathlib import Path
import ida_auto,ida_bytes,ida_funcs,ida_hexrays,ida_loader,ida_pro,idc
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import apply_arxan_branches

def main():
    report=json.loads(Path(idc.ARGV[1]).read_text());out=Path(idc.ARGV[2])
    ida_auto.auto_wait()
    if not ida_hexrays.init_hexrays_plugin():raise RuntimeError('Hex-Rays unavailable')
    if len(idc.ARGV)>3:
        plugin=ida_loader.load_plugin(idc.ARGV[3])
        if plugin is None:raise RuntimeError('Unslopper load failed')
        ida_loader.run_plugin(plugin,2)
    lo,hi=[int(x,16) for x in report['text']]
    before=hashlib.sha256(ida_bytes.get_bytes(lo,hi-lo)).hexdigest()
    plan=apply_arxan_branches.apply(report)
    picked=[];owners=set()
    for row in plan['accepted']:
        fn=ida_funcs.get_func(int(row['ea'],16))
        if fn.start_ea not in owners and fn.end_ea-fn.start_ea<=12000:
            picked.append(row);owners.add(fn.start_ea)
            if len(picked)==3:break
    if not picked:raise RuntimeError('No eligible small functions')
    def decompile():
        output={}
        for owner in sorted(owners):
            ida_hexrays.mark_cfunc_dirty(owner,False)
            cf=ida_hexrays.decompile(owner)
            if cf is None:raise RuntimeError('Decompilation failed: '+hex(owner))
            text=str(cf);output[hex(owner)]=dict(lines=len(text.splitlines()),jumpouts=text.count('JUMPOUT'),asm_blocks=text.count('__asm'))
        return output
    baseline=decompile()
    reduced=dict(report,records=picked)
    applied=apply_arxan_branches.apply(reduced,True)
    first=decompile();second=decompile()
    after=hashlib.sha256(ida_bytes.get_bytes(lo,hi-lo)).hexdigest()
    if before!=after:raise RuntimeError('Machine bytes changed')
    if first!=second:raise RuntimeError('Repeat decompilation metrics differ')
    reasons={}
    for row in plan['skipped']:reasons[row['reason']]=reasons.get(row['reason'],0)+1
    out.write_text(json.dumps(dict(sha256=report['sha256'],eligible=len(plan['accepted']),skipped=reasons,
        annotations=applied['applied'],baseline=baseline,after=first,repeat_matches=True,machine_bytes_unchanged=True),indent=2)+'\n')
    print('Arxan annotations verified:',len(plan['accepted']),'eligible;',len(picked),'functions exercised')

try:
    main()
except Exception as exc:
    if len(idc.ARGV)>2:Path(idc.ARGV[2]).write_text(json.dumps(dict(error=str(exc))))
    print('Arxan harness failed:',exc)
    ida_pro.qexit(1)
else:ida_pro.qexit(0)
