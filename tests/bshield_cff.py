"""Run in IDAPython on BShield with only the candidate optimizer loaded.

    import runpy
    suite = runpy.run_path('/path/to/tests/bshield_cff.py')
    suite['run']('/path/to/unslopper.dylib', '/path/to/results')

Never modifies machine bytes, names or types. Uses the plugin's documented
off/on actions; leaves it enabled. Captures 21 decompilations and strict verifies.
"""
import json
import hashlib
from pathlib import Path
import ida_hexrays, ida_loader, ida_nalt

TARGETS=[0x3a95b4,0x28f444,0x11970,0x2a233c,0x2a15a4,0xc874,0x4dcc]

def run(plugin_path,output,binary_path=None):
    digest=ida_nalt.retrieve_input_file_sha256()
    expected='206dbaf5382a5d6ad5c592c82e2eac263891310c18d51203a7e57c200450e8b6'
    actual=hashlib.sha256(Path(binary_path).read_bytes()).hexdigest() if binary_path else bytes(digest).hex() if digest else None
    if actual!=expected:
        raise ValueError('This regression requires the pinned BShield sample')
    plugin=ida_loader.load_plugin(str(plugin_path))
    if not plugin: raise RuntimeError('Plugin did not load')
    out=Path(output); out.mkdir(parents=True,exist_ok=True)
    rows=[]
    try:
        for ea in TARGETS:
            row={'ea':hex(ea)}; texts={}
            for name,arg in [('off',1),('on',2),('repeat',2)]:
                ida_loader.run_plugin(plugin,arg)
                ida_hexrays.mark_cfunc_dirty(ea,False)
                cf=ida_hexrays.decompile(ea)
                if cf is None: raise RuntimeError('Decompilation failed')
                cf.mba.verify(True)
                text=str(cf); texts[name]=text
                (out/(hex(ea)+'-'+name+'.c')).write_text(text)
                row[name]={'lines':len(text.splitlines()),'while':text.count('while ('),'verified':True}
            assert texts['on']==texts['repeat'], 'Repeated decompilation changed output'
            if ea==0x4dcc: assert texts['off']==texts['on'], 'Negative control changed'
            else: assert row['on']['lines']<row['off']['lines'], 'Expected CFF reduction absent'
            rows.append(row)
            (out/'validation.json').write_text(json.dumps(rows,indent=2)+'\n')
    finally:
        ida_loader.run_plugin(plugin,2)
    return rows
