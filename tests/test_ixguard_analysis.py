"""Proof and differential checks for the exact new arithmetic rules/slices."""
import importlib.util,json,random,sys,unittest
from pathlib import Path
import z3
import unicorn as uc
from unicorn import arm64_const as ar

MODULE=Path(__file__).resolve().parents[1]/'tools/ixguard_analysis.py'
spec=importlib.util.spec_from_file_location('ixguard_analysis',MODULE)
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

class ArithmeticProofs(unittest.TestCase):
    def test_constant_and_dynamic_slices(self):
        class Image:
            def __init__(self,words):
                import struct
                self.data=b''.join(struct.pack('<I',w) for w in words)
                self.sections={'__text':(0x1000,len(self.data),0)}
            def read(self,ea,size):return self.data[ea-0x1000:ea-0x1000+size]
        # MOV W16,#159; SVC. W-register write zero-extends the X-register.
        s=m.Slice(Image([0x528013f0,0xd4001001]),0x1004)
        self.assertEqual(s.reg('x16',len(s.ins)),159)
        # Caller-selected X0 and a control-flow boundary are not constants.
        for image,site in [(Image([0xaa0003f0,0xd4001001]),0x1004),
                           (Image([0x528013f0,0x14000001,0xd4001001]),0x1008)]:
            s=m.Slice(image,site)
            with self.assertRaises(m.Unknown):s.reg('x16',len(s.ins))
    def test_annotation_preflight_rejects_changed_data(self):
        spec=importlib.util.spec_from_file_location('apply_syscalls',MODULE.with_name('apply_ixguard_syscalls.py'))
        apply=importlib.util.module_from_spec(spec);spec.loader.exec_module(apply)
        mem={0x1000:bytes.fromhex('011000d4'),0x2000:b'\x01'*8}
        row={'ea':'0x1000','status':'file_snapshot','window':{'ea':'0x1000','bytes':'011000d4'},
             'reads':[{'ea':'0x2000','bytes':('01'*8)}]}
        report={'sha256':'fixture','base':'0x1000','records':[row]}
        self.assertEqual(len(apply.validate(report,lambda ea,n:mem[ea][:n],'fixture',0x1000)),1)
        mem[0x2000]=b'\x02'*8
        with self.assertRaises(ValueError):apply.validate(report,lambda ea,n:mem[ea][:n],'fixture',0x1000)
    def test_bitvector_identities(self):
        for width in (8,16,32,64):
            a,b=z3.BitVecs('a b',width)
            pairs=[(2*(a|b)-(a^b),a+b),((a|b)+(a&b),a+b),
                   ((a^b)+2*(a&b),a+b),(a-(~b+1),a+b),
                   (a-(~b-1),a+b+2)]
            for left,right in pairs:
                solver=z3.Solver();solver.add(left!=right)
                self.assertEqual(solver.check(),z3.unsat,(width,left))
            wrong=z3.Solver();wrong.add(a-(~b-1)!=a+b)
            self.assertEqual(wrong.check(),z3.sat)
    def test_unknown_upper_bytes(self):
        for width in (16,32,64):
            x=z3.BitVec('x',width)
            for low in (0,1,255):
                s=z3.Solver();s.add((x&255)==low,(x&1)!=(low&1))
                self.assertEqual(s.check(),z3.unsat)
                s=z3.Solver();s.add((x&255)==low,(x&256)!=0)
                self.assertEqual(s.check(),z3.sat) # must not invent upper zeroes

def verify_slices(binary,report_path):
    image=m.MachO(binary);report=json.loads(Path(report_path).read_text())
    assert report['sha256']==image.sha
    machine=uc.Uc(uc.UC_ARCH_ARM64,uc.UC_MODE_ARM)
    mapped=set()
    def page(ea):
        p=ea&~4095
        if p not in mapped:machine.mem_map(p,4096);mapped.add(p)
    rng=random.Random(0x535643);checked=0
    for row in report['records']:
        if row['status']=='unresolved':continue
        site=int(row['ea'],16)
        for proof in row['evidence']:
            ea=int(proof['ea'],16);page(ea)
            raw=bytes.fromhex(proof['bytes']);assert image.read(ea,4)==raw
            machine.mem_write(ea,raw)
        for read in row['reads']:
            ea=int(read['ea'],16);page(ea);page(ea+len(bytes.fromhex(read['bytes']))-1)
            machine.mem_write(ea,bytes.fromhex(read['bytes']))
        expected=m.Slice(image,site).reg('x16',len(m.Slice(image,site).ins))
        for _ in range(3):
            for n in range(29):machine.reg_write(getattr(ar,'UC_ARM64_REG_X'+str(n)),rng.getrandbits(64))
            for proof in row['evidence']:
                ea=int(proof['ea'],16)
                # Replay original opcodes at original PCs, only the dependency
                # slice. No SVC, calls, branches, or host API execution.
                machine.emu_start(ea,ea+4,count=1)
            actual=machine.reg_read(ar.UC_ARM64_REG_X16)
            assert actual==expected,(hex(site),hex(actual),hex(expected))
        checked+=1
    return {'sites':checked,'executions':checked*3,'all_matched':True,
            'scope':'Original dependency-slice opcodes under recorded file reads; no SVC executed.'}

if __name__=='__main__':
    if len(sys.argv)>1 and sys.argv[1]=='slices':
        result=verify_slices(sys.argv[2],sys.argv[3]);print(json.dumps(result))
        if len(sys.argv)>4:Path(sys.argv[4]).write_text(json.dumps(result,indent=2))
    else:unittest.main()
