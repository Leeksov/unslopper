"""Compare every reported local BR rewrite using original ARM64 in Unicorn.
Usage: python3 tests/arxan_differential.py binary report.json output.json
This test never runs SDK functions, imports, or integrity-failure callbacks.
"""
import hashlib,json,random,struct,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
from arxan_analysis import MachO
from apply_arxan_branches import validate
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM
from unicorn import arm64_const as R


def verify(binary,report_path,output):
    image=MachO(binary);report=json.loads(Path(report_path).read_text())
    rows=validate(report,image,image.sha,image.base)
    u=Uc(UC_ARCH_ARM64,UC_MODE_ARM)
    low=min(s[0] for s in image.segments)//0x1000*0x1000
    high=(max(s[0]+s[1] for s in image.segments)+0xfff)//0x1000*0x1000
    u.mem_map(low,high-low)
    for va,vs,fo,fs,prot in image.segments:
        if fs:u.mem_write(va,image.data[fo:fo+fs])
    stack=high+0x1000000;u.mem_map(stack,0x4000000)
    regs=[getattr(R,'UC_ARM64_REG_X'+str(i)) for i in range(31)]+[R.UC_ARM64_REG_SP,R.UC_ARM64_REG_NZCV]
    rng=random.Random(365);comparisons=0
    for row in rows:
        site,target,start=[int(x,16) for x in (row['ea'],row['target'],row['window']['ea'])]
        displacement=(target-site)//4
        if not -(1<<25)<=displacement<(1<<25):raise ValueError('Direct B out of range')
        patched=struct.pack('<I',0x14000000|(displacement&0x3ffffff));old=image.read(site,4)
        for trial in range(3):
            initial=[rng.getrandbits(64) for _ in regs]
            initial[29]=stack+0x2010000;initial[31]=stack+0x2000000;initial[32]=0
            states=[]
            for instruction in (old,patched):
                u.mem_write(site,instruction);u.ctl_remove_cache(start,site+4)
                for reg,value in zip(regs,initial):u.reg_write(reg,value)
                u.emu_start(start,target,count=64)
                if u.reg_read(R.UC_ARM64_REG_PC)!=target:raise AssertionError('Unexpected destination '+row['ea'])
                states.append([u.reg_read(reg) for reg in regs])
            if states[0]!=states[1]:raise AssertionError('Register-state mismatch '+row['ea'])
            comparisons+=1
        u.mem_write(site,old);u.ctl_remove_cache(start,site+4)
    result=dict(sha256=image.sha,records=len(rows),comparisons=comparisons,matched=True,
                scope='Local instruction/reg/SP/NZCV equivalence at slice entry; no whole-program, alternate-entry, or live-device proof.')
    Path(output).write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result))


if __name__=='__main__':verify(*sys.argv[1:])
