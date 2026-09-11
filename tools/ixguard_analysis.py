"""Offline Mach-O evidence: bounded ARM64 syscall slices and audited FNV recipe.

No target API is executed. Writable data reads are explicitly file-snapshot
assumptions, never silently treated as runtime invariants.
"""
import argparse, hashlib, json, struct
from pathlib import Path
from functools import lru_cache
import capstone as cs
from capstone.arm64 import ARM64_OP_REG, ARM64_OP_IMM, ARM64_OP_MEM

NAMES = {-47:'mach_msg2_trap',-31:'mach_msg_trap',-28:'task_self_trap',
         1:'exit',2:'fork',5:'open',6:'close',10:'unlink',20:'getpid',26:'ptrace',
         33:'access',37:'kill',39:'getppid',73:'munmap',74:'mprotect',92:'fcntl',
         138:'utimes',159:'unmount',169:'csops',170:'csops_audittoken',191:'pathconf',197:'mmap',
         202:'sysctl',338:'stat64',339:'fstat64',340:'lstat64',381:'__mac_syscall',
         437:'openat',463:'fstatat64'}

class MachO:
    def __init__(self,path):
        self.data=Path(path).read_bytes();self.sha=hashlib.sha256(self.data).hexdigest()
        h=struct.unpack_from('<8I',self.data)
        if h[0]!=0xfeedfacf or h[1]!=0x100000c:raise ValueError('ARM64 Mach-O required')
        self.segments=[];self.sections={};o=32
        for _ in range(h[4]):
            cmd,size=struct.unpack_from('<II',self.data,o)
            if cmd==0x19:
                _,_,name,va,vs,fo,fs,_,prot,nsect,_=struct.unpack_from('<II16sQQQQiiII',self.data,o)
                self.segments.append((va,vs,fo,fs,prot))
                for n in range(nsect):
                    sn,sg,a,s,f=struct.unpack_from('<16s16sQQI',self.data,o+72+80*n)
                    self.sections[sn.rstrip(b'\0').decode()]=(a,s,f)
            o+=size
        self.base=min(v[0] for v in self.segments if v[3])
    def read(self,ea,size):
        for va,vs,fo,fs,prot in self.segments:
            if va<=ea and ea+size<=va+fs:return self.data[fo+ea-va:fo+ea-va+size]
        raise ValueError('unbacked address '+hex(ea))
    def writable(self,ea):
        return any(va<=ea<va+vs and prot&2 for va,vs,fo,fs,prot in self.segments)

class Unknown(Exception):pass

class Slice:
    def __init__(self,image,site,window=96):
        self.image=image;self.site=site
        text,_,_=image.sections['__text'];start=max(text,site-window*4)
        md=cs.Cs(cs.CS_ARCH_ARM64,cs.CS_MODE_LITTLE_ENDIAN);md.detail=True
        self.ins=list(md.disasm(image.read(start,site-start),start));self.proof={};self.reads={}
        if self.ins and self.ins[-1].address+4!=site:raise Unknown('undecodable slice')
    @staticmethod
    def key(reg):return 'x'+reg[1:] if reg.startswith('w') else reg
    def arg(self,i,o,pos):
        if o.type==ARM64_OP_IMM:v=o.imm
        elif o.type==ARM64_OP_REG:v=self.reg(i.reg_name(o.reg),pos)
        else:raise Unknown('unsupported operand')
        if o.ext:raise Unknown('extended arithmetic operand')
        if o.shift.value:
            if o.shift.type==cs.arm64.ARM64_SFT_LSL:v<<=o.shift.value
            elif o.shift.type==cs.arm64.ARM64_SFT_LSR:v=(v&((1<<64)-1))>>o.shift.value
            else:raise Unknown('unsupported shifted operand')
        return v
    @lru_cache(None)
    def reg(self,reg,pos):
        if reg in ('wzr','xzr'):return 0
        wanted=self.key(reg)
        for j in range(pos-1,-1,-1):
            i=self.ins[j];m=i.mnemonic;o=i.operands
            if i.group(cs.CS_GRP_JUMP) or i.group(cs.CS_GRP_CALL) or i.group(cs.CS_GRP_RET) or m in ('svc','brk'):
                raise Unknown('control-flow boundary before '+reg)
            _,writes=i.regs_access()
            if wanted not in {self.key(i.reg_name(r)) for r in writes}:continue
            if not o or o[0].type!=ARM64_OP_REG:raise Unknown('implicit register definition')
            dest=i.reg_name(o[0].reg)
            if self.key(dest)!=wanted:raise Unknown('multi-register definition')
            width=32 if dest.startswith('w') else 64;mask=(1<<width)-1
            a=lambda n:self.arg(i,o[n],j)
            if m in ('mov','movz','adr','adrp'):v=a(1)
            elif m=='movn':v=~a(1)
            elif m=='movk':
                shift=o[1].shift.value
                v=(self.reg(dest,j)&~(65535<<shift))|a(1)
            elif m in ('add','sub','eor','orr','and','bic','orn','eon'):
                x,y=a(1),a(2)
                v={'add':lambda:x+y,'sub':lambda:x-y,'eor':lambda:x^y,
                   'orr':lambda:x|y,'and':lambda:x&y,'bic':lambda:x&~y,
                   'orn':lambda:x|~y,'eon':lambda:x^~y}[m]()
            elif m in ('neg','mvn'):v=-a(1) if m=='neg' else ~a(1)
            elif m in ('lsl','lsr','asr'):
                x,n=a(1)&mask,a(2)
                if n>=width:raise Unknown('out-of-range shift')
                if m=='lsl':v=x<<n
                elif m=='lsr':v=x>>n
                else:v=(x-(1<<width) if x>>(width-1) else x)>>n
            elif m in ('ldr','ldur','ldrb','ldrh','ldrsw') and o[1].type==ARM64_OP_MEM:
                mem=o[1].mem
                if mem.index or i.writeback:raise Unknown('indexed/writeback load')
                address=self.reg(i.reg_name(mem.base),j)+mem.disp
                size={'ldrb':1,'ldrh':2,'ldrsw':4}.get(m,width//8)
                raw=self.image.read(address,size)
                v=int.from_bytes(raw,'little',signed=m=='ldrsw')
                self.reads[address]={'ea':hex(address),'bytes':raw.hex(),
                                     'writable':bool(self.image.writable(address))}
            else:raise Unknown('unsupported definition: '+m)
            self.proof[i.address]={'ea':hex(i.address),'bytes':bytes(i.bytes).hex(),
                                   'asm':m+' '+i.op_str}
            return (v&mask)&((1<<32)-1 if reg.startswith('w') else (1<<64)-1)
        raise Unknown('slice input '+reg)

def syscalls(image):
    base,size,_=image.sections['__text'];rows=[]
    blob=image.read(base,size)
    for offset in range(0,len(blob)-3,4):
        if blob[offset:offset+4]!=bytes.fromhex('011000d4'):continue
        site=base+offset;row={'ea':hex(site),'rva':hex(site-image.base)}
        try:
            s=Slice(image,site);v=s.reg('x16',len(s.ins))
            if v>>32 not in (0,0xffffffff):raise Unknown('noncanonical syscall selector')
            n=v&0xffffffff;n=n-(1<<32) if n>>31 else n
            row.update(number=n,name=NAMES.get(n),namespace='mach' if n<0 else 'bsd',
                       evidence=list(sorted(s.proof.values(),key=lambda r:int(r['ea'],16))),
                       reads=list(s.reads.values()),
                       status='file_snapshot' if any(r['writable'] for r in s.reads.values()) else 'constant')
            start=max(base,site-96*4)
            row['window']={'ea':hex(start),'bytes':image.read(start,site-start+4).hex()}
            # Arguments are separate slices, so failure cannot contaminate the selector proof.
            args={}
            for reg in ('x0','x1'):
                try:
                    arg=Slice(image,site);args[reg]={'value':hex(arg.reg(reg,len(arg.ins))),
                                                   'reads':list(arg.reads.values())}
                except (Unknown,ValueError):pass
            row['arguments']=args
        except (Unknown,ValueError) as e:row.update(status='unresolved',reason=str(e))
        rows.append(row)
    return {'sha256':image.sha,'base':hex(image.base),'records':rows,
            'contract':'Intra-block backward slices; writable reads are file-snapshot assumptions.'}

FNV_RVA=0x193e78
FNV_SIZE=0xec
SEED_RVA=0x2425fe8
SEED=0xc8dba56f43099739
SAMPLE_SHA='a256ae2b4b296f675c268d10dfcd06cfd64b43f6c7f938d95684c223523ea389'

def fnv(flag,salt):
    h=0xcbf29ce484222325
    for b in (((flag&0xffffffff)<<32)|(salt&0xffffffff)).to_bytes(8,'little'):
        h=((h^b)*0x100000001b3)&((1<<64)-1)
    return h

def audit_hash(image):
    if image.sha!=SAMPLE_SHA:raise ValueError('no audited hash recipe for this input')
    if int.from_bytes(image.read(image.base+SEED_RVA,8),'little')!=SEED:raise ValueError('unexpected seed')
    import unicorn as uc
    from unicorn import arm64_const as ar
    import random
    machine=uc.Uc(uc.UC_ARCH_ARM64,uc.UC_MODE_ARM)
    code=image.base+FNV_RVA;seed=image.base+SEED_RVA
    machine.mem_map(code&~4095,4096);machine.mem_write(code,image.read(code,FNV_SIZE))
    machine.mem_map(seed&~4095,4096);machine.mem_write(seed,SEED.to_bytes(8,'little'))
    stop=0x7000000000;machine.mem_map(stop,4096)
    rng=random.Random(0x495847)
    vectors=[(b,s) for b in (0,1) for s in (0,1,0xffffffff,1290241587)]
    vectors += [(rng.getrandbits(32),rng.getrandbits(32)) for _ in range(256)]
    for flag,salt in vectors:
        machine.reg_write(ar.UC_ARM64_REG_X0,flag);machine.reg_write(ar.UC_ARM64_REG_X1,salt)
        machine.reg_write(ar.UC_ARM64_REG_X30,stop)
        machine.emu_start(code,stop,count=2000)
        if machine.reg_read(ar.UC_ARM64_REG_PC)!=stop:raise AssertionError('helper exceeded bound')
        if machine.reg_read(ar.UC_ARM64_REG_X0)!=fnv(flag,salt):raise AssertionError('FNV mismatch')
    return {'sha256':image.sha,'helper_rva':hex(FNV_RVA),
            'code':image.read(code,FNV_SIZE).hex(),'seed_rva':hex(SEED_RVA),'seed':hex(SEED),
            'vectors_verified':len(vectors),'flag0':hex(fnv(0,1290241587)),
            'flag1':hex(fnv(1,1290241587)),
            'contract':'FNV64 LE over uint32(flag)||uint32(salt), under the explicit fixed-seed snapshot.'}

def main():
    p=argparse.ArgumentParser();p.add_argument('mode',choices=['syscalls','hash'])
    p.add_argument('binary');p.add_argument('output');a=p.parse_args()
    image=MachO(a.binary);result=syscalls(image) if a.mode=='syscalls' else audit_hash(image)
    Path(a.output).write_text(json.dumps(result,indent=2))
    if a.mode=='syscalls':
        from collections import Counter
        print(dict(Counter(r['status'] for r in result['records'])))
    else:print('audited vectors:',result['vectors_verified'])

if __name__=='__main__':main()
