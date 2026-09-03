"""Offline DexGuard computed-BR resolver / annotator for libc1ef.so.

DexGuard obfuscates control flow on this lib with computed indirect branches
(`BR Xn`) and computed SVC numbers. ~4700 BR sites live in .text
(0x2C000..0x11A7BC). This annotator resolves each site and writes IDA comments
at the disassembly/evidence level (rva == ea because the .so loads at image
base 0), mirroring the proven apply_svc_map.py / apply_dispatch_map.py pattern.

Idiom classes (a target is annotated only when it is non-null and lands in
.text or a named import — never invented):

  idiom-1  static tail-jump      LDR Xt, off_XXXX ; BR Xt          (or ADRP/ADD
                                 + indexed LDR); target = *off = a .text sub_
  idiom-3  dispatch table        idx computed by a DexGuard MBA expression;
                                 BR Xt loads off_126B90[idx]; target = table[idx]
  idiom-2  2-way CSEL tail-jump  BR reg defined by CSEL of two off_* pointers;
                                 annotated with BOTH targets, NEVER patched
  svc      computed syscall NR   X8 computed by MBA; SVC #0 -> resolved NR

RESOLUTION ENGINE. The DexGuard index/NR math is a full mixed boolean-arithmetic
expression (MVN/NEG/ORR/EOR/LSL/SMADDL/…), not a single linear identity, so a
straight-line AArch64 integer emulator over the BR's basic block computes the
concrete index/target. A weak linear-identity brute force (`_mba_resolve`, ported
from the snb tools) and a first-off_*-ref window scan remain as fallbacks for the
minority of sites the emulator cannot fold, and are reported separately/honestly.

Run headless:
    IDAUSR=<nusr> TVHEADLESS=1 idat -A -L<log> \
        -S'<repo>/tools/apply_dexguard_branches.py [--patch]' <copy.i64>
Or inside IDA:  exec(open('apply_dexguard_branches.py').read())

--patch  additionally patch SINGLE-TARGET sites (idiom-1 + idiom-3) from
         `BR Xn` to a direct `B target` and add a code cref, so Hex-Rays follows
         the real flow (mirrors deflatten.patch_brs). 2-way CSEL idiom-2 sites
         are NEVER patched (lossy). Only emulator-resolved single targets are
         patched (loose/weak-fallback sites are annotated, not patched).

Evidence sidecar: if an `evidence/` dir exists next to `tools/`, a JSON
{br_rva -> {target|dispatch_col|syscall}} is written there; else skipped
(reported honestly).
"""
import json, os, re
import idc, idaapi, idautils, ida_ua, ida_funcs, ida_bytes, ida_xref, ida_gdl

try:
    from ida_auto import auto_wait
    auto_wait()
except Exception:
    pass

# ---------------------------------------------------------------------------
# Constants (same basis as snb deobfuscate.py / deflatten.py)
# ---------------------------------------------------------------------------
TEXT_START = 0x2C000
TEXT_END   = 0x11A7BC
TABLE_ADDR = 0x126B90
TABLE_SIZE = 238
SVC_OPCODE = 0xD4000001
KEY_LO, KEY_HI = 0x120000, 0x12E400
OFF_LO, OFF_HI = 0x120000, 0x147000
IMP_LO, IMP_HI = 0x146960, 0x146BA8
M64 = (1 << 64) - 1
M32 = (1 << 32) - 1

IMPORTS = {
    0x146960:"__cxa_finalize",0x146968:"__cxa_atexit",0x146970:"__errno",
    0x146988:"__stack_chk_fail",0x146990:"__system_property_find_nth",
    0x146998:"__system_property_foreach",0x1469a0:"__system_property_get",
    0x1469a8:"__system_property_read",0x1469b0:"_exit",0x1469b8:"atoi",
    0x1469c0:"basename",0x1469c8:"calloc",0x1469d0:"close",0x1469d8:"closedir",
    0x1469e0:"dladdr",0x1469e8:"dlerror",0x1469f0:"dlopen",0x1469f8:"dlsym",
    0x146a00:"dup2",0x146a08:"execv",0x146a10:"fclose",0x146a18:"fcntl",
    0x146a20:"fopen",0x146a28:"fork",0x146a30:"free",0x146a38:"getpagesize",
    0x146a40:"getppid",0x146a48:"ioctl",0x146a50:"isupper",0x146a58:"kill",
    0x146a60:"killpg",0x146a68:"malloc",0x146a70:"memcpy",0x146a78:"memmove",
    0x146a80:"memset",0x146a88:"mprotect",0x146a90:"opendir",0x146a98:"pathconf",
    0x146aa0:"pipe",0x146aa8:"pipe2",0x146ab0:"poll",0x146ab8:"prctl",
    0x146ac0:"pthread_create",0x146ac8:"raise",0x146ad0:"read",0x146ad8:"readdir",
    0x146ae0:"realloc",0x146b10:"sigaction",0x146b18:"siglongjmp",
    0x146b20:"sigsetjmp",0x146b28:"stat",0x146b30:"statfs",0x146b38:"syscall",
    0x146b40:"sysconf",0x146b48:"usleep",0x146b50:"waitpid",0x146b58:"write",
    0x146b60:"abort",0x146ba0:"__system_property_read_callback",
}

SYSCALL_NAMES = {
    0:'read_nr0',17:'sched_getscheduler',29:'ioctl',48:'faccessat',
    56:'openat',57:'close',62:'lstat',63:'read',64:'write',73:'ppoll',
    79:'fstatat',80:'fstat',93:'exit',94:'exit_group',96:'set_tid_address',
    98:'futex',101:'nanosleep',113:'clock_gettime',117:'ptrace',129:'kill',
    131:'tgkill',134:'rt_sigaction',135:'rt_sigprocmask',160:'uname',
    167:'prctl',172:'getpid',173:'getppid',178:'gettid',198:'socket',
    215:'munmap',220:'clone',221:'execve',222:'mmap',226:'mprotect',
    233:'madvise',260:'wait4',280:'pipe2',435:'clone3',437:'openat2',
}

# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------
def _iter_insns(start, end):
    ea = start
    while ea < end and ea != idaapi.BADADDR:
        yield ea
        ea = idc.next_head(ea, end)

def _in_text(v):
    return TEXT_START <= v < TEXT_END

def _target_name(v):
    if v in IMPORTS:
        return IMPORTS[v]
    return idc.get_name(v) or ("sub_%X" % v)

def _sx(v, bits):
    v &= (1 << bits) - 1
    if v & (1 << (bits - 1)):
        v -= (1 << bits)
    return v

def _build_off_map():
    off_map = {}
    for oe in range(OFF_LO, OFF_HI, 8):
        nm = idc.get_name(oe)
        if nm and nm.startswith("off_"):
            val = idc.get_qword(oe)
            if _in_text(val) or (IMP_LO <= val < IMP_HI):
                off_map[oe] = (nm, val, _target_name(val))
    return off_map

def _mba_resolve(key32, consts, max_val):
    """Weak linear-identity brute force (ported from snb deobfuscate.py).
    FALLBACK ONLY — the emulator is authoritative."""
    neg = (-key32) & M32
    inv = (~key32) & M32
    for c in consts:
        for cand in ((neg + c) & M32, (c - key32) & M32, (inv + c) & M32,
                     (c - key32 + 1) & M32, (c - key32 - 1) & M32):
            if cand < max_val:
                return int(cand)
    return None

# ---------------------------------------------------------------------------
# Straight-line AArch64 integer emulator (per basic block)
# ---------------------------------------------------------------------------
_REG = re.compile(r'^([WX])(\d+|ZR|SP)$', re.I)

def _parse_reg(tok):
    m = _REG.match(tok.strip())
    if not m:
        return None
    w = m.group(1).upper() == 'W'
    n = m.group(2).upper()
    idx = n if n in ('ZR', 'SP') else int(n)
    return (w, idx)

def _split_ops(s):
    out = []; depth = 0; cur = ""
    for ch in s:
        if ch == '[':
            depth += 1; cur += ch
        elif ch == ']':
            depth -= 1; cur += ch
        elif ch == ',' and depth == 0:
            out.append(cur.strip()); cur = ""
        else:
            cur += ch
    if cur.strip():
        out.append(cur.strip())
    return out

def _named_dref(ea):
    for r in idautils.DataRefsFrom(ea):
        nm = idc.get_name(r) or ""
        if nm.startswith(("off_", "qword_", "dword_", "unk_", "byte_", "word_")):
            return r
    return None

class Emu(object):
    def __init__(self):
        self.x = {}       # idx -> 64-bit int (None = unknown)
        self.src = {}     # idx -> address a value was LDR'd from (provenance)
        self.lastw = {}   # idx -> (ea, mnem, ops)

    def get(self, tok):
        pr = _parse_reg(tok)
        if pr is None:
            return None
        w, idx = pr
        if idx == 'ZR':
            return 0
        v = self.x.get(idx)
        if v is None:
            return None
        return (v & M32) if w else (v & M64)

    def set(self, tok, val, src=None):
        pr = _parse_reg(tok)
        if pr is None:
            return
        w, idx = pr
        if idx in ('ZR', 'SP'):
            return
        self.x[idx] = None if val is None else ((val & M32) if w else (val & M64))
        if src is not None:
            self.src[idx] = src
        elif idx in self.src:
            del self.src[idx]

    def imm(self, tok):
        t = tok.strip().lstrip('#').split('@')[0]
        try:
            return int(t, 16) if t.lower().startswith('0x') else int(t, 0)
        except Exception:
            try:
                return int(t)
            except Exception:
                return None

    def shifted(self, tok):
        tok = tok.strip()
        if tok.startswith('#'):
            return self.imm(tok)
        parts = tok.split(',')
        v = self.get(parts[0].strip())
        if v is None:
            v = self.imm(parts[0].strip())
        if v is None:
            return None
        if len(parts) > 1:
            m = re.match(r'(LSL|LSR|ASR)#(\w+)', parts[1].strip().upper())
            if m:
                amt = int(m.group(2), 0)
                if m.group(1) == 'LSL':
                    v = (v << amt) & M64
                elif m.group(1) == 'LSR':
                    v = (v & M64) >> amt
                else:
                    v = _sx(v, 32) >> amt
        return v

    def eff_addr(self, ea, memtok):
        d = _named_dref(ea)
        if d is not None:
            return d
        if '[' not in memtok:
            return None
        inner = memtok[memtok.find('[') + 1:memtok.rfind(']')]
        ps = _split_ops(inner)
        base = self.get(ps[0])
        if base is None:
            return None
        addr = base
        if len(ps) >= 2:
            p = ps[1].strip()
            if p.startswith('#'):
                addr = base + (self.imm(p) or 0)
            else:
                extra = (' ' + ' '.join(ps[2:])) if len(ps) >= 3 else ''
                iv = self.get(p.split(',')[0].strip())
                if iv is None:
                    return None
                m2 = re.search(r'(SXTW|UXTW|SXTX|UXTX|LSL)\s*#?(\d+)?', p + extra, re.I)
                sc = 0; signed = False
                if m2:
                    if m2.group(1).upper() in ('SXTW', 'SXTX'):
                        signed = True
                    sc = int(m2.group(2)) if m2.group(2) else 0
                if signed:
                    iv = _sx(iv, 32)
                addr = base + (iv << sc)
        return addr & M64

    def step(self, ea, mnem, ops):
        if not ops:
            return
        dst = ops[0]
        if mnem in ("ADRP", "ADR"):
            d = _named_dref(ea)
            if d is not None:
                self.set(dst, (d & ~0xFFF) if mnem == "ADRP" else d)
            else:
                self.set(dst, self.imm(ops[1]) if len(ops) > 1 else None)
            return
        # address-forming ADD Xd, Xn, #sym@PAGEOFF
        if mnem == "ADD":
            d = _named_dref(ea)
            if d is not None:
                self.set(dst, d)
                return
        if mnem in ("MOV", "MOVZ"):
            rv = self.get(ops[1])
            src = self.src.get(_parse_reg(ops[1])[1]) if _parse_reg(ops[1]) and _parse_reg(ops[1])[1] not in ('ZR', 'SP') else None
            if rv is None:
                rv = self.imm(ops[1]); src = None
            self.set(dst, rv, src)
            return
        if mnem == "MOVK":
            cur = self.get(dst) or 0
            im = self.imm(ops[1]); sh = 0
            if len(ops) >= 3:
                m = re.search(r'LSL#(\d+)', ops[2])
                if m:
                    sh = int(m.group(1))
            if im is not None:
                cur = (cur & ~(0xFFFF << sh)) | ((im & 0xFFFF) << sh)
                self.set(dst, cur)
            return
        if mnem == "MVN":
            v = self.shifted(ops[1]); self.set(dst, (~v) & M64 if v is not None else None); return
        if mnem == "NEG":
            v = self.shifted(ops[1]); self.set(dst, (-v) & M64 if v is not None else None); return
        if mnem in ("ADD", "SUB", "AND", "ORR", "EOR", "EON", "BIC", "ORN"):
            a = self.get(ops[1]); b = self.shifted(ops[2]) if len(ops) >= 3 else None
            if a is None or b is None:
                self.set(dst, None); return
            r = {"ADD": a + b, "SUB": a - b, "AND": a & b, "ORR": a | b,
                 "EOR": a ^ b, "EON": a ^ (~b), "ORN": a | (~b), "BIC": a & (~b)}[mnem]
            self.set(dst, r & M64); return
        if mnem in ("LSL", "LSR", "ASR"):
            a = self.get(ops[1])
            b = self.imm(ops[2]) if len(ops) >= 3 else None
            if b is None and len(ops) >= 3:
                b = self.get(ops[2])
            if a is None or b is None:
                self.set(dst, None); return
            r = (a << b) & M64 if mnem == "LSL" else ((a & M64) >> b if mnem == "LSR" else _sx(a, 32) >> b)
            self.set(dst, r & M64); return
        if mnem == "MUL":
            a = self.get(ops[1]); b = self.get(ops[2])
            self.set(dst, (a * b) & M64 if a is not None and b is not None else None); return
        if mnem in ("MADD", "MSUB"):
            a = self.get(ops[1]); b = self.get(ops[2]); c = self.get(ops[3])
            if None in (a, b, c):
                self.set(dst, None); return
            self.set(dst, ((c + a * b) if mnem == "MADD" else (c - a * b)) & M64); return
        if mnem in ("SMADDL", "UMADDL", "SMSUBL", "UMSUBL"):
            a = self.get(ops[1]); b = self.get(ops[2]); c = self.get(ops[3])
            if None in (a, b, c):
                self.set(dst, None); return
            if mnem[0] == "S":
                a = _sx(a, 32); b = _sx(b, 32)
            else:
                a &= M32; b &= M32
            self.set(dst, ((c + a * b) if "ADD" in mnem else (c - a * b)) & M64); return
        if mnem in ("SMULL", "UMULL"):
            a = self.get(ops[1]); b = self.get(ops[2])
            if None in (a, b):
                self.set(dst, None); return
            if mnem[0] == "S":
                a = _sx(a, 32); b = _sx(b, 32)
            else:
                a &= M32; b &= M32
            self.set(dst, (a * b) & M64); return
        if mnem == "LDR":
            addr = self.eff_addr(ea, ops[1] if len(ops) >= 2 else "")
            if addr is None:
                self.set(dst, None); return
            self.set(dst, idc.get_qword(addr), src=addr); return
        # unmodelled -> destroy dest
        self.set(dst, None)

_FC_CACHE = {}

def _fc(f):
    k = f.start_ea
    fc = _FC_CACHE.get(k)
    if fc is None:
        fc = ida_gdl.FlowChart(f)
        _FC_CACHE[k] = fc
    return fc

def _block_of(fc, ea):
    for b in fc:
        if b.start_ea <= ea < b.end_ea:
            return b
    return None

def _pred_chain(blk, maxlen=4):
    """Straight-line predecessor blocks feeding `blk` unconditionally.
    A predecessor is chained only when it has EXACTLY one successor (so control
    flows into `blk` with no branch condition) and `blk` has exactly one
    predecessor — a sound linear extension, safe against the flattening
    dispatcher (which has many predecessors/successors). Returns blocks in
    execution order ending with `blk`."""
    chain = [blk]
    seen = {blk.id}
    cur = blk
    for _ in range(maxlen):
        preds = list(cur.preds())
        if len(preds) != 1:
            break
        p = preds[0]
        if p.id in seen or len(list(p.succs())) != 1:
            break
        chain.append(p); seen.add(p.id); cur = p
    chain.reverse()
    return chain

def emulate_to(ea):
    """Emulate up to (not incl.) `ea`, over the basic block containing `ea`
    plus any straight-line single-predecessor blocks feeding it.
    Returns (emu, ops_at_ea, mnem_at_ea) or (None, None, None)."""
    f = ida_funcs.get_func(ea)
    if not f:
        return None, None, None
    emu = Emu()
    try:
        fc = _fc(f)
        blk = _block_of(fc, ea)
    except Exception:
        blk = None
    if blk is None:
        blocks = [(max(ea - 240, f.start_ea), ea)]
    else:
        chain = _pred_chain(blk)
        blocks = []
        for b in chain:
            end = ea if b.id == blk.id else b.end_ea
            blocks.append((b.start_ea, end))
    for bs, be in blocks:
        cur = bs
        while cur != idaapi.BADADDR and cur < be:
            mnem = idc.print_insn_mnem(cur)
            dis = re.sub(r';.*$', '', idc.GetDisasm(cur)).strip()
            ops = _split_ops(dis[len(mnem):].strip()) if len(dis) > len(mnem) else []
            if ops and _parse_reg(ops[0]):
                pr = _parse_reg(ops[0])
                if pr[1] not in ('ZR', 'SP'):
                    emu.lastw[pr[1]] = (cur, mnem, ops)
            try:
                emu.step(cur, mnem, ops)
            except Exception:
                if ops:
                    emu.set(ops[0], None)
            cur = idc.next_head(cur, be)
    mnem = idc.print_insn_mnem(ea)
    dis = re.sub(r';.*$', '', idc.GetDisasm(ea)).strip()
    ops = _split_ops(dis[len(mnem):].strip()) if len(dis) > len(mnem) else []
    return emu, ops, mnem

def _classify_value(val, src):
    """Given a concrete BR-reg value and its load source addr, classify.
    Returns (idiom, info) or None."""
    if src is not None and TABLE_ADDR <= src < TABLE_ADDR + TABLE_SIZE * 8:
        col = (src - TABLE_ADDR) // 8
        tgt = idc.get_qword(TABLE_ADDR + col * 8)
        if _in_text(tgt) or tgt in IMPORTS:
            return (3, {"dispatch_col": col, "target": tgt})
        return None
    if val is not None and (_in_text(val) or val in IMPORTS):
        info = {"target": val}
        if src is not None:
            nm = idc.get_name(src)
            if nm:
                info["via"] = nm
        return (1, info)
    return None

# ---------------------------------------------------------------------------
# BR resolution
# ---------------------------------------------------------------------------
def resolve_brs(off_map, evidence, patch=False):
    c = {"idiom1": 0, "idiom2": 0, "idiom3": 0,
         "weak": 0, "loose": 0, "unresolved": 0, "patched": 0}
    total = 0
    for ea in _iter_insns(TEXT_START, TEXT_END):
        if idc.print_insn_mnem(ea) != "BR":
            continue
        total += 1
        emu, ops, _ = emulate_to(ea)
        reg = ops[0] if ops else None
        pr = _parse_reg(reg) if reg else None

        # --- idiom-2: BR reg last defined by a CSEL of two resolvable targets
        if emu is not None and pr and pr[1] not in ('ZR', 'SP') and pr[1] in emu.lastw:
            wea, wmnem, wops = emu.lastw[pr[1]]
            if wmnem in ("CSEL", "CSINC", "CSINV", "CSNEG") and len(wops) >= 3:
                arms = []
                for arm in (wops[1], wops[2]):
                    ap = _parse_reg(arm)
                    if not ap or ap[1] in ('ZR', 'SP'):
                        arms.append(None); continue
                    av = emu.get(arm); asrc = emu.src.get(ap[1])
                    arms.append(_classify_value(av, asrc))
                good = [a for a in arms if a and a[0] in (1, 3)]
                if len(good) == 2:
                    ta, tb = good[0][1]["target"], good[1][1]["target"]
                    idc.set_cmt(ea, "DexGuard 2-way CSEL BR -> %s / %s" % (
                        _target_name(ta), _target_name(tb)), 0)
                    evidence["%X" % ea] = {"idiom": 2, "target": "0x%X" % ta,
                                           "target_name": _target_name(ta),
                                           "target2": "0x%X" % tb,
                                           "target2_name": _target_name(tb)}
                    c["idiom2"] += 1
                    continue  # NEVER patch (lossy)
                if len(good) == 1:
                    t = good[0][1]["target"]
                    idc.set_cmt(ea, "DexGuard 2-way CSEL BR -> %s (one arm resolved)" % _target_name(t), 0)
                    evidence["%X" % ea] = {"idiom": 2, "partial": True,
                                           "target": "0x%X" % t, "target_name": _target_name(t)}
                    c["idiom2"] += 1
                    continue

        # --- idiom-3 / idiom-1: emulate the BR register directly
        if emu is not None and pr and pr[1] not in ('ZR', 'SP'):
            val = emu.get(reg); src = emu.src.get(pr[1])
            cls = _classify_value(val, src)
            if cls:
                idiom, info = cls
                if idiom == 3:
                    tgt = info["target"]; col = info["dispatch_col"]
                    idc.set_cmt(ea, "DexGuard dispatch off_126B90[%d] -> %s" % (col, _target_name(tgt)), 0)
                    evidence["%X" % ea] = {"idiom": 3, "dispatch_col": col,
                                           "target": "0x%X" % tgt, "target_name": _target_name(tgt)}
                    c["idiom3"] += 1
                    if patch and _in_text(tgt):
                        c["patched"] += _patch_br(ea, tgt)
                    continue
                else:
                    tgt = info["target"]
                    via = (" (via %s)" % info["via"]) if info.get("via") else ""
                    idc.set_cmt(ea, "DexGuard BR -> %s%s" % (_target_name(tgt), via), 0)
                    ev = {"idiom": 1, "target": "0x%X" % tgt, "target_name": _target_name(tgt)}
                    if info.get("via"):
                        ev["via"] = info["via"]
                    evidence["%X" % ea] = ev
                    c["idiom1"] += 1
                    if patch and _in_text(tgt):
                        c["patched"] += _patch_br(ea, tgt)
                    continue

        # --- fallback 1: weak dispatch resolve (linear identity)  [not patched]
        wc = _weak_dispatch(ea)
        if wc is not None:
            col, tgt = wc
            idc.set_cmt(ea, "DexGuard dispatch off_126B90[%d] -> %s [weak]" % (col, _target_name(tgt)), 0)
            evidence["%X" % ea] = {"idiom": 3, "weak": True, "dispatch_col": col,
                                   "target": "0x%X" % tgt, "target_name": _target_name(tgt)}
            c["weak"] += 1
            continue

        # --- fallback 2: first in-.text off_* ref in window  [not patched]
        loose = _loose_off(ea, off_map)
        if loose is not None:
            idc.set_cmt(ea, "DexGuard BR -> %s (via %s) [window-scan]" % (loose[2], loose[0]), 0)
            evidence["%X" % ea] = {"idiom": 1, "loose": True, "target": "0x%X" % loose[1],
                                   "target_name": loose[2], "via": loose[0]}
            c["loose"] += 1
            continue

        c["unresolved"] += 1
    return c, total

def _weak_dispatch(ea):
    """Fallback: window-scan qword key + additive imms through _mba_resolve."""
    scan = max(ea - 200, TEXT_START)
    has_disp = False; qw = None; consts = []
    insns = list(_iter_insns(scan, ea))
    for i, s in enumerate(insns):
        if "off_126B90" in (idc.GetDisasm(s) or ""):
            has_disp = True
        for ref in idautils.DataRefsFrom(s):
            if KEY_LO <= ref < KEY_HI:
                nm = idc.get_name(ref)
                if nm and nm.startswith("qword_"):
                    qw = ref
        if idc.print_insn_mnem(s) in ("MOV", "MOVZ"):
            ins = ida_ua.insn_t(); ida_ua.decode_insn(ins, s)
            if ins.ops[1].type == 5:
                v = ins.ops[1].value & M32
                if v != M32 and v > 0xFFFF:
                    reg = ins.ops[0].reg
                    for j in range(i + 1, min(i + 5, len(insns))):
                        if idc.print_insn_mnem(insns[j]) == "MOVK":
                            ins2 = ida_ua.insn_t(); ida_ua.decode_insn(ins2, insns[j])
                            if ins2.ops[0].reg == reg:
                                v = (v & 0xFFFF) | ((ins2.ops[1].value & 0xFFFF) << 16)
                                break
                    consts.append(v & M32)
    if has_disp and qw and consts:
        k32 = idc.get_qword(qw) & M32
        col = _mba_resolve(k32, consts, TABLE_SIZE)
        if col is not None:
            tgt = idc.get_qword(TABLE_ADDR + col * 8)
            if _in_text(tgt) or tgt in IMPORTS:
                return col, tgt
    return None

def _loose_off(ea, off_map):
    scan = max(ea - 200, TEXT_START)
    for s in _iter_insns(scan, ea):
        for ref in idautils.DataRefsFrom(s):
            if ref in off_map:
                o = off_map[ref]
                if _in_text(o[1]) or o[1] in IMPORTS:
                    return o
    return None

def _patch_br(ea, tgt):
    if tgt == ea or not _in_text(tgt):
        return 0
    delta = tgt - ea
    if delta % 4 != 0 or abs(delta) > 0x7FFFFFF:
        return 0
    ida_bytes.patch_dword(ea, (0x14000000 | ((delta >> 2) & 0x03FFFFFF)) & 0xFFFFFFFF)
    ida_xref.add_cref(ea, tgt, ida_xref.fl_JN)
    return 1

# ---------------------------------------------------------------------------
# SVC resolution (emulator-first: X8 holds the NR; weak resolve as fallback)
# ---------------------------------------------------------------------------
def resolve_svcs(evidence):
    resolved = weak = total = 0
    ea = TEXT_START
    while ea < TEXT_END:
        if idc.get_wide_dword(ea) == SVC_OPCODE:
            total += 1
            nr = _emu_svc_nr(ea)
            tag = ""
            if nr is None:
                nr = _weak_svc_nr(ea)
                if nr is not None:
                    tag = " [weak]"; weak += 1
            else:
                resolved += 1
            if nr is not None:
                name = SYSCALL_NAMES.get(nr, "sys_%d" % nr)
                idc.set_cmt(ea, "DexGuard svc NR=%d (%s)%s" % (nr, name, tag), 0)
                evidence["%X" % ea] = {"syscall": nr, "syscall_name": name,
                                       "weak": bool(tag)}
        ea += 4
    return resolved, weak, total

def _emu_svc_nr(ea):
    emu, _, _ = emulate_to(ea)
    if emu is None:
        return None
    v = emu.get("X8")
    if v is None:
        return None
    v &= M32
    return int(v) if 0 <= v < 512 else None

def _weak_svc_nr(ea):
    scan = max(ea - 160, TEXT_START)
    qw = None; consts = []
    for s in _iter_insns(scan, ea):
        for ref in idautils.DataRefsFrom(s):
            if KEY_LO <= ref < KEY_HI:
                nm = idc.get_name(ref)
                if nm and nm.startswith("qword_"):
                    qw = ref
        if idc.print_insn_mnem(s) in ("MOV", "MOVZ"):
            ins = ida_ua.insn_t(); ida_ua.decode_insn(ins, s)
            if ins.ops[1].type == 5:
                v = ins.ops[1].value
                if v and v != M32 and v != M64:
                    reg = ins.ops[0].reg
                    nxt = idc.next_head(s, ea)
                    if nxt != idaapi.BADADDR and idc.print_insn_mnem(nxt) == "MOVK":
                        ins2 = ida_ua.insn_t(); ida_ua.decode_insn(ins2, nxt)
                        if ins2.ops[0].reg == reg:
                            v = (v & 0xFFFF) | ((ins2.ops[1].value & 0xFFFF) << 16)
                    if v > 0xFF:
                        consts.append(v & M64)
    if qw and consts:
        k64 = idc.get_qword(qw); k32 = k64 & M32
        nr = _mba_resolve(k32, [x & M32 for x in consts], 512)
        if nr is None:
            neg64 = (-k64) & M64
            for x in consts:
                cand = (neg64 + x) & M64
                if cand < 512:
                    nr = int(cand); break
        return nr
    return None

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def run(patch=False):
    try:
        idaapi.auto_wait()
    except Exception:
        pass
    print("[dexguard] building off_* map ...")
    off_map = _build_off_map()
    print("[dexguard] off_* pointers: %d" % len(off_map))

    evidence = {}
    print("[dexguard] resolving BR sites%s ..." % (" (+patch)" if patch else ""))
    c, total_br = resolve_brs(off_map, evidence, patch=patch)
    print("[dexguard] resolving SVC sites ...")
    svc_res, svc_weak, svc_total = resolve_svcs(evidence)

    if patch:
        idc.plan_and_wait(TEXT_START, TEXT_END)
        try:
            idc.auto_wait()
        except Exception:
            pass

    resolved_br = c["idiom1"] + c["idiom2"] + c["idiom3"] + c["weak"] + c["loose"]
    print("[dexguard] BR: %d/%d resolved  (emu idiom1=%d idiom3=%d idiom2/CSEL=%d ; "
          "fallback weak=%d loose=%d ; unresolved=%d ; patched=%d)" % (
        resolved_br, total_br, c["idiom1"], c["idiom3"], c["idiom2"],
        c["weak"], c["loose"], c["unresolved"], c["patched"]))
    print("[dexguard] SVC: %d/%d resolved (emu=%d weak=%d)" % (
        svc_res + svc_weak, svc_total, svc_res, svc_weak))

    try:
        tools_dir = os.path.dirname(os.path.abspath(__file__))
    except NameError:
        tools_dir = os.path.dirname(os.path.abspath(idc.ARGV[0])) if idc.ARGV else os.getcwd()
    ev_dir = os.path.join(os.path.dirname(tools_dir), "evidence")
    if os.path.isdir(ev_dir):
        out = os.path.join(ev_dir, "dexguard_branches.json")
        with open(out, "w") as fh:
            json.dump({"image_base": 0, "text": [TEXT_START, TEXT_END],
                       "br_total": total_br, "svc_total": svc_total,
                       "counts": c, "svc_resolved": svc_res, "svc_weak": svc_weak,
                       "sites": evidence}, fh, indent=1)
        print("[dexguard] evidence sidecar -> %s (%d sites)" % (out, len(evidence)))
    else:
        print("[dexguard] no evidence/ dir next to tools/ (%s) -> sidecar skipped" % ev_dir)

    return c, total_br, svc_res, svc_weak, svc_total


if __name__ == "__main__":
    argv = list(idc.ARGV[1:]) if hasattr(idc, "ARGV") else []
    do_patch = "--patch" in argv
    run(patch=do_patch)
    try:
        # persist the annotations (and any patches) into the .i64 so a later
        # read-back run sees them
        idc.save_database("")
        print("[dexguard] database saved")
        import ida_pro
        ida_pro.qexit(0)
    except Exception:
        pass
