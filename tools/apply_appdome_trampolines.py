"""Annotate AppDome import-hiding trampolines in the open IDB.

WHAT THESE ARE
--------------
AppDome hides imports behind ~0x48-byte trampoline stubs. Each stub:

    BL   saver            ; save-context helper (sub_A381F8)
    STP  X0,X1 .. X29,X30 ; push volatile regs
    MOV  X0, #<id>        ; <-- unique 16-bit trampoline id (0..0xFFFF)
    BL   0x518894         ; shared resolver
    MOV  X9, X0           ; resolved target address
    LDP  ... (restore)
    BR   X9              ; jump to the real import

RESOLVER 0x518894  (characterised on samples/appdome.i64)
---------------------------------------------------------
    v1     = decrypted_name_blob + dword_C44230[id]   ; static offset table
    if (*v1 == '_') v1++                              ; skip leading underscore
    return dlsym(RTLD_DEFAULT(-2), v1)               ; <-- RUNTIME dlsym

So id -> TARGET ADDRESS is RUNTIME (dlsym; only exists at runtime).
The id -> SYMBOL NAME string lives in a STATIC but ENCRYPTED blob:
    ciphertext  : unk_B44210  (0x100000 bytes)
    32-byte key : ymmword_C44210
    16-byte IV  : xmmword_C84240
    offset tbl  : dword_C44230[id]  -> byte offset of the name in the blob
    cipher      : sub_39F330 + sub_2CB198 (-> 0x2CAB20), decrypted at runtime.

The name strings are therefore NOT plaintext statically. This tool does NOT
reimplement that cipher (doing so risks fabricating wrong names), so it
annotates every stub with its id + the static name-blob offset, and marks it
runtime-resolved. That is the honest static ceiling. Feeding a decrypted blob
back in later would let a follow-up pass fill the real names using the
per-id offset this tool already records.

USAGE (headless on an analysed copy):
  IDAUSR=... TVHEADLESS=1 idat -A -L<log> -S"apply_appdome_trampolines.py" copy.i64
or inside IDA:  exec(open('apply_appdome_trampolines.py').read())

__TEXT vmaddr==0 in these slices, so RVA == ea.
"""
import idc, ida_bytes, ida_xref, ida_name, ida_funcs, ida_ua, os, json

try:
    from ida_auto import auto_wait; auto_wait()
except Exception:
    pass

RESOLVER   = 0x518894      # shared dlsym resolver
OFFTBL     = 0xC44230      # dword_C44230[id] -> byte offset into (encrypted) name blob
ENC_BLOB   = 0xB44210      # unk_B44210, encrypted name strings
D_MOV_OFF  = -0x04         # MOV X0,#id is immediately before the BL resolver
D_ENTRY    = -0x24         # stub entry (BL saver) relative to BL resolver
D_BR       = +0x24         # BR X9 relative to BL resolver


def _mnem(ea):
    try:
        return (idc.print_insn_mnem(ea) or "").upper()
    except Exception:
        return ""


def apply():
    # 1) collect every code xref INTO the resolver == every trampoline BL site
    callers = []
    ea = ida_xref.get_first_cref_to(RESOLVER)
    while ea != idc.BADADDR:
        callers.append(ea)
        ea = ida_xref.get_next_cref_to(RESOLVER, ea)
    callers.sort()

    stubs = 0
    named = 0
    resolved_names = 0          # provable static names — 0 (blob is encrypted)
    skipped = 0
    records = []

    for c in callers:
        mov = idc.prev_head(c)
        # must be  MOV X0, #imm  directly feeding the resolver
        if mov == idc.BADADDR or _mnem(mov) != "MOV":
            skipped += 1
            continue
        # NB: for a register operand, get_operand_value returns the reg INDEX
        # (X0 == 129 in arm64), not 0 -> compare the printed operand instead.
        if idc.get_operand_type(mov, 0) != idc.o_reg or (idc.print_operand(mov, 0) or "").upper() != "X0":
            skipped += 1
            continue
        if idc.get_operand_type(mov, 1) != idc.o_imm:
            skipped += 1
            continue
        tid = idc.get_operand_value(mov, 1) & 0xFFFFFFFF

        # entry = first STP of the register-save block that precedes MOV X0.
        # (walk back over the pushes; stub0 also has an extra BL saver before them.)
        entry = mov
        p = idc.prev_head(mov)
        while p != idc.BADADDR and _mnem(p) == "STP":
            entry = p
            p = idc.prev_head(p)
        entry_ok = entry != mov
        br    = c + D_BR
        br_ok    = _mnem(br) == "BR"

        # static name-blob offset for this id (metadata for a future decrypt pass)
        off = ida_bytes.get_wide_dword(OFFTBL + tid * 4)
        off_s = "0x%X" % off if off != 0xFFFFFFFF else "?"

        cmt = ("AppDome import trampoline id=%d (runtime-resolved via dlsym @0x518894; "
               "name in ENCRYPTED tbl 0xB44210 off=%s)" % (tid, off_s))
        idc.set_cmt(mov, cmt, False)
        idc.set_cmt(c,   "AppDome resolver call id=%d -> dlsym (target address only at runtime)" % tid, False)
        if br_ok:
            idc.set_cmt(br, "AppDome trampoline BR id=%d (jumps to runtime dlsym target in X9)" % tid, False)

        if entry_ok:
            if ida_name.set_name(entry, "appdome_tramp_%d" % tid,
                                 ida_name.SN_NOWARN | ida_name.SN_FORCE):
                named += 1

        stubs += 1
        records.append({"id": tid, "mov_ea": "0x%X" % mov, "bl_ea": "0x%X" % c,
                        "br_ea": ("0x%X" % br) if br_ok else None,
                        "entry_ea": ("0x%X" % entry) if entry_ok else None,
                        "name_blob_off": ("0x%X" % off) if off != 0xFFFFFFFF else None,
                        "resolved_name": None})

    print("[appdome_tramp] resolver 0x%X: id->target is RUNTIME dlsym (names in ENCRYPTED static tbl)" % RESOLVER)
    print("[appdome_tramp] trampoline stubs annotated : %d" % stubs)
    print("[appdome_tramp]   with entry renamed        : %d" % named)
    print("[appdome_tramp]   with provable static name : %d  (blob is encrypted -> id-only)" % resolved_names)
    print("[appdome_tramp]   xref sites skipped (not a MOV X0,#imm stub) : %d" % skipped)

    # in-process self-verification: read back a spread of annotations
    print("[appdome_tramp] --- readback spot-checks ---")
    for r in (records[:1] + records[len(records)//2:len(records)//2+1] + records[-1:]):
        bl = int(r["bl_ea"], 16)
        print("[appdome_tramp]   id=%d bl=%s cmt=%r name=%r"
              % (r["id"], r["bl_ea"], idc.get_cmt(bl, False),
                 ida_name.get_name(int(r["entry_ea"], 16)) if r["entry_ea"] else None))

    # best-effort sidecar map for reuse / future decrypt pass
    try:
        outdir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "evidence")
        if os.path.isdir(outdir):
            outp = os.path.join(outdir, "appdome_trampolines.json")
            json.dump({"resolver": "0x518894", "id_to_target": "runtime_dlsym",
                       "name_table": {"encrypted_blob": "0xB44210", "offset_table": "0xC44230",
                                      "key": "0xC44210", "iv": "0xC84240",
                                      "cipher_fns": ["0x39F330", "0x2CB198->0x2CAB20"]},
                       "stub_count": stubs, "records": records}, open(outp, "w"), indent=1)
            print("[appdome_tramp] wrote %s" % outp)
    except Exception as e:
        print("[appdome_tramp] sidecar write skipped: %s" % e)

    return stubs, named, resolved_names


if __name__ == "__main__":
    apply()
    try:
        import ida_pro; ida_pro.qexit(0)
    except Exception:
        pass
