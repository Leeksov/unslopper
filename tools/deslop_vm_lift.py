#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
deslop_vm_lift.py -- runtime-assisted devirtualiser for the OLLVM-22 `vm` pass.

The `vm` pass compiles an entire function body into a private bytecode stream and
replaces the function with a fetch-decode-execute interpreter (`__vm_engine`) plus
a thin per-function wrapper and three per-function globals:

    @<fn>.vm.bytecode    [L x i8]           encrypted bytecode stream
    @<fn>.vm.ophandlers  [OP_COUNT x ptr]   permuted handler-address table
    @<fn>.vm.callees     [C x ptr]          callee function-pointer table

The ISA has 51 logical opcodes (OP_COUNT = 0x33), four typed register files
(i32 / i64 / f64 / ptr), variable-width little-endian encoding, and several
hardening layers.  This tool recovers the original logic as readable C-like
pseudocode.

--------------------------------------------------------------------------------
WHY RUNTIME-ASSISTED (READ THIS FIRST)
--------------------------------------------------------------------------------
The bytecode you can read statically in the binary is NOT directly decodable:

  * Layer 2b (useAES=1, the default) encrypts @<fn>.vm.bytecode with AES-128-CTR.
    The per-function AES key is generated from the compile-time RNG hierarchy and
    only ever materialises inside a `.init_array` constructor that runs before
    `main()`.  The key is not stored anywhere the static decoder can reach, so the
    plaintext bytecode ONLY exists in process memory after the ctor has run.

  * Layer 2a (useAES=0) uses an LCG keystream mixed with the load-time (ASLR)
    address of the global, so the transform differs on every process launch and
    likewise cannot be reproduced offline.

  * Layer 5 (antiDebug=1, active only with hardened=1) corrupts the salt via an
    RDTSC timing gate.  Under a debugger the salt can be poisoned, so register
    indices deobfuscate to the WRONG slots and execution silently misbehaves.
    Dump the salt from a NON-time-dilated run (Frida with a well-behaved
    interpreter loop, or a hardware target) and prefer hooking `__vm_engine`
    entry over single-stepping.

Consequently this tool is split into runtime and offline stages:

    locate()   IDA/static  -- find __vm_engine, wrappers, and the 3 globals.
    dump()     runtime      -- read decrypted bytecode + salt + regkeys from a
                              live process (Frida snippet or IDA debugger) into a
                              JSON sidecar.
    decode()   offline      -- full ISA decode of the dumped bytecode using the
                              recovered permutation + salt.
    lift()     offline      -- emit C-like pseudocode from the decoded stream.

`decode` and `lift` run fully offline from the sidecar; `locate` and `dump`
require IDA (or a live process for the Frida path).

--------------------------------------------------------------------------------
LIMITS / CAVEATS
--------------------------------------------------------------------------------
  * AES key lives in .init_array -> plaintext bytecode is runtime-only (see above).
  * antiDebug salt corruption -> dump salt carefully, avoid single-stepping.
  * regEncrypt (layer 3) encrypts register VALUES, not the bytecode; it does not
    affect static decoding of the instruction stream, but the lifted pseudocode's
    runtime register contents would be XORed by regkeys[slot].  The regkey tables
    are dumped for completeness and annotated in the lift output.
  * Opcode permutation is per-function; the physical->logical map must be rebuilt
    per function from its @<fn>.vm.ophandlers table (reverse_permutation()).
  * Handler->logical identification (guess_handler_map) is a best-effort heuristic
    on the shared engine; verify/patch it once, then it is reused for all funcs.
"""

from __future__ import annotations

import argparse
import binascii
import json
import struct
import sys

# ---------------------------------------------------------------------------
# Optional IDA imports.  The module is import-safe without IDA so that the
# decode/lift stages can run under a plain python3 interpreter.
# ---------------------------------------------------------------------------
try:  # pragma: no cover - environment dependent
    import idaapi  # noqa: F401
    import idautils
    import idc
    import ida_bytes
    import ida_name
    import ida_funcs
    import ida_dbg
    import ida_ida
    _HAVE_IDA = True
except Exception:  # noqa: BLE001
    _HAVE_IDA = False


# ===========================================================================
# ISA definition (from docs/ollvm22_vm_spec.md)
# ===========================================================================

OP_COUNT = 0x33  # 51 logical opcodes

# Logical opcode value -> mnemonic.
OP_NAMES = {
    0x00: "OP_LOADI",       0x01: "OP_MOVR",        0x02: "OP_BINOP",
    0x03: "OP_ICMP",        0x04: "OP_CAST",        0x05: "OP_PTRTOINT",
    0x06: "OP_INTTOPTR",    0x07: "OP_LOAD32",      0x08: "OP_STORE32",
    0x09: "OP_GEP",         0x0A: "OP_JMP",         0x0B: "OP_JMPC",
    0x0C: "OP_RET_VOID",    0x0D: "OP_RET_INT",     0x0E: "OP_RET_PTR",
    0x0F: "OP_CALL_VOID",   0x10: "OP_CALL_INT",    0x11: "OP_CALL_PTR",
    0x12: "OP_SELECT",      0x13: "OP_PTRTOINT64",  0x14: "OP_LOAD64",
    0x15: "OP_STORE64",     0x16: "OP_CAST64",      0x17: "OP_BINOP64",
    0x18: "OP_SWITCH",      0x19: "OP_GEP64",       0x1A: "OP_ICMP64",
    0x1B: "OP_LOAD8",       0x1C: "OP_STORE8",      0x1D: "OP_LOAD16",
    0x1E: "OP_STORE16",     0x1F: "OP_LOADPTR",     0x20: "OP_STOREPTR",
    0x21: "OP_LOADI_F",     0x22: "OP_MOVR_F",      0x23: "OP_BINOP_F",
    0x24: "OP_FCMP",        0x25: "OP_FCAST_FF",    0x26: "OP_LOAD_F",
    0x27: "OP_STORE_F",     0x28: "OP_RET_F",       0x29: "OP_SELECT_F",
    0x2A: "OP_CALL_INT64",  0x2B: "OP_CALL_F",      0x2C: "OP_FNEG",
    0x2D: "OP_LOAD_F32",    0x2E: "OP_STORE_F32",   0x2F: "OP_FCAST_FV",
    0x30: "OP_FCAST_FV64",  0x31: "OP_FCAST_VF",    0x32: "OP_FCAST_V64F",
}
NAME_TO_OP = {v: k for k, v in OP_NAMES.items()}

# Register files.
F_I32, F_I64, F_F64, F_PTR = "i32", "i64", "f64", "ptr"
REG_PREFIX = {F_I32: "r", F_I64: "q", F_F64: "f", F_PTR: "p", None: "v"}

# Field kinds used by the fixed-layout encoding table.
#   ("name", "reg", file)  register-index byte (subject to layer-1 salt XOR)
#   ("name", "u8", None)   raw byte (subop/kind/pred/flags/nargs/...)
#   ("name", "u16", None)  2-byte little-endian
#   ("name", "i32", None)  4-byte little-endian signed immediate
#   ("name", "u32", None)  4-byte little-endian bytecode offset (branch target)
#   ("name", "f64", None)  8-byte little-endian IEEE-754 double immediate
#
# Opcodes with a data-dependent length (OP_SWITCH and the five call opcodes) are
# NOT in this table; they are handled explicitly in decode().
FIXED_ENC = {
    0x00: [("dst", "reg", F_I32), ("imm", "i32", None)],
    0x01: [("dst", "reg", F_I32), ("src", "reg", F_I32)],
    0x02: [("dst", "reg", F_I32), ("a", "reg", F_I32), ("b", "reg", F_I32), ("subop", "u8", None)],
    0x03: [("dst", "reg", F_I32), ("a", "reg", F_I32), ("b", "reg", F_I32), ("pred", "u8", None)],
    0x04: [("dst", "reg", F_I32), ("src", "reg", F_I32), ("kind", "u8", None)],
    0x05: [("dst", "reg", F_I32), ("srcp", "reg", F_PTR)],
    0x06: [("dstp", "reg", F_PTR), ("src", "reg", F_I32)],
    0x07: [("dst", "reg", F_I32), ("ptrreg", "reg", F_PTR)],
    0x08: [("val", "reg", F_I32), ("ptrreg", "reg", F_PTR)],
    0x09: [("dstp", "reg", F_PTR), ("basep", "reg", F_PTR), ("idx", "reg", F_I32), ("elemsz", "u16", None)],
    0x0A: [("target", "u32", None)],
    0x0B: [("cond", "reg", F_I32), ("tgt_t", "u32", None), ("tgt_f", "u32", None)],
    0x0C: [],
    0x0D: [("src", "reg", F_I32)],
    0x0E: [("srcp", "reg", F_PTR)],
    # 0x0F..0x11 calls -> variable
    0x12: [("kind", "u8", None), ("dst", "reg", None), ("cond", "reg", F_I32),
           ("t", "reg", None), ("f", "reg", None)],
    0x13: [("dst64", "reg", F_I64), ("srcp", "reg", F_PTR)],
    0x14: [("dst64", "reg", F_I64), ("ptrreg", "reg", F_PTR)],
    0x15: [("val64", "reg", F_I64), ("ptrreg", "reg", F_PTR)],
    0x16: [("dst", "reg", None), ("src", "reg", None), ("kind", "u8", None)],  # files resolved from kind
    0x17: [("dst64", "reg", F_I64), ("a64", "reg", F_I64), ("b64", "reg", F_I64), ("subop", "u8", None)],
    # 0x18 switch -> variable
    0x19: [("dstp", "reg", F_PTR), ("basep", "reg", F_PTR), ("idx64", "reg", F_I64), ("elemsz", "u16", None)],
    0x1A: [("dst", "reg", F_I32), ("a64", "reg", F_I64), ("b64", "reg", F_I64), ("pred", "u8", None)],
    0x1B: [("dst", "reg", F_I32), ("ptrreg", "reg", F_PTR)],
    0x1C: [("val", "reg", F_I32), ("ptrreg", "reg", F_PTR)],
    0x1D: [("dst", "reg", F_I32), ("ptrreg", "reg", F_PTR)],
    0x1E: [("val", "reg", F_I32), ("ptrreg", "reg", F_PTR)],
    0x1F: [("dstp", "reg", F_PTR), ("ptrreg", "reg", F_PTR)],
    0x20: [("valp", "reg", F_PTR), ("ptrreg", "reg", F_PTR)],
    0x21: [("dst", "reg", F_F64), ("imm", "f64", None)],
    0x22: [("dst", "reg", F_F64), ("src", "reg", F_F64)],
    0x23: [("dst", "reg", F_F64), ("a", "reg", F_F64), ("b", "reg", F_F64), ("subop", "u8", None)],
    0x24: [("dst", "reg", F_I32), ("a", "reg", F_F64), ("b", "reg", F_F64), ("pred", "u8", None)],
    0x25: [("dst_fr", "reg", F_F64), ("src_fr", "reg", F_F64), ("kind", "u8", None)],
    0x26: [("dst", "reg", F_F64), ("ptrreg", "reg", F_PTR)],
    0x27: [("val", "reg", F_F64), ("ptrreg", "reg", F_PTR)],
    0x28: [("src", "reg", F_F64)],
    0x29: [("dst", "reg", F_F64), ("cond", "reg", F_I32), ("t", "reg", F_F64), ("f", "reg", F_F64)],
    # 0x2A..0x2B calls -> variable
    0x2C: [("dst_fr", "reg", F_F64), ("src_fr", "reg", F_F64)],
    0x2D: [("dst", "reg", F_F64), ("ptrreg", "reg", F_PTR)],
    0x2E: [("val", "reg", F_F64), ("ptrreg", "reg", F_PTR)],
    0x2F: [("dst", "reg", F_I32), ("src", "reg", F_F64), ("kind", "u8", None)],
    0x30: [("dst64", "reg", F_I64), ("src", "reg", F_F64), ("kind", "u8", None)],
    0x31: [("dst", "reg", F_F64), ("src", "reg", F_I32), ("kind", "u8", None)],
    0x32: [("dst", "reg", F_F64), ("src64", "reg", F_I64), ("kind", "u8", None)],
}

# Call opcodes and their return-register file (None = void, no dst byte).
CALL_OPS = {
    0x0F: None,     # OP_CALL_VOID
    0x10: F_I32,    # OP_CALL_INT   -> dst   vreg
    0x11: F_PTR,    # OP_CALL_PTR   -> dstp  preg
    0x2A: F_I64,    # OP_CALL_INT64 -> dst64 vreg64
    0x2B: F_F64,    # OP_CALL_F     -> dstf  freg
}

SWITCH_OP = 0x18

# Sub-opcode tables.
BINSUBOP = {
    0: "+", 1: "-", 2: "*", 3: "&", 4: "|", 5: "^", 6: "<<", 7: ">>u",
    8: ">>s", 9: "/s", 10: "/u", 11: "%s", 12: "%u",
}
BINSUBOP_NAME = {
    0: "BS_ADD", 1: "BS_SUB", 2: "BS_MUL", 3: "BS_AND", 4: "BS_OR", 5: "BS_XOR",
    6: "BS_SHL", 7: "BS_LSHR", 8: "BS_ASHR", 9: "BS_SDIV", 10: "BS_UDIV",
    11: "BS_SREM", 12: "BS_UREM",
}

FBINSUBOP = {0: "+", 1: "-", 2: "*", 3: "/", 4: "frem"}
FBINSUBOP_NAME = {0: "FBS_FADD", 1: "FBS_FSUB", 2: "FBS_FMUL", 3: "FBS_FDIV", 4: "FBS_FREM"}
FBS_F32_FLAG = 0x80

CASTKIND = {
    0: "zext_i1_i32", 1: "zext_i8_i32", 2: "zext_i16_i32",
    3: "sext_i8_i32", 4: "sext_i16_i32",
    5: "trunc_i32_i1", 6: "trunc_i32_i8", 7: "trunc_i32_i16",
}

# Cast64Kind: values 0-3 zext (src i32 -> dst i64), 4-6 sext (src i32 -> dst i64),
# 7-10 trunc (src i64 -> dst i32).
CAST64KIND = {
    0: "zext_i1_i64", 1: "zext_i8_i64", 2: "zext_i16_i64", 3: "zext_i32_i64",
    4: "sext_i8_i64", 5: "sext_i16_i64", 6: "sext_i32_i64",
    7: "trunc_i64_i1", 8: "trunc_i64_i8", 9: "trunc_i64_i16", 10: "trunc_i64_i32",
}
# For OP_CAST64, which side is i64 vs i32 depends on the kind.
CAST64_DST_I64 = set(range(0, 7))   # 0..6 produce an i64 dst from an i32 src
CAST64_DST_I32 = set(range(7, 11))  # 7..10 produce an i32 dst from an i64 src

FCASTKIND = {
    0: "fpext", 1: "fptrunc", 2: "fptosi", 3: "fptoui", 4: "sitofp",
    5: "uitofp", 6: "fptosi64", 7: "fptoui64", 8: "si64tofp", 9: "ui64tofp",
}

# LLVM CmpInst predicate byte values.
ICMP_PRED = {
    32: "==", 33: "!=", 34: ">u", 35: ">=u", 36: "<u", 37: "<=u",
    38: ">s", 39: ">=s", 40: "<s", 41: "<=s",
}
FCMP_PRED = {
    0: "false", 1: "oeq", 2: "ogt", 3: "oge", 4: "olt", 5: "ole", 6: "one",
    7: "ord", 8: "uno", 9: "ueq", 10: "ugt", 11: "uge", 12: "ult", 13: "ule",
    14: "une", 15: "true",
}

# Call argument category codes (2 bits per argument, packed little-endian).
CAT_FILE = {0: F_I32, 1: F_PTR, 2: F_I64, 3: F_F64}
CF_NONE = 0x00
CF_VARARG = 0x01

# Names for the three per-function globals.
G_BYTECODE = ".vm.bytecode"
G_OPHANDLERS = ".vm.ophandlers"
G_CALLEES = ".vm.callees"
ENGINE_NAME = "__vm_engine"


# ===========================================================================
# Low-level byte readers
# ===========================================================================

def _u8(bc, i):
    return bc[i]


def _u16(bc, i):
    return bc[i] | (bc[i + 1] << 8)


def _i32(bc, i):
    return struct.unpack_from("<i", bc, i)[0]


def _u32(bc, i):
    return struct.unpack_from("<I", bc, i)[0]


def _f64(bc, i):
    return struct.unpack_from("<d", bc, i)[0]


# ===========================================================================
# Stage 3: reverse_permutation
# ===========================================================================

def reverse_permutation(ophandlers, handler_logical_map):
    """Build the physical->logical and logical->physical opcode maps.

    ``@<fn>.vm.ophandlers`` is indexed by *physical* opcode byte; each entry is
    the address of the handler basic block in ``__vm_engine`` that implements the
    logical opcode.  Once we know, for the shared engine, which handler address
    implements which logical VMOp (see :func:`guess_handler_map` for the
    heuristic, or supply it by hand), the permutation is just a table lookup.

    Parameters
    ----------
    ophandlers : list[int]
        The OP_COUNT handler-block addresses, in physical index order (i.e.
        ``ophandlers[physical_byte] == handler_addr``).
    handler_logical_map : dict[int, int]
        ``handler_addr -> logical_opcode``.  Shared across all functions in a
        module because ``__vm_engine`` is emitted once.

    Returns
    -------
    (p2l, l2p) : (dict[int,int], dict[int,int])
    """
    p2l, l2p = {}, {}
    hlm = {int(k): int(v) for k, v in handler_logical_map.items()}
    for physical, addr in enumerate(ophandlers):
        addr = int(addr)
        if addr not in hlm:
            raise KeyError(
                "handler address 0x%x (physical opcode %d) is not in the "
                "handler->logical map; run guess_handler_map or fill it in "
                "the sidecar under 'handler_logical_map'." % (addr, physical))
        logical = hlm[addr]
        p2l[physical] = logical
        l2p[logical] = physical
    return p2l, l2p


def _undo_reg_xor(slot, salt, obf_reg_idx):
    """Layer-1 recovery: real_slot = bytecode_slot ^ (salt & 0xFF)."""
    if obf_reg_idx:
        return slot ^ (salt & 0xFF)
    return slot


# ===========================================================================
# Stage 4: decode  (the complete ISA decoder)
# ===========================================================================

def decode(bytecode, p2l=None, salt=0, obf_reg_idx=True, layer2="aes"):
    """Decode a (load-time-decrypted) bytecode stream into a list of instructions.

    Parameters
    ----------
    bytecode : bytes | bytearray
        The bytecode as it exists in process memory AFTER the .init_array
        decryption constructor has run (see :func:`dump`).  For ``useAES=1`` and
        the unencrypted case this is already the plaintext instruction stream.
    p2l : dict[int,int] | None
        physical-byte -> logical-opcode map (from :func:`reverse_permutation`).
        If ``None`` the physical byte is assumed to already equal the logical
        opcode (i.e. no permutation).
    salt : int
        The full 32-bit runtime salt (from :func:`dump`).  ``salt & 0xFF`` undoes
        the layer-1 register-index XOR; the full value drives the layer-2a
        opcode-byte XOR.
    obf_reg_idx : bool
        Whether layer-1 register-index XOR is active (default on).
    layer2 : {"aes", "none", "lcg"}
        ``aes``/``none`` -> the in-memory bytecode is plaintext; opcode byte is
        used as-is.  ``lcg`` -> each fetched opcode byte is additionally XORed
        with ``(salt ^ ip) & 0xFF`` at dispatch time (layer 2a).  NOTE: under LCG
        the whole-array keystream must already have been reversed in the dump;
        this decoder only replays the per-opcode dispatch XOR.

    Returns
    -------
    list[dict]
        One dict per instruction, each with at least ``off``, ``op``, ``opname``,
        ``length``, and opcode-specific operand fields.  Register operands are
        recorded as ``(file, slot)`` tuples under their field name.
    """
    bc = bytes(bytecode)
    n = len(bc)

    def logical_of(raw_opc, ip):
        phys = raw_opc
        if layer2 == "lcg":
            phys = raw_opc ^ ((salt ^ ip) & 0xFF)
        if p2l is not None:
            if phys not in p2l:
                raise ValueError(
                    "physical opcode 0x%02x at ip %d has no permutation entry" % (phys, ip))
            return p2l[phys]
        return phys

    def reg(slot, file):
        return (file, _undo_reg_xor(slot, salt, obf_reg_idx))

    out = []
    ip = 0
    while ip < n:
        off = ip
        raw = bc[ip]
        op = logical_of(raw, ip)
        name = OP_NAMES.get(op, "OP_UNK_0x%02x" % op)
        ins = {"off": off, "op": op, "opname": name, "raw_opc": raw}
        p = ip + 1  # cursor past the opcode byte

        if op in CALL_OPS:
            # opc [dst:u8] fn:u8 nargs:u8 flags:u8 argtypes:u16le [arg:u8]*nargs
            ret_file = CALL_OPS[op]
            if ret_file is not None:
                ins["dst"] = reg(_u8(bc, p), ret_file)
                p += 1
            fn = _u8(bc, p); p += 1
            nargs = _u8(bc, p); p += 1
            flags = _u8(bc, p); p += 1
            argtypes = _u16(bc, p); p += 2
            args = []
            for k in range(nargs):
                cat = (argtypes >> (2 * k)) & 0x3
                afile = CAT_FILE[cat]
                args.append(reg(_u8(bc, p), afile))
                p += 1
            ins["fn"] = fn
            ins["nargs"] = nargs
            ins["flags"] = flags
            ins["vararg"] = bool(flags & CF_VARARG)
            ins["args"] = args
            ins["length"] = p - off
            out.append(ins)
            ip = p
            continue

        if op == SWITCH_OP:
            # opc cond:u8 ncases:u16le def:u32le [case:u32le tgt:u32le]*ncases
            ins["cond"] = reg(_u8(bc, p), F_I32); p += 1
            ncases = _u16(bc, p); p += 2
            ins["default"] = _u32(bc, p); p += 4
            cases = []
            for _ in range(ncases):
                cval = _i32(bc, p); p += 4
                tgt = _u32(bc, p); p += 4
                cases.append((cval, tgt))
            ins["ncases"] = ncases
            ins["cases"] = cases
            ins["length"] = p - off
            out.append(ins)
            ip = p
            continue

        # Fixed-layout opcode.
        fields = FIXED_ENC.get(op)
        if fields is None:
            raise ValueError("no encoding for logical opcode 0x%02x at ip %d" % (op, off))

        # OP_CAST64 files depend on the kind byte, which is last; peek it first.
        cast64_kind = None
        if op == 0x16:
            cast64_kind = _u8(bc, p + 2)

        for (fname, kind, file) in fields:
            if kind == "reg":
                rfile = file
                if op == 0x16 and fname in ("dst", "src"):
                    if cast64_kind in CAST64_DST_I64:
                        rfile = F_I64 if fname == "dst" else F_I32
                    else:  # trunc: dst i32, src i64
                        rfile = F_I32 if fname == "dst" else F_I64
                ins[fname] = reg(_u8(bc, p), rfile); p += 1
            elif kind == "u8":
                ins[fname] = _u8(bc, p); p += 1
            elif kind == "u16":
                ins[fname] = _u16(bc, p); p += 2
            elif kind == "i32":
                ins[fname] = _i32(bc, p); p += 4
            elif kind == "u32":
                ins[fname] = _u32(bc, p); p += 4
            elif kind == "f64":
                ins[fname] = _f64(bc, p); p += 8
            else:  # pragma: no cover
                raise ValueError("unknown field kind %r" % kind)

        ins["length"] = p - off
        out.append(ins)
        ip = p

    return out


def branch_targets(ins):
    """Return the set of bytecode offsets referenced as branch targets by ``ins``."""
    tgts = set()
    op = ins["op"]
    if op == 0x0A:  # JMP
        tgts.add(ins["target"])
    elif op == 0x0B:  # JMPC
        tgts.add(ins["tgt_t"])
        tgts.add(ins["tgt_f"])
    elif op == SWITCH_OP:
        tgts.add(ins["default"])
        for _, t in ins["cases"]:
            tgts.add(t)
    return tgts


_TERMINATORS = {0x0A, 0x0B, 0x18, 0x0C, 0x0D, 0x0E, 0x28}  # jmp/jmpc/switch/ret*


# ===========================================================================
# Stage 5: lift  (emit C-like pseudocode)
# ===========================================================================

def _rname(rt):
    file, slot = rt
    return REG_PREFIX.get(file, "v") + str(slot)


def _callee_name(idx, callees):
    if callees and 0 <= idx < len(callees):
        c = callees[idx]
        if isinstance(c, str) and c:
            return c
        return "sub_%X" % int(c) if isinstance(c, int) else "callee[%d]" % idx
    return "callee[%d]" % idx


def _render_insn(ins, callees):
    op = ins["op"]
    nm = ins["opname"]

    def r(f):
        return _rname(ins[f])

    if op == 0x00:  # LOADI
        return "%s = %d;  /* 0x%x */" % (r("dst"), ins["imm"], ins["imm"] & 0xFFFFFFFF)
    if op == 0x21:  # LOADI_F
        return "%s = %r;" % (r("dst"), ins["imm"])
    if op in (0x01, 0x22):  # MOVR / MOVR_F
        return "%s = %s;" % (r("dst"), r("src"))
    if op in (0x02, 0x17):  # BINOP / BINOP64
        return "%s = %s %s %s;" % (r("dst" if op == 0x02 else "dst64"),
                                   r("a" if op == 0x02 else "a64"),
                                   BINSUBOP.get(ins["subop"], "bs%d" % ins["subop"]),
                                   r("b" if op == 0x02 else "b64"))
    if op == 0x23:  # BINOP_F
        sub = ins["subop"] & 0x7F
        f32 = " /*f32*/" if ins["subop"] & FBS_F32_FLAG else ""
        oper = FBINSUBOP.get(sub, "fbs%d" % sub)
        if sub == 4:
            return "%s = frem(%s, %s);%s" % (r("dst"), r("a"), r("b"), f32)
        return "%s = %s %s %s;%s" % (r("dst"), r("a"), oper, r("b"), f32)
    if op == 0x03:  # ICMP
        return "%s = (%s %s %s);" % (r("dst"), r("a"),
                                     ICMP_PRED.get(ins["pred"], "icmp%d" % ins["pred"]), r("b"))
    if op == 0x1A:  # ICMP64
        return "%s = (%s %s %s);" % (r("dst"), r("a64"),
                                     ICMP_PRED.get(ins["pred"], "icmp%d" % ins["pred"]), r("b64"))
    if op == 0x24:  # FCMP
        return "%s = fcmp_%s(%s, %s);" % (r("dst"),
                                          FCMP_PRED.get(ins["pred"], "p%d" % ins["pred"]),
                                          r("a"), r("b"))
    if op == 0x04:  # CAST
        return "%s = %s(%s);" % (r("dst"), CASTKIND.get(ins["kind"], "ck%d" % ins["kind"]), r("src"))
    if op == 0x16:  # CAST64
        return "%s = %s(%s);" % (r("dst"), CAST64KIND.get(ins["kind"], "c64k%d" % ins["kind"]), r("src"))
    if op in (0x25, 0x2F, 0x30, 0x31, 0x32):  # FCAST_*
        srcf = "src_fr" if op == 0x25 else ("src64" if op == 0x32 else "src")
        dstf = "dst_fr" if op == 0x25 else ("dst64" if op == 0x30 else "dst")
        return "%s = %s(%s);" % (r(dstf), FCASTKIND.get(ins["kind"], "fk%d" % ins["kind"]), r(srcf))
    if op == 0x2C:  # FNEG
        return "%s = -%s;" % (r("dst_fr"), r("src_fr"))
    if op == 0x05:  # PTRTOINT
        return "%s = (i32)(uintptr_t)%s;" % (r("dst"), r("srcp"))
    if op == 0x13:  # PTRTOINT64
        return "%s = (i64)(uintptr_t)%s;" % (r("dst64"), r("srcp"))
    if op == 0x06:  # INTTOPTR
        return "%s = (ptr)%s;" % (r("dstp"), r("src"))
    if op in (0x07, 0x1B, 0x1D, 0x14, 0x1F, 0x26, 0x2D):  # loads
        szmap = {0x07: "i32", 0x1B: "i8", 0x1D: "i16", 0x14: "i64",
                 0x1F: "ptr", 0x26: "f64", 0x2D: "f32"}
        dstf = "dst64" if op == 0x14 else ("dstp" if op == 0x1F else "dst")
        return "%s = *(%s*)%s;" % (r(dstf), szmap[op], r("ptrreg"))
    if op in (0x08, 0x1C, 0x1E, 0x15, 0x20, 0x27, 0x2E):  # stores
        szmap = {0x08: "i32", 0x1C: "i8", 0x1E: "i16", 0x15: "i64",
                 0x20: "ptr", 0x27: "f64", 0x2E: "f32"}
        valf = "val64" if op == 0x15 else ("valp" if op == 0x20 else "val")
        return "*(%s*)%s = %s;" % (szmap[op], r("ptrreg"), r(valf))
    if op == 0x09:  # GEP
        return "%s = %s + %s * %d;" % (r("dstp"), r("basep"), r("idx"), ins["elemsz"])
    if op == 0x19:  # GEP64
        return "%s = %s + %s * %d;" % (r("dstp"), r("basep"), r("idx64"), ins["elemsz"])
    if op in (0x12, 0x29):  # SELECT / SELECT_F
        knote = " /* kind=%d */" % ins["kind"] if op == 0x12 else ""
        return "%s = %s ? %s : %s;%s" % (r("dst"), r("cond"), r("t"), r("f"), knote)
    if op == 0x0A:  # JMP
        return "goto L_%04x;" % ins["target"]
    if op == 0x0B:  # JMPC
        return "if (%s) goto L_%04x; else goto L_%04x;" % (r("cond"), ins["tgt_t"], ins["tgt_f"])
    if op == SWITCH_OP:
        parts = ["switch (%s) {" % r("cond")]
        for cval, tgt in ins["cases"]:
            parts.append("        case %d: goto L_%04x;" % (cval, tgt))
        parts.append("        default: goto L_%04x;" % ins["default"])
        parts.append("    }")
        return "\n    ".join(parts)
    if op == 0x0C:  # RET_VOID
        return "return;"
    if op == 0x0D:  # RET_INT
        return "return %s;" % r("src")
    if op == 0x0E:  # RET_PTR
        return "return %s;" % r("srcp")
    if op == 0x28:  # RET_F
        return "return %s;" % r("src")
    if op in CALL_OPS:
        arglist = ", ".join(_rname(a) for a in ins["args"])
        va = ", ..." if ins["vararg"] else ""
        callexpr = "%s(%s%s)" % (_callee_name(ins["fn"], callees), arglist, va)
        if CALL_OPS[op] is None:
            return "%s;" % callexpr
        return "%s = %s;" % (r("dst"), callexpr)
    return "/* unhandled %s */" % nm


def lift(insns, callees=None, func_name="vm_func", regkeys_note=None):
    """Emit readable C-like pseudocode for a decoded instruction list.

    Blocks are formed at branch targets and fall-through boundaries; each block
    gets an ``L_<offset>:`` label.
    """
    by_off = {i["off"]: i for i in insns}
    offs = sorted(by_off)

    leaders = {offs[0]} if offs else set()
    for idx, o in enumerate(offs):
        ins = by_off[o]
        for t in branch_targets(ins):
            leaders.add(t)
        if ins["op"] in _TERMINATORS and idx + 1 < len(offs):
            leaders.add(offs[idx + 1])
    leaders = {o for o in leaders if o in by_off}

    lines = []
    lines.append("/* devirtualised %s (%d bytecode instructions) */" % (func_name, len(insns)))
    if regkeys_note:
        lines.append("/* %s */" % regkeys_note)
    lines.append("void %s(void) {" % func_name)
    for o in offs:
        ins = by_off[o]
        if o in leaders:
            lines.append("L_%04x:" % o)
        body = _render_insn(ins, callees)
        for j, sub in enumerate(body.split("\n")):
            lines.append(("    " if j == 0 else "") + sub if j == 0 else sub)
    lines.append("}")
    return "\n".join(lines)


# ===========================================================================
# Stage 1: locate  (IDA)
# ===========================================================================

def _require_ida():
    if not _HAVE_IDA:
        raise RuntimeError(
            "this stage requires IDAPython (idaapi/idautils/idc). Run it inside "
            "IDA, or use the offline decode/lift stages on a sidecar JSON.")


def _read_ptr(ea):
    if ida_ida.inf_is_64bit():
        return ida_bytes.get_qword(ea)
    return ida_bytes.get_dword(ea)


def _ptr_size():
    return 8 if ida_ida.inf_is_64bit() else 4


def locate(engine_name=ENGINE_NAME):
    """Locate ``__vm_engine`` and every per-function VM wrapper + its globals.

    Returns
    -------
    dict
        {
          "engine_ea": int | None,
          "functions": [
             {"name", "bytecode_ea", "bytecode_len", "ophandlers_ea",
              "ophandlers": [addr,...], "callees_ea", "callees": [addr,...],
              "wrapper_ea": int | None}
          ]
        }
    """
    _require_ida()

    engine_ea = ida_name.get_name_ea(idaapi.BADADDR, engine_name)
    if engine_ea == idaapi.BADADDR:
        engine_ea = None
        # Heuristic fallback: a single module fn with ~OP_COUNT jump-table targets
        # and an indirect dispatch. Left to guess_handler_map / manual review.

    # Group the three per-function globals by their <fn> prefix.
    prefixes = {}

    def _stem(nm, suffix):
        # names look like "<fn>.vm.bytecode" (possibly mangled/underscored)
        if nm.endswith(suffix):
            return nm[: -len(suffix)]
        return None

    for ea, nm in idautils.Names():
        for suf, key in ((G_BYTECODE, "bytecode"),
                         (G_OPHANDLERS, "ophandlers"),
                         (G_CALLEES, "callees")):
            stem = _stem(nm, suf)
            if stem is not None:
                prefixes.setdefault(stem, {})[key] = ea
                break

    functions = []
    psize = _ptr_size()
    for stem, gmap in sorted(prefixes.items()):
        entry = {"name": stem, "wrapper_ea": None}

        bc_ea = gmap.get("bytecode")
        entry["bytecode_ea"] = bc_ea
        entry["bytecode_len"] = _global_len(bc_ea) if bc_ea is not None else None

        oh_ea = gmap.get("ophandlers")
        entry["ophandlers_ea"] = oh_ea
        entry["ophandlers"] = (
            [_read_ptr(oh_ea + i * psize) for i in range(OP_COUNT)]
            if oh_ea is not None else [])

        ce_ea = gmap.get("callees")
        entry["callees_ea"] = ce_ea
        if ce_ea is not None:
            clen = _global_len(ce_ea)
            n = (clen // psize) if clen else 0
            entry["callees"] = [_read_ptr(ce_ea + i * psize) for i in range(n)]
        else:
            entry["callees"] = []

        # Wrapper is the function whose name equals the demangled stem, if present.
        w = ida_name.get_name_ea(idaapi.BADADDR, stem)
        if w != idaapi.BADADDR and ida_funcs.get_func(w):
            entry["wrapper_ea"] = w

        functions.append(entry)

    return {"engine_ea": engine_ea, "functions": functions}


def _global_len(ea):
    """Best-effort byte length of a defined data item starting at ``ea``."""
    if ea is None:
        return None
    try:
        sz = ida_bytes.get_item_size(ea)
        if sz > 1:
            return sz
    except Exception:  # noqa: BLE001
        pass
    return None


def guess_handler_map(engine_ea):
    """Best-effort ``handler_addr -> logical_opcode`` map for ``__vm_engine``.

    HEURISTIC ONLY.  Each logical opcode's handler advances the interpreter IP by
    the opcode's fixed encoding length and has a characteristic body (a callee-
    table indirect call for OP_CALL_*, a return for OP_RET_*, a memory load/store
    for OP_LOAD*/OP_STORE*, etc).  We bucket handlers by the IP-advance immediate
    we can find in each handler block and by coarse category, then match against
    the expected per-opcode fingerprint.  Opcodes that share a length+category
    bucket are reported as ambiguous and MUST be resolved by hand (edit the
    resulting map, or the sidecar's 'handler_logical_map').

    Returns
    -------
    (mapping, ambiguous) : (dict[int,int], list[str])
        ``mapping`` is handler_ea -> logical opcode for the confidently matched
        handlers; ``ambiguous`` lists human-readable notes for the rest.
    """
    _require_ida()
    if engine_ea is None:
        raise ValueError("engine_ea is None; locate __vm_engine first")

    # Fixed encoding length per logical opcode (variable-length ops -> None).
    enc_len = {}
    for op, fields in FIXED_ENC.items():
        ln = 1
        for (_, kind, _f) in fields:
            ln += {"reg": 1, "u8": 1, "u16": 2, "i32": 4, "u32": 4, "f64": 8}[kind]
        enc_len[op] = ln
    for op in CALL_OPS:
        enc_len[op] = None
    enc_len[SWITCH_OP] = None

    # Discover handler block heads: the OP_COUNT indirect-branch targets. We read
    # them from the first ophandlers table we can find (permuted, but the SET of
    # addresses is the full handler set regardless of permutation).
    handler_eas = _collect_engine_handler_eas(engine_ea)

    mapping = {}
    ambiguous = []
    # Bucket expected opcodes by (length, category).
    buckets = {}
    for op in OP_NAMES:
        buckets.setdefault((enc_len.get(op), _op_category(op)), []).append(op)

    for hea in handler_eas:
        ln = _handler_ip_advance(hea)
        cat = _handler_category(hea)
        cands = buckets.get((ln, cat), [])
        if len(cands) == 1:
            mapping[hea] = cands[0]
        else:
            ambiguous.append(
                "handler 0x%x: len=%s cat=%s candidates=%s" % (
                    hea, ln, cat, [OP_NAMES[o] for o in cands]))
    return mapping, ambiguous


def _op_category(op):
    if op in CALL_OPS:
        return "call"
    if op in (0x0C, 0x0D, 0x0E, 0x28):
        return "ret"
    if op in (0x0A, 0x0B, 0x18):
        return "branch"
    if op in (0x07, 0x1B, 0x1D, 0x14, 0x1F, 0x26, 0x2D):
        return "load"
    if op in (0x08, 0x1C, 0x1E, 0x15, 0x20, 0x27, 0x2E):
        return "store"
    return "compute"


def _collect_engine_handler_eas(engine_ea):
    """Collect handler block heads inside __vm_engine (best-effort)."""
    _require_ida()
    f = ida_funcs.get_func(engine_ea)
    heads = set()
    if f is None:
        return []
    # Any ophandlers table in the module lists exactly the handler set.
    for ea, nm in idautils.Names():
        if nm.endswith(G_OPHANDLERS):
            psize = _ptr_size()
            for i in range(OP_COUNT):
                a = _read_ptr(ea + i * psize)
                if f.start_ea <= a < f.end_ea:
                    heads.add(a)
            if len(heads) >= OP_COUNT:
                break
    return sorted(heads)


def _handler_ip_advance(hea):
    """Scan a handler block for an `add ip, imm` to recover the encoding length."""
    _require_ida()
    ea = hea
    end = min(hea + 0x200, idc.get_func_attr(hea, idc.FUNCATTR_END) or (hea + 0x200))
    best = None
    while ea < end and ea != idaapi.BADADDR:
        mnem = idc.print_insn_mnem(ea)
        if mnem in ("add", "adds"):
            v = idc.get_operand_value(ea, 2) if idc.get_operand_type(ea, 2) == idc.o_imm \
                else idc.get_operand_value(ea, 1)
            if 1 <= v <= 12:
                best = v if best is None else best
        if mnem in ("ret", "b", "br", "blr"):
            break
        ea = idc.next_head(ea, end)
    return best


def _handler_category(hea):
    """Coarse classification of a handler by the instructions it contains."""
    _require_ida()
    ea = hea
    end = min(hea + 0x200, idc.get_func_attr(hea, idc.FUNCATTR_END) or (hea + 0x200))
    has_call = has_ret = has_load = has_store = False
    while ea < end and ea != idaapi.BADADDR:
        mnem = idc.print_insn_mnem(ea)
        if mnem in ("blr", "bl"):
            has_call = True
        elif mnem == "ret":
            has_ret = True
        elif mnem.startswith("ldr"):
            has_load = True
        elif mnem.startswith("str"):
            has_store = True
        if mnem in ("ret", "b", "br"):
            break
        ea = idc.next_head(ea, end)
    if has_call:
        return "call"
    if has_ret:
        return "ret"
    if has_store:
        return "store"
    if has_load:
        return "load"
    return "compute"


# ===========================================================================
# Stage 2: dump_runtime
# ===========================================================================

FRIDA_SNIPPET = r"""
// deslop_vm_lift -- Frida runtime dump for the OLLVM-22 `vm` pass.
//
// Hook __vm_engine on entry and dump its arguments. After the .init_array
// bytecode-decryption ctor has run, arg0 (bc) points at the PLAINTEXT stream,
// so this captures exactly what decode() needs -- decrypted bytecode, the
// runtime salt, the permuted handler table, and (if regEncrypt) the regkeys.
//
//   frida -f ./target -l dump_vm.js --no-pause
//   # or: frida -n target -l dump_vm.js
//
// Edit ENGINE below to the __vm_engine address or export name, and OP_COUNT if
// the ISA was extended. Output is one JSON object per distinct bytecode ptr,
// printed as  DESLOP_VM_DUMP <json>  -- pipe/grep it into a sidecar file.

const ENGINE = Module.findExportByName(null, "__vm_engine")
             || ptr("0x0"); // <-- set to the __vm_engine address if not exported
const OP_COUNT = 0x33;
const PTR = Process.pointerSize;
const seen = {};

Interceptor.attach(ENGINE, {
    onEnter(args) {
        // Param order (see spec): 0 bc, 1 bc_len, 2 regs, 3 regs64, 4 fregs,
        // 5 pregs, 6 callees, 7 salt, 8..11 masks, 12 handlers, 13 fty,
        // 14 regkeys, 15 reg64keys, 16 fregkeys, 17 callee_mask.
        const bc = args[0];
        const bc_len = args[1].toInt32() >>> 0;
        const salt = args[7].toInt32() >>> 0;
        const handlers = args[12];
        const regkeys = args[14];
        const reg64keys = args[15];
        const fregkeys = args[16];

        const key = bc.toString();
        if (seen[key]) return;
        seen[key] = true;

        const bytes = Array.from(new Uint8Array(bc.readByteArray(bc_len)));

        const oph = [];
        for (let i = 0; i < OP_COUNT; i++)
            oph.push(handlers.add(i * PTR).readPointer().toString());

        function dumpKeys(p, count, wide) {
            if (p.isNull()) return null;
            const out = [];
            for (let i = 0; i < count; i++) {
                const e = p.add(i * (wide ? 8 : 4));
                out.push(wide ? e.readU64().toString() : e.readU32());
            }
            return out;
        }

        const obj = {
            engine: ENGINE.toString(),
            bytecode_hex: bytes.map(b => ("0" + b.toString(16)).slice(-2)).join(""),
            bytecode_len: bc_len,
            salt: salt,
            ophandlers: oph,
            // Bump these counts to your NVR/NVR64/NFR if regEncrypt is enabled.
            regkeys: dumpKeys(regkeys, 256, false),
            reg64keys: dumpKeys(reg64keys, 256, true),
            fregkeys: dumpKeys(fregkeys, 256, true)
        };
        console.log("DESLOP_VM_DUMP " + JSON.stringify(obj));
    }
});
"""


def frida_snippet(engine_name=ENGINE_NAME):
    """Return the Frida JS used to dump decrypted bytecode + salt + tables."""
    return FRIDA_SNIPPET


def dump_ida_debugger(func_entry, engine_ea=None):
    """Read decrypted bytecode + salt + tables from a LIVE IDA debugger session.

    This must be called while the process is suspended AT ``__vm_engine`` entry
    (set a breakpoint on ``engine_ea`` first). On arm64 the AAPCS64 convention
    puts the first 8 args in x0..x7 and the remainder on the stack; the 18-param
    ``__vm_engine`` therefore has:

        x0=bc  w1=bc_len  x2=regs x3=regs64 x4=fregs x5=pregs x6=callees
        x7=salt  [sp+0..]=regMask..pregMask  [sp+32]=handlers  [sp+40]=fty
        [sp+48]=regkeys [sp+56]=reg64keys [sp+64]=fregkeys [sp+72]=callee_mask

    (Stack slots assume the standard 8-arg-in-regs, rest-on-stack lowering; verify
    against the disassembly of the specific build.)
    """
    _require_ida()
    if not ida_dbg.is_debugger_on():
        raise RuntimeError("no active debugger; set a bp at __vm_engine and run to it")

    def reg(n):
        return idc.get_reg_value(n)

    bc = reg("X0")
    bc_len = reg("X1") & 0xFFFFFFFF
    salt = reg("X7") & 0xFFFFFFFF
    sp = reg("SP")
    psize = _ptr_size()

    handlers = _read_ptr(sp + 32)
    regkeys = _read_ptr(sp + 48)
    reg64keys = _read_ptr(sp + 56)
    fregkeys = _read_ptr(sp + 64)

    raw = ida_bytes.get_bytes(bc, bc_len) or b""
    oph = [_read_ptr(handlers + i * psize) for i in range(OP_COUNT)]

    def keys(p, wide, count=256):
        if not p:
            return None
        out = []
        for i in range(count):
            if wide:
                out.append(ida_bytes.get_qword(p + i * 8))
            else:
                out.append(ida_bytes.get_dword(p + i * 4))
        return out

    return {
        "engine_ea": engine_ea,
        "bytecode_hex": binascii.hexlify(raw).decode(),
        "bytecode_len": bc_len,
        "salt": salt,
        "ophandlers": [str(a) for a in oph],
        "regkeys": keys(regkeys, False),
        "reg64keys": keys(reg64keys, True),
        "fregkeys": keys(fregkeys, True),
    }


# ===========================================================================
# Sidecar helpers
# ===========================================================================

def _sidecar_load(path):
    with open(path, "r") as fh:
        return json.load(fh)


def _sidecar_save(path, obj):
    with open(path, "w") as fh:
        json.dump(obj, fh, indent=2)


def _p2l_from_sidecar(sc):
    """Resolve the physical->logical map from a sidecar, if derivable."""
    if "p2l" in sc and sc["p2l"]:
        return {int(k): int(v) for k, v in sc["p2l"].items()}
    oph = sc.get("ophandlers")
    hlm = sc.get("handler_logical_map")
    if oph and hlm:
        oph = [int(x, 0) if isinstance(x, str) else int(x) for x in oph]
        p2l, _ = reverse_permutation(oph, hlm)
        return p2l
    return None


def _bytecode_from_sidecar(sc):
    return binascii.unhexlify(sc["bytecode_hex"])


def _decode_from_sidecar(sc):
    return decode(
        _bytecode_from_sidecar(sc),
        p2l=_p2l_from_sidecar(sc),
        salt=int(sc.get("salt", 0)),
        obf_reg_idx=bool(sc.get("obf_reg_idx", True)),
        layer2=sc.get("layer2", "aes"),
    )


def _serialisable(insns):
    """Make decoded instructions JSON-friendly (tuples -> lists)."""
    out = []
    for ins in insns:
        d = {}
        for k, v in ins.items():
            if isinstance(v, tuple):
                d[k] = list(v)
            elif k == "args":
                d[k] = [list(a) for a in v]
            elif k == "cases":
                d[k] = [list(c) for c in v]
            else:
                d[k] = v
        out.append(d)
    return out


# ===========================================================================
# CLI
# ===========================================================================

def _cmd_locate(args):
    res = locate(args.engine_name)
    if args.out:
        _sidecar_save(args.out, res)
        print("wrote %s (%d functions)" % (args.out, len(res["functions"])))
    else:
        print(json.dumps(res, indent=2, default=str))
    return 0


def _cmd_dump(args):
    if args.emit_frida:
        text = frida_snippet(args.engine_name)
        if args.out:
            with open(args.out, "w") as fh:
                fh.write(text)
            print("wrote Frida snippet to %s" % args.out)
        else:
            sys.stdout.write(text)
        return 0
    # Live IDA debugger path.
    res = dump_ida_debugger(args.func, engine_ea=None)
    if args.layer2:
        res["layer2"] = args.layer2
    res["obf_reg_idx"] = not args.no_reg_idx
    if args.out:
        _sidecar_save(args.out, res)
        print("wrote %s (%d bytes bytecode, salt=0x%x)" %
              (args.out, res["bytecode_len"], res["salt"]))
    else:
        print(json.dumps(res, indent=2, default=str))
    return 0


def _cmd_decode(args):
    sc = _sidecar_load(args.sidecar)
    insns = _decode_from_sidecar(sc)
    payload = {"func_name": sc.get("func_name", "vm_func"),
               "count": len(insns),
               "insns": _serialisable(insns)}
    if args.out:
        _sidecar_save(args.out, payload)
        print("decoded %d instructions -> %s" % (len(insns), args.out))
    else:
        print(json.dumps(payload, indent=2, default=str))
    return 0


def _cmd_lift(args):
    if args.decoded:
        dec = _sidecar_load(args.decoded)
        raw = dec["insns"]
        insns = []
        for d in raw:
            ins = dict(d)
            for k in ("dst", "src", "a", "b", "dst64", "a64", "b64", "cond",
                      "srcp", "dstp", "basep", "idx", "idx64", "ptrreg", "val",
                      "val64", "valp", "src_fr", "dst_fr", "src64", "t", "f"):
                if k in ins and isinstance(ins[k], list):
                    ins[k] = tuple(ins[k])
            if "args" in ins:
                ins["args"] = [tuple(a) for a in ins["args"]]
            if "cases" in ins:
                ins["cases"] = [tuple(c) for c in ins["cases"]]
            insns.append(ins)
        func_name = dec.get("func_name", "vm_func")
        callees = None
        regnote = None
    else:
        sc = _sidecar_load(args.sidecar)
        insns = _decode_from_sidecar(sc)
        func_name = sc.get("func_name", "vm_func")
        callees = sc.get("callees")
        regnote = None
        if sc.get("regkeys"):
            regnote = "regEncrypt active: runtime register values are XORed by regkeys[slot]"

    text = lift(insns, callees=callees, func_name=func_name, regkeys_note=regnote)
    if args.out:
        with open(args.out, "w") as fh:
            fh.write(text + "\n")
        print("wrote pseudocode to %s" % args.out)
    else:
        print(text)
    return 0


def build_argparser():
    p = argparse.ArgumentParser(
        prog="deslop_vm_lift",
        description="Runtime-assisted devirtualiser for the OLLVM-22 `vm` pass.")
    sub = p.add_subparsers(dest="cmd", required=True)

    pl = sub.add_parser("locate", help="[IDA] find __vm_engine, wrappers, and globals")
    pl.add_argument("--engine-name", default=ENGINE_NAME)
    pl.add_argument("--out", help="write result JSON sidecar")
    pl.set_defaults(func=_cmd_locate)

    pd = sub.add_parser("dump", help="dump decrypted bytecode/salt/tables from a live process")
    pd.add_argument("--emit-frida", action="store_true",
                    help="print the Frida JS snippet instead of using the IDA debugger")
    pd.add_argument("--func", help="[IDA dbg] wrapper/func name being dumped")
    pd.add_argument("--engine-name", default=ENGINE_NAME)
    pd.add_argument("--layer2", choices=["aes", "lcg", "none"], default="aes")
    pd.add_argument("--no-reg-idx", action="store_true",
                    help="set if obfRegIdx=0 (layer-1 register XOR disabled)")
    pd.add_argument("--out", help="write sidecar JSON / Frida snippet")
    pd.set_defaults(func=_cmd_dump)

    pc = sub.add_parser("decode", help="[offline] decode bytecode from a sidecar JSON")
    pc.add_argument("sidecar", help="sidecar JSON (from dump) with bytecode_hex + salt + perm")
    pc.add_argument("--out", help="write decoded-instruction JSON")
    pc.set_defaults(func=_cmd_decode)

    pf = sub.add_parser("lift", help="[offline] emit C-like pseudocode")
    src = pf.add_mutually_exclusive_group(required=True)
    src.add_argument("--sidecar", help="sidecar JSON (decode inline)")
    src.add_argument("--decoded", help="pre-decoded JSON (from `decode --out`)")
    pf.add_argument("--out", help="write pseudocode")
    pf.set_defaults(func=_cmd_lift)

    return p


def main(argv=None):
    args = build_argparser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
