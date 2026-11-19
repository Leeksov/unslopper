"""Read-only IDAPython fallback for Unslopper action 40.

Run in the IDA database opened from the audited Valu 10.5.3 ARM32 image:

    # IDA Python console: File -> Script file -> promon_thumb_audit.py

This script does not patch bytes, create names or xrefs, or alter function
boundaries. Explicit script execution is the opt-in gate. It only reads the
input hash, processor mode, bytes and xrefs.
"""

import ida_bytes
import ida_funcs
import ida_ida
import ida_idp
import ida_nalt
import ida_segregs
import ida_xref


EXPECTED_SHA256 = "776e99e7b60bf9803f7ed59afc46907e6a3e8d3c9a198a9b4ec101675d0406b0"
HUBS = (
    (0x465654, 0x466504, 0x0B34F7E32F2234D1, 0xB7C4D4BF7CD51286, 0x18555161),
    (0x1F92EA, 0x1FA1D8, 0x32F3575B7801472A, 0xEAB260691F023B09, 0x32094048),
)
HELPER = (0x451E40, 64, 0x90A3968796FE47D7)
PRODUCER = (0x4657E8, 48, 0xF4D1011491654268)


def fnv64(address, size):
    data = ida_bytes.get_bytes(address, size)
    if data is None or len(data) != size:
        return None
    result = 0xCBF29CE484222325
    for byte in data:
        result = ((result ^ byte) * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
    return result


def incoming_code_xrefs(hub, pred, pred_size):
    xref = ida_xref.xrefblk_t()
    count = 0
    pred_edge = False
    ok = xref.first_to(hub, ida_xref.XREF_CODE)
    while ok:
        if xref.iscode and xref.type in (ida_xref.fl_JN, ida_xref.fl_JF, ida_xref.fl_F):
            count += 1
            pred_edge |= pred <= xref.frm < pred + pred_size
        ok = xref.next_to()
    return count, pred_edge


def audit():
    if ida_ida.inf_get_procname() != "ARM" or ida_ida.inf_is_64bit():
        print("[unslop-promon32] rejected: requires 32-bit ARM database")
        return 0
    input_hash = ida_nalt.retrieve_input_file_sha256()
    if input_hash is None or input_hash.hex() != EXPECTED_SHA256:
        print("[unslop-promon32] rejected: input SHA-256 is not the audited Valu image")
        return 0

    base = ida_nalt.get_imagebase()
    thumb_reg = ida_idp.str2reg("T")
    accepted = 0
    for hub_off, pred_off, hub_hash, pred_hash, state in HUBS:
        hub, pred = base + hub_off, base + pred_off
        bytes_ok = fnv64(hub, 64) == hub_hash and fnv64(pred, 24) == pred_hash
        thumb_ok = thumb_reg >= 0 and all(
            ida_segregs.get_sreg(ea, thumb_reg) == 1 for ea in (hub, pred)
        )
        incoming, pred_edge = incoming_code_xrefs(hub, pred, 24)
        graph_ok = incoming >= 20 and pred_edge
        owner = ida_funcs.get_func(hub)
        ok = bytes_ok and thumb_ok and graph_ok
        accepted += int(ok)
        print(
            f"[unslop-promon32] hub=0x{hub:x} "
            f"owner={hex(owner.start_ea) if owner else 'none'} "
            f"incoming={incoming} example_state=0x{state:08x} "
            f"bytes={int(bytes_ok)} thumb={int(thumb_ok)} "
            f"backedge={int(pred_edge)} {'candidate' if ok else 'rejected'}"
        )

    helper, hsize, hhash = HELPER
    producer, psize, phash = PRODUCER
    encoded_ok = (
        thumb_reg >= 0
        and ida_segregs.get_sreg(base + helper, thumb_reg) == 1
        and ida_segregs.get_sreg(base + producer, thumb_reg) == 1
        and fnv64(base + helper, hsize) == hhash
        and fnv64(base + producer, psize) == phash
    )
    print(
        f"[unslop-promon32] encoded-call descriptor XOR anchor=0x{base+helper:x} "
        f"producer=0x{base+producer:x} matched={int(encoded_ok)}; "
        "no target resolution or IDB changes"
    )
    print(f"[unslop-promon32] audited {accepted}/{len(HUBS)} CFF hubs; report only, no CFG rewrite")
    return accepted


audit()
