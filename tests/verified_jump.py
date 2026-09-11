"""Live IDA regression for GENERATED verified-jump recovery.

The active plugin must include verified_jump.cpp. Only analysis metadata is
changed, and all comments/xrefs are restored even if an assertion fails.
"""
import ida_funcs
import ida_hexrays
import ida_xref
import idc


def verify_verified_jump(entry=0xA9F26C, site=0xA9F324,
                         target=0xA9FF04, conflict=0xA9F7DC):
    comment = idc.get_cmt(site, False)
    original_refs = []
    xb = ida_xref.xrefblk_t()
    ok = xb.first_from(site, ida_xref.XREF_FAR)
    while ok:
        if xb.iscode and xb.user:
            original_refs.append((xb.to, xb.type))
        ok = xb.next_from()
    assert (target, ida_xref.fl_JN) in original_refs
    assert all(ea != conflict for ea, unused in original_refs)
    marker = 'UNSLOPPER_VERIFIED_JUMP: ' + hex(target)
    rows = []

    def check(label, wanted):
        mba = ida_hexrays.gen_microcode(
            ida_hexrays.mba_ranges_t(ida_funcs.get_func(entry)),
            None, None, 0, ida_hexrays.MMAT_GENERATED)
        assert mba is not None
        matches = []
        for i in range(mba.qty):
            tail = mba.get_mblock(i).tail
            if tail is not None and tail.ea == site:
                matches.append(tail.opcode)
                if wanted == ida_hexrays.m_goto:
                    assert tail.l.t == ida_hexrays.mop_v
                    assert tail.l.g == target
        assert matches == [wanted], (label, matches, wanted)
        rows.append({'case': label, 'opcode': wanted})

    try:
        for label, text, wanted in [
            ('valid', marker, ida_hexrays.m_goto),
            ('absent', '', ida_hexrays.m_ijmp),
            ('trailing', marker + ' junk', ida_hexrays.m_ijmp),
            ('outside', 'UNSLOPPER_VERIFIED_JUMP: 0x10', ida_hexrays.m_ijmp),
        ]:
            idc.set_cmt(site, text, False)
            check(label, wanted)
        idc.set_cmt(site, marker, False)
        ida_xref.del_cref(site, target, False)
        check('missing_user_xref', ida_hexrays.m_ijmp)
        ida_xref.add_cref(site, target, ida_xref.fl_JN | ida_xref.XREF_USER)
        ida_xref.add_cref(site, conflict, ida_xref.fl_JN | ida_xref.XREF_USER)
        check('ambiguous_user_xrefs', ida_hexrays.m_ijmp)
    finally:
        ida_xref.del_cref(site, conflict, False)
        for ea, kind in original_refs:
            ida_xref.add_cref(site, ea, kind | ida_xref.XREF_USER)
        idc.set_cmt(site, comment or '', False)
    texts = []
    for unused in range(3):
        ida_hexrays.mark_cfunc_dirty(entry, False)
        texts.append(str(ida_hexrays.decompile(entry)))
    assert texts[0] == texts[1] == texts[2]
    assert 'sub_BB060' in texts[0] and 'dword_1A89D08 = 3' in texts[0]
    return {'cases': rows, 'repeat_lines': [len(s.splitlines()) for s in texts],
            'identical': True}
