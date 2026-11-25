"""Read-only F5 regression for the exact Appdome-marked libloader image.

Run in IDA 9.5 with a disposable IDB and UNSLOP_AFFINE_CONTEXT=1 in the
environment before IDA starts. The proprietary image is not in this repo.
"""

import ida_funcs
import ida_hexrays
import ida_loader
import ida_nalt


EXPECTED_SHA256 = "aa4ba77dc142c944b64fdbd8d3fb83a38b7e7200b13cb79422dc9da88cf10970"
FULL_OR_PARTIAL = (0x691DC, 0x2BD47C, 0x1140B4, 0xC2EF8)
MIXED = 0x73340  # primary CFF removed; secondary ordinary switch remains
NO_CHANGE = (0x24A28, 0x273610, 0x2DF908, 0x401E80,
             0x25CA34, 0xD68E8)  # final two exceed the 128-case cap
EFFECT_OPCODES = (ida_hexrays.m_call, ida_hexrays.m_icall,
                  ida_hexrays.m_stx, ida_hexrays.m_ext)


def f5_metrics(ea):
    ida_hexrays.mark_cfunc_dirty(ea, False)
    cfunc = ida_hexrays.decompile(ea)
    if cfunc is None:
        raise AssertionError("F5 failed at 0x%X" % ea)
    text = str(cfunc)
    return len(text.splitlines()), text.count("goto "), text.count("switch ")


def effect_origins(ea):
    mba = ida_hexrays.gen_microcode(
        ida_hexrays.mba_ranges_t(ida_funcs.get_func(ea)),
        None, None, 0, ida_hexrays.MMAT_GLBOPT1)
    if mba is None:
        raise AssertionError("microcode failed at 0x%X" % ea)
    found = {}

    def walk(insn, depth=0):
        if depth > 16:
            raise AssertionError("nested microcode depth exceeded at 0x%X" % ea)
        if insn.opcode in EFFECT_OPCODES:
            key = (int(insn.opcode), int(insn.ea))
            found[key] = found.get(key, 0) + 1
        for operand in (insn.l, insn.r, insn.d):
            if operand.t == ida_hexrays.mop_d and operand.d is not None:
                walk(operand.d, depth + 1)

    for serial in range(mba.qty):
        insn = mba.get_mblock(serial).head
        while insn is not None:
            walk(insn)
            insn = insn.next
    return found


def run(addresses=None):
    actual = ida_nalt.retrieve_input_file_sha256().hex()
    if actual != EXPECTED_SHA256:
        raise AssertionError("wrong libloader image: %s" % actual)
    plugin = ida_loader.find_plugin("unslopper") or ida_loader.load_plugin("unslopper")
    if plugin is None:
        raise AssertionError("Unslopper did not load")
    targets = addresses if addresses is not None else FULL_OR_PARTIAL + (MIXED,) + NO_CHANGE
    passed = 0
    try:
        for ea in targets:
            if not ida_loader.load_and_run_plugin("unslopper", 1):
                raise AssertionError("could not disable Unslopper")
            off = f5_metrics(ea)
            off_effects = effect_origins(ea) if ea not in NO_CHANGE else None

            if not ida_loader.load_and_run_plugin("unslopper", 2):
                raise AssertionError("could not enable Unslopper")
            on = f5_metrics(ea)
            on_again = f5_metrics(ea)
            if on[1:] != on_again[1:]:
                raise AssertionError("F5 not repeatable at 0x%X: %r != %r" %
                                     (ea, on, on_again))
            if ea in FULL_OR_PARTIAL:
                if not (on[1] < off[1] and on[2] <= off[2]):
                    raise AssertionError("CFF not reduced at 0x%X: %r -> %r" %
                                         (ea, off, on))
            elif ea == MIXED:
                if not (on[0] < off[0] and on[1] < off[1]):
                    raise AssertionError("mixed recovery regressed at 0x%X" % ea)
            elif on[1:] != off[1:]:
                raise AssertionError("control changed at 0x%X: %r -> %r" %
                                     (ea, off, on))
            if off_effects is not None and off_effects != effect_origins(ea):
                raise AssertionError("call/store origins changed at 0x%X" % ea)
            print("0x%X OFF %r ON %r repeat %r" % (ea, off, on, on_again))
            passed += 1
    finally:
        ida_loader.load_and_run_plugin("unslopper", 1)
    print("Appdome affine context regression: %d/%d passed" %
          (passed, len(targets)))


if __name__ == "__main__":
    run()
