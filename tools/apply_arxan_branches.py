"""Import checked Arxan-pattern edges for Unslopper's verified-jump pass.

Default is a read-only plan. --apply writes comments/user jump xrefs only;
no instructions, function boundaries, or integrity predicates are patched.
Conflicting analyst comments and cross-function edges are left untouched.
"""
from arxan_analysis import match_at

PREFIX = 'UNSLOPPER_VERIFIED_JUMP: '


def validate(report, image, sha, base):
    if report.get('schema') != 1 or report.get('sha256') != sha or int(report['base'], 16) != base:
        raise ValueError('Report identity/base does not match the database')
    rows, seen = [], set()
    for row in report['records']:
        ea = int(row['ea'], 16)
        if ea in seen:
            raise ValueError('Duplicate report site')
        seen.add(ea)
        rebuilt = match_at(image, ea)
        if rebuilt is None or any(row.get(k) != rebuilt[k] for k in ('ea', 'target', 'pattern', 'window', 'reads')):
            raise ValueError('Instruction proof changed or report was edited at ' + row['ea'])
        rows.append(rebuilt)
    return rows


def plan(rows, function_owner, incoming, get_comment, outgoing):
    """Callbacks make all eligibility gates testable without IDA."""
    accepted, skipped = [], []
    for row in rows:
        site, target, start = int(row['ea'], 16), int(row['target'], 16), int(row['window']['ea'], 16)
        owner = function_owner(start)
        reason = None
        if owner is None or any(function_owner(a) != owner for a in [target, *range(start, site + 4, 4)]):
            reason = 'different_or_missing_function'
        elif any(not start <= source <= site for a in range(start + 4, site + 4, 4) for source in incoming(a)):
            reason = 'unexpected_entry_into_proof'
        elif get_comment(site) not in ('', PREFIX + hex(target)):
            reason = 'existing_comment'
        elif any(destination != target for destination in outgoing(site)):
            reason = 'conflicting_jump_xref'
        if reason:
            skipped.append(dict(ea=row['ea'], reason=reason))
        else:
            accepted.append(row)
    return dict(accepted=accepted, skipped=skipped)


def apply(report, commit=False):
    import ida_auto, ida_bytes, ida_funcs, ida_nalt, ida_segment, ida_xref, idautils
    ida_auto.auto_wait()
    sections = [s for s in idautils.Segments() if ida_segment.get_segm_name(ida_segment.getseg(s)) == '__text']
    if len(sections) != 1:
        raise ValueError('Expected a single IDA __text segment')
    segment = ida_segment.getseg(sections[0])
    class Image:
        text = (segment.start_ea, segment.end_ea)
        @staticmethod
        def read(ea, size):
            data = ida_bytes.get_bytes(ea, size)
            if data is None or len(data) != size:
                raise ValueError('Unbacked database read')
            return data
        @staticmethod
        def readonly(ea, size):
            seg = ida_segment.getseg(ea)
            return bool(seg and ea + size <= seg.end_ea and not seg.perm & ida_segment.SEGPERM_WRITE)
    rows = validate(report, Image(), ida_nalt.retrieve_input_file_sha256().hex(), ida_nalt.get_imagebase())
    def owner(ea):
        f = ida_funcs.get_func(ea)
        return f.start_ea if f else None
    def incoming(ea):
        return [x.frm for x in idautils.XrefsTo(ea) if x.iscode]
    def outgoing(ea):
        return [x.to for x in idautils.XrefsFrom(ea) if x.iscode and x.type in (ida_xref.fl_JN, ida_xref.fl_JF)]
    result = plan(rows, owner, incoming, lambda a: ida_bytes.get_cmt(a, False) or '', outgoing)
    result['applied'] = 0
    if not commit:
        return result
    # All byte proofs are validated before the first write. Eligibility checks
    # preserve existing comments and leave ownership repairs to the analyst.
    for row in result['accepted']:
        ea, target = int(row['ea'], 16), int(row['target'], 16)
        old = ida_bytes.get_cmt(ea, False) or ''
        if not ida_xref.add_cref(ea, target, ida_xref.fl_JN | ida_xref.XREF_USER):
            raise RuntimeError('Could not add jump xref at ' + row['ea'])
        if old != PREFIX + hex(target) and not ida_bytes.set_cmt(ea, PREFIX + hex(target), False):
            raise RuntimeError('Could not set verified-jump marker at ' + row['ea'])
        result['applied'] += 1
    return result


if __name__ == '__main__':
    import argparse, json, sys
    from pathlib import Path
    import idc
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('report', type=Path)
    parser.add_argument('--apply', action='store_true')
    parser.add_argument('--output', type=Path)
    args = parser.parse_args(idc.ARGV[1:])
    result = apply(json.loads(args.report.read_text()), commit=args.apply)
    if args.output:
        args.output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({k: len(v) if isinstance(v, list) else v for k, v in result.items()}))
