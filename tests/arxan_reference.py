"""Conservative offline ARM64 Arxan-pattern discovery; no sample addresses required.

The name is an attribution, not a vendor detector. __ETC,__PII is reported as
layout evidence. A match proves a local edge given entry at the slice start;
the C++ plugin additionally checks incoming xrefs and function ownership.
"""
import argparse
import bisect
import hashlib
import json
import struct
from pathlib import Path

BR8, BR9 = 0xd61f0100, 0xd61f0120
TAIL = (0x8a0b0109, 0xd280004a, 0x9b0a7d29, 0xca0b0108, 0x8b090108, BR8)


def signed(value, bits):
    return value - (1 << bits) if value & (1 << (bits - 1)) else value


def adr(word, ea, reg):
    if word & 0x9f00001f != 0x10000000 | reg:
        return None
    return ea + signed(((word >> 5) & 0x7ffff) * 4 + ((word >> 29) & 3), 21)


class MachO:
    def __init__(self, path):
        self.data = Path(path).read_bytes()
        self.sha = hashlib.sha256(self.data).hexdigest()
        if len(self.data) < 32:
            raise ValueError('Truncated Mach-O')
        h = struct.unpack_from('<8I', self.data)
        if h[:2] != (0xfeedfacf, 0x100000c):
            raise ValueError('A thin little-endian ARM64 Mach-O is required')
        self.segments, self.sections, self.functions = [], [], []
        pos, end, starts_blob = 32, 32 + h[5], None
        if end > len(self.data):
            raise ValueError('Truncated load commands')
        for _ in range(h[4]):
            if pos + 8 > end:
                raise ValueError('Missing load command')
            cmd, size = struct.unpack_from('<II', self.data, pos)
            if size < 8 or pos + size > end:
                raise ValueError('Invalid load command size')
            if cmd == 0x19:
                if size < 72:
                    raise ValueError('Truncated segment')
                _, _, name, va, vs, fo, fs, _, prot, count, _ = struct.unpack_from('<II16sQQQQiiII', self.data, pos)
                if fo + fs > len(self.data) or 72 + 80 * count > size:
                    raise ValueError('Invalid segment bounds')
                self.segments.append((va, vs, fo, fs, prot))
                for index in range(count):
                    sn, sg, ea, length, offset = struct.unpack_from('<16s16sQQI', self.data, pos + 72 + 80 * index)
                    self.sections.append(dict(segment=sg.rstrip(b'\0').decode(), name=sn.rstrip(b'\0').decode(), ea=ea, size=length, offset=offset))
            elif cmd in (0x21, 0x2c):
                if size < 20:
                    raise ValueError('Truncated encryption command')
                if struct.unpack_from('<I', self.data, pos + 16)[0] != 0:
                    raise ValueError('Encrypted text: a decrypted sample is required')
            elif cmd == 0x26:
                if size < 16:
                    raise ValueError('Truncated LC_FUNCTION_STARTS')
                offset, length = struct.unpack_from('<II', self.data, pos + 8)
                if offset + length > len(self.data):
                    raise ValueError('Truncated function starts')
                starts_blob = self.data[offset:offset + length]
            pos += size
        if pos != end or not self.segments:
            raise ValueError('Invalid command list')
        self.base = min(s[0] for s in self.segments if s[3])
        text = [s for s in self.sections if s['segment'] == '__TEXT' and s['name'] == '__text']
        if len(text) != 1:
            raise ValueError('Exactly one __TEXT,__text section required')
        self.text = (text[0]['ea'], text[0]['ea'] + text[0]['size'])
        self.read(self.text[0], self.text[1] - self.text[0])
        if starts_blob is not None:
            ea, value, shift = self.base, 0, 0
            for byte in starts_blob:
                value |= (byte & 127) << shift
                if byte & 128:
                    shift += 7
                    if shift > 63:
                        raise ValueError('Invalid ULEB128')
                    continue
                if value == 0:
                    break
                ea += value
                if self.text[0] <= ea < self.text[1]:
                    self.functions.append(ea)
                value, shift = 0, 0
            if shift:
                raise ValueError('Truncated ULEB128')

    def read(self, ea, size):
        if size < 0:
            raise ValueError('Negative read')
        for va, _, fo, fs, _ in self.segments:
            if va <= ea and ea + size <= va + fs:
                return self.data[fo + ea - va:fo + ea - va + size]
        raise ValueError('Unbacked address')

    def readonly(self, ea, size):
        return any(va <= ea and ea + size <= va + fs and not prot & 2
                   for va, _, _, fs, prot in self.segments)


def match_at(image, site):
    """Re-derivable local proof. Unknown or mismatched instructions return None."""
    def word(a):
        if not image.text[0] <= a < image.text[1] or a % 4:
            raise ValueError('Outside aligned text')
        return struct.unpack('<I', image.read(a, 4))[0]
    try:
        end = word(site)
        start, target, pattern, reads = None, None, None, []
        if end == BR8:
            for candidate in (site - 32, site - 40):
                try:
                    store, load = word(candidate), word(candidate + 4)
                except ValueError:
                    continue
                unsigned = store & 0xffc0001f == 0xf900001f and load & 0xffc0001f == 0xf940000b
                unscaled = store & 0xffe00c1f == 0xf800001f and load & 0xffe00c1f == 0xf840000b
                if not (unsigned or unscaled) or (store & 0x003fffe0) != (load & 0x003fffe0):
                    continue
                base = (store >> 5) & 31
                proof_start = candidate
                if base not in (29, 31):
                    # Address laundering is accepted only for X8 derived immediately
                    # from SP/FP by ADD/SUB immediate. General pointer stores are not.
                    if base != 8:
                        continue
                    previous = word(candidate - 4)
                    if previous & 0xff80001f not in (0x91000008, 0xd1000008) or (previous >> 5) & 31 not in (29, 31):
                        continue
                    proof_start -= 4
                destination = adr(word(candidate + 8), candidate + 8, 8)
                if destination is None:
                    continue
                tail, literal_reads = candidate + 12, []
                if candidate == site - 40:
                    if (word(tail), word(tail + 4)) != (0xb9800109, 0x8b080128):
                        continue
                    if not image.readonly(destination, 4):
                        continue
                    raw = image.read(destination, 4)
                    literal_reads.append(dict(ea=hex(destination), bytes=raw.hex()))
                    destination += struct.unpack('<i', raw)[0]
                    tail += 8
                if tuple(word(tail + i * 4) for i in range(6)) != TAIL:
                    continue
                start, target, pattern, reads = proof_start, destination, 'zero_mask_constant', literal_reads
                break
            if start is None and word(site - 12) == 0xd2800028 and word(site - 4) == 0x9b087d28:
                destination = adr(word(site - 8), site - 8, 9)
                if destination is not None:
                    start, target, pattern = site - 12, destination, 'multiply_one'
        elif end == BR9:
            candidate = site - 24
            destination = adr(word(candidate), candidate, 9)
            if destination == site + 4 and tuple(word(candidate + i * 4) for i in range(1, 7)) == (
                0xcb0b0129, 0xd10023ff, 0x14000002, 0xcb0b0129, 0x8b0b0129, BR9
            ) and word(site + 4) == 0x910023ff:
                start, target, pattern = candidate, destination, 'cancelled_address_offset'
        if start is None or target % 4 or not image.text[0] <= target or target + 4 > image.text[1] or target == site:
            return None
        return dict(ea=hex(site), target=hex(target), pattern=pattern,
                    window=dict(ea=hex(start), bytes=image.read(start, site + 4 - start).hex()),
                    reads=reads)
    except (ValueError, struct.error):
        return None


def analyze(image):
    code = image.read(image.text[0], image.text[1] - image.text[0])
    records, counts, candidates = [], {}, 0
    for pos in range(0, len(code) - 3, 4):
        if code[pos:pos + 4] not in (b'\x00\x01\x1f\xd6', b'\x20\x01\x1f\xd6'):
            continue
        candidates += 1
        row = match_at(image, image.text[0] + pos)
        if row is None:
            continue
        start, target, site = int(row['window']['ea'], 16), int(row['target'], 16), int(row['ea'], 16)
        index = bisect.bisect_right(image.functions, start) - 1
        lo = image.functions[index] if index >= 0 else None
        hi = image.functions[index + 1] if index + 1 < len(image.functions) else image.text[1]
        row['canonical_function'] = hex(lo) if lo is not None and site < hi and lo <= target < hi else None
        counts[row['pattern']] = counts.get(row['pattern'], 0) + 1
        records.append(row)
    return dict(schema=1, sha256=image.sha, base=hex(image.base), text=[hex(a) for a in image.text],
                markers=[s for s in image.sections if s['name'] == '__PII'],
                br_x8_x9_candidates=candidates, counts=counts, matched=len(records), records=records,
                scope='Local instruction proofs only. IDA entry-xref and ownership checks required before use. No guard removal or whole-protector claim.')


def validate_report(report, image):
    if report.get('schema') != 1 or report.get('sha256') != image.sha or int(report['base'],16) != image.base:
        raise ValueError('Report identity/base mismatch')
    rows=[];seen=set()
    for row in report['records']:
        ea=int(row['ea'],16)
        if ea in seen:raise ValueError('Duplicate report site')
        seen.add(ea)
        rebuilt=match_at(image,ea)
        if rebuilt is None or any(row.get(k)!=rebuilt[k] for k in ('ea','target','pattern','window','reads')):
            raise ValueError('Changed instruction proof')
        rows.append(rebuilt)
    return rows


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    report = analyze(MachO(args.binary))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({k: v for k, v in report.items() if k != 'records'}, indent=2))
