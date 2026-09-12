"""Synthetic positive/negative proof fixtures; no proprietary binary required."""
import copy
import hashlib
import json
from pathlib import Path
import random
import struct
import sys
import tempfile
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import arxan_analysis as m
import apply_arxan_branches as applier


def adr(reg, at, target):
    delta = (target - at) & ((1 << 21) - 1)
    return 0x10000000 | ((delta & 3) << 29) | ((delta >> 2) << 5) | reg


class Image:
    def __init__(self, words, writable=False):
        self.data = b''.join(struct.pack('<I', x) for x in words)
        self.text = (0x1000, 0x1000 + len(self.data))
        self.functions = [0x1000]
        self.sha = hashlib.sha256(self.data).hexdigest()
        self.base = 0x1000
        self.sections = []
        self.writable = writable
    def read(self, at, size):
        if at < self.text[0] or at + size > self.text[1]:
            raise ValueError('out of bounds')
        return self.data[at - self.text[0]:at - self.text[0] + size]
    def readonly(self, at, size):
        return not self.writable and self.text[0] <= at and at + size <= self.text[1]


def multiply():
    return Image([0xd2800028, adr(9, 0x1004, 0x1010), 0x9b087d28, m.BR8, 0xd65f03c0])


def zero(literal=False, writable=False):
    if literal:
        words = [0xf90023ff, 0xf94023eb, adr(8, 0x1008, 0x102c), 0xb9800109, 0x8b080128, *m.TAIL, 4, 0xd65f03c0]
    else:
        words = [0xf90023ff, 0xf94023eb, adr(8, 0x1008, 0x1024), *m.TAIL, 0xd65f03c0]
    return Image(words, writable)


def cancelled():
    return Image([adr(9, 0x1000, 0x101c), 0xcb0b0129, 0xd10023ff, 0x14000002,
                  0xcb0b0129, 0x8b0b0129, m.BR9, 0x910023ff, 0xd65f03c0])


class Patterns(unittest.TestCase):
    def test_exact_three_families(self):
        for image, site, target, kind in [
            (multiply(), 0x100c, 0x1010, 'multiply_one'),
            (zero(), 0x1020, 0x1024, 'zero_mask_constant'),
            (zero(True), 0x1028, 0x1030, 'zero_mask_constant'),
            (cancelled(), 0x1018, 0x101c, 'cancelled_address_offset')]:
            row = m.match_at(image, site)
            self.assertEqual((row['target'], row['pattern']), (hex(target), kind))

    def test_mutable_literal_rejected(self):
        self.assertIsNone(m.match_at(zero(True, True), 0x1028))

    def test_nonzero_store_rejected(self):
        image = zero()
        image.data = struct.pack('<I', 0xf90023fe) + image.data[4:]
        self.assertIsNone(m.match_at(image, 0x1020))

    def test_general_pointer_store_rejected(self):
        image = zero()
        image.data = struct.pack('<II', 0xf900011f, 0xf940010b) + image.data[8:]
        self.assertIsNone(m.match_at(image, 0x1020))

    def test_frame_address_laundering(self):
        words = [0x910103e8, 0xf900011f, 0xf940010b, adr(8, 0x100c, 0x1028), *m.TAIL, 0xd65f03c0]
        row = m.match_at(Image(words), 0x1024)
        self.assertEqual(row['window']['ea'], '0x1000')
        words[0] = 0x91010008  # X8 derived from caller-selected X0, not SP/FP.
        self.assertIsNone(m.match_at(Image(words), 0x1024))

    def test_wrong_skip_edge_rejected(self):
        image = cancelled()
        image.data = image.data[:12] + struct.pack('<I', 0x14000001) + image.data[16:]
        self.assertIsNone(m.match_at(image, 0x1018))

    def test_external_target_rejected(self):
        image = multiply()
        image.data = image.data[:4] + struct.pack('<I', adr(9, 0x1004, 0x2000)) + image.data[8:]
        self.assertIsNone(m.match_at(image, 0x100c))

    def test_function_boundary_is_not_assumed(self):
        image = multiply(); image.functions = [0x1000, 0x1010]
        self.assertIsNone(m.analyze(image)['records'][0]['canonical_function'])


class ImportGates(unittest.TestCase):
    def setUp(self):
        self.image = multiply()
        self.report = m.analyze(self.image)
        self.rows = applier.validate(self.report, self.image, self.image.sha, self.image.base)
    def plan(self, **options):
        args = dict(function_owner=lambda a: 0x1000, incoming=lambda a: [a - 4], get_comment=lambda a: '', outgoing=lambda a: [])
        args.update(options)
        return applier.plan(self.rows, **args)
    def test_accepts_local_edge(self):
        self.assertEqual(len(self.plan()['accepted']), 1)
    def test_rejects_edited_target(self):
        report = copy.deepcopy(self.report); report['records'][0]['target'] = '0x1000'
        with self.assertRaises(ValueError): applier.validate(report, self.image, self.image.sha, self.image.base)
    def test_rejects_changed_window(self):
        self.image.data = bytes(4) + self.image.data[4:]
        with self.assertRaises(ValueError): applier.validate(self.report, self.image, self.image.sha, self.image.base)
    def test_rejects_identity_change(self):
        with self.assertRaises(ValueError): applier.validate(self.report, self.image, 'other', self.image.base)
    def test_rejects_middle_entry(self):
        self.assertEqual(self.plan(incoming=lambda a: [0x999])['skipped'][0]['reason'], 'unexpected_entry_into_proof')
    def test_preserves_comment(self):
        self.assertEqual(self.plan(get_comment=lambda a: 'analyst note')['skipped'][0]['reason'], 'existing_comment')
    def test_rejects_other_function(self):
        self.assertEqual(self.plan(function_owner=lambda a: a)['skipped'][0]['reason'], 'different_or_missing_function')
    def test_rejects_conflicting_edge(self):
        self.assertEqual(self.plan(outgoing=lambda a: [0x1004])['skipped'][0]['reason'], 'conflicting_jump_xref')
    def test_rejects_duplicate_record(self):
        self.report['records'] *= 2
        with self.assertRaises(ValueError): applier.validate(self.report, self.image, self.image.sha, self.image.base)


class MachOParsing(unittest.TestCase):
    def test_vm_file_offset_translation(self):
        b = bytearray(0x310)
        struct.pack_into('<8I', b, 0, 0xfeedfacf, 0x100000c, 0, 6, 2, 304, 0, 0)
        for pos, name, va, fo, size, sn, sectaddr, sectoff, sectsize, prot in [
            (32, b'__TEXT', 0x1000, 0, 0x214, b'__text', 0x1200, 0x200, 20, 5),
            (184, b'__ETC', 0x9000, 0x300, 16, b'__PII', 0x9000, 0x300, 16, 3)]:
            struct.pack_into('<II16sQQQQiiII', b, pos, 0x19, 152, name, va, size, fo, size, prot, prot, 1, 0)
            struct.pack_into('<16s16sQQI', b, pos + 72, sn, name, sectaddr, sectsize, sectoff)
        b[0x300:0x310] = b'0123456789abcdef'
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'image'; path.write_bytes(b)
            image = m.MachO(path)
            self.assertEqual(image.read(0x9000, 16), b'0123456789abcdef')
            self.assertFalse(image.readonly(0x9000, 4))
            self.assertEqual(image.text, (0x1200, 0x1214))
    def test_encrypted_input_rejected(self):
        data = struct.pack('<8I', 0xfeedfacf, 0x100000c, 0, 6, 1, 24, 0, 0) + struct.pack('<6I', 0x2c, 24, 0, 0, 1, 0)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'image'; path.write_bytes(data)
            with self.assertRaisesRegex(ValueError, 'Encrypted'): m.MachO(path)

    def test_truncated_header(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'image'; path.write_bytes(b'bad')
            with self.assertRaises(ValueError): m.MachO(path)


if __name__ == '__main__': unittest.main()
