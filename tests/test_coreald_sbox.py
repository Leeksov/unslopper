"""CoreALD native-slice proof tests, including rejection controls."""

import importlib.util
from pathlib import Path
import unittest


path = Path(__file__).resolve().parents[1] / "tools" / "coreald_sbox.py"
spec = importlib.util.spec_from_file_location("coreald_sbox", path)
module = importlib.util.module_from_spec(spec)
import sys
sys.modules[spec.name] = module
spec.loader.exec_module(module)


class Image:
    def __init__(self):
        self.instructions = {
            0x1000: ("AND", "X11", "X10", "#0xFF"),
            0x1004: ("ADRL", "X15", "table1", ""),
            0x1008: ("", "", "", ""),
            0x100C: ("LDRB", "W11", "[X15,X11]", ""),
            0x1010: ("MOV", "W15", "#0xEC", ""),
            0x1014: ("EOR", "W11", "W11", "W15"),
            0x1018: ("ADRL", "X15", "table2", ""),
            0x101C: ("", "", "", ""),
            0x1020: ("LDRB", "W11", "[X15,W11,UXTW]", ""),
            0x1024: ("EOR", "W10", "W10", "W11"),
            0x1028: ("AND", "W10", "W10", "#0xFF"),
        }
        self.imm = {(0x1004, 1): 0x2000, (0x1018, 1): 0x2100,
                    (0x1010, 1): 0xEC}
        inner = bytes((5 * x + 7) & 255 for x in range(256))
        outer = bytearray(256)
        for x in range(256):
            outer[inner[x] ^ 0xEC] = x ^ 0x45
        self.tables = {0x2000: inner, 0x2100: bytes(outer)}
        self.code = bytes(range(44))
        self.writable = set()
        self.entries = set()

    def mnem(self, ea):
        return self.instructions.get(ea, ("",))[0]

    def operand(self, ea, index):
        return self.instructions.get(ea, ("", "", "", ""))[index + 1]

    def operand_value(self, ea, index):
        return self.imm[(ea, index)]

    def read(self, ea, size):
        if ea in self.tables:
            return self.tables[ea][:size]
        if 0x1000 <= ea and ea + size <= 0x102C:
            return self.code[ea - 0x1000:ea - 0x1000 + size]
        return b""

    def readonly(self, ea, size):
        return ea in self.tables and ea not in self.writable and size == 256

    def same_function(self, a, b):
        return 0x1000 <= a <= b <= 0x1028

    def writes_register(self, ea, register):
        return self.instructions.get(ea, ("", ""))[1] == register

    def external_entry(self, ea, start, end):
        return ea in self.entries


class IndirectImage(Image):
    def __init__(self):
        self.instructions = {
            0x1000: ("LDR", "X16", "[X10,#(qword_3000 - 0x2800)]", ""),
            0x1004: ("ADD", "X16", "X16", "W14,UXTB"),
            0x1008: ("LDURB", "W16", "[X16,#-0xC]", ""),
            0x100C: ("MOV", "W17", "#0xEE", ""),
            0x1010: ("EOR", "W16", "W16", "W17"),
            0x1014: ("LDR", "X17", "[X10,#(qword_3010 - 0x2800)]", ""),
            0x1018: ("ADD", "X16", "X17", "X16"),
            0x101C: ("LDURB", "W16", "[X16,#-0xC]", ""),
            0x1020: ("EOR", "W14", "W16", "W14"),
            0x1024: ("AND", "W14", "W14", "#0xFF"),
        }
        self.imm = {(0x100C, 1): 0xEE}
        inner_ea, outer_ea = module.CACHE_BASE + 0x2000, module.CACHE_BASE + 0x2100
        inner = bytes((5 * x + 7) & 255 for x in range(256))
        outer = bytearray(256)
        for x in range(256):
            outer[inner[x] ^ 0xEE] = x ^ 0x8D
        self.tables = {
            inner_ea: inner,
            outer_ea: bytes(outer),
            0x3000: ((1 << 52) | (inner_ea + 12 - module.CACHE_BASE)).to_bytes(8, "little"),
            0x3010: ((1 << 52) | (outer_ea + 12 - module.CACHE_BASE)).to_bytes(8, "little"),
        }
        self.code = bytes(range(40))
        self.writable = set()
        self.entries = set()

    def read(self, ea, size):
        if ea in self.tables:
            return self.tables[ea][:size]
        if 0x1000 <= ea and ea + size <= 0x1028:
            return self.code[ea - 0x1000:ea - 0x1000 + size]
        return b""

    def readonly(self, ea, size):
        return ea in self.tables and ea not in self.writable and len(self.tables[ea]) >= size

    def same_function(self, a, b):
        return 0x1000 <= a <= b <= 0x1024

    def writes_register(self, ea, register):
        row = self.instructions.get(ea, ("", ""))
        return (row[0] not in {""} and module._same_register(row[1], register)
                and row[0] not in {"B", "RET"})


class NativeProof(unittest.TestCase):
    def test_real_shape_proves_low_byte_for_all_inputs(self):
        image = Image()
        proof = module.analyze_site(image, 0x1028)
        self.assertIsNotNone(proof)
        self.assertEqual((proof.inner, proof.outer, proof.xor_byte, proof.constant),
                         (0x2000, 0x2100, 0xEC, 0x45))
        self.assertTrue(proof.marker().startswith(module.MARKER))
        self.assertEqual(proof.fingerprint, module.proof_hash(
            proof.start, proof.site, proof.inner, proof.outer, proof.xor_byte,
            proof.constant, image.code, image.tables[0x2000], image.tables[0x2100]))

    def test_changed_data_changes_fingerprint(self):
        image = Image()
        original = module.analyze_site(image, 0x1028)
        image.code = image.code[:4] + b"\xff" + image.code[5:]
        changed = module.analyze_site(image, 0x1028)
        self.assertNotEqual(original.fingerprint, changed.fingerprint)

    def test_immediate_xor_variant(self):
        image = Image()
        image.instructions[0x1014] = ("EOR", "W11", "W11", "#0xEC")
        image.imm[(0x1014, 2)] = 0xEC
        self.assertEqual(module.analyze_site(image, 0x1028).constant, 0x45)

    def test_reject_mutable_or_nonpermutation_table(self):
        image = Image(); image.writable.add(0x2000)
        self.assertIsNone(module.analyze_site(image, 0x1028))
        image = Image(); image.tables[0x2100] = bytes(256)
        self.assertIsNone(module.analyze_site(image, 0x1028))

    def test_reject_register_clobber_branch_and_external_entry(self):
        image = Image(); image.instructions[0x101C] = ("ADD", "W10", "W10", "#1")
        self.assertIsNone(module.analyze_site(image, 0x1028))
        image = Image(); image.instructions[0x101C] = ("B", "0x1020", "", "")
        self.assertIsNone(module.analyze_site(image, 0x1028))
        image = Image(); image.entries.add(0x101C)
        self.assertIsNone(module.analyze_site(image, 0x1028))

    def test_reject_different_source_or_table_index(self):
        image = Image(); image.instructions[0x1000] = ("AND", "X11", "X12", "#0xFF")
        self.assertIsNone(module.analyze_site(image, 0x1028))
        image = Image(); image.instructions[0x1020] = (
            "LDRB", "W11", "[X15,W12,UXTW]", "")
        self.assertIsNone(module.analyze_site(image, 0x1028))

    def test_indirect_shared_cache_rebases_are_in_fingerprint(self):
        image = IndirectImage()
        proof = module.analyze_site(image, 0x1024)
        self.assertIsNotNone(proof)
        self.assertEqual((proof.constant, proof.xor_byte, proof.inner_slot, proof.outer_slot),
                         (0x8D, 0xEE, 0x3000, 0x3010))
        image.tables[0x3000] = ((1 << 52) | 0x200D).to_bytes(8, "little")
        changed = module.analyze_site(image, 0x1024)
        self.assertIsNone(changed)  # The shifted table is no longer a permutation window.

    def test_reject_authenticated_or_writable_rebase(self):
        image = IndirectImage()
        raw = int.from_bytes(image.tables[0x3000], "little")
        image.tables[0x3000] = (raw | (1 << 63)).to_bytes(8, "little")
        self.assertIsNone(module.analyze_site(image, 0x1024))
        image = IndirectImage(); image.writable.add(0x3010)
        self.assertIsNone(module.analyze_site(image, 0x1024))


if __name__ == "__main__":
    unittest.main()
