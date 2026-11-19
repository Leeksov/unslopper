#!/usr/bin/env python3
"""Independent native-byte checks for the read-only Valu ARM32 audit.

Usage: python3 tests/test_promon_thumb_audit.py /path/to/stage2_plus_data.so
The target image is deliberately not copied into this repository.
"""

import hashlib
import pathlib
import sys
import unittest

from capstone import CS_ARCH_ARM, CS_MODE_THUMB, Cs


EXPECTED_SHA256 = "776e99e7b60bf9803f7ed59afc46907e6a3e8d3c9a198a9b4ec101675d0406b0"
SITES = (
    (0x465654, 0x466504, 0x18555161,
     "b167821fe294fb47dff60e6f3d8be4c644fb320002566bb99cadf62ac8b80057",
     "f0125e8cf9a8443630ffe12f992eae0058bb8c7fdd1b0478a14095376f2af2c9",
     0x0B34F7E32F2234D1, 0xB7C4D4BF7CD51286),
    (0x1F92EA, 0x1FA1D8, 0x32094048,
     "51718987c48b783d6e85c488607cd2a33fa2109ce1aae0f893d023062617b25d",
     "56541f291cb39bb752abc5030f4502c33cbb85432143cdd634dd1d08dc55a9a1",
     0x32F3575B7801472A, 0xEAB260691F023B09),
)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def fnv64(data):
    h = 0xCBF29CE484222325
    for byte in data:
        h = ((h ^ byte) * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
    return h


def load_sample():
    if len(sys.argv) != 2:
        raise SystemExit("usage: test_promon_thumb_audit.py /path/to/stage2_plus_data.so")
    path = pathlib.Path(sys.argv[1])
    sys.argv[:] = sys.argv[:1]
    return path.read_bytes()


SAMPLE = load_sample()


class PromonThumbAuditTest(unittest.TestCase):
    def test_exact_sample_and_byte_windows(self):
        self.assertEqual(sha256(SAMPLE), EXPECTED_SHA256)
        for hub, pred, _, hub_sha, pred_sha, hub_fnv, pred_fnv in SITES:
            with self.subTest(hub=hex(hub)):
                self.assertEqual(sha256(SAMPLE[hub:hub + 64]), hub_sha)
                self.assertEqual(sha256(SAMPLE[pred:pred + 24]), pred_sha)
                self.assertEqual(fnv64(SAMPLE[hub:hub + 64]), hub_fnv)
                self.assertEqual(fnv64(SAMPLE[pred:pred + 24]), pred_fnv)
                mutated = bytearray(SAMPLE[hub:hub + 64])
                mutated[0] ^= 1
                self.assertNotEqual(sha256(mutated), hub_sha)
                self.assertNotEqual(fnv64(mutated), hub_fnv)

        self.assertEqual(fnv64(SAMPLE[0x451E40:0x451E80]), 0x90A3968796FE47D7)
        self.assertEqual(fnv64(SAMPLE[0x4657E8:0x465818]), 0xF4D1011491654268)

    def test_thumb_state_backedges_and_comparison_tree(self):
        decoder = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
        for hub, pred, state, _, _, _, _ in SITES:
            with self.subTest(hub=hex(hub)):
                pred_insns = list(decoder.disasm(SAMPLE[pred:pred + 24], pred))
                low = next(i for i in pred_insns if i.mnemonic == "movw" and i.op_str.startswith("r0,"))
                high = next(i for i in pred_insns if i.mnemonic == "movt" and i.op_str.startswith("r0,"))
                low_half = int(low.op_str.rsplit("#", 1)[1], 16)
                high_half = int(high.op_str.rsplit("#", 1)[1], 16)
                self.assertEqual(low_half | (high_half << 16), state)
                self.assertTrue(any(i.mnemonic == "b.w" and i.op_str == f"#{hub:#x}"
                                    for i in pred_insns))

                hub_insns = list(decoder.disasm(SAMPLE[hub:hub + 64], hub))
                self.assertTrue(any(i.mnemonic == "cmp" for i in hub_insns[:10]))
                self.assertTrue(any(i.mnemonic.startswith("b") and i.mnemonic != "b"
                                    for i in hub_insns[:10]))


if __name__ == "__main__":
    unittest.main()
