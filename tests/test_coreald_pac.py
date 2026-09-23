"""Format-13 pointer decoding regression tests from the audited IDB."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from coreald_pac import decode_shared_cache_auth_rebase, decode_shared_cache_rebase


class SharedCachePointerTests(unittest.TestCase):
    def test_authenticated_code_pointer(self):
        pointer = decode_shared_cache_auth_rebase(0x80139D34C2511324)
        self.assertEqual(pointer.target, 0x242511324)
        self.assertEqual(pointer.diversity, 0xE74D)
        self.assertEqual((pointer.addr_div, pointer.key_is_data), (0, 0))

    def test_two_distinct_null_dispatch_targets(self):
        first = decode_shared_cache_auth_rebase(0x80121A74C252FBB4)
        second = decode_shared_cache_auth_rebase(0x80121A74C252FBAC)
        self.assertEqual((first.target, second.target),
                         (0x24252FBB4, 0x24252FBAC))
        self.assertEqual((first.diversity, second.diversity),
                         (0x869D, 0x869D))

    def test_auth_and_unauth_formats_do_not_mix(self):
        self.assertIsNone(decode_shared_cache_auth_rebase(0x1000010561CA20))
        self.assertIsNone(decode_shared_cache_rebase(0x80139D34C2511324))
        self.assertEqual(decode_shared_cache_rebase(0x1000010561CA20),
                         0x28561CA20)

    def test_unauth_rebase_rejects_high_bits(self):
        self.assertIsNone(decode_shared_cache_rebase(1 << 42))
        self.assertIsNone(decode_shared_cache_rebase(1 << 34))
        self.assertIsNone(decode_shared_cache_auth_rebase(1 << 64))


if __name__ == "__main__":
    unittest.main()
