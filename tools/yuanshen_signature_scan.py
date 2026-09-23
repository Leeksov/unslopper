"""Find libyuanshen.so 7.1 functions resembling two verified IDA problem sites.

Usage: python3 yuanshen_signature_scan.py /path/to/libyuanshen.so
Requires numpy and pyelftools. Read-only; does not open or modify an IDB.

Signatures are byte-level candidates. Check decoded instructions, table
contents, function ownership, and runtime table mutability before any rewrite.
"""

import argparse
import hashlib
import struct
from collections import Counter

import numpy as np
from elftools.elf.elffile import ELFFile


EXPECTED_SHA256 = "9d59283b3235ba5afe3f220d952133b9dbad49af6e88da16ae03ff6e3289171e"
B_NEXT = 0x14000001
BR_X8 = 0xD61F0100
LDR_PTR = 0xF8695908          # LDR X8, [X8, W9, UXTW #3]
LDR_PTR_SXTW = 0xF869D908     # LDR X8, [X8, W9, SXTW #3]
LDR_STRIDED = 0xF8696908      # LDR X8, [X8, X9]
LDR_SCALED = 0xF8697908       # LDR X8, [X8, X9, LSL #3]
LDRSW_REL = 0xB8AB7949       # LDRSW X9, [X10, X11, LSL #2]
ADD_REL = 0x8B090108         # ADD X8, X8, X9


def _hash(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _fde_starts(elf):
    section = elf.get_section_by_name(".eh_frame_hdr")
    data = section.data()
    count = struct.unpack_from("<I", data, 8)[0]
    pairs = np.frombuffer(data, dtype="<i4", count=2 * count, offset=12)
    starts = pairs[::2].astype(np.int64) + section["sh_addr"]
    if np.any(starts[1:] < starts[:-1]):
        raise ValueError("Unwind lookup table is not sorted")
    return starts


def _top_functions(addresses, starts, limit=12):
    if not len(addresses):
        return []
    indices = np.searchsorted(starts, addresses, side="right") - 1
    indices = indices[indices >= 0]
    ranked = Counter(int(index) for index in indices)
    return [(int(starts[index]), int(starts[index + 1]), n)
            for index, n in ranked.most_common(limit) if index + 1 < len(starts)]


def _function_counts(addresses, starts):
    if not len(addresses):
        return Counter()
    indices = np.searchsorted(starts, addresses, side="right") - 1
    return Counter(int(index) for index in indices if 0 <= index < len(starts) - 1)


def _pointer_table_base(words, section_start, index):
    """Decode ADRP X8; ADD X8, X8, #imm immediately before LDR/BR."""
    if index < 3:
        return None
    adrp = int(words[index - 3])
    add = int(words[index - 2])
    if adrp & 0x9F00001F != 0x90000008:
        return None
    if add & 0xFF8003FF != 0x91000108:
        return None
    pc = section_start + (index - 3) * 4
    page_delta = (((adrp >> 5) & 0x7FFFF) << 2) | ((adrp >> 29) & 3)
    if page_delta & (1 << 20):
        page_delta -= 1 << 21
    immediate = (add >> 10) & 0xFFF
    if add & (1 << 22):
        immediate <<= 12
    return (pc & ~0xFFF) + (page_delta << 12) + immediate


def _addresses(indices, section_start):
    return section_start + indices.astype(np.int64) * 4


def scan(path):
    digest = _hash(path)
    if digest != EXPECTED_SHA256:
        raise ValueError("Unexpected SHA-256 %s; signatures are pinned to 7.1" % digest)
    with open(path, "rb") as stream:
        elf = ELFFile(stream)
        starts = _fde_starts(elf)
        print("SHA-256:", digest)
        print("Unwind entries:", len(starts))
        for section_name in (".text", "il2cpp"):
            section = elf.get_section_by_name(section_name)
            words = np.memmap(path, dtype="<u4", mode="r",
                              offset=section["sh_offset"], shape=(section["sh_size"] // 4,))
            b_next = np.flatnonzero(words == B_NEXT)
            br = np.flatnonzero(words == BR_X8)
            pointer_uxtw = br[(br >= 3) & (words[br - 1] == LDR_PTR)]
            pointer_sxtw = br[(br >= 3) & (words[br - 1] == LDR_PTR_SXTW)]
            pointer = np.sort(np.concatenate((pointer_uxtw, pointer_sxtw)))
            strided = br[(br >= 4) &
                         ((words[br - 1] == LDR_STRIDED) |
                          (words[br - 1] == LDR_SCALED))]
            relative = br[(br >= 2) & (words[br - 1] == ADD_REL)
                          & (words[br - 2] == LDRSW_REL)]
            base = section["sh_addr"]
            tables = Counter(_pointer_table_base(words, base, int(i)) for i in pointer)
            print("\n%s: B +4=%d, BR X8=%d, pointer UXTW=%d, pointer SXTW=%d, "
                  "strided=%d, relative pattern=%d" %
                  (section_name, len(b_next), len(br), len(pointer_uxtw),
                   len(pointer_sxtw), len(strided), len(relative)))
            print("Pointer table bases:", [(hex(t) if t is not None else "unresolved", n)
                                           for t, n in tables.most_common(12)])
            for label, indices in (("pointer", pointer), ("relative", relative),
                                   ("B +4", b_next)):
                addresses = _addresses(indices, base)
                function_counts = _function_counts(addresses, starts)
                print("Distinct %s FDE functions: %d" % (label, len(function_counts)))
                print("Top %s functions (start, next FDE start, signature count):" % label)
                for start, end, count in _top_functions(addresses, starts):
                    print("  0x%X  0x%X  %d" % (start, end, count))
                if section_name == ".text" and label == "pointer":
                    compact = [(int(starts[i]), int(starts[i + 1]), n)
                               for i, n in function_counts.items()
                               if 5 <= n <= 20 and starts[i + 1] - starts[i] <= 0x4000]
                    compact.sort(key=lambda row: (-row[2], row[1] - row[0], row[0]))
                    print("Compact candidates (5–20 pointer sites, <=16 KiB):")
                    for start, end, count in compact[:12]:
                        print("  0x%X  0x%X  %d" % (start, end, count))
                    sample_like = [(int(starts[i]), int(starts[i + 1]), n)
                                   for i, n in function_counts.items()
                                   if 5 <= n <= 10 and starts[i + 1] - starts[i] <= 0x2000]
                    sample_like.sort(key=lambda row:
                                     (abs(row[2] - 6), abs((row[1] - row[0]) - 0x1424), row[0]))
                    print("Closest in size and site count to sub_6A44C1C:")
                    for start, end, count in sample_like[:12]:
                        print("  0x%X  0x%X  %d" % (start, end, count))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", help="Path to the exact libyuanshen.so 7.1 sample")
    args = parser.parse_args()
    scan(args.binary)
