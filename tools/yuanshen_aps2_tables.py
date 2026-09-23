"""Read relocated pointer tables from libyuanshen.so 7.1 without IDA.

Usage: python3 yuanshen_aps2_tables.py /path/to/libyuanshen.so 0x158D76E0 22
Requires pyelftools. Read-only. The APS2 group decoder follows Android
bionic's packed relocation iterator; output addresses assume ELF load bias 0.
"""

import argparse
import hashlib

from elftools.elf.elffile import ELFFile


EXPECTED_SHA256 = "9d59283b3235ba5afe3f220d952133b9dbad49af6e88da16ae03ff6e3289171e"
KNOWN_TABLE = 0x1590E6F0
KNOWN_TARGETS = (
    0x6A44D6C, 0x6A44C78, 0x6A45E58, 0x6A459C0,
    0x6A45A58, 0x6A45E5C, 0x6A459D4, 0x6A45F68,
    0x6A45990, 0x6A45984, 0x6A45FC8, 0x6A44F28,
    0x6A45FF0, 0x6A44C8C, 0x6A45FE4, 0x6A45918,
)


def _sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


class Sleb128:
    def __init__(self, data):
        self.data = data
        self.offset = 0

    def pop(self):
        result = 0
        shift = 0
        while True:
            if self.offset >= len(self.data):
                raise ValueError("Truncated APS2 SLEB128 stream")
            byte = self.data[self.offset]
            self.offset += 1
            result |= (byte & 0x7F) << shift
            shift += 7
            if byte < 0x80:
                if byte & 0x40:
                    result -= 1 << shift
                return result
            if shift > 70:
                raise ValueError("Oversized APS2 SLEB128 integer")


def _packed_relocations(data, requested):
    if data[:4] != b"APS2":
        raise ValueError("Missing APS2 header")
    decoder = Sleb128(data[4:])
    count = decoder.pop()
    offset = decoder.pop()
    if count < 0 or offset < 0:
        raise ValueError("Invalid APS2 relocation count or offset")
    info = 0
    addend = 0
    seen = 0
    found = {}
    while seen < count:
        group_size = decoder.pop()
        flags = decoder.pop()
        if group_size <= 0 or group_size > count - seen or flags & ~0xF:
            raise ValueError("Invalid APS2 group")
        group_delta = decoder.pop() if flags & 2 else 0
        if flags & 1:
            info = decoder.pop()
        if flags & 8 and flags & 4:
            addend += decoder.pop()
        elif not flags & 8:
            addend = 0
        for _ in range(group_size):
            offset += group_delta if flags & 2 else decoder.pop()
            if not flags & 1:
                info = decoder.pop()
            if flags & 8 and not flags & 4:
                addend += decoder.pop()
            if offset in requested:
                found[offset] = (info, addend)
        seen += group_size
    return count, found


def _read_table(path, table, count, start=None, end=None):
    if _sha256(path) != EXPECTED_SHA256:
        raise ValueError("This decoder is pinned to the exact 7.1 sample")
    requested = {table + 8 * i for i in range(count)}
    requested.update(KNOWN_TABLE + 8 * i for i in range(len(KNOWN_TARGETS)))
    with open(path, "rb") as stream:
        elf = ELFFile(stream)
        section = elf.get_section_by_name(".rela.dyn")
        relocation_count, found = _packed_relocations(section.data(), requested)
    known = tuple(found.get(KNOWN_TABLE + 8 * i, (None, None))[1]
                  for i in range(len(KNOWN_TARGETS)))
    if known != KNOWN_TARGETS:
        raise ValueError("APS2 decoder failed known 16-entry table validation: %s" % (known,))
    print("Decoded %d packed relocations; known 16-entry table validated" % relocation_count)
    if start is not None:
        if end is None or end <= start:
            raise ValueError("A valid --end must accompany --start")
        for i in range(count):
            address = table + 8 * i
            if address not in found:
                raise ValueError("No relocation for required slot %d" % i)
            info, addend = found[address]
            if info & 0xFFFFFFFF != 1027 or info >> 32 != 0 or not start <= addend < end:
                raise ValueError("Slot %d does not target the expected function" % i)
        print("All %d targets verified inside 0x%X–0x%X" % (count, start, end))
    for i in range(count):
        address = table + 8 * i
        if address not in found:
            print("%3d  0x%X  no APS2 relocation" % (i, address))
            continue
        info, addend = found[address]
        print("%3d  0x%X  type=%d sym=%d target=0x%X" %
              (i, address, info & 0xFFFFFFFF, info >> 32, addend))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary")
    parser.add_argument("table", type=lambda value: int(value, 0))
    parser.add_argument("count", type=int)
    parser.add_argument("--start", type=lambda value: int(value, 0), help="Expected function start")
    parser.add_argument("--end", type=lambda value: int(value, 0), help="Expected function end")
    args = parser.parse_args()
    if args.count <= 0 or args.count > 4096:
        parser.error("count must be 1..4096")
    _read_table(args.binary, args.table, args.count, args.start, args.end)
