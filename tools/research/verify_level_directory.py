#!/usr/bin/env python3
"""Compare the level-directory inspector with private retail bytes and inventory hashes."""

import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import zlib


def decode(payload):
    cursor = 0

    def take(size):
        nonlocal cursor
        if size > len(payload) - cursor:
            raise ValueError("truncated payload")
        result = payload[cursor:cursor + size]
        cursor += size
        return result

    def u16():
        return struct.unpack("<H", take(2))[0]

    def u32():
        return struct.unpack("<I", take(4))[0]

    prefix = take(u16())
    word1, word2, count = u32(), u32(), u32()
    if count > 4096:
        raise ValueError("entry count exceeds verification limit")
    entries = []
    for _ in range(count):
        value = u32()
        name = take(u16())
        entries.append((value, len(name), zlib.crc32(name)))
    return (len(prefix), zlib.crc32(prefix), word1, word2, entries, len(payload) - cursor)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("inspector", type=Path)
    parser.add_argument("root", type=Path)
    parser.add_argument("inventory", type=Path)
    args = parser.parse_args()
    files = [item for item in json.loads(args.inventory.read_text())["files"]
             if Path(item["path"]).suffix.lower() == ".lvl" and "candidate_table" in item]
    if not files:
        parser.error("inventory contains no SRSC level candidates")
    failures = []
    counts = []
    tails = []
    gates = 0
    for item in files:
        path = args.root / item["path"]
        try:
            data = path.read_bytes()
            if hashlib.sha256(data).hexdigest() != item["sha256"]:
                raise ValueError("inventory hash mismatch")
            if len(data) < 12 or data[:4] != b"SRSC":
                raise ValueError("bad header")
            version, table, count = struct.unpack_from("<HIH", data, 4)
            if version != 0x100 or table > len(data) or count * 14 > len(data) - table:
                raise ValueError("bad table")
            records = list(struct.iter_unpack("<HHHII", data[table:table + count * 14]))
            matches = [(i, record) for i, record in enumerate(records) if record[:3] == (0, 0, 0)]
            if len(matches) != 1:
                raise ValueError("expected one directory tuple")
            index, (_, _, _, offset, length) = matches[0]
            if offset > len(data) or length > len(data) - offset:
                raise ValueError("bad record range")
            prefix_len, prefix_crc, word1, word2, entries, tail = decode(data[offset:offset + length])
            gate_records = [r for r in records if r[:3] == (0x402, 0, 0)]
            if len(gate_records) == 1:
                _, _, _, start, size = gate_records[0]
                if size >= 4 and start <= len(data) and size <= len(data) - start:
                    gates += struct.unpack_from("<I", data, start)[0] == 0x10c
            result = subprocess.run([str(args.inspector), "--level-directory", str(index), str(path)],
                                    capture_output=True, text=True)
            expected = (f"Level directory record: {index}\nLeading bytes: {prefix_len}\n"
                        f"Leading CRC32: {prefix_crc:08x}\nWord 1: {word1}\nWord 2: {word2}\n"
                        f"Entries: {len(entries)}\n")
            expected += "".join(f"Entry {i}: value={value} bytes={size} crc32={crc:08x}\n"
                                for i, (value, size, crc) in enumerate(entries))
            expected += f"Trailing bytes (unvalidated): {tail}\n"
            if result.returncode != 0 or expected not in result.stdout:
                raise ValueError("inspector mismatch")
            counts.append(len(entries))
            tails.append(tail)
        except (OSError, ValueError, struct.error) as error:
            failures.append(f"{item['path']}: {error}")
    print(f"Level directories: {len(counts)}/{len(files)} matched; "
          f"entries={sum(counts)}, entry count range={min(counts, default=0)}..{max(counts, default=0)}, "
          f"nonzero tails={sum(tail != 0 for tail in tails)}, gate 0x10c={gates}")
    if failures:
        print(*failures, sep="\n")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
