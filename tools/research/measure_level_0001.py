#!/usr/bin/env python3
"""Measure the traced prefix of selector (1,0,0) in hashed US level files."""

import argparse
import hashlib
import json
from pathlib import Path
import struct


def decode_prefix(payload):
    """Decode only the first loop and leave subsequent record bytes opaque."""
    cursor = 0

    def take(size):
        nonlocal cursor
        if size < 0 or size > len(payload) - cursor:
            raise ValueError("truncated prefix")
        result = payload[cursor:cursor + size]
        cursor += size
        return result

    def word():
        return struct.unpack("<I", take(4))[0]

    count = word()
    if count > 4096:
        raise ValueError("outer count exceeds measurement limit")
    item_counts, names, indices = [], [], []
    for _ in range(count):
        take(7 * 4)
        name = take(struct.unpack("<H", take(2))[0])
        take(6 * 4)
        item_count = word()
        if item_count > 4096:
            raise ValueError("inner count exceeds measurement limit")
        values = struct.iter_unpack("<I", take(item_count * 4))
        indices.extend(value[0] for value in values)
        item_counts.append(item_count)
        names.append(len(name))
    return count, item_counts, names, indices, len(payload) - cursor


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path)
    parser.add_argument("inventory", type=Path)
    args = parser.parse_args()
    files = [item for item in json.loads(args.inventory.read_text())["files"]
             if Path(item["path"]).suffix.lower() == ".lvl" and "candidate_table" in item]
    if not files:
        parser.error("inventory contains no SRSC level candidates")
    counts, inner, names, tails = [], [], [], []
    indices_total = out_of_range = high_words = 0
    failures = []
    for item in files:
        try:
            data = (args.root / item["path"]).read_bytes()
            if hashlib.sha256(data).hexdigest() != item["sha256"]:
                raise ValueError("inventory hash mismatch")
            if len(data) < 12 or data[:4] != b"SRSC":
                raise ValueError("bad header")
            version, table, count = struct.unpack_from("<HIH", data, 4)
            if version != 0x100 or table > len(data) or count * 14 > len(data) - table:
                raise ValueError("bad table")
            records = list(struct.iter_unpack("<HHHII", data[table:table + count * 14]))
            matches = [record for record in records if record[:3] == (1, 0, 0)]
            if len(matches) != 1:
                raise ValueError("expected one (1,0,0) record")
            _, _, _, offset, length = matches[0]
            if offset > len(data) or length > len(data) - offset:
                raise ValueError("bad record range")
            outer, item_counts, name_lengths, values, tail = decode_prefix(data[offset:offset + length])
            counts.append(outer)
            inner.extend(item_counts)
            names.extend(name_lengths)
            tails.append(tail)
            indices_total += len(values)
            out_of_range += sum(value >= outer for value in values)
            high_words += sum(value > 0xffff for value in values)
        except (OSError, ValueError, struct.error) as error:
            failures.append(f"{item['path']}: {error}")
    print(f"Level prefixes: {len(counts)}/{len(files)}; "
          f"outer total={sum(counts)}, range={min(counts, default=0)}..{max(counts, default=0)}; "
          f"inner values={indices_total}, per-entry range={min(inner, default=0)}..{max(inner, default=0)}; "
          f"values >= outer count={out_of_range}, values > 65535={high_words}; "
          f"name length range={min(names, default=0)}..{max(names, default=0)}; "
          f"trailing bytes range={min(tails, default=0)}..{max(tails, default=0)}")
    if failures:
        print(*failures, sep="\n")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
