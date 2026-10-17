#!/usr/bin/env python3
"""Measure selector (1,0,0) block framing in hashed private level files."""

import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import zlib

MAX_COUNT = 4096
MAX_BLOCK = 32 * 1024 * 1024


def measure(payload, on_cell=None, on_grid=None, on_cell_detail=None):
    pos = 0

    def take(n):
        nonlocal pos
        if n < 0 or n > len(payload) - pos:
            raise ValueError("truncated level record")
        result = payload[pos:pos + n]
        pos += n
        return result

    def u32():
        return struct.unpack("<I", take(4))[0]

    count = u32()
    if count > MAX_COUNT:
        raise ValueError("outer count exceeds limit")
    sizes = []
    inner_total = 0
    for _ in range(count):
        first = struct.unpack("<7I", take(28))
        width, height = first[1:3]
        # Dimensions are used in signed arithmetic on the traced path.
        if width > MAX_BLOCK or height > MAX_BLOCK:
            raise ValueError("dimension exceeds limit")
        size = 4 * (width + 1) * (height + 1) + 26 * width * height
        if size > MAX_BLOCK:
            raise ValueError("decoded block exceeds limit")
        sizes.append((size, 4 * (width + 1) * (height + 1), first))
        take(struct.unpack("<H", take(2))[0])
        take(24)
        inner = u32()
        if inner > MAX_COUNT:
            raise ValueError("inner count exceeds limit")
        inner_total += inner
        take(inner * 4)
    storage = u32()
    compressed = 0 < storage < 0x80000000
    streams = 0
    checksum = 0
    grid_items = 0
    minimum = maximum = None
    cells = flag0 = flag1 = negative_first = negative_second = 0
    for entry_index, (size, grid_bytes, prefix) in enumerate(sizes):
        length_word = u32()
        if compressed:
            if length_word > MAX_BLOCK:
                raise ValueError("stored block exceeds limit")
            block = take(length_word)
            decoder = zlib.decompressobj()
            decoded = decoder.decompress(block, size + 1)
            if (len(decoded) != size or not decoder.eof or decoder.unused_data
                    or decoder.unconsumed_tail):
                raise ValueError("zlib stream length or termination mismatch")
            streams += 1
        else:
            # The traced raw path reads the derived size, not the length word.
            decoded = take(size)
        checksum = zlib.crc32(decoded, checksum)
        for point_index, (word0, word) in enumerate(struct.iter_unpack("<HH", decoded[:grid_bytes])):
            if on_grid is not None:
                on_grid(entry_index, prefix, point_index, word0, word)
            value = 2 * word - 65536
            minimum = value if minimum is None else min(minimum, value)
            maximum = value if maximum is None else max(maximum, value)
            grid_items += 1
        for cell_index, cell in enumerate(struct.iter_unpack("<Hii8H", decoded[grid_bytes:])):
            if on_cell_detail is not None:
                on_cell_detail(entry_index, prefix, cell_index, cell)
            flags, first, second = cell[:3]
            if on_cell is not None:
                on_cell(first, second)
            cells += 1
            flag0 += bool(flags & 1)
            flag1 += bool(flags & 2)
            negative_first += first < 0
            negative_second += second < 0
    return (storage, count, streams, len(payload) - pos, sum(size for size, _, _ in sizes),
            checksum, inner_total, grid_items, minimum, maximum, cells, flag0, flag1,
            negative_first, negative_second)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path)
    parser.add_argument("inventory", type=Path)
    parser.add_argument("--inspector", type=Path, help="compare the C++ inspector summary")
    args = parser.parse_args()
    files = [item for item in json.loads(args.inventory.read_text())["files"]
             if Path(item["path"]).suffix.lower() == ".lvl" and "candidate_table" in item]
    if not files:
        parser.error("inventory contains no SRSC level candidates")
    successes, blocks, streams, tails, words, failures = 0, 0, 0, [], {}, []
    all_items = 0
    ranges = []
    cell_totals = [0] * 5
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
            records = struct.iter_unpack("<HHHII", data[table:table + count * 14])
            matches = [(i, r) for i, r in enumerate(records) if r[:3] == (1, 0, 0)]
            if len(matches) != 1:
                raise ValueError("expected one (1,0,0) record")
            index, (_, _, _, offset, length) = matches[0]
            if offset > len(data) or length > len(data) - offset:
                raise ValueError("bad record range")
            (storage, count, stream_count, tail, decoded_size, checksum, inner_total,
             grid_items, minimum, maximum, cells, flag0, flag1,
             negative_first, negative_second) = measure(data[offset:offset + length])
            if args.inspector:
                result = subprocess.run([str(args.inspector), "--level-blocks", str(index),
                                         str(args.root / item["path"])], capture_output=True, text=True)
                expected = (f"Level blocks record: {index}\nEntries: {count}\nInner values: {inner_total}\n"
                            f"Storage word: {storage}\nDecoded bytes: {decoded_size}\n"
                            f"Decoded CRC32: {checksum:08x}\nTrailing bytes (unvalidated): {tail}\n"
                            f"Grid items: {grid_items}\nTransformed word range: "
                            f"{f'{minimum}..{maximum}' if minimum is not None else 'none'}\n"
                            f"Cell items: {cells}\nCell flag bit 0: {flag0}\nCell flag bit 1: {flag1}\n"
                            f"Negative cell dword at +2: {negative_first}\n"
                            f"Negative cell dword at +6: {negative_second}\n")
                if result.returncode != 0 or expected not in result.stdout:
                    raise ValueError("inspector summary mismatch: " + result.stderr.strip())
            successes += 1
            blocks += count
            streams += stream_count
            tails.append(tail)
            words[storage] = words.get(storage, 0) + 1
            all_items += grid_items
            if minimum is not None:
                ranges.append((minimum, maximum))
            cell_totals = [x + y for x, y in zip(cell_totals,
                           (cells, flag0, flag1, negative_first, negative_second))]
        except (OSError, ValueError, struct.error, zlib.error) as error:
            failures.append(f"{item['path']}: {error}")
    print(f"Level records: {successes}/{len(files)}; blocks={blocks}, "
          f"complete zlib streams={streams}; storage words={dict(sorted(words.items()))}; "
          f"trailing bytes range={min(tails, default=0)}..{max(tails, default=0)}; "
          f"grid items={all_items}, transformed word range="
          f"{min((r[0] for r in ranges), default=0)}..{max((r[1] for r in ranges), default=0)}; "
          f"cells, bit0, bit1, negative +2, negative +6={cell_totals}")
    if failures:
        print(*failures, sep="\n")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
