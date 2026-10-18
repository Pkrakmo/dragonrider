#!/usr/bin/env python3
"""Compare observed model records and optional inspector output with private retail data."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import zlib


def decode(points, groups):
    if len(points) < 2 or len(groups) < 2:
        raise ValueError('missing count')
    count = struct.unpack_from('<H', points)[0]
    point_end = 2 + count * 12
    if point_end > len(points):
        raise ValueError('truncated points')
    group_count = struct.unpack_from('<H', groups)[0]
    pos = 2
    corner_count = out_of_range = 0
    sizes = Counter()
    for _ in range(group_count):
        if len(groups) - pos < 6:
            raise ValueError('truncated group header')
        _, size, _ = struct.unpack_from('<HHH', groups, pos)
        pos += 6
        if size > (len(groups) - pos) // 10:
            raise ValueError('truncated corners')
        sizes[size] += 1
        corner_count += size
        for j in range(size):
            out_of_range += struct.unpack_from('<H', groups, pos + j * 10)[0] >= count
        pos += size * 10
    return count, group_count, corner_count, out_of_range, point_end, pos, sizes


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', type=Path)
    parser.add_argument('inventory', type=Path)
    parser.add_argument('--inspector', type=Path)
    args = parser.parse_args()
    root = args.root.resolve(strict=True)
    inventory = json.loads(args.inventory.read_text(encoding='utf-8'))
    candidates = [f for f in inventory['files'] if f['path'].lower().endswith('.mod')]
    if not candidates:
        raise ValueError('inventory contains no model containers')
    totals = Counter()
    group_sizes = Counter()
    for item in candidates:
        path = (root / item['path']).resolve(strict=True)
        if not path.is_relative_to(root) or not path.is_file():
            raise ValueError('inventory path escapes root or is not a file')
        data = path.read_bytes()
        if len(data) != item['size'] or hashlib.sha256(data).hexdigest() != item['sha256']:
            raise ValueError('inventory length or hash mismatch')
        if len(data) < 12 or data[:4] != b'SRSC':
            raise ValueError('invalid SRSC header')
        version, table, count = struct.unpack_from('<HIH', data, 4)
        if version != 0x100 or table > len(data) or count * 14 > len(data) - table:
            raise ValueError('invalid SRSC table')
        entries = list(struct.iter_unpack('<HHHII', data[table:table + count * 14]))
        for index, entry in enumerate(entries):
            if entry[0] != 0x200:
                continue
            if index + 3 >= len(entries):
                raise ValueError('model record sequence truncated')
            sequence = entries[index:index + 4]
            if tuple(x[0] for x in sequence) != (0x200, 0x206, 0x203, 0x204):
                raise ValueError('unexpected model record sequence')
            if any(x[1:3] != entry[1:3] for x in sequence):
                raise ValueError('selector values differ in sequence')
            def payload(record):
                start, length = record[3:]
                if start > len(data) or length > len(data) - start:
                    raise ValueError('record range exceeds file')
                return data[start:start + length]
            points, groups = payload(sequence[2]), payload(sequence[3])
            point_count, group_count, corners, out_of_range, point_end, group_end, sizes = decode(points, groups)
            totals.update(models=1, points=point_count, groups=group_count, corners=corners,
                          out_of_range=out_of_range, point_tails=len(points) != point_end,
                          group_tails=len(groups) != group_end)
            group_sizes.update(sizes)
            if args.inspector:
                result = subprocess.run([str(args.inspector), '--model-geometry', str(index + 2), str(index + 3), str(path)],
                                        capture_output=True, text=True, check=True)
                expected = (f'Point record: {index + 2}\nGroup record: {index + 3}\nOther selectors match: yes\n'
                            f'Points: {point_count}\nGroups: {group_count}\nCorners: {corners}\n'
                            f'Out-of-range point indices: {out_of_range}\n'
                            f'Point CRC32: {zlib.crc32(points[:point_end]):08x}\n'
                            f'Group CRC32: {zlib.crc32(groups[:group_end]):08x}\n'
                            f'Point trailing bytes (unvalidated): {len(points) - point_end}\n'
                            f'Group trailing bytes (unvalidated): {len(groups) - group_end}\n')
                if result.stdout != expected:
                    raise ValueError('inspector output differs from independent decoder')
                totals['comparisons'] += 1
        totals['files'] += 1
    if not totals['models']:
        raise ValueError('no selected model records')
    print(f'files={totals["files"]} models={totals["models"]} points={totals["points"]} '
          f'groups={totals["groups"]} corners={totals["corners"]} out_of_range={totals["out_of_range"]} '
          f'point_tails={totals["point_tails"]} group_tails={totals["group_tails"]} '
          f'group_sizes={dict(sorted(group_sizes.items()))} inspector_comparisons={totals["comparisons"]}')


if __name__ == '__main__':
    main()
