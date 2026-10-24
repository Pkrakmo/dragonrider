#!/usr/bin/env python3
"""Compare palette inspector output against independently read retail bytes."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import tempfile
import zlib

from measure_level_0001 import safe_inventory_path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('inspector', type=Path)
    parser.add_argument('root', type=Path)
    parser.add_argument('manifest', type=Path)
    args = parser.parse_args()
    root = args.root.resolve(strict=True)
    items = [item for item in json.loads(args.manifest.read_text())['files'] if 'candidate_table' in item]
    matched = total = 0
    for item in items:
        path = safe_inventory_path(root, item['path'])
        source = path.read_bytes()
        if (len(source) != item['size']
                or hashlib.sha256(source).hexdigest() != item['sha256']):
            raise ValueError('inventory size or hash mismatch')
        table = item['candidate_table']
        offset, record_count = table['offset'], table['count']
        if (type(offset) is not int or type(record_count) is not int or offset < 12
                or record_count <= 0 or offset > len(source)
                or record_count > (len(source) - offset) // 14):
            raise ValueError('invalid candidate table bounds')
        records = source[offset:offset + record_count * 14]
        if len(records) != record_count * 14:
            raise ValueError('truncated table')
        selected = []
        for index, (a, _b, c, start, length) in enumerate(struct.iter_unpack('<HHHII', records)):
            if a != 0x30 or c != 0:
                continue
            total += 1
            if length < 2 or start > len(source) or length > len(source) - start:
                continue
            count = int.from_bytes(source[start:start + 2], 'little')
            if count > (length - 2) // 4:
                continue
            entries = source[start + 2:start + 2 + count * 4]
            if len(entries) != count * 4:
                continue
            selected.append((index, count, entries, length))
        if not selected:
            continue
        with tempfile.TemporaryDirectory(prefix='dragonrider-palette-inspector-') as directory:
            snapshot = Path(directory) / 'verified-sample.srsc'
            snapshot.write_bytes(source)
            for index, count, entries, length in selected:
                result = subprocess.run([str(args.inspector), '--palette', str(index), str(snapshot)],
                                        capture_output=True, text=True)
                expected = (f'Entries: {count}\nEntry CRC32: {zlib.crc32(entries):08x}\n'
                            f'Trailing bytes (unvalidated): {length - 2 - len(entries)}\n')
                matched += result.returncode == 0 and expected in result.stdout
    print(f'Private 0x0030 palette entry inspections: {matched}/{total} matched')
    if total == 0 or matched != total:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
