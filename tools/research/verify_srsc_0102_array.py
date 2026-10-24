#!/usr/bin/env python3
"""Compare 0x0102 array diagnostics against hash-checked private inputs."""
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
    parser.add_argument('root', type=Path)
    parser.add_argument('inventory', type=Path)
    parser.add_argument('inspector', type=Path)
    args = parser.parse_args()
    root = args.root.resolve(strict=True)
    entries = json.loads(args.inventory.read_text(encoding='utf-8'))['files']
    files_with_records = comparisons = total_entries = 0
    with tempfile.TemporaryDirectory(prefix='dragonrider-srsc-0102-array-') as directory:
        snapshot = Path(directory) / 'verified-sample.srsc'
        for item in entries:
            if item['status'] != 'examined':
                raise ValueError('inventory contains unexamined files')
            path = safe_inventory_path(root, item['path'])
            data = path.read_bytes()
            if len(data) != item['file_size'] or hashlib.sha256(data).hexdigest() != item['sha256']:
                raise ValueError('inventory length or hash mismatch')
            if len(data) < 12 or data[:4] != b'SRSC':
                raise ValueError('invalid SRSC header')
            version, table, count = struct.unpack_from('<HIH', data, 4)
            if version != 0x100 or not count or table > len(data) or count * 14 > len(data) - table:
                raise ValueError('invalid SRSC table')
            records = list(struct.iter_unpack('<HHHII', data[table:table + count * 14]))
            if any(start > len(data) or length > len(data) - start for _, _, _, start, length in records):
                raise ValueError('record outside file')
            if any(kind == 0x102 for kind, _, _, _, _ in records):
                snapshot.write_bytes(data)
            found = False
            for index, (kind, _, _, start, length) in enumerate(records):
                if kind != 0x102:
                    continue
                found = True
                payload = data[start:start + length]
                if len(payload) < 2:
                    raise ValueError('short prefix length')
                prefix_length = struct.unpack_from('<H', payload)[0]
                pos = 2 + prefix_length + 10
                if pos > len(payload) or len(payload) - pos < 8:
                    raise ValueError('truncated prefix or array header')
                compared, n = struct.unpack_from('<II', payload, pos)
                pos += 8
                if n > 1000000 or n > (len(payload) - pos) // 4:
                    raise ValueError('array outside payload or inspector limit')
                end = pos + n * 4
                expected = (f'Record: {index}\nCompared dword: {compared}\nArray count: {n}\n'
                            f'Array CRC32: {zlib.crc32(payload[pos:end]):08x}\n'
                            f'Trailing bytes (unvalidated): {len(payload) - end}\n')
                result = subprocess.run([str(args.inspector), '--record-0102-array', str(index), str(snapshot)],
                                        capture_output=True, text=True, check=True)
                if result.stdout != expected:
                    raise ValueError('inspector output differs from independent decoder')
                comparisons += 1
                total_entries += n
            files_with_records += found
    if not comparisons:
        raise ValueError('no selected records')
    print(f'files={len(entries)} files_with_0102={files_with_records} comparisons={comparisons} entries={total_entries}')


if __name__ == '__main__':
    main()
