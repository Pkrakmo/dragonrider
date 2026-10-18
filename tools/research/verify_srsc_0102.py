#!/usr/bin/env python3
"""Compare 0x0102 inspector fields against a hash-checked private inventory."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import zlib


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', type=Path)
    parser.add_argument('inventory', type=Path)
    parser.add_argument('inspector', type=Path)
    args = parser.parse_args()
    root = args.root.resolve(strict=True)
    entries = json.loads(args.inventory.read_text(encoding='utf-8'))['files']
    files_with_records = comparisons = tails = 0
    for item in entries:
        if item['status'] != 'examined':
            raise ValueError('inventory contains unexamined files')
        path = (root / item['path']).resolve(strict=True)
        if not path.is_relative_to(root) or not path.is_file():
            raise ValueError('inventory path escapes root or is not a file')
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
        found = False
        for index, (kind, _, third, start, length) in enumerate(records):
            if kind != 0x102:
                continue
            found = True
            payload = data[start:start + length]
            if len(payload) < 2:
                raise ValueError('short prefix length')
            prefix_length = struct.unpack_from('<H', payload)[0]
            end = 2 + prefix_length
            if len(payload) - end < 10:
                raise ValueError('truncated prefix or fields')
            prefix = payload[2:end]
            skipped, raw, following, last = struct.unpack_from('<HIHH', payload, end)
            tail = len(payload) - end - 10
            expected = (f'Record: {index}\nPrefix bytes: {prefix_length}\nPrefix CRC32: {zlib.crc32(prefix):08x}\n'
                        f'Skipped word: {skipped}\nThird selector: {third}\nRaw dword: {raw}\n'
                        f'Dword low word: {raw & 65535}\nDword high word: {raw >> 16}\n'
                        f'Following word: {following}\nLast skipped word: {last}\n'
                        f'Trailing bytes (unvalidated): {tail}\n')
            result = subprocess.run([str(args.inspector), '--record-0102', str(index), str(path)],
                                    capture_output=True, text=True, check=True)
            if result.stdout != expected:
                raise ValueError('inspector output differs from independent decoder')
            comparisons += 1
            tails += tail != 0
        files_with_records += found
    if not comparisons:
        raise ValueError('no selected records')
    print(f'files={len(entries)} files_with_0102={files_with_records} comparisons={comparisons} records_with_tails={tails}')


if __name__ == '__main__':
    main()
