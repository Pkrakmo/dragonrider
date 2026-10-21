#!/usr/bin/env python3
"""Independently compare new-object 0x0302 framing with an inspector."""
import argparse
import json
from pathlib import Path
import struct
import subprocess
import zlib

from measure_0102_model_candidates import table
from measure_srsc_prefix_selector import read_verified


def expected(payload, index):
    if len(payload) < 2:
        raise ValueError('short prefix')
    prefix_len = int.from_bytes(payload[:2], 'little')
    start = 2 + prefix_len
    if start + 32 > len(payload):
        raise ValueError('short header')
    values = struct.unpack_from('<IHHIIIIII', payload, start)
    first, word1, word2, *rest = values
    fields, mode = rest[:5], rest[5]
    offset = start + 32
    if mode:
        if offset + 4 > len(payload):
            raise ValueError('short stored length')
        size = int.from_bytes(payload[offset:offset + 4], 'little')
        offset += 4
    else:
        size = fields[4]
    if size > 32 * 1024 * 1024 or size > len(payload) - offset:
        raise ValueError('body exceeds bound')
    crc = lambda b: f'{zlib.crc32(b):08x}'
    return '\n'.join((f'Record: {index}', f'Prefix bytes: {prefix_len}',
                      f'Prefix CRC32: {crc(payload[2:start])}', f'First dword: {first:08x}',
                      f'Words: {word1} {word2}',
                      'Following dwords: ' + ' '.join(f'{x:08x}' for x in fields),
                      f'Mode: {mode}', f'Body bytes: {size}',
                      f'Body CRC32: {crc(payload[offset:offset + size])}',
                      f'Trailing bytes (unvalidated): {len(payload) - offset - size}', ''))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', type=Path)
    parser.add_argument('inventory', type=Path)
    parser.add_argument('inspector', type=Path)
    args = parser.parse_args()
    root = args.root.resolve(strict=True)
    inspector = args.inspector.resolve(strict=True)
    entries = json.loads(args.inventory.read_text(encoding='utf-8'))['files']
    if not entries or any(e['status'] != 'examined' for e in entries):
        raise ValueError('empty or incomplete inventory')
    count = files = 0
    for entry in entries:
        data = read_verified(root, entry)
        end, records = table(data)
        found = False
        for index, (kind, _, _, offset, length) in enumerate(records):
            if kind != 0x0302:
                continue
            if offset < 12 or offset > end or length > end - offset:
                raise ValueError('selected record outside payload')
            want = expected(data[offset:offset + length], index)
            proc = subprocess.run([str(inspector), '--record-0302-new', str(index), str(root / entry['path'])],
                                  capture_output=True, text=True, check=True)
            if proc.stdout != want:
                raise ValueError(f'inspector mismatch at record {index}')
            count += 1
            found = True
        files += found
    print(f'files examined: {len(entries)}; files with 0x0302: {files}; records matched: {count}')


if __name__ == '__main__':
    main()
