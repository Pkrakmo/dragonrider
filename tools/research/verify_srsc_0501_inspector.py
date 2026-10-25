#!/usr/bin/env python3
"""Compare the 0x0501 inspector output against hash-verified SRSC snapshots."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import tempfile
import zlib

from measure_level_0001 import safe_inventory_path
from measure_srsc_0501_payloads import validate_unique_inventory_paths


MAX_OBSERVED = 2 + 65535 + 7 * 4


def expected_output(data, index, record):
    """Build metadata-only CLI output from a verified immutable byte snapshot."""
    kind, _, _, offset, length = record
    if kind != 0x0501:
        raise ValueError("record selector is not 0x0501")
    amount = min(length, MAX_OBSERVED)
    payload = data[offset:offset + amount]
    if len(payload) != amount:
        raise ValueError("record payload exceeds verified snapshot")
    if len(payload) < 2:
        raise ValueError("truncated observed prefix length")
    prefix_length = struct.unpack_from("<H", payload)[0]
    consumed = 2 + prefix_length + 28
    if consumed > len(payload):
        raise ValueError("truncated observed 0x0501 prefix")
    prefix = payload[2:2 + prefix_length]
    words = struct.unpack_from("<7I", payload, 2 + prefix_length)
    window_remainder = payload[consumed:]
    return (
        f"Record: {index}\nSkipped bytes: {prefix_length}\n"
        f"Skipped bytes CRC32: {zlib.crc32(prefix):08x}\n"
        f"Raw dwords:{''.join(f' {word}' for word in words)}\n"
        f"Observed bytes consumed: {consumed}\n"
        f"Opaque remainder bytes: {length - consumed}\n"
        f"Read-window remainder CRC32: {zlib.crc32(window_remainder):08x}\n"
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', type=Path)
    parser.add_argument('inventory', type=Path)
    parser.add_argument('inspector', type=Path)
    args = parser.parse_args()
    root = args.root.resolve(strict=True)
    entries = json.loads(args.inventory.read_text(encoding='utf-8'))['files']
    if not isinstance(entries, list) or not entries:
        raise ValueError('inventory must contain a non-empty files list')
    validate_unique_inventory_paths(root, entries)
    comparisons = files_with_records = 0
    with tempfile.TemporaryDirectory(prefix='dragonrider-srsc-0501-') as directory:
        snapshot = Path(directory) / 'verified-sample.srsc'
        for item in entries:
            if not isinstance(item, dict) or item.get('status') != 'examined':
                raise ValueError('inventory contains an unexamined file')
            path = safe_inventory_path(root, item.get('path'))
            data = path.read_bytes()
            if len(data) != item.get('file_size') or hashlib.sha256(data).hexdigest() != item.get('sha256'):
                raise ValueError('inventory length or hash mismatch')
            if len(data) < 12 or data[:4] != b'SRSC':
                raise ValueError('invalid SRSC header')
            version, table, count = struct.unpack_from('<HIH', data, 4)
            if version != 0x0100 or not count or table < 12 or table > len(data) or count > (len(data) - table) // 14:
                raise ValueError('invalid SRSC table')
            records = list(struct.iter_unpack('<HHHII', data[table:table + count * 14]))
            if any(start < 12 or start > table or length > table - start for _, _, _, start, length in records):
                raise ValueError('record outside payload area')
            selected = [(index, row) for index, row in enumerate(records) if row[0] == 0x0501]
            if not selected:
                continue
            files_with_records += 1
            snapshot.write_bytes(data)
            for index, record in selected:
                expected = expected_output(data, index, record)
                result = subprocess.run(
                    [str(args.inspector), '--record-0501-observed-prefix', str(index), str(snapshot)],
                    capture_output=True, text=True, check=True,
                )
                if result.stdout != expected:
                    raise ValueError('inspector output differs from independent snapshot decoder')
                comparisons += 1
    if not comparisons:
        raise ValueError('no selected records')
    print(f'files={len(entries)} files_with_0501={files_with_records} comparisons={comparisons}')


if __name__ == '__main__':
    main()
