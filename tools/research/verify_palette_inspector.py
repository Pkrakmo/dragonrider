#!/usr/bin/env python3
"""Compare palette inspector output against independently read retail bytes."""
import argparse
import json
from pathlib import Path
import struct
import subprocess
import zlib


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('inspector', type=Path)
    parser.add_argument('root', type=Path)
    parser.add_argument('manifest', type=Path)
    args = parser.parse_args()
    items = [item for item in json.loads(args.manifest.read_text())['files'] if 'candidate_table' in item]
    matched = total = 0
    for item in items:
        path = args.root / item['path']
        table = item['candidate_table']
        with path.open('rb') as stream:
            stream.seek(table['offset'])
            data = stream.read(table['count'] * 14)
            if len(data) != table['count'] * 14:
                raise ValueError('truncated table')
            for index, (a, _b, c, offset, length) in enumerate(struct.iter_unpack('<HHHII', data)):
                if a != 0x30 or c != 0:
                    continue
                total += 1
                if length < 2 or offset + length > item['size']:
                    continue
                stream.seek(offset)
                count_bytes = stream.read(2)
                if len(count_bytes) != 2:
                    continue
                count = int.from_bytes(count_bytes, 'little')
                if count * 4 > length - 2:
                    continue
                entries = stream.read(count * 4)
                if len(entries) != count * 4:
                    continue
                result = subprocess.run([str(args.inspector), '--palette', str(index), str(path)],
                                        capture_output=True, text=True)
                expected = (f'Entries: {count}\nEntry CRC32: {zlib.crc32(entries):08x}\n'
                            f'Trailing bytes (unvalidated): {length - 2 - len(entries)}\n')
                matched += result.returncode == 0 and expected in result.stdout
    print(f'Private 0x0030 palette entry inspections: {matched}/{total} matched')
    if total == 0 or matched != total:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
