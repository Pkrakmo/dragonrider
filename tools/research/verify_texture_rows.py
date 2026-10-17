#!/usr/bin/env python3
"""Compare inspector base-row CRCs against independent Python decoding."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import subprocess
import zlib

LIMIT = 32 * 1024 * 1024


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('inspector', type=Path)
    parser.add_argument('root', type=Path)
    parser.add_argument('manifest', type=Path)
    args = parser.parse_args()
    data = json.loads(args.manifest.read_text())
    items = [(args.root / f['path'], record) for f in data['files'] for record in f['records']]
    if not items:
        parser.error('manifest contains no selected records')

    def check(item):
        path, record = item
        try:
            if record['length'] > LIMIT:
                return False
            with path.open('rb') as source:
                source.seek(record['start'])
                payload = source.read(record['length'])
            if len(payload) != record['length'] or len(payload) < 50:
                return False
            size = record['b'] * record['c']
            if size > LIMIT:
                return False
            control = int.from_bytes(payload[46:50], 'little')
            if control == 0 or control & 0x80000000:
                rows = payload[50:50 + size]
            elif control == 1 and len(payload) >= 54:
                length = int.from_bytes(payload[50:54], 'little')
                stream = payload[54:54 + length]
                if len(stream) != length:
                    return False
                inflater = zlib.decompressobj()
                rows = inflater.decompress(stream, size + 1)
                if not inflater.eof or inflater.unused_data or inflater.unconsumed_tail:
                    return False
            else:
                return False
            if len(rows) != size:
                return False
            result = subprocess.run([str(args.inspector), '--texture-rows', str(record['index']), str(path)],
                                    capture_output=True, text=True)
            expected = f'Base row bytes: {size}\nBase row CRC32: {zlib.crc32(rows):08x}\n'
            return result.returncode == 0 and expected in result.stdout
        except (OSError, ValueError, zlib.error):
            return False

    with ThreadPoolExecutor(max_workers=8) as pool:
        matched = sum(pool.map(check, items))
    print(f'Private 0x0040 base rows: {matched}/{len(items)} matched')
    if matched != len(items):
        raise SystemExit(1)


if __name__ == '__main__':
    main()
