#!/usr/bin/env python3
"""Compare inspector base-row CRCs against independent Python decoding."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import zlib

from measure_level_0001 import safe_inventory_path

LIMIT = 32 * 1024 * 1024


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('inspector', type=Path)
    parser.add_argument('root', type=Path)
    parser.add_argument('manifest', type=Path)
    args = parser.parse_args()
    data = json.loads(args.manifest.read_text())
    root = args.root.resolve(strict=True)
    items = [f for f in data['files'] if f.get('records')]
    if not items:
        parser.error('manifest contains no selected records')

    def check(item):
        try:
            path = safe_inventory_path(root, item['path'])
            source = path.read_bytes()
            if hashlib.sha256(source).hexdigest() != item['sha256']:
                return 0
            with tempfile.TemporaryDirectory(prefix='dragonrider-texture-rows-') as directory:
                snapshot = Path(directory) / 'verified-sample.srsc'
                snapshot.write_bytes(source)
                matched = 0
                for record in item['records']:
                    if record['length'] > LIMIT:
                        continue
                    start, length = record['start'], record['length']
                    if start > len(source) or length > len(source) - start:
                        continue
                    payload = source[start:start + length]
                    if len(payload) < 50:
                        continue
                    size = record['b'] * record['c']
                    if size > LIMIT:
                        continue
                    control = int.from_bytes(payload[46:50], 'little')
                    if control == 0 or control & 0x80000000:
                        rows = payload[50:50 + size]
                    elif control == 1 and len(payload) >= 54:
                        stored_length = int.from_bytes(payload[50:54], 'little')
                        stream = payload[54:54 + stored_length]
                        if len(stream) != stored_length:
                            continue
                        inflater = zlib.decompressobj()
                        rows = inflater.decompress(stream, size + 1)
                        if not inflater.eof or inflater.unused_data or inflater.unconsumed_tail:
                            continue
                    else:
                        continue
                    if len(rows) != size:
                        continue
                    result = subprocess.run(
                        [str(args.inspector), '--texture-rows', str(record['index']), str(snapshot)],
                        capture_output=True, text=True)
                    expected = f'Base row bytes: {size}\nBase row CRC32: {zlib.crc32(rows):08x}\n'
                    matched += result.returncode == 0 and expected in result.stdout
                return matched
        except (KeyError, OSError, TypeError, ValueError, zlib.error):
            return 0

    with ThreadPoolExecutor(max_workers=8) as pool:
        matched = sum(pool.map(check, items))
    expected = sum(len(item['records']) for item in items)
    print(f'Private 0x0040 base rows: {matched}/{expected} matched')
    if matched != expected:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
