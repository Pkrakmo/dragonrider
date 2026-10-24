#!/usr/bin/env python3
"""Compare inspector texture headers with private selector-0x0040 measurements."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import tempfile

from measure_level_0001 import safe_inventory_path


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
            with tempfile.TemporaryDirectory(prefix='dragonrider-texture-header-') as directory:
                snapshot = Path(directory) / 'verified-sample.srsc'
                snapshot.write_bytes(source)
                matched = 0
                for record in item['records']:
                    start, length = record['start'], record['length']
                    if start > len(source) or length > len(source) - start or length < 38:
                        continue
                    header = source[start + 14:start + 38]
                    word14, word18 = struct.unpack_from('<II', header)
                    word34 = struct.unpack_from('<I', header, 20)[0]
                    result = subprocess.run(
                        [str(args.inspector), '--texture', str(record['index']), str(snapshot)],
                        capture_output=True, text=True)
                    expected = (f"Width: {record['a']}\nHeight: {record['b']}\nRow bytes: {record['c']}\n"
                                f"Bit depth: {record['d'] & 65535}\nStorage word: {record['word_at_46']}\n")
                    words = (f"Word at +14: 0x{word14:08x}\nWord at +18: 0x{word18:08x}\n"
                             f"Word at +34: 0x{word34:08x}\n")
                    matched += result.returncode == 0 and expected in result.stdout and words in result.stdout
                return matched
        except (KeyError, OSError, TypeError, ValueError):
            return 0

    with ThreadPoolExecutor(max_workers=8) as pool:
        matched = sum(pool.map(check, items))
    expected = sum(len(item['records']) for item in items)
    print(f'Private 0x0040 texture headers: {matched}/{expected} matched')
    if matched != expected:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
