#!/usr/bin/env python3
"""Compare inspector texture headers with private selector-0x0040 measurements."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import struct
import subprocess


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
        with path.open('rb') as stream:
            stream.seek(record['start'] + 14)
            header = stream.read(24)
        if len(header) != 24:
            return False
        word14, word18 = struct.unpack_from('<II', header)
        word34 = struct.unpack_from('<I', header, 20)[0]
        result = subprocess.run([str(args.inspector), '--texture', str(record['index']), str(path)],
                                capture_output=True, text=True)
        expected = (f"Width: {record['a']}\nHeight: {record['b']}\nRow bytes: {record['c']}\n"
                    f"Bit depth: {record['d'] & 65535}\nStorage word: {record['word_at_46']}\n")
        words = (f"Word at +14: 0x{word14:08x}\nWord at +18: 0x{word18:08x}\n"
                 f"Word at +34: 0x{word34:08x}\n")
        return result.returncode == 0 and expected in result.stdout and words in result.stdout

    with ThreadPoolExecutor(max_workers=8) as pool:
        matched = sum(pool.map(check, items))
    print(f'Private 0x0040 texture headers: {matched}/{len(items)} matched')
    if matched != len(items):
        raise SystemExit(1)


if __name__ == '__main__':
    main()
