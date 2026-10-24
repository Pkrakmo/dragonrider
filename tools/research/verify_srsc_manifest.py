#!/usr/bin/env python3
"""Compare all physical manifest ranges with independently decoded private SRSC tables."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import tempfile

from measure_level_0001 import safe_inventory_path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("inspector", type=Path)
    parser.add_argument("root", type=Path)
    parser.add_argument("inventory", type=Path)
    args = parser.parse_args()
    items = [entry for entry in json.loads(args.inventory.read_text())["files"]
             if "candidate_table" in entry]
    if not items:
        parser.error("inventory contains no candidate tables")
    root = args.root.resolve(strict=True)
    failures = []
    total = 0
    with tempfile.TemporaryDirectory(prefix='dragonrider-srsc-manifest-') as directory:
        snapshot = Path(directory) / 'verified-sample.srsc'
        for item in items:
            try:
                path = safe_inventory_path(root, item['path'])
                data = path.read_bytes()
                if (len(data) != item['size']
                        or hashlib.sha256(data).hexdigest() != item['sha256']):
                    raise ValueError('inventory size or hash mismatch')
                table = item['candidate_table']
                offset, count = table['offset'], table['count']
                if (type(offset) is not int or type(count) is not int or offset < 12
                        or count <= 0 or offset > len(data) or count > (len(data) - offset) // 14):
                    raise ValueError('invalid candidate table bounds')
                records = data[offset:offset + count * 14]
                if len(records) != count * 14:
                    raise ValueError('truncated table')
                expected = [(i, record_offset, length)
                            for i, (_, _, _, record_offset, length)
                            in enumerate(struct.iter_unpack('<HHHII', records))]
                snapshot.write_bytes(data)
                result = subprocess.run(
                    [str(args.inspector), '--manifest', 'us-retail', str(snapshot)],
                    capture_output=True, text=True)
                found = re.findall(r'^Physical record (\d+): offset=(\d+) length=(\d+)$',
                                   result.stdout, re.MULTILINE)
                observed = [tuple(map(int, row)) for row in found]
                if (result.returncode != 0 or observed != expected or
                        f'Size: {len(data)} bytes\n' not in result.stdout or
                        f'Edition: us-retail\nContainer: {snapshot}\nSHA-256: not provided\n'
                        not in result.stdout):
                    raise ValueError('inspector output differs from verified table')
                total += len(observed)
            except (KeyError, OSError, TypeError, ValueError):
                failures.append(item.get('path', '<invalid inventory entry>'))
    print(f"Private SRSC manifests: {len(items) - len(failures)}/{len(items)} matched; "
          f"{total} record ranges matched")
    if failures:
        print(*failures, sep="\n")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
