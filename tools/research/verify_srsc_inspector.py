#!/usr/bin/env python3
"""Compare inspector record output with a private installed-tree manifest."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import tempfile

from measure_level_0001 import safe_inventory_path


_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_RECORD = re.compile(r"^Record \d+: selectors=(\d+),(\d+),(\d+) offset=(\d+) length=(\d+)$", re.M)


def verified_records(root, item):
    if not isinstance(item, dict) or not isinstance(item.get("path"), str):
        raise ValueError("invalid inventory entry")
    size = item.get("size")
    digest = item.get("sha256")
    if type(size) is not int or size < 0:
        raise ValueError("invalid inventory file size")
    if not isinstance(digest, str) or not _SHA256.fullmatch(digest):
        raise ValueError("invalid inventory hash")
    path = safe_inventory_path(root, item["path"])
    data = path.read_bytes()
    if len(data) != size or hashlib.sha256(data).hexdigest() != digest:
        raise ValueError("inventory size or hash mismatch")
    table = item.get("candidate_table")
    if not isinstance(table, dict):
        raise ValueError("invalid candidate table")
    offset, count = table.get("offset"), table.get("count")
    if type(offset) is not int or type(count) is not int or offset < 12 or count <= 0:
        raise ValueError("invalid candidate table bounds")
    if len(data) < 12:
        raise ValueError("truncated SRSC header")
    magic, version, header_offset, header_count = struct.unpack_from("<4sHIH", data)
    if (magic != b"SRSC" or version != 0x100 or header_offset != offset
            or header_count != count):
        raise ValueError("inventory table metadata disagrees with SRSC header")
    if ("version" in table and table["version"] != version
            or "end" in table and table["end"] != offset + count * 14):
        raise ValueError("invalid candidate table metadata")
    end = offset + count * 14
    if end > len(data):
        raise ValueError("candidate table outside inventory file")
    records = list(struct.iter_unpack("<HHHII", data[offset:end]))
    if len(records) != count:
        raise ValueError("truncated candidate table")
    return path, records, data


def parse_inspector_records(output):
    return [tuple(map(int, row)) for row in _RECORD.findall(output)]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('inspector', type=Path)
    parser.add_argument('root', type=Path)
    parser.add_argument('manifest', type=Path)
    args = parser.parse_args()
    root = args.root.resolve(strict=True)
    if not root.is_dir():
        parser.error('root must be a directory')
    try:
        manifest = json.loads(args.manifest.read_text(encoding='utf-8'))
        raw_items = manifest['files']
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError) as error:
        parser.error(f'invalid manifest: {error}')
    if not isinstance(raw_items, list):
        parser.error('manifest files must be a list')
    if type(manifest.get('file_count')) is not int or manifest['file_count'] != len(raw_items):
        parser.error('manifest file_count does not match files list')
    all_paths = [item.get('path') if isinstance(item, dict) else None for item in raw_items]
    if any(not isinstance(path, str) for path in all_paths) or len(set(all_paths)) != len(all_paths):
        parser.error('manifest contains invalid or duplicate paths')
    items = [item for item in raw_items if isinstance(item, dict) and 'candidate_table' in item]
    if not items:
        parser.error('manifest contains no candidate tables')
    failures = []
    with tempfile.TemporaryDirectory(prefix='dragonrider-srsc-inspector-') as directory:
        snapshot = Path(directory) / 'verified-sample.srsc'
        for item in items:
            try:
                _, expected, data = verified_records(root, item)
            except (OSError, ValueError):
                failures.append(item.get('path', '<invalid inventory entry>'))
                continue
            snapshot.write_bytes(data)
            result = subprocess.run([str(args.inspector), '--records', str(snapshot)],
                                    capture_output=True, text=True)
            observed = parse_inspector_records(result.stdout)
            if result.returncode != 0 or observed != expected[:50]:
                failures.append(item['path'])
    print(f'Private SRSC record inspections: {len(items) - len(failures)}/{len(items)} matched')
    if failures:
        print(*failures, sep='\n')
        raise SystemExit(1)


if __name__ == '__main__':
    main()
