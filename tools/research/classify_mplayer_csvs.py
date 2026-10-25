#!/usr/bin/env python3
"""Report bounded aggregate row shapes for the inventoried Mplayer CSV files."""
import argparse
import csv
from collections import Counter
import hashlib
import io
import json
from pathlib import Path
import re

from measure_level_0001 import safe_inventory_path

TARGETS = {
    "English_-_Mplayer_Files/System/mphisto.csv",
    "English_-_Mplayer_Files/System/mpusage.csv",
}
MAX_BYTES = 64 * 1024


def classify(root, entries):
    root = Path(root).resolve(strict=True)
    selected = [entry for entry in entries
                if isinstance(entry, dict) and entry.get("path") in TARGETS]
    if (len(selected) != len(TARGETS)
            or {entry["path"] for entry in selected} != TARGETS):
        raise ValueError("expected exactly the two inventoried Mplayer CSV paths")
    results = []
    for entry in sorted(selected, key=lambda item: item["path"]):
        size = entry.get("size")
        digest = entry.get("sha256")
        if (type(size) is not int or size < 0 or size > MAX_BYTES
                or not isinstance(digest, str)
                or not re.fullmatch(r"[0-9a-f]{64}", digest)):
            raise ValueError("invalid or oversized CSV inventory metadata")
        path = safe_inventory_path(root, entry["path"])
        if path.stat().st_size != size:
            raise ValueError("CSV size mismatch before read")
        data = path.read_bytes()
        if len(data) != size or hashlib.sha256(data).hexdigest() != digest:
            raise ValueError("CSV size or SHA-256 mismatch")
        try:
            text = data.decode("ascii")
            rows = list(csv.reader(io.StringIO(text, newline=""), strict=True))
        except (UnicodeDecodeError, csv.Error) as error:
            raise ValueError("CSV candidate is not parseable ASCII CSV") from error
        field_counts = Counter(len(row) for row in rows)
        results.append({
            "path": entry["path"],
            "size": len(data),
            "sha256": digest,
            "parsed_rows": len(rows),
            "field_count_distribution": {
                str(key): value for key, value in sorted(field_counts.items())
            },
            "crlf_count": data.count(b"\r\n"),
            "bare_lf_count": data.count(b"\n") - data.count(b"\r\n"),
            "source_lines_with_quotes": sum(
                b'"' in line for line in data.splitlines()
            ),
            "content_values_emitted": False,
        })
    return {"files": results}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path, help="installed US extraction root")
    parser.add_argument("inventory", type=Path, help="private hash inventory JSON")
    args = parser.parse_args()
    manifest = json.loads(args.inventory.read_text(encoding="utf-8"))
    if not isinstance(manifest, dict) or not isinstance(manifest.get("files"), list):
        raise ValueError("invalid retail inventory document")
    print(json.dumps(classify(args.root, manifest["files"]), indent=2))


if __name__ == "__main__":
    main()
