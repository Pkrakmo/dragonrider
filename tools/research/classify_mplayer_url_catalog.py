#!/usr/bin/env python3
"""Report aggregate structure for the hash-verified Mplayer mpurl.dat file."""
import argparse
import hashlib
import json
from pathlib import Path
import re

from measure_level_0001 import safe_inventory_path

TARGET = "English_-_Mplayer_Files/Assets/mpurl.dat"
MAX_BYTES = 1024 * 1024
SCHEME = re.compile(rb"(?i)\b(https?|ftp)://")


def classify(root, entries):
    root = Path(root).resolve(strict=True)
    selected = [entry for entry in entries
                if isinstance(entry, dict) and entry.get("path") == TARGET]
    if len(selected) != 1:
        raise ValueError("expected exactly one mpurl.dat inventory entry")
    entry = selected[0]
    size = entry.get("size")
    digest = entry.get("sha256")
    if (type(size) is not int or size < 0 or size > MAX_BYTES
            or not isinstance(digest, str)
            or not re.fullmatch(r"[0-9a-f]{64}", digest)):
        raise ValueError("invalid or oversized mpurl.dat inventory metadata")
    path = safe_inventory_path(root, TARGET)
    data = path.read_bytes()
    if len(data) != size or hashlib.sha256(data).hexdigest() != digest:
        raise ValueError("mpurl.dat size or SHA-256 mismatch")
    if any(byte >= 0x80 for byte in data):
        raise ValueError("mpurl.dat is not ASCII")

    # Treat CRLF as one newline and LF as a newline. The inspected source has
    # no other ASCII control characters, so splitlines()' broader rules are
    # unnecessary here.
    lines = data.replace(b"\r\n", b"\n").split(b"\n")
    if lines[-1] == b"":
        lines.pop()
    nonempty = [line for line in lines if line.strip()]
    schemes = {"http": 0, "https": 0, "ftp": 0}
    for match in SCHEME.finditer(data):
        scheme = match.group(1).decode("ascii").lower()
        schemes[scheme] += 1
    uri_lines = sum(bool(SCHEME.search(line)) for line in nonempty)
    return {
        "path": TARGET,
        "size": len(data),
        "sha256": digest,
        "ascii": True,
        "nul_bytes": data.count(b"\0"),
        "line_count": len(lines),
        "nonempty_line_count": len(nonempty),
        "blank_line_count": len(lines) - len(nonempty),
        "line_length_min": min(map(len, lines), default=0),
        "line_length_max": max(map(len, lines), default=0),
        "uri_scheme_token_counts": schemes,
        "uri_bearing_nonempty_lines": uri_lines,
        "records_or_format_identified": False,
        "content_values_emitted": False,
    }


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
