#!/usr/bin/env python3
"""Scan hash-verified Mplayer PE files for bounded target-name substrings."""
import argparse
import hashlib
import json
from pathlib import Path
import re

from measure_level_0001 import safe_inventory_path

GROUP = "English_-_Mplayer_Files/"
PE_EXTENSIONS = {".exe", ".dll", ".ocx"}
EXPECTED_FILES = 21
MAX_PE_FILE_BYTES = 16 * 1024 * 1024
TARGETS = {
    "mpdrakan.mpi": b"mpdrakan.mpi",
    "mpurl.dat": b"mpurl.dat",
    "mphisto.csv": b"mphisto.csv",
    "mpusage.csv": b"mpusage.csv",
    "drakan.tln": b"drakan.tln",
    ".mpi": b".mpi",
    ".tln": b".tln",
}
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


def scan(root, entries):
    root = Path(root).resolve(strict=True)
    selected = [entry for entry in entries
                if isinstance(entry, dict)
                and isinstance(entry.get("path"), str)
                and entry["path"].startswith(GROUP)
                and Path(entry["path"]).suffix.lower() in PE_EXTENSIONS]
    if len(selected) != EXPECTED_FILES:
        raise ValueError(f"expected {EXPECTED_FILES} Mplayer PE files, found {len(selected)}")
    paths = [entry["path"] for entry in selected]
    if len(set(paths)) != len(paths):
        raise ValueError("duplicate Mplayer PE inventory paths")

    matches = {encoding: {name: [] for name in TARGETS}
               for encoding in ("ascii", "utf16le")}
    for entry in selected:
        relative = entry["path"]
        size = entry.get("size")
        digest = entry.get("sha256")
        if (type(size) is not int or size < 0 or size > MAX_PE_FILE_BYTES
                or not isinstance(digest, str)
                or not _SHA256.fullmatch(digest)):
            raise ValueError("invalid or oversized Mplayer PE inventory size or SHA-256")
        path = safe_inventory_path(root, relative)
        data = path.read_bytes()
        if len(data) != size or hashlib.sha256(data).hexdigest() != digest:
            raise ValueError("Mplayer PE size or SHA-256 mismatch")
        lowered = data.lower()
        for label, needle in TARGETS.items():
            if needle in lowered:
                matches["ascii"][label].append(Path(relative).name)
            wide = b"".join(bytes((byte, 0)) for byte in needle)
            if wide in lowered:
                matches["utf16le"][label].append(Path(relative).name)

    return {"files_scanned": len(selected),
            "ascii": {key: sorted(value) for key, value in matches["ascii"].items()},
            "utf16le": {key: sorted(value) for key, value in matches["utf16le"].items()},
            "executed_binaries": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path, help="installed US extraction root")
    parser.add_argument("inventory", type=Path, help="private hash inventory JSON")
    args = parser.parse_args()
    manifest = json.loads(args.inventory.read_text(encoding="utf-8"))
    if not isinstance(manifest, dict) or not isinstance(manifest.get("files"), list):
        raise ValueError("invalid retail inventory document")
    print(json.dumps(scan(args.root, manifest["files"]), indent=2))


if __name__ == "__main__":
    main()
