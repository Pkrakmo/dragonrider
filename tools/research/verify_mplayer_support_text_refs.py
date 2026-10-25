#!/usr/bin/env python3
"""Check support-text basename literals in hash-pinned retail programs.

This reports static literal presence only. It does not establish file opens,
runtime use, or the purpose of any support file.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re

from measure_level_0001 import safe_inventory_path

GROUP = "English_-_Mplayer_Files/"
PE_EXTENSIONS = {".exe", ".dll", ".ocx"}
PROGRAM = "English_-_Program_Files/Drakan.exe"
EXPECTED_PE_COUNT = 21
MAX_FILE_BYTES = 16 * 1024 * 1024
TARGETS = {
    "Blank.htm", "Dismiss.htm", "layout.htm", "MplayerLocal.ini",
    "MplayerWeb.ini", "install.url", "mic-help.htm", "ReadMe.txt",
}
SHA256 = re.compile(r"[0-9a-f]{64}\Z")


def verify(root, entries):
    root = Path(root).resolve(strict=True)
    if not root.is_dir() or not isinstance(entries, list):
        raise ValueError("invalid retail root or inventory")
    index = {}
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("path"), str):
            raise ValueError("invalid inventory entry")
        if entry["path"] in index:
            raise ValueError("duplicate inventory path")
        index[entry["path"]] = entry
    programs = sorted(
        path for path in index
        if path.startswith(GROUP) and Path(path).suffix.lower() in PE_EXTENSIONS
    )
    if len(programs) != EXPECTED_PE_COUNT or PROGRAM not in index:
        raise ValueError("expected the 21 Mplayer PEs and retail Drakan.exe")
    selected = programs + [PROGRAM]
    snapshots = {}
    for relative in selected:
        entry = index[relative]
        size, digest = entry.get("size"), entry.get("sha256")
        if (type(size) is not int or size < 0 or size > MAX_FILE_BYTES
                or not isinstance(digest, str) or not SHA256.fullmatch(digest)):
            raise ValueError("invalid or oversized program inventory metadata")
        path = safe_inventory_path(root, relative)
        if path.stat().st_size != size:
            raise ValueError("program size mismatch before read")
        data = path.read_bytes()
        if len(data) != size or hashlib.sha256(data).hexdigest() != digest:
            raise ValueError("program size or SHA-256 mismatch")
        snapshots[Path(relative).name] = data.lower()

    ascii_matches = {target: [] for target in sorted(TARGETS)}
    utf16_matches = {target: [] for target in sorted(TARGETS)}
    for target, needle_text in ((name, name.lower()) for name in sorted(TARGETS)):
        needle = needle_text.encode("ascii")
        wide = b"".join(bytes((byte, 0)) for byte in needle)
        for program_name, data in snapshots.items():
            if needle in data:
                ascii_matches[target].append(program_name)
            if wide in data:
                utf16_matches[target].append(program_name)
    return {
        "program_snapshots_verified": len(snapshots),
        "ascii_basename_literal_programs": ascii_matches,
        "utf16le_basename_literal_programs": utf16_matches,
        "executed_programs": False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path, help="installed US extraction root")
    parser.add_argument("inventory", type=Path, help="private hash inventory JSON")
    args = parser.parse_args()
    manifest = json.loads(args.inventory.read_text(encoding="utf-8"))
    if not isinstance(manifest, dict) or not isinstance(manifest.get("files"), list):
        raise ValueError("invalid retail inventory document")
    print(json.dumps(verify(args.root, manifest["files"]), indent=2))


if __name__ == "__main__":
    main()
