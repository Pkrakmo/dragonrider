#!/usr/bin/env python3
"""Report aggregate path-line shapes in the inventoried US LFL/MPL text files."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re

from measure_level_0001 import safe_inventory_path

TARGETS = {
    "English_-_Multi-Player_Data_Files/Multiplayer/Air Only.lfl",
    "English_-_Multi-Player_Data_Files/Multiplayer/Ground Only.lfl",
    "English_-_Multi-Player_Data_Files/Multiplayer/Master of the Dragon.lfl",
    "English_-_Single-Player_Data_Files/Islands_World/Islands_Night/Islands Night.mpl",
}
MAX_BYTES = 64 * 1024
ENDING = re.compile(rb"\.([A-Za-z0-9]{1,5})\Z")


def classify(root, entries):
    root = Path(root).resolve(strict=True)
    selected = [entry for entry in entries
                if isinstance(entry, dict) and entry.get("path") in TARGETS]
    if len(selected) != len(TARGETS) or {entry["path"] for entry in selected} != TARGETS:
        raise ValueError("expected exactly the four inventoried LFL/MPL paths")
    results = []
    for entry in sorted(selected, key=lambda item: item["path"]):
        size = entry.get("size")
        digest = entry.get("sha256")
        if (type(size) is not int or size < 0 or size > MAX_BYTES
                or not isinstance(digest, str)
                or not re.fullmatch(r"[0-9a-f]{64}", digest)):
            raise ValueError("invalid or oversized LFL/MPL inventory metadata")
        path = safe_inventory_path(root, entry["path"])
        data = path.read_bytes()
        if len(data) != size or hashlib.sha256(data).hexdigest() != digest:
            raise ValueError("LFL/MPL size or SHA-256 mismatch")
        if any(byte >= 0x80 for byte in data) or b"\0" in data:
            raise ValueError("LFL/MPL input is not NUL-free ASCII")
        normalized = data.replace(b"\r\n", b"\n")
        lines = normalized.split(b"\n")
        if lines[-1] == b"":
            lines.pop()
        if any(b"\r" in line for line in lines):
            raise ValueError("bare carriage return in LFL/MPL input")
        nonempty = [line for line in lines if line.strip()]
        endings = Counter()
        path_lines = 0
        for line in nonempty:
            if b"/" in line or b"\\" in line:
                path_lines += 1
            match = ENDING.search(line.rstrip())
            endings[match.group(1).decode("ascii").lower() if match else "none"] += 1
        results.append({
            "path": entry["path"],
            "size": len(data),
            "sha256": digest,
            "line_count": len(lines),
            "nonempty_line_count": len(nonempty),
            "blank_line_count": len(lines) - len(nonempty),
            "crlf_count": data.count(b"\r\n"),
            "bare_lf_count": data.count(b"\n") - data.count(b"\r\n"),
            "slash_or_backslash_lines": path_lines,
            "line_ending_suffix_counts": dict(sorted(endings.items())),
        })
    return {"files": results, "content_values_emitted": False}


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
