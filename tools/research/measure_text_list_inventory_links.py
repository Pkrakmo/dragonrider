#!/usr/bin/env python3
"""Compare hash-pinned LFL/MPL path-shaped rows with installed inventory names."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path, PurePosixPath, PureWindowsPath
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


def _safe_relative(value):
    """Normalize only bounded relative path text; never resolve outside the inventory."""
    if not isinstance(value, str) or not value or "\0" in value:
        return None
    value = value.replace("\\", "/")
    windows = PureWindowsPath(value)
    posix = PurePosixPath(value)
    if windows.drive or windows.root or posix.is_absolute():
        return None
    parts = posix.parts
    if not parts or any(part in ("", ".", "..") for part in parts):
        return None
    return PurePosixPath(*parts).as_posix()


def measure(root, entries):
    root = Path(root).resolve(strict=True)
    if not isinstance(entries, list):
        raise ValueError("inventory files must be a list")
    by_path = {}
    exact_names = Counter()
    folded_names = Counter()
    stems = Counter()
    for item in entries:
        if not isinstance(item, dict) or not isinstance(item.get("path"), str):
            raise ValueError("invalid inventory entry")
        relative = _safe_relative(item["path"])
        if relative is None or relative in by_path:
            raise ValueError("unsafe or duplicate inventory path")
        by_path[relative] = item
        exact_names[PurePosixPath(relative).name] += 1
        folded_names[PurePosixPath(relative).name.casefold()] += 1
        stems[PurePosixPath(relative).stem.casefold()] += 1
    lower_paths = {path.casefold() for path in by_path}
    selected = [by_path[path] for path in TARGETS if path in by_path]
    if len(selected) != len(TARGETS):
        raise ValueError("inventory must contain exactly the four required LFL/MPL paths")

    results = []
    for entry in sorted(selected, key=lambda item: item["path"]):
        relative = entry["path"]
        size, digest = entry.get("size"), entry.get("sha256")
        if (type(size) is not int or not 0 <= size <= MAX_BYTES
                or not isinstance(digest, str)
                or not re.fullmatch(r"[0-9a-f]{64}", digest)):
            raise ValueError("invalid or oversized LFL/MPL inventory metadata")
        data = safe_inventory_path(root, relative).read_bytes()
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
        path_rows = []
        for line in lines:
            value = line.strip()
            if not value or (b"/" not in value and b"\\" not in value):
                continue
            suffix = ENDING.search(value)
            if suffix is None:
                raise ValueError("path-shaped row has no bounded file suffix")
            path_rows.append((value.decode("ascii").replace("\\", "/"),
                              suffix.group(1).decode("ascii").casefold()))

        parent = PurePosixPath(relative).parent
        root_exact = root_casefold = parent_exact = parent_casefold = 0
        basename_unique = folded_basename_unique = 0
        basename_stem_match = basename_stem_unique = 0
        suffix_rows = Counter()
        safe_rows = 0
        for value, suffix in path_rows:
            suffix_rows[suffix] += 1
            safe = _safe_relative(value)
            if safe is None:
                continue
            safe_rows += 1
            rel_parent = (parent / PurePosixPath(safe)).as_posix()
            root_exact += int(safe in by_path)
            root_casefold += int(safe.casefold() in lower_paths)
            parent_exact += int(rel_parent in by_path)
            parent_casefold += int(rel_parent.casefold() in lower_paths)
            basename = PurePosixPath(safe).name.casefold()
            exact_basename = PurePosixPath(safe).name
            stem = PurePosixPath(safe).stem.casefold()
            basename_unique += int(exact_names[exact_basename] == 1)
            folded_basename_unique += int(folded_names[basename] == 1)
            basename_stem_match += int(stems[stem] > 0)
            basename_stem_unique += int(stems[stem] == 1)
        results.append({
            "path": relative,
            "path_rows": len(path_rows),
            "unsafe_or_nonrelative_rows": len(path_rows) - safe_rows,
            "suffix_counts": dict(sorted(suffix_rows.items())),
            "normalized_root_relative_exact_inventory_matches": root_exact,
            "normalized_root_relative_casefold_inventory_matches": root_casefold,
            "normalized_list_directory_relative_exact_inventory_matches": parent_exact,
            "normalized_list_directory_relative_casefold_inventory_matches": parent_casefold,
            "unique_exact_basename_inventory_matches": basename_unique,
            "unique_casefold_basename_inventory_matches": folded_basename_unique,
            "basename_stem_inventory_matches": basename_stem_match,
            "unique_basename_stem_inventory_matches": basename_stem_unique,
        })
    return {"files": results, "row_values_emitted": False,
            "path_meaning_established": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path, help="installed US extraction root")
    parser.add_argument("inventory", type=Path, help="private hash inventory JSON")
    args = parser.parse_args()
    document = json.loads(args.inventory.read_text(encoding="utf-8"))
    if not isinstance(document, dict) or not isinstance(document.get("files"), list):
        parser.error("invalid retail inventory document")
    print(json.dumps(measure(args.root, document["files"]), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
