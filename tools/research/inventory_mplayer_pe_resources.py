#!/usr/bin/env python3
"""Count resource types in hash-verified Mplayer-group PE snapshots."""
import argparse
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile

from measure_level_0001 import safe_inventory_path

GROUP = "English_-_Mplayer_Files/"
PE_EXTENSIONS = {".exe", ".dll", ".ocx"}
EXPECTED_FILES = 21
MAX_PE_FILE_BYTES = 16 * 1024 * 1024
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_TYPE = re.compile(r"(?:^|\s)--type=(?:([0-9]+)|'([A-Z0-9_]+)')(?:\s|$)")


def inventory(root, entries, wrestool="wrestool"):
    """Return aggregate resource-type counts without resource names."""
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

    resource_counts = Counter()
    files_by_type = defaultdict(int)
    resources_total = 0
    for entry in selected:
        relative = entry["path"]
        size = entry.get("size")
        digest = entry.get("sha256")
        if (type(size) is not int or size < 0 or size > MAX_PE_FILE_BYTES
                or not isinstance(digest, str) or not _SHA256.fullmatch(digest)):
            raise ValueError("invalid or oversized Mplayer PE inventory size or SHA-256")
        path = safe_inventory_path(root, relative)
        data = path.read_bytes()
        if len(data) != size or hashlib.sha256(data).hexdigest() != digest:
            raise ValueError("Mplayer PE size or SHA-256 mismatch")

        # wrestool reads the exact checked snapshot, not a reopened source path.
        with tempfile.NamedTemporaryFile(suffix=Path(relative).suffix) as snapshot:
            snapshot.write(data)
            snapshot.flush()
            completed = subprocess.run([wrestool, "-l", snapshot.name],
                                       check=False, capture_output=True, text=True)
        if completed.returncode:
            raise ValueError("wrestool failed for a hash-verified Mplayer PE")
        no_resources = bool(re.fullmatch(
            r"wrestool: .*: file contains no resources\n", completed.stderr))
        if completed.stderr and not no_resources:
            raise ValueError("wrestool emitted an unrecognized diagnostic for a Mplayer PE")
        counts = Counter()
        for line in completed.stdout.splitlines():
            match = _TYPE.search(line)
            if match is None:
                raise ValueError("unrecognized wrestool resource listing")
            type_id = int(match.group(1)) if match.group(1) else match.group(2)
            counts[type_id] += 1
        resources_total += sum(counts.values())
        resource_counts.update(counts)
        for type_id in counts:
            files_by_type[type_id] += 1

    return {
        "files_scanned": len(selected),
        "resource_entries": resources_total,
        "types": {str(type_id): {"entries": resource_counts[type_id],
                                 "files": files_by_type[type_id]}
                  for type_id in sorted(resource_counts,
                                        key=lambda value: (isinstance(value, str), value))},
        "executed_binaries": False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path, help="installed US extraction root")
    parser.add_argument("inventory", type=Path, help="private hash inventory JSON")
    parser.add_argument("--wrestool", default="wrestool")
    args = parser.parse_args()
    manifest = json.loads(args.inventory.read_text(encoding="utf-8"))
    if not isinstance(manifest, dict) or not isinstance(manifest.get("files"), list):
        raise ValueError("invalid retail inventory document")
    print(json.dumps(inventory(args.root, manifest["files"], args.wrestool), indent=2))


if __name__ == "__main__":
    main()
