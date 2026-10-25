#!/usr/bin/env python3
"""Search one hash-pinned US executable/module for exact level-frame tokens.

The report contains aggregate counts only. A literal byte match does not
establish a producer or runtime association.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct

from measure_level_frame_payload_matches import automaton, find_patterns, level_frames, safe_read


EXPECTED_CANDIDATES = {
    "Dragon.rfl": (
        1724416,
        "9b6496b65e962cf35dd1e18f424f2c8af08ceade78331dcc0b6da332ce844ac3",
    ),
    "Drakan.exe": (
        552960,
        "23630f48e20e8a9f42026501165ae1df407cfcee545a784ec930a4c25ee70648",
    ),
}


def read_candidate(path):
    path = Path(path)
    expected = EXPECTED_CANDIDATES.get(path.name)
    if expected is None:
        raise ValueError(f"unsupported candidate snapshot: {path.name}")
    expected_size, expected_digest = expected
    try:
        metadata = path.lstat()
    except OSError as error:
        raise ValueError(f"could not stat candidate: {error}") from error
    if path.is_symlink() or not path.is_file() or metadata.st_nlink != 1:
        raise ValueError("candidate input must be a singly linked regular file")
    if metadata.st_size != expected_size:
        raise ValueError(f"unexpected candidate size: {metadata.st_size}")
    with path.open("rb") as source:
        data = source.read(expected_size + 1)
    if len(data) != expected_size:
        raise ValueError(f"unexpected candidate size while reading: {len(data)}")
    digest = hashlib.sha256(data).hexdigest()
    if digest != expected_digest:
        raise ValueError(f"unexpected candidate SHA-256: {digest}")
    return data, digest


def measure(level_sets, module_bytes):
    tokens = {struct.pack("<IH", tag, len(body)) + body
              for frames in level_sets for tag, body in frames
              if len(body) <= 0xffff}
    found = find_patterns(module_bytes, automaton(tokens)) if tokens else set()
    return {
        "level_files": len(level_sets),
        "distinct_level_frame_tokens": len(tokens),
        "distinct_exact_tokens_found": len(found),
    }


def measure_inventory(root, inventory, module_bytes):
    try:
        items = json.loads(Path(inventory).read_text(encoding="utf-8"))["files"]
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError) as error:
        raise ValueError("invalid SRSC inventory") from error
    if not isinstance(items, list) or not items:
        raise ValueError("empty or malformed SRSC inventory")
    selected_levels = []
    seen = set()
    for item in items:
        if not isinstance(item, dict):
            raise ValueError("invalid inventory entry")
        relative = item.get("path")
        if not isinstance(relative, str) or relative in seen:
            raise ValueError("invalid or duplicate inventory path")
        seen.add(relative)
        if Path(relative).suffix.lower() == ".lvl":
            selected_levels.append(item)
    level_sets = []
    for item in selected_levels:
        data = safe_read(root, item)
        if data[:4] != b"SRSC":
            raise ValueError("level inventory entry is not SRSC")
        level_sets.append(level_frames(data))
    if not level_sets:
        raise ValueError("inventory contains no level files")
    return measure(level_sets, module_bytes)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path, help="installed asset root")
    parser.add_argument("inventory", type=Path, help="hash-pinned SRSC inventory")
    parser.add_argument("candidate", type=Path,
                        help="Drakan.exe or Dragon.rfl matching the pinned US snapshot")
    args = parser.parse_args()
    root = args.root.resolve(strict=True)
    if not root.is_dir():
        raise ValueError("root is not a directory")
    candidate, digest = read_candidate(args.candidate)
    result = measure_inventory(root, args.inventory, candidate)
    result.update({"candidate": args.candidate.name, "candidate_size": len(candidate),
                   "candidate_sha256": digest,
                   "method": "exact tag/length/body byte-token scan"})
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
