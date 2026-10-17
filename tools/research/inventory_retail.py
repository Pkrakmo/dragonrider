#!/usr/bin/env python3
"""Produce a private, deterministic inventory of an extracted retail tree."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import struct


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    if not args.root.is_dir():
        parser.error("root must be a directory")
    files = []
    for path in sorted(p for p in args.root.rglob("*") if p.is_file()):
        digest = hashlib.sha256()
        size = 0
        header = b""
        with path.open("rb") as stream:
            while chunk := stream.read(1024 * 1024):
                if not size:
                    header = chunk[:12]
                digest.update(chunk)
                size += len(chunk)
        item = {"path": path.relative_to(args.root).as_posix(), "size": size,
                "sha256": digest.hexdigest(), "header_hex": header.hex()}
        if len(header) == 12 and header[:4] == b"SRSC":
            version, offset, count = struct.unpack_from("<HIH", header, 4)
            end = offset + count * 14
            item["candidate_table"] = {"version": version, "offset": offset,
                                       "count": count, "end": end,
                                       "within_file": end <= size,
                                       "ends_at_eof": end == size}
        files.append(item)
    result = {"root": str(args.root), "file_count": len(files), "files": files}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print("files:", len(files))
    candidates = [f for f in files if "candidate_table" in f]
    print("extensions:", dict(sorted(Counter(Path(f["path"]).suffix.lower() or "<none>" for f in files).items())))
    print("SRSC extensions:", dict(sorted(Counter(Path(f["path"]).suffix.lower() or "<none>" for f in candidates).items())))
    print("SRSC versions:", dict(sorted(Counter(f["candidate_table"]["version"] for f in candidates).items())))
    print("SRSC tables within file:", sum(f["candidate_table"]["within_file"] for f in candidates))
    print("SRSC tables ending at EOF:", sum(f["candidate_table"]["ends_at_eof"] for f in candidates))
    print("private inventory:", args.output)


if __name__ == "__main__":
    main()
