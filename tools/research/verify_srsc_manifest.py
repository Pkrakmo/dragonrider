#!/usr/bin/env python3
"""Compare all physical manifest ranges with independently decoded private SRSC tables."""

import argparse
import json
from pathlib import Path
import re
import struct
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("inspector", type=Path)
    parser.add_argument("root", type=Path)
    parser.add_argument("inventory", type=Path)
    args = parser.parse_args()
    items = [entry for entry in json.loads(args.inventory.read_text())["files"]
             if "candidate_table" in entry]
    if not items:
        parser.error("inventory contains no candidate tables")
    failures = []
    total = 0
    for item in items:
        path = args.root / item["path"]
        table = item["candidate_table"]
        with path.open("rb") as stream:
            stream.seek(table["offset"])
            data = stream.read(table["count"] * 14)
        if len(data) != table["count"] * 14:
            failures.append(item["path"])
            continue
        expected = [(i, offset, length) for i, (_, _, _, offset, length)
                    in enumerate(struct.iter_unpack("<HHHII", data))]
        result = subprocess.run([str(args.inspector), "--manifest", "us-retail", str(path)],
                                capture_output=True, text=True)
        found = re.findall(r"^Physical record (\d+): offset=(\d+) length=(\d+)$",
                           result.stdout, re.MULTILINE)
        observed = [tuple(map(int, row)) for row in found]
        if (result.returncode != 0 or observed != expected or
                f"Size: {path.stat().st_size} bytes\n" not in result.stdout or
                f"Edition: us-retail\nContainer: {path}\nSHA-256: not provided\n" not in result.stdout):
            failures.append(item["path"])
        else:
            total += len(observed)
    print(f"Private SRSC manifests: {len(items) - len(failures)}/{len(items)} matched; "
          f"{total} record ranges matched")
    if failures:
        print(*failures, sep="\n")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
