#!/usr/bin/env python3
"""Validate and summarize the public research coverage map."""
from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any


def load_map(path: Path, repository_root: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"cannot read coverage map: {error}") from error
    if not isinstance(data, dict) or data.get("schema_version") != 1:
        raise ValueError("coverage map must be a schema-version-1 object")
    dimensions, topics = data.get("dimensions"), data.get("topics")
    if not isinstance(dimensions, dict) or not isinstance(topics, list) or not topics:
        raise ValueError("coverage map requires nonempty dimensions and topics")
    required = ("id", "title", "status", "byte_layout", "loader_behavior", "runtime_behavior", "implementation", "validation", "next_question")
    ids: set[str] = set()
    for index, topic in enumerate(topics):
        if not isinstance(topic, dict) or any(not isinstance(topic.get(key), str) for key in required):
            raise ValueError(f"topic {index} is missing a required string field")
        if topic["id"] in ids:
            raise ValueError(f"duplicate topic id: {topic['id']}")
        ids.add(topic["id"])
        if topic["status"] not in {"active", "blocked", "not_started", "deferred"}:
            raise ValueError(f"topic {topic['id']} has an invalid status")
        for key, allowed in dimensions.items():
            if topic.get(key) not in allowed:
                raise ValueError(f"topic {topic['id']} has invalid {key}")
        evidence = topic.get("evidence")
        if not isinstance(evidence, list) or not evidence or not all(isinstance(item, str) for item in evidence):
            raise ValueError(f"topic {topic['id']} needs nonempty evidence paths")
        for relative in evidence:
            candidate = (repository_root / relative).resolve()
            if repository_root not in candidate.parents or not candidate.is_file():
                raise ValueError(f"topic {topic['id']} cites missing or unsafe evidence: {relative}")
    return data


def summarize(data: dict[str, Any]) -> str:
    topics = data["topics"]
    lines = [f"Coverage topics: {len(topics)}", "Status:"]
    for name, count in sorted(Counter(topic["status"] for topic in topics).items()):
        lines.append(f"  {name}: {count}")
    for dimension in ("byte_layout", "loader_behavior", "runtime_behavior", "implementation", "validation"):
        lines.append(f"{dimension}:")
        for name, count in sorted(Counter(topic[dimension] for topic in topics).items()):
            lines.append(f"  {name}: {count}")
    lines.append("Note: these are topic counts, not a compatibility percentage.")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("map", type=Path)
    parser.add_argument("--repository-root", type=Path, default=Path.cwd())
    args = parser.parse_args()
    try:
        print(summarize(load_map(args.map, args.repository_root.resolve())))
    except ValueError as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
