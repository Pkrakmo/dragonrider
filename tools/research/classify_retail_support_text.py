#!/usr/bin/env python3
"""Classify bounded shapes of hash-pinned retail support text files.

The report intentionally excludes text contents, URLs, configuration values,
HTML attributes, and README prose.
"""
import argparse
from collections import Counter
from html.parser import HTMLParser
import hashlib
import json
from pathlib import Path
import re

from measure_level_0001 import safe_inventory_path

TARGETS = {
    "English_-_Common_Data_Files/ReadMe.txt",
    "English_-_Mplayer_Files/Assets/Blank.htm",
    "English_-_Mplayer_Files/Assets/Magazine01/Dismiss.htm",
    "English_-_Mplayer_Files/Assets/Magazine01/layout.htm",
    "English_-_Mplayer_Files/System/MplayerLocal.ini",
    "English_-_Mplayer_Files/System/MplayerWeb.ini",
    "English_-_Mplayer_Files/System/install.url",
    "English_-_Mplayer_Files/System/mic-help.htm",
}
MAX_BYTES = 128 * 1024
SECTION = re.compile(r"^\s*\[([^\]\r\n]+)\]\s*(?:[;#].*)?$")
ASSIGNMENT = re.compile(r"^\s*([^=:#\s][^=:]*?)\s*[=:]")


class _HtmlShape(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.tags = Counter()
        self.doctypes = 0
        self.references = Counter()

    def handle_starttag(self, tag, attrs):
        self.tags[tag.lower()] += 1
        self._references(attrs)

    def handle_startendtag(self, tag, attrs):
        self.tags[tag.lower()] += 1
        self._references(attrs)

    def handle_decl(self, decl):
        if decl.lower().startswith("doctype"):
            self.doctypes += 1

    def _references(self, attrs):
        for key, value in attrs:
            if key.lower() not in {"href", "src", "action"} or not value:
                continue
            folded = value.strip().lower()
            if folded.startswith(("http://", "https://")):
                self.references["http"] += 1
            elif folded.startswith("mailto:"):
                self.references["mailto"] += 1
            elif folded.startswith(("javascript:", "data:")):
                self.references["other_scheme"] += 1
            elif folded.startswith(("#", "\\", "/")):
                self.references["fragment_or_rooted"] += 1
            else:
                self.references["relative_or_empty_scheme"] += 1


def _line_shape(text):
    crlf = text.count("\r\n")
    lf = text.count("\n") - crlf
    cr = text.count("\r") - crlf
    lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    return {"line_count": len(lines), "blank_lines": sum(not line.strip() for line in lines),
            "crlf": crlf, "bare_lf": lf, "bare_cr": cr}


def _ini_shape(text):
    sections = []
    section_keys = Counter()
    duplicate_keys = 0
    assignment_count = 0
    comments = 0
    malformed = 0
    current = ""
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith((";", "#")):
            comments += 1
            continue
        match = SECTION.fullmatch(raw)
        if match:
            current = match.group(1).strip().casefold()
            sections.append(current)
            continue
        match = ASSIGNMENT.match(raw)
        if match:
            key = match.group(1).strip().casefold()
            marker = (current, key)
            section_keys[marker] += 1
            if section_keys[marker] > 1:
                duplicate_keys += 1
            assignment_count += 1
            continue
        malformed += 1
    return {
        "section_count": len(sections),
        "distinct_section_count": len(set(sections)),
        "duplicate_section_count": len(sections) - len(set(sections)),
        "assignment_count": assignment_count,
        "duplicate_key_count": duplicate_keys,
        "comment_line_count": comments,
        "unclassified_line_count": malformed,
    }


def _readme_shape(text):
    lines = text.splitlines()
    return {
        "line_count": len(lines),
        "blank_line_count": sum(not line.strip() for line in lines),
        "indented_line_count": sum(bool(line[:1].isspace()) for line in lines if line),
        "bullet_line_count": sum(bool(re.match(r"^\s*(?:[-*+]\s|\d+[.)]\s)", line)) for line in lines),
        "heading_marker_line_count": sum(bool(re.match(r"^\s*={3,}\s*$", line)) for line in lines),
    }


def _classify(relative, data):
    try:
        text = data.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise ValueError("support text is not valid UTF-8") from error
    suffix = Path(relative).suffix.lower()
    result = {"path": relative, "size": len(data), "sha256": hashlib.sha256(data).hexdigest(),
              "text_encoding": "UTF-8", "line_endings": _line_shape(text),
              "content_values_emitted": False}
    if suffix == ".htm":
        parser = _HtmlShape()
        parser.feed(text)
        parser.close()
        result["html_shape"] = {"doctype_count": parser.doctypes,
                                "start_tag_counts": dict(sorted(parser.tags.items())),
                                "reference_kind_counts": dict(sorted(parser.references.items()))}
    elif suffix in {".ini", ".url"}:
        result["ini_shape"] = _ini_shape(text)
    elif suffix == ".txt":
        result["prose_shape"] = _readme_shape(text)
    else:
        raise ValueError("unsupported support text extension")
    return result


def classify(root, entries):
    root = Path(root).resolve(strict=True)
    if not root.is_dir() or not isinstance(entries, list):
        raise ValueError("invalid root or inventory entries")
    selected = [entry for entry in entries
                if isinstance(entry, dict) and entry.get("path") in TARGETS]
    if len(selected) != len(TARGETS) or {entry["path"] for entry in selected} != TARGETS:
        raise ValueError("expected exactly the eight inventoried support-text paths")
    results = []
    for entry in sorted(selected, key=lambda item: item["path"]):
        size, digest = entry.get("size"), entry.get("sha256")
        if (type(size) is not int or size < 0 or size > MAX_BYTES
                or not isinstance(digest, str)
                or not re.fullmatch(r"[0-9a-f]{64}", digest)):
            raise ValueError("invalid or oversized support-text inventory metadata")
        path = safe_inventory_path(root, entry["path"])
        if path.stat().st_size != size:
            raise ValueError("support-text size mismatch before read")
        data = path.read_bytes()
        if len(data) != size or hashlib.sha256(data).hexdigest() != digest:
            raise ValueError("support-text size or SHA-256 mismatch")
        if b"\0" in data:
            raise ValueError("support text contains NUL bytes")
        results.append(_classify(entry["path"], data))
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
