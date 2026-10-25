"""Synthetic validation for aggregate cross-level reference-pair reuse."""

import hashlib
from pathlib import Path
import struct
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch
import zlib

from measure_level_cell_reference_pairs import MAX_INPUT_SIZE, measure_inventory


def level(cells):
    prefix = struct.pack("<I7I", 1, 7, len(cells), 1, 0, 0, 0, 0)
    prefix += struct.pack("<H", 0) + struct.pack("<6I", *([0] * 6))
    prefix += struct.pack("<I", 0) + struct.pack("<I", 1)
    grid_words = (len(cells) + 1) * 4
    decoded = struct.pack("<" + "H" * grid_words, *([0] * grid_words))
    decoded += b"".join(
        struct.pack("<Hii8H", 1, first, second, *([0] * 8))
        for first, second in cells
    )
    compressed = zlib.compress(decoded)
    payload = prefix + struct.pack("<I", len(compressed)) + compressed
    table_offset = 12 + len(payload)
    record = struct.pack("<HHHII", 1, 0, 0, 12, len(payload))
    return b"SRSC" + struct.pack("<HIH", 0x100, table_offset, 1) + payload + record


def entry(root, name, data):
    (root / name).write_bytes(data)
    return {"path": name, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()}


class LevelCellReferencePairTests(unittest.TestCase):
    def test_aggregates_unique_ordered_pairs_without_emitting_values(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            entries = [
                entry(root, "a.lvl", level([(11, 22), (22, 11), (11, 22)])),
                entry(root, "b.lvl", level([(11, 22)])),
                entry(root, "c.lvl", level([(11, 33)])),
            ]
            result = measure_inventory(root, entries)
            self.assertEqual(result, {
                "selected_levels": 3,
                "decoded_cells": 5,
                "distinct_pairs_within_levels_total": 4,
                "distinct_ordered_pairs_across_levels": 3,
                "ordered_pairs_present_in_multiple_levels": 1,
                "extra_level_pair_occurrences": 1,
                "level_pairs_with_shared_ordered_pairs": 1,
                "possible_level_pairs": 3,
                "maximum_levels_sharing_one_ordered_pair": 2,
            })
            self.assertNotIn("pairs", result)
            self.assertNotIn("paths", result)

    def test_rejects_stale_hash(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            data = level([(1, 2)])
            (root / "a.lvl").write_bytes(data)
            with self.assertRaisesRegex(ValueError, "size or hash"):
                measure_inventory(root, [{"path": "a.lvl", "size": len(data), "sha256": "0" * 64}])

    def test_rejects_duplicate_path(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            item = entry(root, "a.lvl", level([(1, 2)]))
            with self.assertRaisesRegex(ValueError, "duplicate level inventory path"):
                measure_inventory(root, [item, item])

    def test_rejects_symlinked_path(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            outside = root.parent / (root.name + "-outside.lvl")
            data = level([(1, 2)])
            outside.write_bytes(data)
            (root / "linked.lvl").symlink_to(outside)
            item = {"path": "linked.lvl", "size": len(data), "sha256": hashlib.sha256(data).hexdigest()}
            try:
                with self.assertRaisesRegex(ValueError, "symlink"):
                    measure_inventory(root, [item])
            finally:
                outside.unlink(missing_ok=True)

    def test_rejects_manifest_over_limit_before_opening(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            with self.assertRaisesRegex(ValueError, "256 MiB limit"):
                measure_inventory(root, [{"path": "a.lvl", "size": MAX_INPUT_SIZE + 1,
                                         "sha256": "0" * 64}])

    def test_rejects_on_disk_over_limit_before_reading(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "a.lvl"
            source.write_bytes(b"small fixture")
            item = {"path": "a.lvl", "size": 12, "sha256": "0" * 64}
            real_stat = Path.stat

            def fake_stat(path, *args, **kwargs):
                if path == source:
                    return SimpleNamespace(st_mode=source.lstat().st_mode,
                                           st_size=MAX_INPUT_SIZE + 1)
                return real_stat(path, *args, **kwargs)

            with patch.object(Path, "stat", fake_stat), \
                    patch.object(Path, "open", side_effect=AssertionError("must not read")):
                with self.assertRaisesRegex(ValueError, "input file exceeds 256 MiB limit"):
                    measure_inventory(root, [item])

    def test_caps_snapshot_read_at_expected_size_plus_one(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            data = level([(1, 2)])
            item = entry(root, "a.lvl", data)
            source = root / item["path"]
            real_open = Path.open
            requested = []

            class Recorder:
                def __init__(self, wrapped):
                    self.wrapped = wrapped

                def __enter__(self):
                    self.wrapped.__enter__()
                    return self

                def __exit__(self, *args):
                    return self.wrapped.__exit__(*args)

                def read(self, size=-1):
                    requested.append(size)
                    return self.wrapped.read(size)

            def open_recorded(path, *args, **kwargs):
                handle = real_open(path, *args, **kwargs)
                return Recorder(handle) if path == source else handle

            with patch.object(Path, "open", open_recorded):
                measure_inventory(root, [item])
            self.assertEqual(requested, [len(data) + 1])


if __name__ == "__main__":
    unittest.main()
