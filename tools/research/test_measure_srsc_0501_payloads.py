import unittest
import struct
from pathlib import Path
import tempfile

from measure_srsc_0501_payloads import (
    measure_0501_payloads,
    summarize_payload_shapes,
    summarize_stable_order_neighbors,
    validate_unique_inventory_paths,
)


class Srsc0501PayloadMeasurements(unittest.TestCase):
    def test_stable_order_neighbor_summary_counts_kinds_and_equal_keys(self):
        selectors = [
            (0x0502, 9, 0),
            (0x0501, 7, 0),
            (0x0503, 7, 0),
            (0x0502, 7, 0),
            (0x0501, 9, 0),
        ]
        self.assertEqual(summarize_stable_order_neighbors(selectors), {
            "records_0501": 2,
            "with_two_following": 1,
            "kind_sequence_0503_0502": 1,
            "same_second_word": 1,
            "first_match_pairs_in_files": 2,
            "first_match_pair_with_two_following_in_files": 1,
            "first_match_pair_with_expected_sequence_in_files": 1,
        })

    def test_stable_order_neighbor_summary_uses_first_duplicate_pair(self):
        selectors = [
            (0x0501, 7, 0), (0x0503, 7, 0), (0x0502, 7, 0),
            (0x0501, 7, 0), (0x0503, 7, 0), (0x0502, 7, 0),
        ]
        result = summarize_stable_order_neighbors(selectors)
        self.assertEqual(result["records_0501"], 2)
        self.assertEqual(result["first_match_pairs_in_files"], 1)
        self.assertEqual(result["first_match_pair_with_expected_sequence_in_files"], 1)

    def test_stable_order_neighbor_summary_rejects_invalid_selector(self):
        with self.assertRaisesRegex(ValueError, "selector triple"):
            summarize_stable_order_neighbors([(0x0501, -1, 0)])

    def make_snapshot(self, records):
        table_offset = 12 + sum(len(payload) for _, _, _, payload in records)
        data = bytearray(b"SRSC" + struct.pack("<HIH", 0x100, table_offset, len(records)))
        for _, _, _, payload in records:
            data.extend(payload)
        selectors = []
        offset = 12
        for first, second, third, payload in records:
            selectors.append((first, second, third))
            data.extend(struct.pack("<HHHII", first, second, third, offset, len(payload)))
            offset += len(payload)
        return bytes(data), selectors

    def test_measures_only_selected_payloads_and_retains_word_distributions(self):
        data, selectors = self.make_snapshot([
            (0x0501, 2, 7, b"abc"),
            (0x0501, 2, 9, b"de"),
            (0x0102, 2, 7, b"ignored"),
        ])
        result = measure_0501_payloads(data, selectors)
        self.assertNotIn("payloads", result)
        self.assertEqual(result["records_0501"], 2)
        self.assertEqual(result["payload_bytes"], 5)
        self.assertEqual(result["payload_length_min"], 2)
        self.assertEqual(result["payload_length_max"], 3)
        self.assertEqual(result["second_word_occurrences"], {2: 2})
        self.assertEqual(result["third_word_occurrences"], {7: 1, 9: 1})
        self.assertEqual(result["payload_length_occurrences"], {2: 1, 3: 1})
        self.assertEqual(result["selector_length_occurrences"], {2: {2: 1, 3: 1}})

    def test_rejects_selector_mismatch_and_out_of_bounds_selected_range(self):
        data, selectors = self.make_snapshot([(0x0501, 2, 7, b"abc")])
        with self.assertRaisesRegex(ValueError, "selector snapshot"):
            measure_0501_payloads(data, [(0x0501, 2, 8)])
        table_offset = struct.unpack_from("<I", data, 6)[0]
        corrupt = bytearray(data)
        struct.pack_into("<II", corrupt, table_offset + 6, len(data), 2)
        with self.assertRaisesRegex(ValueError, "exceeds input"):
            measure_0501_payloads(bytes(corrupt), selectors)

    def test_rejects_table_count_mismatch(self):
        data, selectors = self.make_snapshot([(0x0501, 2, 7, b"abc")])
        with self.assertRaisesRegex(ValueError, "selector count"):
            measure_0501_payloads(data, selectors + [(0, 0, 0)])

    def test_summarizes_payload_shape_without_returning_payload_bytes(self):
        result = summarize_payload_shapes([
            b"\x01\x00Name\0\x80\x3f",
            b"\x01\x00Name\0\x80\x3f",
            b"\x02\x00X\0\x00\x00",
        ])
        self.assertEqual(result["unique_exact_payloads"], 2)
        self.assertEqual(result["duplicate_occurrences"], 1)
        self.assertEqual(result["maximum_exact_payload_multiplicity"], 2)
        self.assertEqual(result["first_nul_before_offset_18"], 3)
        self.assertEqual(result["fully_printable_prefixes_before_early_nul"], 3)
        self.assertEqual(result["first_nul_distinct_offsets"], 2)
        self.assertEqual(result["aligned_u16_slots"]["0"]["distinct_values"], 2)
        self.assertNotIn("payloads", result)

    def test_rejects_duplicate_resolved_inventory_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "sample.srsc").write_bytes(b"synthetic")
            entries = [
                {"path": "sample.srsc"},
                {"path": "./sample.srsc"},
            ]
            with self.assertRaisesRegex(ValueError, "duplicate inventory path"):
                validate_unique_inventory_paths(root, entries)


if __name__ == "__main__":
    unittest.main()
