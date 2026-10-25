import struct
import unittest

from measure_srsc_0501_payload_layout import measure_file


class Srsc0501PayloadLayoutTests(unittest.TestCase):
    def payload_trio(self, count_52=1, count_8=2, prefix_8=None,
                     prefix_52=None, second=7, suffix16=b""):
        if prefix_8 is None:
            prefix_8 = count_8
        if prefix_52 is None:
            prefix_52 = count_52
        payload_0501 = (
            struct.pack("<H", 0) + b"READ" + b"SKIP"
            + struct.pack("<IIIII", count_52, 0, count_8, 0, 0)
            + suffix16
        )
        return [
            (0x0501, second, 0, payload_0501),
            (0x0503, second, 0, struct.pack("<H", prefix_8) + b"A" * (8 * prefix_8)),
            (0x0502, second, 0, struct.pack("<H", prefix_52) + b"B" * (52 * count_52)),
        ]

    def make_snapshot(self, records, gap_before=None):
        gap_before = gap_before or set()
        payloads = bytearray()
        selectors = []
        rows = []
        for index, (first, second, third, payload) in enumerate(records):
            if index in gap_before:
                payloads.extend(b"G")
            offset = 12 + len(payloads)
            payloads.extend(payload)
            selectors.append((first, second, third))
            rows.append((first, second, third, offset, len(payload)))
        table = 12 + len(payloads)
        header = b"SRSC" + struct.pack("<HIH", 0x0100, table, len(rows))
        data = bytearray(header)
        data.extend(payloads)
        for row in rows:
            data.extend(struct.pack("<HHHII", *row))
        return bytes(data), selectors

    def test_measures_contiguous_selector_trio_and_side_footer(self):
        data, selectors = self.make_snapshot([
            *self.payload_trio(),
            (0x0500, 0, 0, b"123456"),
            (0x0402, 0, 0, b"abcd"),
        ])
        result = measure_file(data, selectors)
        self.assertEqual(result["first_match_keys"], 1)
        self.assertEqual(result["expected_trios"], 1)
        self.assertEqual(result["internal_gap_values"], {0: 2})
        self.assertEqual(result["group_count"], 1)
        self.assertEqual(result["first_group_offset"], 12)
        self.assertEqual(result["table_offset"] - result["last_group_end"], 10)
        self.assertTrue(result["side_footer_0500_0402"])
        self.assertEqual(result["kind_lengths"][0x0502], {54: 1})
        self.assertEqual(result["count_metrics"], {
            "bounded_0501_count_fields": 1,
            "0503_prefix_matches_0501_count": 1,
            "0502_prefix_matches_0501_count": 1,
            "0503_length_matches_2_plus_8_count": 1,
            "0502_length_matches_2_plus_52_count": 1,
        })
        self.assertEqual(result["prefix_extent_deltas"], {0: 1})

    def test_reports_trailing_bytes_after_fixed_0501_reads(self):
        records = self.payload_trio()
        first, second, third, payload = records[0]
        records[0] = (first, second, third, payload + b"TAIL")
        data, selectors = self.make_snapshot(records)
        result = measure_file(data, selectors)
        self.assertEqual(result["prefix_extent_deltas"], {4: 1})

    def test_ignores_unbounded_0501_prefix_without_slicing(self):
        records = self.payload_trio()
        payload = bytearray(records[0][3])
        struct.pack_into("<H", payload, 0, 0xffff)
        records[0] = (*records[0][:3], bytes(payload))
        data, selectors = self.make_snapshot(records)
        result = measure_file(data, selectors)
        self.assertEqual(result["prefix_extent_deltas"], {})

    def test_reports_only_aggregate_suffix16_repetition(self):
        suffix = b"0123456789abcdef"
        records = self.payload_trio(suffix16=suffix)
        records.extend(self.payload_trio(second=9, suffix16=suffix))
        data, selectors = self.make_snapshot(records)
        result = measure_file(data, selectors)
        values = result["suffix16_values"]
        self.assertEqual(sum(values.values()), 2)
        self.assertEqual(values, {suffix: 2})
        aggregate = {"distinct_values": len(values),
                     "duplicate_occurrences": sum(values.values()) - len(values)}
        self.assertEqual(aggregate, {"distinct_values": 1,
                                     "duplicate_occurrences": 1})

    def test_reports_nonzero_extent_gap_without_claiming_contiguity(self):
        data, selectors = self.make_snapshot(self.payload_trio(), gap_before={1})
        result = measure_file(data, selectors)
        self.assertEqual(result["expected_trios"], 1)
        self.assertEqual(result["internal_gap_values"], {0: 1, 1: 1})
        self.assertFalse(result["side_footer_0500_0402"])

    def test_reports_prefix_count_mismatch_separately_from_length_shape(self):
        data, selectors = self.make_snapshot(self.payload_trio(prefix_8=3))
        result = measure_file(data, selectors)
        self.assertEqual(result["count_metrics"][
            "0503_prefix_matches_0501_count"], 0)
        self.assertEqual(result["count_metrics"][
            "0503_length_matches_2_plus_8_count"], 1)

    def test_reports_0502_prefix_count_mismatch_separately_from_length_shape(self):
        data, selectors = self.make_snapshot(self.payload_trio(prefix_52=2))
        result = measure_file(data, selectors)
        self.assertEqual(result["count_metrics"][
            "0502_prefix_matches_0501_count"], 0)
        self.assertEqual(result["count_metrics"][
            "0502_length_matches_2_plus_52_count"], 0)

    def test_rejects_selector_snapshot_mismatch(self):
        data, selectors = self.make_snapshot(self.payload_trio())
        with self.assertRaisesRegex(ValueError, "selector snapshot"):
            measure_file(data, selectors[:-1] + [(0x0502, 8, 0)])

    def test_rejects_out_of_bounds_payload_extent(self):
        data, selectors = self.make_snapshot(self.payload_trio())
        table = struct.unpack_from("<I", data, 6)[0]
        corrupt = bytearray(data)
        struct.pack_into("<I", corrupt, table + 6, len(data) + 1)
        with self.assertRaisesRegex(ValueError, "exceeds input"):
            measure_file(bytes(corrupt), selectors)

    def test_rejects_payload_extent_overlapping_header(self):
        data, selectors = self.make_snapshot(self.payload_trio())
        table = struct.unpack_from("<I", data, 6)[0]
        corrupt = bytearray(data)
        struct.pack_into("<I", corrupt, table + 6, 8)
        with self.assertRaisesRegex(ValueError, "exceeds input"):
            measure_file(bytes(corrupt), selectors)


if __name__ == "__main__":
    unittest.main()
