"""Synthetic tests for bounded 0x0502 row float slot measurements."""
import math
import struct
import unittest

from measure_srsc_0501_float_slots import measure_file, summarize_0502_payload


def row_payload(values):
    row = bytearray(52)
    for offset, value in zip((40, 44, 48), values):
        struct.pack_into("<f", row, offset, value)
    return struct.pack("<H", 1) + row


class MeasureSrsc0501FloatSlotsTests(unittest.TestCase):
    def test_reports_aggregate_ranges_without_values(self):
        result = summarize_0502_payload(row_payload((-1.5, 2.0, 3.25)))
        self.assertEqual(result["row_count"], 1)
        self.assertEqual(result["consumed_bytes"], 54)
        self.assertEqual([item["row_offset"] for item in result["slots"]], [40, 44, 48])
        self.assertEqual([item["minimum_before_scale"] for item in result["slots"]],
                         [-1.5, 2.0, 3.25])

    def test_counts_non_finite_values(self):
        result = summarize_0502_payload(row_payload((math.nan, math.inf, -math.inf)))
        self.assertEqual([item["non_finite_count"] for item in result["slots"]], [1, 1, 1])
        self.assertIsNone(result["slots"][0]["minimum_before_scale"])

    def test_rejects_truncated_prefix_and_rows(self):
        for payload in (b"\x01", b"\x01\x00", b"\x01\x00" + bytes(51)):
            with self.subTest(size=len(payload)), self.assertRaises(ValueError):
                summarize_0502_payload(payload)

    def test_measures_only_first_stable_order_trio(self):
        selectors = [(0x0501, 7, 1), (0x0503, 7, 9),
                     (0x0502, 7, 8), (0x0502, 9, 0)]
        payloads = [b"", b"", row_payload((1.0, 2.0, 3.0)), b"\0\0"]
        header_size = 12
        cursor = header_size
        table_rows = []
        chunks = []
        for (first, second, third), payload in zip(selectors, payloads):
            table_rows.append(struct.pack("<HHHII", first, second, third,
                                          cursor, len(payload)))
            chunks.append(payload)
            cursor += len(payload)
        table_offset = cursor
        header = b"SRSC" + struct.pack("<HIH", 0x0100, table_offset, 4)
        data = header + b"".join(chunks) + b"".join(table_rows)
        result = measure_file(data, selectors)
        self.assertEqual(result["matched_trios"], 1)
        self.assertEqual(result["all_0502_rows"], 2)
        self.assertEqual(result["selected_0502_rows"], 1)
        self.assertEqual(result["unselected_0502_rows"], 1)
        self.assertEqual(result["rows"], 1)
        self.assertEqual([slot["minimum_before_scale"] for slot in result["slots"]],
                         [1.0, 2.0, 3.0])

    def test_rejects_payload_range_past_table(self):
        selectors = [(0x0501, 7, 0), (0x0503, 7, 0), (0x0502, 7, 0)]
        header = b"SRSC" + struct.pack("<HIH", 0x0100, 12, 3)
        table = b"".join(struct.pack("<HHHII", *row, 12, 100)
                         for row in selectors)
        with self.assertRaisesRegex(ValueError, "payload range"):
            measure_file(header + table, selectors)


if __name__ == "__main__":
    unittest.main()
