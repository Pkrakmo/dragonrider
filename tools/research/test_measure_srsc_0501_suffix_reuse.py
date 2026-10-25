import struct
import unittest

from measure_srsc_0501_suffix_reuse import measure_file


class Srsc0501SuffixReuseTests(unittest.TestCase):
    def make_snapshot(self, suffix=b"0123456789abcdef", include_in=(),
                      add_other_kind=False, add_other_0501=False,
                      add_same_second_0501=False):
        payload_0501 = (struct.pack("<H", 0) + b"READ" + b"SKIP"
                        + struct.pack("<IIIII", 1, 0, 2, 0, 0) + suffix)
        payload_0503 = struct.pack("<H", 2) + b"A" * 16
        payload_0502 = struct.pack("<H", 1) + b"B" * 52
        if 0x0503 in include_in:
            payload_0503 += suffix + suffix
        if 0x0502 in include_in:
            payload_0502 += suffix
        records = [
            (0x0501, 7, 0, payload_0501),
            (0x0503, 7, 0, payload_0503),
            (0x0502, 7, 0, payload_0502),
        ]
        if add_other_kind:
            records.append((0x0102, 9, 0, b"other" + suffix + b"tail"))
        if add_other_0501:
            records.append((0x0501, 9, 0, payload_0501))
        if add_same_second_0501:
            records.append((0x0501, 7, 1, payload_0501))
        payloads = bytearray()
        rows = []
        selectors = []
        for first, second, third, payload in records:
            offset = 12 + len(payloads)
            payloads.extend(payload)
            rows.append((first, second, third, offset, len(payload)))
            selectors.append((first, second, third))
        table = 12 + len(payloads)
        data = bytearray(b"SRSC" + struct.pack("<HIH", 0x0100, table, len(rows)))
        data.extend(payloads)
        for row in rows:
            data.extend(struct.pack("<HHHII", *row))
        return bytes(data), selectors

    def test_counts_full_suffix_matches_by_follower_kind(self):
        data, selectors = self.make_snapshot(include_in=(0x0503, 0x0502))
        result = measure_file(data, selectors)
        self.assertEqual(result["trios_with_16_byte_suffix"], 1)
        self.assertEqual(result["suffix_records_found_in_0503"], 1)
        self.assertEqual(result["suffix_occurrences_in_0503"], 2)
        self.assertEqual(result["distinct_suffix_values_found_in_0503"], 1)
        self.assertEqual(result["suffix_records_found_in_0502"], 1)
        self.assertEqual(result["suffix_occurrences_in_0502"], 1)
        self.assertEqual(result["suffix_records_found_in_non_0501_payloads"], 1)
        self.assertEqual(result["suffix_occurrences_in_non_0501_payloads"], 3)

    def test_reports_no_match_when_suffix_is_absent(self):
        data, selectors = self.make_snapshot()
        result = measure_file(data, selectors)
        self.assertEqual(result["trios_with_16_byte_suffix"], 1)
        self.assertEqual(result["suffix_records_found_in_0503"], 0)
        self.assertEqual(result["suffix_records_found_in_0502"], 0)
        self.assertEqual(result["suffix_records_found_in_non_0501_payloads"], 0)

    def test_finds_match_in_a_nonadjacent_record_kind(self):
        data, selectors = self.make_snapshot(add_other_kind=True)
        result = measure_file(data, selectors)
        self.assertEqual(result["suffix_records_found_in_0503"], 0)
        self.assertEqual(result["suffix_records_found_in_0502"], 0)
        self.assertEqual(result["suffix_records_found_in_non_0501_payloads"], 1)
        self.assertEqual(result["suffix_occurrences_in_non_0501_payloads"], 1)

    def test_reports_repetition_in_other_0501_payloads_separately(self):
        data, selectors = self.make_snapshot(add_other_0501=True)
        result = measure_file(data, selectors)
        self.assertEqual(result["suffix_records_found_in_other_0501_payloads"], 1)
        self.assertEqual(result["suffix_occurrences_in_other_0501_payloads"], 1)
        self.assertEqual(result["suffix_records_found_in_other_0501_different_second"], 1)
        self.assertEqual(result["suffix_records_found_in_other_0501_same_second"], 0)
        self.assertEqual(result["suffix_records_found_in_non_0501_payloads"], 0)

    def test_classifies_same_second_selector_repeat(self):
        data, selectors = self.make_snapshot(add_same_second_0501=True)
        result = measure_file(data, selectors)
        self.assertEqual(result["suffix_records_found_in_other_0501_same_second"], 1)
        self.assertEqual(result["suffix_occurrences_in_other_0501_same_second"], 1)
        self.assertEqual(result["suffix_records_found_in_other_0501_different_second"], 0)

    def test_ignores_0501_payloads_without_exactly_16_trailing_bytes(self):
        data, selectors = self.make_snapshot(suffix=b"short")
        result = measure_file(data, selectors)
        self.assertEqual(result["trios_with_16_byte_suffix"], 0)

    def test_rejects_selector_snapshot_mismatch(self):
        data, selectors = self.make_snapshot()
        selectors[1] = (0x0502, 7, 0)
        with self.assertRaisesRegex(ValueError, "selector snapshot"):
            measure_file(data, selectors)


if __name__ == "__main__":
    unittest.main()
