import unittest
from collections import Counter
from contextlib import redirect_stdout
import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
from unittest.mock import patch

import measure_0102_indirect_ranges as scanner
from measure_0102_indirect_ranges import measure, measure_units, zero_third_0400
from test_measure_0102_array_types import body, resource
from test_measure_srsc_prefix_selector import fixture


class IndirectRangeTests(unittest.TestCase):
    def test_raw_guards_signed_high_and_end_boundary(self):
        flags = [0x1005] * 8
        units = [0, 0x00010000, 3, 0xffff0004, 0x00010008,
                 0x00030009, 0x0001000c, 0x00020008, 0, 0, 0, 0]
        result = measure_units(units, flags)
        self.assertEqual(result['flagged'], 8)
        self.assertEqual(result['clear_low_zero'], 2)
        self.assertEqual(result['clear_high_zero'], 2)
        self.assertEqual(result['clear_both_zero'], 1)
        self.assertEqual(result['negative_high'], 1)
        self.assertEqual(result['in_bounds'], 3)
        self.assertEqual(result['end_outside'], 1)
        self.assertEqual(result['in_bounds_base_overlap'], 0)
        self.assertEqual(result['in_bounds_prior_range_overlap'], 1)
        self.assertEqual(result['in_bounds_unique_extra_elements'], 4)

    def test_overlaps_base_and_counts_uncovered_extra(self):
        counts = measure_units([0x00020001, 0, 0, 0, 0], [0x1005, 9])
        self.assertEqual(counts['in_bounds_base_overlap'], 1)
        self.assertEqual(counts['in_bounds_elements'], 2)
        self.assertEqual(counts['in_bounds_unique_extra_elements'], 1)
        self.assertEqual(counts['extra_elements_not_covered'], 2)
        with self.assertRaises(ValueError):
            measure_units([], [0x1000])

    def test_type10_candidate_spans_and_overlap(self):
        counts = measure_units([0x00020003, 0x00020004, 0, 0, 0, 0], [0x1005, 10])
        self.assertEqual(counts['type10_entries'], 1)
        self.assertEqual(counts['type10_nonempty_in_bounds'], 1)
        self.assertEqual(counts['type10_extra_elements'], 2)
        self.assertEqual(counts['type10_overlaps_flagged_extra'], 1)
        self.assertEqual(counts['extra_not_covered_by_either'], 1)
        counts = measure_units([0x00020001], [10])
        self.assertEqual(counts['type10_nonempty_outside'], 1)

    def test_type10_span_bytes_are_bounded(self):
        counts = measure_units([0x00020001, 0x3178303c, 0x0000003e], [10])
        self.assertEqual(counts['type10_nul_in_span'], 1)
        self.assertEqual(counts['type10_printable_before_nul'], 1)
        self.assertEqual(counts['type10_hex_tag_prefix'], 1)
        counts = measure_units([0x00020001, 0x3178303c, 0x0000003e], [10], tag_index=Counter({1: 2}))
        self.assertEqual(counts['type10_tag_0400_multiple'], 1)
        counts = measure_units([0x00020001, 0x3178303c, 0x0000003e], [10], tag_index=Counter({1: 1}))
        self.assertEqual(counts['type10_tag_0400_unique'], 1)
        counts = measure_units([0x00020001, 0x3178303c, 0x0000003e], [10], tag_index=Counter())
        self.assertEqual(counts['type10_tag_0400_missing'], 1)

    def test_type10_tag_u32_limit_and_low_word(self):
        payload = b'<0x10001>\0\0\0'
        units = [0x00030001] + [int.from_bytes(payload[i:i + 4], 'little') for i in range(0, len(payload), 4)]
        counts = measure_units(units, [10], tag_index=Counter({1: 1}))
        self.assertEqual(counts['type10_tag_high_nonzero'], 1)
        self.assertEqual(counts['type10_tag_0400_unique'], 1)
        payload = b'<0x100000000>\0\0\0'
        units = [0x00040001] + [int.from_bytes(payload[i:i + 4], 'little') for i in range(0, len(payload), 4)]
        counts = measure_units(units, [10], tag_index=Counter())
        self.assertEqual(counts['type10_tag_over_u32'], 1)

    def test_tag_index_uses_zero_third_and_rejects_invalid_payload(self):
        data = fixture([(0x400, 3, 0, b'ab'), (0x400, 4, 1, b'cd')])
        entries = zero_third_0400(data)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0][:2], (3, 2))
        malformed = bytearray(data)
        table_offset = int.from_bytes(malformed[6:10], 'little')
        malformed[table_offset + 6:table_offset + 10] = (table_offset + 1).to_bytes(4, 'little')
        with self.assertRaises(ValueError):
            zero_third_0400(malformed)

    def test_type5_and_9_elements_and_duplicate_dependency_ids(self):
        units = [0x00030002, 0x00020005, 0, 0x00030004, 0x00070001,
                 0x00000011, 0x00080001]
        counts = measure_units(units, [0x1005, 0x1009], Counter({3: 1, 7: 2, 8: 1}))
        self.assertEqual(counts['indirect_5_units'], 3)
        self.assertEqual(counts['indirect_5_zero'], 1)
        self.assertEqual(counts['indirect_5_dependency_unique'], 1)
        self.assertEqual(counts['indirect_5_dependency_multiple'], 1)
        self.assertEqual(counts['indirect_9_units'], 2)
        self.assertEqual(counts['indirect_9_high_zero'], 1)
        self.assertEqual(counts['indirect_9_high_nonzero'], 1)
        missing = measure_units(units, [0x1005, 0x1009], Counter())
        self.assertEqual(missing['indirect_5_dependency_missing'], 2)
        no_comparison = measure_units(units, [0x1005, 0x1009])
        self.assertNotIn('indirect_5_dependency_missing', no_comparison)

    def test_framing_and_resource_mismatch(self):
        data = fixture([(0x102, 0, 0, body(7, 1, [0x00010001, 0]))])
        self.assertEqual(measure(data, {7: [[0x1005]]})['in_bounds'], 1)
        self.assertEqual(measure(data, {7: [[0x1005], [5]]})['missing_or_ambiguous_resource'], 1)
        self.assertEqual(measure(data, {7: [[5, 5]]})['mismatched_count'], 1)
        malformed = fixture([(0x102, 0, 0, body(7, 1, [0])[:-1])])
        with self.assertRaises(ValueError):
            measure(malformed, {7: [[5]]})

    def test_cli_integrates_verified_descriptor_and_tag_inventory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            odb = fixture([(0x102, 0, 0, body(7, 2, [0x00010002, 0x00020003,
                                                       0x00030007, 0x3178303c, 0x0000003e])),
                           (0x400, 1, 0, b'payload')])
            descriptor = b'version 1\r\ndependencies 1\r\n3 model\r\n'
            rfl = resource([0x1005, 10])
            (root / 'source.odb').write_bytes(odb)
            (root / 'source.db').write_bytes(descriptor)
            (root / 'candidate.rfl').write_bytes(rfl)
            inventory = {'files': [{'path': 'source.odb', 'status': 'examined', 'file_size': len(odb),
                                    'sha256': hashlib.sha256(odb).hexdigest()}]}
            descriptors = {'files': [{'path': 'source.db', 'size': len(descriptor),
                                      'sha256': hashlib.sha256(descriptor).hexdigest()}]}
            (root / 'srsc.json').write_text(json.dumps(inventory))
            (root / 'assets.json').write_text(json.dumps(descriptors))
            argv = ['scan', str(root), str(root / 'srsc.json'), str(root / 'candidate.rfl'),
                    '--descriptors', str(root / 'assets.json'), '--compare-0400']
            with patch.object(sys, 'argv', argv), patch.object(scanner, 'RESOURCE_OFFSET', 0), \
                    patch.object(scanner, 'RESOURCE_SIZE', len(rfl)), \
                    patch.object(scanner, 'RFL_SHA256', hashlib.sha256(rfl).hexdigest()):
                output = io.StringIO()
                with redirect_stdout(output):
                    scanner.main()
                result = json.loads(output.getvalue())
                self.assertEqual(result['counts']['indirect_5_dependency_unique'], 1)
                self.assertEqual(result['counts']['type10_tag_0400_unique'], 1)
                self.assertEqual(result['descriptor_pairs'], 1)
                descriptors['files'][0]['sha256'] = '0' * 64
                (root / 'assets.json').write_text(json.dumps(descriptors))
                with self.assertRaises(ValueError):
                    scanner.main()


if __name__ == '__main__':
    unittest.main()
