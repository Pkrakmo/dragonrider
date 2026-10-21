import unittest
from collections import Counter

from measure_level_object_metadata import (candidate_records, compare_frame_candidates,
                                           descriptor_string_candidates, join_candidate,
                                           measure_coverage, measure_frame_body, measure_words)
from test_measure_0102_array_types import body, resource
from test_measure_srsc_prefix_selector import fixture


class LevelObjectMetadataTests(unittest.TestCase):
    def test_candidate_offsets_are_bounded_and_compared_positionally(self):
        import struct
        sample = bytearray(resource([5]))
        sample.extend(b'example\0')
        struct.pack_into('<I', sample, 52, len(sample) - 8 - 52)
        candidates = descriptor_string_candidates(bytes(sample))[7][0]
        result = compare_frame_candidates([0], [(5, memoryview(b'example\0'))], candidates)
        self.assertEqual(result['candidate_0_descriptor_equal'], 1)
        self.assertEqual(result['candidate_0_descriptor_bounded'], 1)
        with self.assertRaises(ValueError):
            compare_frame_candidates([0], [], candidates)
        with self.assertRaises(ValueError):
            descriptor_string_candidates(bytes(sample[:50]))

    def test_descriptor_pair_ambiguity(self):
        candidates = [{'0_descriptor': b'a'}, {'0_descriptor': b'a'},
                      {'0_descriptor': b'b'}]
        result = compare_frame_candidates([0, 2, 1], [(5, b'a'), (5, b'b'), (9, b'a')],
                                          candidates, [5, 5, 5])
        self.assertEqual(result['descriptor_pair_multiple'], 1)
        self.assertEqual(result['descriptor_pair_one'], 1)
        self.assertEqual(result['descriptor_pair_none'], 1)
        missing = compare_frame_candidates([0], [(5, b'a')],
                                           [{'0_descriptor': b'a'}, {}], [5, 5])
        self.assertEqual(missing['descriptor_candidates_missing'], 1)
        with self.assertRaises(ValueError):
            compare_frame_candidates([], [], candidates, [])

    def test_frame_body_numeric_candidates_and_nul_boundaries(self):
        decimal = measure_frame_body(b'-1\0', 0xffffffff)
        self.assertEqual(decimal['body_one_terminal_nul'], 1)
        self.assertEqual(decimal['body_decimal_equals_dword_signed'], 1)
        self.assertEqual(decimal['body_decimal_equals_dword_unsigned'], 0)
        self.assertEqual(measure_frame_body(b'0x2a', 42)['body_hex_equals_dword'], 1)
        self.assertEqual(measure_frame_body(b'1.5\0', 0x3fc00000)['body_float_equals_dword'], 1)
        self.assertEqual(measure_frame_body(b'1\0x\0', 1)['body_embedded_nul'], 1)
        self.assertEqual(measure_frame_body(b'9' * 5000, 9)['body_decimal_integer'], 1)

    def test_candidate_selector_preserves_duplicates(self):
        first = body(7, 1, [4])
        second = body(8, 1, [9])
        data = fixture([(0x102, 3, 0, first), (0x102, 3, 1, second),
                        (0x200, 3, 0, b'')])
        self.assertEqual(candidate_records(data)[3], [(7, 1), (8, 1)])
        self.assertNotIn(4, candidate_records(data))

    def test_candidate_rejects_truncated_header_and_array(self):
        for payload in (b'', b'\xff\xff', b'\x00\x00' + bytes(17),
                        body(7, 1, [4])[:-1]):
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                candidate_records(fixture([(0x102, 1, 0, payload)]))

    def test_metadata_indices_and_range_categories(self):
        flags = [7, 0x1005, 0x100c, 0x1001, 0x1002]
        words = [0, 1, 2, 3, 4, 100]
        units = [0, (2 << 16) | 1, 0, (0xffff << 16) | 1,
                 (2 << 16) | 5, 0]
        result = measure_words(words, units, flags)
        self.assertEqual(result['words'], 6)
        self.assertEqual(result['word_outside_metadata'], 1)
        self.assertEqual(result['scalar'], 1)
        self.assertEqual(result['flagged'], 4)
        self.assertEqual(result['flagged_range_inside_units'], 1)
        self.assertEqual(result['flagged_zero_start_or_length'], 1)
        self.assertEqual(result['flagged_negative_length'], 1)
        self.assertEqual(result['flagged_end_outside_units'], 1)

    def test_position_outside_units_is_counted(self):
        result = measure_words([0, 1], [], [7, 0x1005])
        self.assertEqual(result['scalar_position_outside_units'], 1)
        self.assertEqual(result['flagged_position_outside_units'], 1)

    def test_frames_are_positional_and_checked(self):
        result = measure_words([0, 1], [0, 0], [7, 9], [(0, b'hi\0'), (9, b'\xff')])
        self.assertEqual(result['frame_tag_equals_word'], 1)
        self.assertEqual(result['frame_tag_equals_descriptor_flags'], 1)
        self.assertEqual(result['frame_ends_nul'], 1)
        self.assertEqual(result['frame_printable_or_nul'], 1)
        with self.assertRaises(ValueError):
            measure_words([0, 1], [0, 0], [7, 9], [(0, b'')])

    def test_scalar_dependency_counts_and_duplicates(self):
        result = measure_words([0, 0, 0, 1, 1],
                               [(3 << 16) | 1, 4 << 16, 0, 5 << 16, 7],
                               [5, 9], dependency_ids=Counter([3, 3, 4]))
        self.assertEqual(result['scalar_5_units'], 3)
        self.assertEqual(result['scalar_5_dependency_multiple'], 1)
        self.assertEqual(result['scalar_5_dependency_unique'], 1)
        self.assertEqual(result['scalar_5_high_zero'], 1)
        self.assertEqual(result['scalar_9_high_zero'], 1)

    def test_duplicate_flagged_keys_use_first_position(self):
        result = measure_words([0, 0], [(1 << 16) | 1, 0], [0x1005])
        self.assertEqual(result['flagged_range_inside_units'], 2)
        self.assertEqual(result['flagged_zero_start_or_length'], 0)

    def test_type_10_spans_are_bounded(self):
        result = measure_words([0, 0, 0], [(1 << 16) | 2, (2 << 16) | 2, 0x00006968], [10])
        self.assertEqual(result['type_10_spans_inside_units'], 1)
        self.assertEqual(result['type_10_spans_outside_units'], 1)
        self.assertEqual(result['type_10_empty_spans'], 1)
        self.assertEqual(result['type_10_spans_nul_terminated'], 1)
        self.assertEqual(result['type_10_spans_printable_prefix'], 1)

    def test_candidate_coverage_counts_overlap_and_uncovered(self):
        # Two base units, a flagged interval covering 2..4, and a type-10
        # span covering 4..5. Unit 6 remains uncovered.
        result = measure_coverage([0, 1], [(3 << 16) | 2, (2 << 16) | 4, 0, 0, 0, 0, 0],
                                  [0x1005, 10])
        self.assertEqual(result['base_units'], 2)
        self.assertEqual(result['extra_units'], 5)
        self.assertEqual(result['extra_units_flagged_only'], 2)
        self.assertEqual(result['extra_units_both'], 1)
        self.assertEqual(result['extra_units_type10_only'], 1)
        self.assertEqual(result['extra_units_uncovered'], 1)
        self.assertEqual(measure_coverage([3], [0], [7])['coverage_objects_skipped'], 1)
        self.assertEqual(measure_coverage([0, 0], [0], [7])['coverage_objects_skipped'], 1)

    def test_join_requires_unique_sources_files_records_and_metadata(self):
        key = (3 << 16) | 4
        sources = {3: ['candidate']}
        records = {4: [(7, 2)]}
        indexed = {'candidate': [(records, Counter([9]))]}
        metadata = {7: [[5, 9]]}
        self.assertEqual(join_candidate(key, sources, indexed, metadata), (None, [5, 9], Counter([9])))
        cases = [({}, indexed, metadata, 'source_id_missing'),
                 ({3: ['candidate', 'candidate']}, indexed, metadata, 'source_id_multiple'),
                 ({3: [None]}, indexed, metadata, 'source_path_unusable'),
                 (sources, {}, metadata, 'source_file_missing'),
                 (sources, {'candidate': [({}, None), ({}, None)]}, metadata, 'source_file_multiple'),
                 (sources, {'candidate': [({}, None)]}, metadata, 'record_missing'),
                 (sources, {'candidate': [({4: [(7, 2), (7, 2)]}, None)]}, metadata, 'record_multiple'),
                 (sources, indexed, {7: [[5]]}, 'metadata_missing_ambiguous_or_count_mismatch'),
                 (sources, indexed, {7: [[5, 9], [5, 9]]}, 'metadata_missing_ambiguous_or_count_mismatch')]
        for source, files, metas, reason in cases:
            with self.subTest(reason=reason):
                self.assertEqual(join_candidate(key, source, files, metas)[0], reason)


if __name__ == '__main__':
    unittest.main()
