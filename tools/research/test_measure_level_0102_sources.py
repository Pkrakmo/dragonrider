from collections import Counter
import unittest

from measure_level_0102_sources import candidate_key, classify, ranges
from test_measure_0102_array_types import body
from test_measure_srsc_prefix_selector import fixture


class Level0102SourceTests(unittest.TestCase):
    def test_path_keys_are_lexical_and_reject_unsafe(self):
        self.assertEqual(candidate_key('Group/area/one.lvl', b'..\\shared\\name\0', False),
                         'group/shared/name.odb')
        self.assertEqual(candidate_key('Group/area/one.lvl', b'foo.txd', False), 'group/area/foo.txd')
        self.assertEqual(candidate_key('Install_Group/area_name/one.lvl', b'name', True), 'area name/name.odb')
        for value in (b'../../../../bad', b'C:\\bad', b'/bad', b'a\0b', b'\xff', b'.', b'..', b'foo\\'):
            self.assertIsNone(candidate_key('Group/area/one.lvl', value, False))

    def test_joint_intersection_keeps_independent_candidates(self):
        index = {1: {0, 1}, 2: {1, 2}}
        self.assertEqual(classify([1, 2], index, {0, 1}), (1, 2, 1, 2))
        self.assertEqual(classify([1, 2], index, {0}), (1, 1, 0, 1))
        self.assertEqual(classify([1, 99], index, set()), (0, 0, 0, 0))
        with self.assertRaises(ValueError):
            classify([], index, set())

    def test_ranges_check_bounds_and_metadata(self):
        flags = {7: [[0x100c]]}
        data = fixture([(0x102, 0, 0, body(7, 1, [(2 << 16) | 1, 5, 6]))])
        self.assertEqual(list(ranges(data, flags)), [[5, 6]])
        for invalid in ({}, {7: [[0x100c], [0x100c]]}):
            with self.assertRaises(ValueError):
                list(ranges(data, invalid))
        data = fixture([(0x102, 0, 0, body(7, 1, [(2 << 16) | 2, 5]))])
        self.assertEqual(list(ranges(data, flags)), [])


if __name__ == '__main__':
    unittest.main()
