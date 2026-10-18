import struct
import unittest

from measure_0102_array_types import measure, resource_types
from test_measure_srsc_prefix_selector import fixture


def resource(flags):
    # One 32-byte entry, one group-offset dword, one 12-byte group header.
    data = bytearray(52 + 16 * len(flags))
    struct.pack_into('<I', data, 0, 1)
    struct.pack_into('<I', data, 4, 7)
    struct.pack_into('<III', data, 24, len(flags), 1, 32)
    struct.pack_into('<I', data, 36, 36)
    struct.pack_into('<II', data, 44, len(flags), 12)
    for i, flag in enumerate(flags):
        struct.pack_into('<I', data, 52 + i * 16 + 4, flag)
    return bytes(data)


def body(key, declared, values):
    return (b'\x00' * 8 + struct.pack('<H', key) + b'\x00\x00' +
            struct.pack('<II', declared, len(values)) +
            b''.join(struct.pack('<I', value) for value in values))


class ArrayTypeTests(unittest.TestCase):
    def test_nested_groups_scalar_and_flagged_values(self):
        by_key, stats = resource_types(resource([5, 9, 0x1005, 2]))
        self.assertEqual(stats['groups'], 1)
        self.assertEqual(stats['entries_in_groups'], 4)
        data = fixture([(0x102, 0, 0, body(7, 4, [0x12340001, 23, 42, 4]))])
        result = measure(data, by_key, [0x1234])
        self.assertEqual(result['array_at_least_declared'], 1)
        self.assertEqual(result['scalar_5_high_nonzero'], 1)
        self.assertEqual(result['scalar_5_dependency_unique'], 1)
        self.assertEqual(result['scalar_9_high_zero'], 1)
        self.assertEqual(result['scalar_9_zero'], 0)
        self.assertEqual(result['flagged_entries'], 1)
        self.assertEqual(result['other_scalar_entries'], 1)
        self.assertEqual(measure(data, by_key, [1])['scalar_5_dependency_missing'], 1)
        self.assertEqual(measure(data, by_key, [0x1234, 0x1234])['scalar_5_dependency_multiple'], 1)

    def test_unmatched_short_and_count_mismatch_are_not_interpreted(self):
        by_key, _ = resource_types(resource([5, 9]))
        data = fixture([(0x102, 0, 0, body(8, 2, [1, 2])),
                        (0x102, 0, 0, body(7, 1, [1])),
                        (0x102, 0, 0, body(7, 2, [1]))])
        result = measure(data, by_key)
        self.assertEqual(result['missing_or_ambiguous_resource'], 1)
        self.assertEqual(result['mismatched_count'], 1)
        self.assertEqual(result['array_shorter_than_declared'], 1)
        self.assertEqual(result['scalar_5'], 0)
        result = measure(fixture([(0x102, 0, 0, body(7, 2, [1, 2]))]), {7: [[5, 9], [5, 9]]})
        self.assertEqual(result['missing_or_ambiguous_resource'], 1)

    def test_rejects_truncated_or_invalid_relative_ranges(self):
        sample = resource([5])
        for bad in (b'', sample[:3], sample[:35], sample[:-1]):
            with self.assertRaises(ValueError):
                resource_types(bad)
        bad = bytearray(sample)
        struct.pack_into('<I', bad, 32, 0xffffffff)
        with self.assertRaises(ValueError):
            resource_types(bad)
        bad = bytearray(sample)
        struct.pack_into('<I', bad, 48, 0xffffffff)
        with self.assertRaises(ValueError):
            resource_types(bad)
        bad = bytearray(sample)
        struct.pack_into('<I', bad, 24, 2)
        with self.assertRaises(ValueError):
            resource_types(bad)
        with self.assertRaises(ValueError):
            measure(fixture([(0x102, 0, 0, body(7, 1, [1])[:-1])]), {7: [[5]]})


if __name__ == '__main__':
    unittest.main()
