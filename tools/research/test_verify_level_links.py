import struct
import unittest

from test_measure_srsc_prefix_selector import fixture
from verify_level_links import decode, selected


def level(values):
    return (struct.pack('<I', 1) + bytes(28) + b'\0\0' + bytes(24) +
            struct.pack('<I', len(values)) + b''.join(struct.pack('<I', v) for v in values))


class VerifyLevelLinksTests(unittest.TestCase):
    def test_raw_and_truncated_comparisons(self):
        payload = level([0, 0x10000, 4])
        self.assertEqual(decode(payload), {'Entries': 1, 'Inner values': 3,
            'Nonzero high halves': 1, 'Raw values outside entry count': 2,
            'Low halves outside entry count': 1, 'Low halves equal entry index': 2})
        for length in range(len(payload)):
            with self.assertRaises(ValueError):
                decode(payload[:length])

    def test_gate_selection_and_duplicates(self):
        data = fixture([(1, 0, 0, level([0])), (3, 0, 0, b'')])
        index, counts = selected(data)
        self.assertEqual(index, 0)
        self.assertEqual(counts['Inner values'], 1)
        with self.assertRaises(ValueError):
            selected(fixture([(1, 0, 0, level([])), (1, 0, 0, level([]))]))


if __name__ == '__main__':
    unittest.main()
