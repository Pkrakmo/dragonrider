import struct
import unittest

from measure_srsc_stage_gates import measure
from test_measure_srsc_prefix_selector import fixture


class StageGateTests(unittest.TestCase):
    def test_missing_short_distinct_and_matching(self):
        self.assertEqual(measure(fixture([(1, 0, 0, b'x')]), 0x102)['missing'], 1)
        self.assertEqual(measure(fixture([(0x402, 0, 0, b'xx')]), 0x102)['short'], 1)
        good = fixture([(0x402, 0, 0, struct.pack('<I', 0x102))])
        self.assertEqual(measure(good, 0x102)['match'], 1)
        self.assertEqual(measure(good, 0x104)['different'], 1)
        duplicate = fixture([(0x402, 0, 0, b'abcd'), (0x402, 0, 0, b'efgh')])
        self.assertEqual(measure(duplicate, 0x102)['duplicate'], 1)

    def test_payload_range_rejected(self):
        data = bytearray(fixture([(0x402, 0, 0, b'abcd')]))
        table = struct.unpack_from('<I', data, 6)[0]
        struct.pack_into('<I', data, table + 6, 11)
        with self.assertRaises(ValueError):
            measure(data, 0x102)


if __name__ == '__main__':
    unittest.main()
