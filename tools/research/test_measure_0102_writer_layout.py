import struct
import unittest

from measure_0102_writer_layout import measure
from test_measure_srsc_prefix_selector import fixture


class WriterLayoutTests(unittest.TestCase):
    def test_boundary_lengths_and_gate(self):
        data = fixture([(0x402, 0, 0, struct.pack('<I', 0x102)),
                        (0x102, 0, 0, b'A' * 135), (0x102, 0, 0, b'A' * 136),
                        (0x102, 0, 0, b'A' * 137)])
        counts = measure(data)
        self.assertEqual((counts['shorter'], counts['equal'], counts['longer']), (1, 1, 1))
        self.assertEqual(counts['gate_0102'], 3)

    def test_gate_categories(self):
        record = (0x102, 0, 0, b'')
        cases = [([], 'gate_missing'), ([(0x402, 0, 0, b'')], 'gate_short'),
                 ([(0x402, 0, 0, b'1234'), (0x402, 0, 0, b'1234')], 'gate_multiple'),
                 ([(0x402, 0, 0, struct.pack('<I', 4))], 'gate_4'),
                 ([(0x402, 0, 0, struct.pack('<I', 5))], 'gate_other')]
        for gates, category in cases:
            with self.subTest(category=category):
                self.assertEqual(measure(fixture(gates + [record]))[category], 1)

    def test_invalid_selected_range_and_table(self):
        data = bytearray(fixture([(0x102, 0, 0, b'A')]))
        offset = struct.unpack_from('<I', data, 6)[0]
        struct.pack_into('<I', data, offset + 6, 11)
        with self.assertRaises(ValueError):
            measure(data)
        with self.assertRaises(ValueError):
            measure(b'SRSC')


if __name__ == '__main__':
    unittest.main()
