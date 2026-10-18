import unittest

from measure_srsc_label_payloads import classify


class LabelPayloadTests(unittest.TestCase):
    def test_lengths_and_printable_payload(self):
        self.assertEqual(classify(b'\x03\x00abc')['length_exact'], 1)
        self.assertEqual(classify(b'\x03\x00abc')['nonempty_printable_or_nul'], 1)
        self.assertEqual(classify(b'\x03\x00ab')['length_too_large'], 1)
        self.assertEqual(classify(b'\x01\x00ab')['length_shorter'], 1)
        self.assertEqual(classify(b'\x01')['short_prefix'], 1)
        self.assertEqual(classify(b'\x01\x00\xff')['nonempty_printable_or_nul'], 0)
        self.assertEqual(classify(b'\x00\x00')['nonempty_printable_or_nul'], 0)
        self.assertEqual(classify(b'\x03\x00a\x00\x00')['trailing_nul'], 1)
        self.assertEqual(classify(b'\x03\x00a\x00\x00')['embedded_nul'], 1)
        self.assertEqual(classify(b'\x02\x00a\x00')['length_even'], 1)


if __name__ == '__main__':
    unittest.main()
