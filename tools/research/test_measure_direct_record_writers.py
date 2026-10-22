import unittest

from measure_direct_record_writers import measure


class DirectWriterTests(unittest.TestCase):
    def test_records_immediate_selector_at_direct_call(self):
        disassembly = '''
  0040dd41: 68 02 01 00 00       push   0x102
  0040dd46: 8b cf                mov    ecx,edi
  0040dd4c: e8 af 18 05 00       call   0x45f600
'''
        counts = measure(disassembly)
        self.assertEqual(counts['direct_calls'], 1)
        self.assertEqual(counts['call_0040dd4c'], 1)
        self.assertEqual(counts['selector_0102'], 1)
        self.assertNotIn('selector_pair_0102', counts)

    def test_records_two_immediate_selector_words_in_call_order(self):
        disassembly = '''
  00401610: 68 7b 03 00 00       push   0x37b
  00401615: 68 01 04 00 00       push   0x401
  0040161a: e8 d1 df 14 00       call   0x101562f0
'''
        counts = measure(disassembly, 0x101562f0)
        self.assertEqual(counts['selector_0401'], 1)
        self.assertEqual(counts['selector_pair_0401_037b'], 1)

    def test_records_three_immediate_selector_words_in_call_order(self):
        disassembly = '''
  004372a7: 6a 00                push   0x0
  004372a9: 6a 00                push   0x0
  004372ab: 6a 20                push   0x20
  004372bb: e8 10 7e 02 00       call   0x45f0d0
'''
        counts = measure(disassembly, 0x45f0d0)
        self.assertEqual(counts['selector_0020'], 1)
        self.assertEqual(counts['selector_pair_0020_0000'], 1)
        self.assertEqual(counts['selector_triple_0020_0000_0000'], 1)

    def test_ignores_other_and_reports_missing_immediate(self):
        disassembly = '''
  00400000: 50                   push   eax
  00400001: e8 fa f5 05 00       call   0x45f600
  00400006: 68 20 00 00 00       push   0x20
  0040000b: e8 00 00 00 00       call   0x401010
'''
        counts = measure(disassembly)
        self.assertEqual(counts['direct_calls'], 1)
        self.assertEqual(counts['calls_without_nearby_immediate_push'], 1)
        self.assertNotIn('selector_0020', counts)


if __name__ == '__main__':
    unittest.main()
