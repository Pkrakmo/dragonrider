import unittest

from measure_level_object_consumers import measure


class ConsumerCallTests(unittest.TestCase):
    def test_records_direct_calls_and_immediates_in_source_order(self):
        disassembly = '''
  0040cb43: 6a 07                push   0x7
  0040cb45: 6a 00                push   0x0
  0040cb47: 50                   push   eax
  0040cb4b: e8 80 c9 01 00       call   0x4294d0
'''
        counts = measure(disassembly, [0x4294d0])['0x004294d0']
        self.assertEqual(counts['direct_calls'], 1)
        self.assertEqual(counts['call_0040cb4b'], 1)
        self.assertEqual(counts['first_immediate_00000000'], 1)
        self.assertEqual(counts['immediate_pair_00000000_00000007'], 1)
        self.assertEqual(counts['calls_with_non_immediate_pushes'], 1)

    def test_separates_targets_and_ignores_indirect_calls(self):
        disassembly = '''
  00400000: 6a 01                push   0x1
  00400002: e8 e9 13 02 00       call   0x4213f0
  00400007: ff 10                call   DWORD PTR [eax]
  00400009: 90                   nop
  0040000a: 90                   nop
  0040000b: 90                   nop
  0040000c: 90                   nop
  0040000d: 90                   nop
  0040000e: 90                   nop
  0040000f: 90                   nop
  00400010: 90                   nop
  00400009: e8 c2 94 02 00       call   0x4294d0
'''
        result = measure(disassembly, [0x4294d0, 0x4213f0])
        self.assertEqual(result['0x004213f0']['direct_calls'], 1)
        self.assertEqual(result['0x004213f0']['first_immediate_00000001'], 1)
        self.assertEqual(result['0x004294d0']['direct_calls'], 1)
        self.assertEqual(result['0x004294d0']['calls_without_nearby_immediate_push'], 1)

    def test_lookback_is_bounded(self):
        disassembly = '\n'.join(
            ['  00400000: 6a 02                push   0x2'] +
            [f'  004000{i:02x}: 90                   nop' for i in range(1, 10)] +
            ['  00400010: e8 db 94 02 00       call   0x4294d0'])
        counts = measure(disassembly, [0x4294d0])['0x004294d0']
        self.assertEqual(counts['calls_without_nearby_immediate_push'], 1)

    def test_reports_direct_tail_jumps_separately_from_calls(self):
        disassembly = '''
  00408680: b9 78 2f 48 00       mov    ecx,0x482f78
  00408685: e9 46 0e 02 00       jmp    0x4294d0
  0040868a: ff e0                jmp    eax
  0040868c: e8 3f 0e 02 00       call   0x4294d0
'''
        counts = measure(disassembly, [0x4294d0])['0x004294d0']
        self.assertEqual(counts['direct_tail_jumps'], 1)
        self.assertEqual(counts['tail_jump_00408685'], 1)
        self.assertEqual(counts['direct_calls'], 1)
        self.assertEqual(counts['call_0040868c'], 1)


if __name__ == '__main__':
    unittest.main()
