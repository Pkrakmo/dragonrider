import hashlib
from pathlib import Path
import tempfile
import unittest

from measure_level_frame_payload_matches import automaton, find_patterns, measure, safe_read
from test_measure_srsc_prefix_selector import fixture


class FramePayloadMatchesTests(unittest.TestCase):
    def test_automaton_finds_multiple_overlapping_patterns(self):
        patterns = {b'aba', b'ba', b'zz'}
        matcher = automaton(patterns)
        ids = {pattern: i for i, pattern in enumerate(sorted(patterns))}
        self.assertEqual(find_patterns(b'ababa', matcher), {ids[b'aba'], ids[b'ba']})
        self.assertEqual(find_patterns(b'none', matcher), set())

    def test_aggregate_exact_frame_tokens_by_kind(self):
        token_a = b'\x05\x00\x00\x00\x03\x00abc'
        token_b = b'\x07\x00\x00\x00\x01\x00x'
        payload = token_a + b'gap' + token_b
        blob = fixture([(0x100, 1, 0, payload),
                        (0x101, 1, 0, b'unrelated'),
                        (0x100, 2, 0, token_a)])
        result = measure([{(5, b'abc'): 2, (7, b'x'): 1}], [blob])
        self.assertEqual(result['counts']['distinct_level_frame_tokens'], 2)
        self.assertEqual(result['record_kinds_with_matches']['0x0100'], {
            'records_examined': 2,
            'records_containing_any_exact_frame_token': 2,
            'distinct_level_frame_tokens_found': 2,
        })
        self.assertNotIn('abc', str(result))

    def test_safe_read_rejects_stale_hash(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            data = b'SRSC' + b'x' * 20
            (root / 'sample.adb').write_bytes(data)
            item = {'path': 'sample.adb', 'status': 'examined', 'file_size': len(data),
                    'sha256': hashlib.sha256(data).hexdigest()}
            self.assertEqual(safe_read(root, item), data)
            item['sha256'] = '0' * 64
            with self.assertRaises(ValueError):
                safe_read(root, item)

    def test_safe_read_rejects_oversized_inventory_before_read(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / 'large.lvl'
            with source.open('wb') as output:
                output.truncate(257 * 1024 * 1024)
            item = {'path': source.name, 'status': 'examined',
                    'file_size': source.stat().st_size, 'sha256': '0' * 64}
            with self.assertRaisesRegex(ValueError, 'read limit'):
                safe_read(root, item)

    def test_safe_read_rejects_symlinked_path_within_root(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            data = b'SRSC' + b'x' * 20
            source = root / 'sample.adb'
            source.write_bytes(data)
            linked = root / 'linked.adb'
            try:
                linked.symlink_to(source.name)
            except OSError:
                self.skipTest('symlinks unavailable')
            item = {'path': linked.name, 'status': 'examined', 'file_size': len(data),
                    'sha256': hashlib.sha256(data).hexdigest()}
            with self.assertRaisesRegex(ValueError, 'symlink'):
                safe_read(root, item)

    def test_bad_payload_extent_rejected(self):
        malformed = fixture([(0x100, 1, 0, b'a')])
        damaged = bytearray(malformed)
        table_offset = int.from_bytes(damaged[6:10], 'little')
        damaged[12 + 6:12 + 10] = (table_offset + 1).to_bytes(4, 'little')
        with self.assertRaises(ValueError):
            measure([{}], [bytes(damaged)])


if __name__ == '__main__':
    unittest.main()
