import struct
import unittest
from unittest.mock import patch

from test_measure_srsc_prefix_selector import fixture
from verify_srsc_lookup import expected_lines, verify


class VerifyLookupTests(unittest.TestCase):
    def test_expected_indices_cover_pair_and_triple_duplicates(self):
        entries = [(1, 4, 2, 0, 0), (2, 1, 9, 0, 0), (1, 4, 3, 0, 0),
                   (1, 4, 2, 0, 0)]
        self.assertEqual(list(expected_lines(entries)), [
            (1, 1, 1, 1, 1, 0, 1, 0, 1),
            (0, 0, 0, 0, 0, 1, 0, 1, 0),
            (2, 0, 0, 2, 2, 1, 0, 2, 2),
            (3, 0, 0, 0, 0, 1, 0, 1, 0),
        ])

    def test_probe_output_and_count_checked(self):
        data = fixture([(0x102, 3, 4, b'a'), (0x102, 3, 4, b'b')])
        expected = b'0 0 0 0 0 0 0 0 0\n1 0 0 0 0 0 0 0 0\n'
        with patch('verify_srsc_lookup.subprocess.run') as run:
            run.return_value.stdout = expected
            self.assertEqual(verify('probe', data), 2)
            submitted = run.call_args.kwargs['input']
            self.assertEqual(submitted[:2], struct.pack('<H', 2))
            self.assertEqual(len(submitted), 2 + 2 * 14)
            run.return_value.stdout = expected.splitlines()[0] + b'\n'
            with self.assertRaisesRegex(ValueError, 'line count'):
                verify('probe', data)
            run.return_value.stdout = expected.replace(b'1 0 0', b'1 0 1')
            with self.assertRaisesRegex(ValueError, 'disagrees'):
                verify('probe', data)


if __name__ == '__main__':
    unittest.main()
