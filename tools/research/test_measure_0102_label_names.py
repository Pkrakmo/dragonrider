import struct
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import measure_0102_label_names as scanner
from measure_0102_label_names import measure
from test_measure_0102_model_candidates import srsc


def prefix(value, tail=b''):
    return struct.pack('<H', len(value)) + value + tail


class LabelNameTests(unittest.TestCase):
    def test_matches_chains_and_name_duplicates(self):
        sample = srsc([(0x101, 10, 0, prefix(b'Root\0')),
                       (0x101, 11, 10, prefix(b'Child')),
                       (0x102, 1, 11, prefix(b'Child\0', b'opaque')),
                       (0x102, 2, 11, prefix(b'child')),
                       (0x102, 3, 11, prefix(b'Root')),
                       (0x102, 4, 11, prefix(b'Root'))])
        result = measure(sample)
        self.assertEqual(result['label_unique'], 4)
        self.assertEqual(result['chain_zero'], 4)
        self.assertEqual(result['source_equals_label'], 1)
        self.assertEqual(result['source_equals_label_ascii_casefold'], 2)
        self.assertEqual(result['source_equals_ancestor'], 3)
        self.assertEqual(result['source_duplicate_in_file'], 1)
        self.assertEqual(result['source_duplicate_in_label'], 1)
        self.assertEqual(result['source_casefold_duplicate_in_label'], 2)
        self.assertEqual(result['source_casefold_duplicate_in_file'], 2)
        self.assertEqual(result['chain_zero_two_hops'], 4)

    def test_missing_ambiguous_and_cyclic_chains(self):
        sample = srsc([(0x101, 2, 3, prefix(b'a')),
                       (0x101, 3, 2, prefix(b'b')),
                       (0x101, 4, 0, prefix(b'c')),
                       (0x101, 4, 0, prefix(b'd')),
                       (0x102, 1, 2, prefix(b'x')),
                       (0x102, 2, 4, prefix(b'x')),
                       (0x102, 3, 5, prefix(b'x'))])
        result = measure(sample)
        self.assertEqual(result['chain_cycle'], 1)
        self.assertEqual(result['chain_multiple'], 1)
        self.assertEqual(result['chain_missing'], 1)
        self.assertEqual(result['label_multiple'], 1)
        self.assertEqual(result['label_missing'], 1)

    def test_invalid_payloads_and_unusual_source_names(self):
        with self.assertRaises(ValueError):
            measure(srsc([(0x101, 1, 0, prefix(b'A', b'extra'))]))
        with self.assertRaises(ValueError):
            measure(srsc([(0x102, 1, 0, b'\x04\x00X')]))
        result = measure(srsc([(0x102, 1, 0, prefix(b'a/b\x00c'))]))
        self.assertEqual(result['source_path_separator'], 1)
        self.assertEqual(result['source_internal_nul'], 1)
        self.assertEqual(result['source_nonprintable'], 1)
        self.assertEqual(result['chain_zero'], 1)

    def test_chain_work_is_bounded(self):
        data = srsc([(0x101, 1, 2, prefix(b'A')), (0x101, 2, 0, prefix(b'B')),
                     (0x102, 3, 1, prefix(b'C'))])
        with patch.object(scanner, 'MAX_CHAIN_STEPS_PER_FILE', 1):
            with self.assertRaisesRegex(ValueError, 'step limit'):
                measure(data)

    def test_cli_rechecks_inventory_hash(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data = srsc([(0x101, 1, 0, prefix(b'A')),
                         (0x102, 2, 1, prefix(b'B'))])
            (root / 'fixture.odb').write_bytes(data)
            item = {'path': 'fixture.odb', 'status': 'examined', 'file_size': len(data),
                    'sha256': hashlib.sha256(data).hexdigest()}
            inventory = root / 'inventory.json'
            inventory.write_text(json.dumps({'files': [item]}))
            command = [sys.executable, str(Path(__file__).with_name('measure_0102_label_names.py')),
                       str(root), str(inventory)]
            run = subprocess.run(command, capture_output=True, text=True, check=True)
            self.assertEqual(json.loads(run.stdout)['counts']['label_unique'], 1)
            item['sha256'] = '0' * 64
            inventory.write_text(json.dumps({'files': [item]}))
            run = subprocess.run(command, capture_output=True, text=True, check=False)
            self.assertNotEqual(run.returncode, 0)
            self.assertIn('inventory size or hash mismatch', run.stderr)


if __name__ == '__main__':
    unittest.main()
