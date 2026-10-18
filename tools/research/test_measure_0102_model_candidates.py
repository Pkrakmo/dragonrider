from collections import Counter
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

from measure_0102_model_candidates import candidate_path, measure, model_keys, self_candidate_path


def srsc(items):
    payload = bytearray()
    records = []
    for kind, second, third, body in items:
        records.append(struct.pack('<HHHII', kind, second, third, 12 + len(payload), len(body)))
        payload.extend(body)
    return (b'SRSC' + struct.pack('<HIH', 0x100, 12 + len(payload), len(records))
            + payload + b''.join(records))


def source(low, high):
    return b'\x01\x00X\x00\x00' + struct.pack('<HH', low, high)


class ModelCandidateTests(unittest.TestCase):
    def test_lexical_candidate_paths_and_rejections(self):
        self.assertEqual(candidate_path('group/World/A/source.db', b'..\\B\\model'),
                         'world\\b\\model.mod')
        for value in (b'..\\..\\..\\escape', b'C:\\absolute', b'\\absolute',
                      b'foo/bar', b'existing.mod', b'a\x00b', b'\xff'):
            with self.subTest(value=value):
                self.assertIsNone(candidate_path('group/World/A/source.db', value))

    def test_unique_missing_multiple_and_zero(self):
        odb = srsc([(0x102, 1, 1, source(7, 1)), (0x102, 2, 1, source(8, 1)),
                    (0x102, 3, 1, source(9, 1)), (0x102, 4, 1, source(7, 0)),
                    (0x102, 5, 1, source(7, 2)), (0x102, 6, 1, source(7, 3)),
                    (0x102, 7, 1, source(7, 4))])
        index = {'world\\model.mod': [Counter({7: 1, 9: 2})],
                 'world\\duplicate.mod': [Counter(), Counter()]}
        dependencies = [(1, b'model'), (3, b'duplicate'), (4, b'absent')]
        counts = measure(odb, dependencies, 'group/World/source.db', index)
        self.assertEqual(counts['records'], 7)
        for field in ('low_unique', 'low_missing', 'low_multiple', 'zero_high',
                      'dependency_missing', 'model_multiple', 'model_missing'):
            self.assertEqual(counts[field], 1, field)
        self.assertEqual(counts['model_unique'], 3)
        self.assertEqual(measure(odb, [(1, b'x'), (1, b'y')], 'group/World/source.db', {})
                         ['dependency_multiple'], 3)

    def test_short_data_and_model_table_rejected(self):
        with self.assertRaises(ValueError):
            measure(srsc([(0x102, 0, 0, b'\x04\x00X')]), [], 'group/a.db', {})
        with self.assertRaises(ValueError):
            model_keys(srsc([(0x200, 1, 0, b'')])[:-1])

    def test_zero_key_same_base_candidates_and_selector_multiplicity(self):
        odb = srsc([(0x102, 1, 1, source(low, 0)) for low in (0, 7, 8, 9)])
        path = 'group/World/source.db'
        self.assertEqual(self_candidate_path(path), 'world\\source.mod')
        counts = measure(odb, [], path, {'world\\source.mod': [Counter({0: 1, 7: 1, 9: 2})]})
        self.assertEqual(counts['zero_high'], 4)
        self.assertEqual(counts['zero_high_low_zero'], 1)
        self.assertEqual(counts['self_model_unique'], 4)
        self.assertEqual(counts['self_low_unique'], 2)
        self.assertEqual(counts['self_low_missing'], 1)
        self.assertEqual(counts['self_low_multiple'], 1)
        self.assertEqual(counts['self_low_zero_unique'], 1)
        self.assertEqual(measure(odb, [], path, {})['self_model_missing'], 4)
        self.assertEqual(measure(odb, [], path, {'world\\source.mod': [Counter(), Counter()]})['self_model_multiple'], 4)
        with self.assertRaises(ValueError):
            self_candidate_path('group/../source.db')

    def test_exception_counts_distinct_keys_and_presence_in_other_models(self):
        odb = srsc([(0x102, 1, 1, source(7, 9)), (0x102, 2, 1, source(7, 9)),
                    (0x102, 3, 1, source(8, 9)), (0x102, 4, 1, source(9, 1)),
                    (0x102, 5, 1, source(10, 2))])
        models = {'world\\empty.mod': [Counter()],
                  'world\\one.mod': [Counter({7: 1, 8: 1, 9: 1})],
                  'world\\two.mod': [Counter({8: 1, 9: 1})]}
        paths = {'world\\absent.db', 'world\\absent.odb'}
        result = measure(odb, [(1, b'empty'), (2, b'absent')],
                         'group/World/source.db', models, paths)
        self.assertEqual(result['dependency_missing'], 3)
        self.assertEqual(result['dependency_missing_distinct_per_file'], 2)
        self.assertEqual(result['dependency_missing_inventoried_model_one'], 2)
        self.assertEqual(result['dependency_missing_inventoried_model_multiple'], 1)
        self.assertEqual(result['low_missing_inventoried_model_multiple'], 1)
        self.assertEqual(result['model_missing_inventoried_model_zero'], 1)
        self.assertEqual(result['model_missing_with_db'], 1)
        self.assertEqual(result['model_missing_with_odb'], 1)
        self.assertEqual(result['model_missing_with_both'], 1)

    def test_cli_uses_inventory_and_rejects_stale_model(self):
        script = Path(__file__).with_name('measure_0102_model_candidates.py')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            files = {
                'group/World/source.db': b'version 1\r\ndependencies 1\r\n1 model\r\n',
                'group/World/source.odb': srsc([(0x102, 1, 2, source(7, 1))]),
                'other/World/model.mod': srsc([(0x200, 7, 2, b'')]),
            }
            entries = []
            for name, data in files.items():
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
                entries.append({'path': name, 'size': len(data), 'sha256': hashlib.sha256(data).hexdigest()})
            inventory = root / 'inventory.json'
            inventory.write_text(json.dumps({'files': entries}), encoding='utf-8')
            command = [sys.executable, str(script), str(root), str(inventory)]
            run = subprocess.run(command, capture_output=True, text=True, check=True)
            self.assertEqual(json.loads(run.stdout)['low_unique'], 1)
            entries[-1]['sha256'] = '0' * 64
            inventory.write_text(json.dumps({'files': entries}), encoding='utf-8')
            run = subprocess.run(command, capture_output=True, text=True, check=False)
            self.assertNotEqual(run.returncode, 0)
            self.assertIn('inventory length or hash mismatch', run.stderr)


if __name__ == '__main__':
    unittest.main()
