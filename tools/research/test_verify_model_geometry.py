import contextlib
import hashlib
import io
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

import verify_model_geometry as verifier
from verify_model_geometry import decode


def model_fixture():
    payloads = [b'a', b'b', b'\0\0', b'\0\0']
    offset = 12 + sum(map(len, payloads))
    selectors = (0x200, 0x206, 0x203, 0x204)
    records = []
    current = 12
    for selector, body in zip(selectors, payloads):
        records.append(struct.pack('<HHHII', selector, 0x1234, 0x5678,
                                   current, len(body)))
        current += len(body)
    return (struct.pack('<4sHIH', b'SRSC', 0x100, offset, len(records))
            + b''.join(payloads) + b''.join(records))


def inventory_item(name, data):
    return {'path': name, 'size': len(data), 'sha256': hashlib.sha256(data).hexdigest()}


class ModelGeometryVerificationTest(unittest.TestCase):
    def test_counts_indices_and_tails(self):
        points = struct.pack('<HIII', 1, 0, 0, 0) + b'x'
        groups = struct.pack('<HHHHHII', 1, 7, 1, 9, 1, 4, 5) + b'y'
        self.assertEqual(decode(points, groups)[:6], (1, 1, 1, 1, len(points) - 1, len(groups) - 1))

    def test_truncation_and_hostile_counts(self):
        points = struct.pack('<HIII', 1, 0, 0, 0)
        groups = struct.pack('<HHHHHII', 1, 7, 1, 9, 0, 4, 5)
        for i in range(len(points)):
            with self.assertRaises(ValueError):
                decode(points[:i], groups)
        for i in range(len(groups)):
            with self.assertRaises(ValueError):
                decode(points, groups[:i])
        with self.assertRaisesRegex(ValueError, 'truncated points'):
            decode(struct.pack('<H', 0xffff), b'\0\0')
        with self.assertRaisesRegex(ValueError, 'truncated group header'):
            decode(b'\0\0', struct.pack('<H', 0xffff))
        with self.assertRaisesRegex(ValueError, 'truncated corners'):
            decode(b'\0\0', struct.pack('<HHHH', 1, 0, 0xffff, 0))

    def test_inventory_snapshot_hash_size_and_symlink_validation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data = model_fixture()
            sample = root / 'sample.mod'
            sample.write_bytes(data)
            item = inventory_item(sample.name, data)
            self.assertEqual(verifier.read_verified_snapshot(root, item), data)
            with self.assertRaisesRegex(ValueError, 'size or hash mismatch'):
                verifier.read_verified_snapshot(root, dict(item, size=len(data) + 1))
            with self.assertRaisesRegex(ValueError, 'size or hash mismatch'):
                verifier.read_verified_snapshot(root, dict(item, sha256='0' * 64))
            with self.assertRaisesRegex(ValueError, 'invalid inventory hash'):
                verifier.read_verified_snapshot(root, dict(item, sha256='not-a-digest'))
            with self.assertRaisesRegex(ValueError, 'invalid inventory path'):
                verifier.read_verified_snapshot(root, dict(item, path='../sample.mod'))
            linked = root / 'linked.mod'
            linked.symlink_to(sample)
            with self.assertRaisesRegex(ValueError, 'symlink in inventory path'):
                verifier.read_verified_snapshot(root, dict(item, path=linked.name))

    def test_inventory_requires_matching_top_level_count(self):
        with tempfile.TemporaryDirectory() as directory:
            inventory = Path(directory) / 'inventory.json'
            inventory.write_text(json.dumps({'file_count': 2, 'files': [{}]}),
                                 encoding='utf-8')
            with self.assertRaisesRegex(ValueError, 'file count'):
                verifier.load_inventory(inventory)

    def test_inspector_receives_the_verified_snapshot(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data = model_fixture()
            sample = root / 'sample.mod'
            sample.write_bytes(data)
            item = inventory_item(sample.name, data)
            inventory = root / 'inventory.json'
            inventory.write_text(json.dumps({'file_count': 1, 'files': [item]}),
                                 encoding='utf-8')
            expected = (
                'Point record: 2\nGroup record: 3\nOther selectors match: yes\n'
                'Points: 0\nGroups: 0\nCorners: 0\n'
                'Out-of-range point indices: 0\nPoint CRC32: 41d912ff\n'
                'Group CRC32: 41d912ff\nPoint trailing bytes (unvalidated): 0\n'
                'Group trailing bytes (unvalidated): 0\n')

            def inspect(command, **kwargs):
                self.assertEqual(command[1:4], ['--model-geometry', '2', '3'])
                self.assertNotEqual(Path(command[-1]), sample)
                self.assertEqual(Path(command[-1]).read_bytes(), data)
                return type('Result', (), {'stdout': expected})()

            with patch.object(verifier.subprocess, 'run', side_effect=inspect):
                with patch.object(sys, 'argv', [
                    'verify_model_geometry.py', str(root), str(inventory),
                    '--inspector', '/fake/inspector',
                ]), contextlib.redirect_stdout(io.StringIO()):
                    verifier.main()

    def test_duplicate_normalized_model_paths_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data = model_fixture()
            (root / 'sample.mod').write_bytes(data)
            item = inventory_item('sample.mod', data)
            inventory = root / 'inventory.json'
            inventory.write_text(json.dumps({
                'file_count': 2,
                'files': [item, dict(item, path='./sample.mod')],
            }), encoding='utf-8')
            with patch.object(sys, 'argv', [
                'verify_model_geometry.py', str(root), str(inventory),
            ]):
                with self.assertRaisesRegex(ValueError, 'duplicate model inventory path'):
                    verifier.main()


if __name__ == '__main__':
    unittest.main()
