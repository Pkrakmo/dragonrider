import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
import zlib

from verify_srsc_0501_inspector import expected_output

TOOLS = Path(__file__).parent


class Srsc0501InspectorVerifierTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        prefix = b'a\0b'
        self.prefix = prefix
        words = (1, 2, 3, 4, 5, 6, 7)
        self.payload = struct.pack('<H', len(prefix)) + prefix + struct.pack('<7I', *words) + b'xyz'
        table = 12 + len(self.payload)
        self.data = (b'SRSC' + struct.pack('<HIH', 0x0100, table, 1) + self.payload +
                     struct.pack('<HHHII', 0x0501, 4, 0, 12, len(self.payload)))
        self.source = self.root / 'sample.srsc'
        self.source.write_bytes(self.data)
        self.inventory = self.root / 'inventory.json'
        self.write_inventory()
        self.inspector = self.root / 'snapshot-inspector'

    def write_inventory(self, path='sample.srsc', data=None):
        data = self.data if data is None else data
        self.inventory.write_text(json.dumps({'files': [{
            'path': path, 'status': 'examined', 'file_size': len(data),
            'sha256': hashlib.sha256(data).hexdigest(),
        }]}), encoding='utf-8')

    def write_inspector(self, output):
        source = ('#!/usr/bin/env python3\n'
                  'import pathlib, sys\n'
                  f'expected = bytes.fromhex({self.data.hex()!r})\n'
                  'sample = pathlib.Path(sys.argv[-1])\n'
                  'assert sample.name == "verified-sample.srsc"\n'
                  'assert sample.read_bytes() == expected\n'
                  f'print({output!r}, end="")\n')
        self.inspector.write_text(source, encoding='utf-8')
        self.inspector.chmod(0o755)

    def run_verifier(self):
        return subprocess.run(
            [sys.executable, str(TOOLS / 'verify_srsc_0501_inspector.py'),
             str(self.root), str(self.inventory), str(self.inspector)],
            capture_output=True, text=True, check=False)

    def test_expected_output_preserves_only_opaque_remainder_summary(self):
        row = (0x0501, 4, 0, 12, len(self.payload))
        output = expected_output(self.data, 0, row)
        self.assertIn(f'Skipped bytes CRC32: {zlib.crc32(self.prefix):08x}', output)
        self.assertIn('Raw dwords: 1 2 3 4 5 6 7', output)
        self.assertIn('Opaque remainder bytes: 3', output)

    def test_verifier_passes_hash_checked_snapshot_to_inspector(self):
        output = expected_output(self.data, 0, (0x0501, 4, 0, 12, len(self.payload)))
        self.write_inspector(output)
        result = self.run_verifier()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, 'files=1 files_with_0501=1 comparisons=1\n')

    def test_verifier_rejects_stale_hash_before_inspector_call(self):
        self.write_inspector('unused\n')
        changed = self.data[:-1] + b'!'
        self.source.write_bytes(changed)
        result = self.run_verifier()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('inventory length or hash mismatch', result.stderr)

    def test_verifier_rejects_symlinked_inventory_path(self):
        link = self.root / 'linked.srsc'
        link.symlink_to(self.source)
        self.write_inventory(path=link.name)
        self.write_inspector('unused\n')
        result = self.run_verifier()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('symlink', result.stderr)

    def test_verifier_rejects_duplicate_inventory_paths(self):
        entry = json.loads(self.inventory.read_text(encoding='utf-8'))['files'][0]
        self.inventory.write_text(json.dumps({'files': [entry, entry]}), encoding='utf-8')
        self.write_inspector('unused\n')
        result = self.run_verifier()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('duplicate inventory path', result.stderr)


if __name__ == '__main__':
    unittest.main()
