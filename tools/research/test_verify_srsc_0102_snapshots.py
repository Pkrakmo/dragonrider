import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
import zlib


TOOLS = Path(__file__).parent


class Srsc0102SnapshotVerifierTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.data = None
        self.inspector = self.root / 'snapshot-inspector'

    def fixture(self, payload):
        table = 12 + len(payload)
        record = struct.pack('<HHHII', 0x0102, 1, 5, 12, len(payload))
        self.data = b'SRSC' + struct.pack('<HIH', 0x0100, table, 1) + payload + record
        source = self.root / 'sample.srsc'
        source.write_bytes(self.data)
        inventory = self.root / 'inventory.json'
        inventory.write_text(json.dumps({'files': [{
            'path': source.name, 'status': 'examined', 'file_size': len(self.data),
            'sha256': hashlib.sha256(self.data).hexdigest(),
        }]}), encoding='utf-8')
        return source, inventory

    def write_inspector(self, output):
        source = (
            '#!/usr/bin/env python3\n'
            'import pathlib, sys\n'
            f'expected = bytes.fromhex({self.data.hex()!r})\n'
            'sample = pathlib.Path(sys.argv[-1])\n'
            'assert sample.name == "verified-sample.srsc"\n'
            'assert sample.read_bytes() == expected\n'
            f'print({output!r}, end="")\n'
        )
        self.inspector.write_text(source, encoding='utf-8')
        self.inspector.chmod(0o755)

    def run_verifier(self, script, inventory):
        return subprocess.run(
            [sys.executable, str(TOOLS / script), str(self.root), str(inventory), str(self.inspector)],
            capture_output=True, text=True, check=False,
        )

    def test_record_verifier_passes_verified_snapshot_to_inspector(self):
        payload = b'\0\0' + struct.pack('<HIHH', 0x1234, 0x89ABCDEF, 0x4567, 0x789A)
        _, inventory = self.fixture(payload)
        expected = (
            'Record: 0\nPrefix bytes: 0\nPrefix CRC32: 00000000\n'
            'Skipped word: 4660\nThird selector: 5\nRaw dword: 2309737967\n'
            'Dword low word: 52719\nDword high word: 35243\n'
            'Following word: 17767\nLast skipped word: 30874\n'
            'Trailing bytes (unvalidated): 0\n'
        )
        self.write_inspector(expected)
        result = self.run_verifier('verify_srsc_0102.py', inventory)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, 'files=1 files_with_0102=1 comparisons=1 records_with_tails=0\n')

    def test_array_verifier_passes_verified_snapshot_to_inspector(self):
        payload = b'\0\0' + bytes(10) + struct.pack('<II', 0xABCD, 2) + struct.pack('<II', 7, 9)
        _, inventory = self.fixture(payload)
        expected = (
            'Record: 0\nCompared dword: 43981\nArray count: 2\n'
            f'Array CRC32: {zlib.crc32(struct.pack("<II", 7, 9)):08x}\n'
            'Trailing bytes (unvalidated): 0\n'
        )
        self.write_inspector(expected)
        result = self.run_verifier('verify_srsc_0102_array.py', inventory)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, 'files=1 files_with_0102=1 comparisons=1 entries=2\n')

    def test_both_verifiers_reject_symlink_inventory_paths(self):
        payload = b'\0\0' + struct.pack('<HIHH', 0x1234, 0x89ABCDEF, 0x4567, 0x789A)
        source, inventory = self.fixture(payload)
        link = self.root / 'linked.srsc'
        link.symlink_to(source)
        contents = json.loads(inventory.read_text(encoding='utf-8'))
        contents['files'][0]['path'] = link.name
        inventory.write_text(json.dumps(contents), encoding='utf-8')
        self.write_inspector('unused\n')
        for script in ('verify_srsc_0102.py', 'verify_srsc_0102_array.py'):
            with self.subTest(script=script):
                result = self.run_verifier(script, inventory)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('symlink', result.stderr)


if __name__ == '__main__':
    unittest.main()
