import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
import zlib


SCRIPT = Path(__file__).with_name('verify_palette_inspector.py')


class VerifyPaletteInspectorTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / 'sample.srsc'
        payload = struct.pack('<HII', 2, 0x12345678, 0x9ABCDEF0)
        table_offset = 12 + len(payload)
        record = struct.pack('<HHHII', 0x30, 1, 0, 12, len(payload))
        self.data = b'SRSC' + struct.pack('<HIH', 0x100, table_offset, 1) + payload + record
        self.source.write_bytes(self.data)
        self.manifest = self.root / 'manifest.json'
        self.write_manifest()
        self.inspector = self.root / 'inspector'
        entries = payload[2:]
        output = (f'Entries: 2\nEntry CRC32: {zlib.crc32(entries):08x}\n'
                  'Trailing bytes (unvalidated): 0\n')
        program = (
            '#!/usr/bin/env python3\n'
            'import pathlib, sys\n'
            f'expected = bytes.fromhex({self.data.hex()!r})\n'
            'sample = pathlib.Path(sys.argv[-1])\n'
            'assert sample.name == "verified-sample.srsc"\n'
            'assert sample.read_bytes() == expected\n'
            f'print({output!r}, end="")\n'
        )
        self.inspector.write_text(program, encoding='utf-8')
        self.inspector.chmod(0o755)

    def write_manifest(self, path=None, digest=None):
        table_offset = 12 + 10
        entry = {'path': path or self.source.name, 'size': len(self.data),
                 'sha256': digest or hashlib.sha256(self.data).hexdigest(),
                 'candidate_table': {'offset': table_offset, 'count': 1}}
        self.manifest.write_text(json.dumps({'files': [entry]}), encoding='utf-8')

    def run_verifier(self):
        return subprocess.run(
            [sys.executable, str(SCRIPT), str(self.inspector), str(self.root), str(self.manifest)],
            capture_output=True, text=True, check=False,
        )

    def test_inspector_receives_hash_verified_snapshot(self):
        result = self.run_verifier()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, 'Private 0x0030 palette entry inspections: 1/1 matched\n')

    def test_stale_hash_is_rejected(self):
        self.write_manifest(digest='0' * 64)
        result = self.run_verifier()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('hash mismatch', result.stderr)

    def test_symlink_inventory_path_is_rejected(self):
        link = self.root / 'linked.srsc'
        link.symlink_to(self.source)
        self.write_manifest(path=link.name)
        result = self.run_verifier()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('symlink', result.stderr)


if __name__ == '__main__':
    unittest.main()
