import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).with_name('verify_srsc_manifest.py')


class VerifySrscManifestTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / 'sample.srsc'
        payload = b'abcdefghij'
        table_offset = 12 + len(payload)
        record = struct.pack('<HHHII', 0x102, 1, 0, 12, len(payload))
        self.data = b'SRSC' + struct.pack('<HIH', 0x100, table_offset, 1) + payload + record
        self.source.write_bytes(self.data)
        self.manifest = self.root / 'manifest.json'
        self.write_manifest()
        self.inspector = self.root / 'inspector'
        program = (
            '#!/usr/bin/env python3\n'
            'import pathlib, sys\n'
            f'expected = bytes.fromhex({self.data.hex()!r})\n'
            'sample = pathlib.Path(sys.argv[-1])\n'
            'assert sample.name == "verified-sample.srsc"\n'
            'assert sample.read_bytes() == expected\n'
            'print("Physical record 0: offset=12 length=10")\n'
            'print("Size: 36 bytes")\n'
            'print("Edition: us-retail")\n'
            'print(f"Container: {sample}")\n'
            'print("SHA-256: not provided")\n'
        )
        self.inspector.write_text(program, encoding='utf-8')
        self.inspector.chmod(0o755)

    def write_manifest(self, path=None, digest=None):
        entry = {
            'path': path or self.source.name,
            'size': len(self.data),
            'sha256': digest or hashlib.sha256(self.data).hexdigest(),
            'candidate_table': {'offset': 22, 'count': 1},
        }
        self.manifest.write_text(json.dumps({'files': [entry]}), encoding='utf-8')

    def run_verifier(self):
        return subprocess.run(
            [sys.executable, str(SCRIPT), str(self.inspector), str(self.root), str(self.manifest)],
            capture_output=True, text=True, check=False,
        )

    def test_inspector_receives_hash_verified_snapshot(self):
        result = self.run_verifier()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout,
                         'Private SRSC manifests: 1/1 matched; 1 record ranges matched\n')

    def test_stale_hash_is_reported_as_failure(self):
        self.write_manifest(digest='0' * 64)
        result = self.run_verifier()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('0/1 matched', result.stdout)

    def test_symlink_inventory_path_is_rejected(self):
        link = self.root / 'linked.srsc'
        link.symlink_to(self.source)
        self.write_manifest(path=link.name)
        result = self.run_verifier()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('0/1 matched', result.stdout)


if __name__ == '__main__':
    unittest.main()
