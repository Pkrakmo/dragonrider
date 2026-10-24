import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).with_name('verify_texture_rows.py')


class VerifyTextureRowsTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / 'sample.srsc'
        data = bytearray(80)
        data[62:65] = b'abc'
        self.data = bytes(data)
        self.source.write_bytes(self.data)
        record = {'index': 4, 'start': 12, 'length': 53, 'b': 1, 'c': 3}
        self.manifest = self.root / 'manifest.json'
        self.manifest.write_text(json.dumps({'files': [{
            'path': self.source.name, 'sha256': hashlib.sha256(self.data).hexdigest(),
            'records': [record],
        }]}), encoding='utf-8')
        self.inspector = self.root / 'inspector'
        output = 'Base row bytes: 3\nBase row CRC32: 352441c2\n'
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

    def run_verifier(self):
        return subprocess.run(
            [sys.executable, str(SCRIPT), str(self.inspector), str(self.root), str(self.manifest)],
            capture_output=True, text=True, check=False,
        )

    def test_inspector_receives_hash_verified_snapshot(self):
        result = self.run_verifier()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, 'Private 0x0040 base rows: 1/1 matched\n')

    def test_stale_manifest_hash_is_not_passed_to_inspector(self):
        manifest = json.loads(self.manifest.read_text(encoding='utf-8'))
        manifest['files'][0]['sha256'] = '0' * 64
        self.manifest.write_text(json.dumps(manifest), encoding='utf-8')
        result = self.run_verifier()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, 'Private 0x0040 base rows: 0/1 matched\n')


if __name__ == '__main__':
    unittest.main()
