import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).with_name('verify_texture_inspector.py')


class VerifyTextureInspectorTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / 'sample.srsc'
        data = bytearray(80)
        struct.pack_into('<II', data, 26, 0x11223344, 0x55667788)
        struct.pack_into('<I', data, 46, 0x99AABBCC)
        self.data = bytes(data)
        self.source.write_bytes(self.data)
        record = {'index': 7, 'start': 12, 'length': 50, 'a': 64, 'b': 32,
                  'c': 64, 'd': 0x00080010, 'word_at_46': 1}
        self.manifest = self.root / 'manifest.json'
        self.manifest.write_text(json.dumps({'files': [{
            'path': self.source.name, 'sha256': hashlib.sha256(self.data).hexdigest(),
            'records': [record],
        }]}), encoding='utf-8')
        self.inspector = self.root / 'inspector'
        output = (
            'Width: 64\nHeight: 32\nRow bytes: 64\nBit depth: 16\nStorage word: 1\n'
            'Word at +14: 0x11223344\nWord at +18: 0x55667788\n'
            'Word at +34: 0x99aabbcc\n'
        )
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
        self.assertEqual(result.stdout, 'Private 0x0040 texture headers: 1/1 matched\n')

    def test_stale_manifest_hash_is_not_passed_to_inspector(self):
        manifest = json.loads(self.manifest.read_text(encoding='utf-8'))
        manifest['files'][0]['sha256'] = '0' * 64
        self.manifest.write_text(json.dumps(manifest), encoding='utf-8')
        result = self.run_verifier()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, 'Private 0x0040 texture headers: 0/1 matched\n')


if __name__ == '__main__':
    unittest.main()
