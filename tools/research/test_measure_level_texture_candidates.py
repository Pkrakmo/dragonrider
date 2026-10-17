import hashlib
from pathlib import Path
import struct
import tempfile
import unittest

from measure_level_texture_candidates import candidate_key, directory_entries, texture_selectors, verified


class LevelTextureCandidatesTest(unittest.TestCase):
    def test_keys_and_overlay_are_only_lexical(self):
        level = 'Group/Level_One/Sub/level.lvl'
        name = b'..\\..\\Common Stuff\\textures\0'
        self.assertEqual(candidate_key(level, name), 'group/common stuff/textures.txd')
        self.assertEqual(candidate_key(level, name, True), 'common stuff/textures.txd')
        self.assertEqual(candidate_key(level, b'folder\\file.ext'), 'group/level_one/sub/folder/file.ext')
        for bad in (b'c:\\outside', b'\\\\server\\file', b'..\\..\\..\\..\\file',
                    b'bad\0name', b'\xff', b''):
            with self.subTest(bad=bad):
                self.assertIsNone(candidate_key(level, bad))

    def test_directory_and_texture_selector_bounds(self):
        directory = b'\0\0' + struct.pack('<III', 0, 0, 1) + struct.pack('<IH', 4, 3) + b'abc'
        self.assertEqual(directory_entries(directory), [(4, b'abc')])
        with self.assertRaises(ValueError):
            directory_entries(directory[:-1])
        entries = (struct.pack('<HHHII', 0x40, 7, 0, 0, 0) +
                   struct.pack('<HHHII', 0x40, 7, 1, 0, 0) +
                   struct.pack('<HHHII', 0x30, 7, 0, 0, 0))
        table = b'SRSC' + struct.pack('<HIH', 0x100, 12, 3) + entries
        self.assertEqual(texture_selectors(table)[7], 2)
        with self.assertRaises(ValueError):
            texture_selectors(table[:-1])
        bad = bytearray(table); bad[18:22] = struct.pack('<I', 0xffffffff)
        with self.assertRaises(ValueError):
            texture_selectors(bad)

    def test_hash_and_root_checks(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            (root / 'sample').write_bytes(b'data')
            item = {'path': 'sample', 'sha256': hashlib.sha256(b'data').hexdigest()}
            self.assertEqual(verified(root, item)[1], b'data')
            with self.assertRaises(ValueError):
                verified(root, {**item, 'sha256': 'bad'})
            with self.assertRaises(ValueError):
                verified(root, {**item, 'path': '../sample'})
            with tempfile.TemporaryDirectory() as other:
                external = Path(other) / 'outside'
                external.write_bytes(b'data')
                try:
                    (root / 'link').symlink_to(external)
                except OSError:
                    self.skipTest('symlinks unavailable')
                with self.assertRaises(ValueError):
                    verified(root, {**item, 'path': 'link'})


if __name__ == '__main__':
    unittest.main()
