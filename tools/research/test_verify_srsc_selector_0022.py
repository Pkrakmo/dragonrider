import hashlib
import json
from pathlib import Path
import struct
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from verify_srsc_selector_0022 import (EXPECTED, measure_inventory,
                                       parse_instructions, selector_records,
                                       verify_executable)
import verify_srsc_selector_0022 as verifier


def fixture(records, payload=b''):
    table = 12 + len(payload)
    header = b'SRSC' + struct.pack('<HIH', 0x100, table, len(records))
    encoded = b''.join(struct.pack('<HHHII', *row) for row in records)
    return header + payload + encoded


class Selector0022Tests(unittest.TestCase):
    def test_parses_instruction_anchors(self):
        text = '\n'.join(f'  {address:x}:\t90\t\t{instruction}'
                         for address, instruction in EXPECTED.items())
        self.assertEqual(parse_instructions(text), EXPECTED)

    def test_finds_tuple_and_bounds_its_payload(self):
        data = fixture([(0x22, 0, 0, 12, 4), (0x40, 1, 0, 12, 4)], b'abcd')
        self.assertEqual(selector_records(data), [(0, 12, 4)])
        self.assertEqual(selector_records(fixture([(0x40, 0, 0, 12, 4)], b'abcd')), [])
        with self.assertRaisesRegex(ValueError, 'outside file'):
            selector_records(fixture([(0x22, 0, 0, 12, 100)], b'abcd'))

    def test_rejects_bad_header_and_truncated_table(self):
        with self.assertRaisesRegex(ValueError, 'header'):
            selector_records(b'bad')
        with self.assertRaisesRegex(ValueError, 'table bounds'):
            selector_records(b'SRSC' + struct.pack('<HIH', 0x100, 12, 2) + bytes(14))

    def test_verifies_pinned_binary_and_instruction_anchors(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / 'sample.exe'
            content = b'synthetic pinned fixture'
            binary.write_bytes(content)
            disassembly = '\n'.join(f' {address:x}:\t90\t\t{line}'
                                     for address, line in EXPECTED.items())
            disassembly += '\n' + '\n'.join(
                f' {0x500000 + index:x}:\te8 00 00 00 00\tcall   0x45f0d0'
                for index in range(verifier.EXPECTED_LOOKUP_CALLERS - 1))
            fake_objdump = root / 'objdump'
            fake_objdump.write_text('#!/bin/sh\ncat <<\'EOF\'\n' + disassembly + '\nEOF\n')
            fake_objdump.chmod(0o755)
            with patch.object(verifier, 'EXPECTED_SHA256', hashlib.sha256(content).hexdigest()):
                result = verify_executable(binary, str(fake_objdump))
            self.assertEqual(result, {'sha256': hashlib.sha256(content).hexdigest(),
                                      'lookup_direct_calls': 26,
                                      'lookup_direct_jumps': 0,
                                      'consumer_entry_direct_calls': 0,
                                      'consumer_entry_direct_jumps': 0})

    def test_objdump_uses_the_hashed_snapshot_if_source_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / 'sample.exe'
            content = b'synthetic pinned fixture'
            binary.write_bytes(content)
            disassembly = '\n'.join(f' {address:x}:\t90\t\t{line}'
                                     for address, line in EXPECTED.items())
            disassembly += '\n' + '\n'.join(
                f' {0x500000 + index:x}:\te8 00 00 00 00\tcall   0x45f0d0'
                for index in range(verifier.EXPECTED_LOOKUP_CALLERS - 1))

            def run(command, **kwargs):
                self.assertEqual(Path(command[-1]).read_bytes(), content)
                binary.write_bytes(b'changed after hashing')
                return SimpleNamespace(stdout=disassembly)

            with patch.object(verifier, 'EXPECTED_SHA256', hashlib.sha256(content).hexdigest()), \
                    patch.object(verifier.subprocess, 'run', side_effect=run):
                result = verify_executable(binary, 'objdump')
            self.assertEqual(result['sha256'], hashlib.sha256(content).hexdigest())
            self.assertEqual(binary.read_bytes(), b'changed after hashing')

    def test_measures_verified_inventory_and_rejects_stale_hash(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'sample.srsc'
            data = fixture([(0x22, 0, 0, 12, 4)], b'abcd')
            source.write_bytes(data)
            entry = {'path': source.name, 'status': 'examined', 'size': len(data),
                     'sha256': hashlib.sha256(data).hexdigest()}
            result = measure_inventory(root, [entry])
            self.assertEqual(result['files'], {'total': 1, 'with_selector': 1})
            self.assertEqual(result['selector_records'], {'records': 1, 'files': 1})
            with patch.dict(entry, {'sha256': '0' * 64}):
                with self.assertRaisesRegex(ValueError, 'SHA-256'):
                    measure_inventory(root, [entry])
            for invalid_size in (None, True, -1, str(len(data))):
                invalid = dict(entry, size=invalid_size)
                invalid.pop('file_size', None)
                with self.subTest(size=invalid_size), self.assertRaisesRegex(ValueError, 'size'):
                    measure_inventory(root, [invalid])
            for invalid_hash in ('g' * 64, 'A' * 64, '0' * 63):
                with self.subTest(hash=invalid_hash), self.assertRaisesRegex(ValueError, 'SHA-256'):
                    measure_inventory(root, [dict(entry, sha256=invalid_hash)])
            with self.assertRaisesRegex(ValueError, 'duplicate paths'):
                measure_inventory(root, [entry, dict(entry)])


if __name__ == '__main__':
    unittest.main()
