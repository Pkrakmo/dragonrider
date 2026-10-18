#!/usr/bin/env python3
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
SERVER = HERE / 'mcp_loader_server.py'
spec = importlib.util.spec_from_file_location('mcp_loader', SERVER)
mcp = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mcp)


class BridgeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='dragonrider-mcp-test-', dir='/tmp')
        self.root = Path(self.temp.name)
        self.project = self.root / 'project'
        self.project.mkdir()
        (self.project / 'Disposable.gpr').write_text('')
        (self.project / 'Disposable.rep').mkdir()
        self.home = self.root / 'ghidra'
        (self.home / 'support').mkdir(parents=True)
        mock = self.home / 'support' / 'analyzeHeadless'
        mock.write_text('''#!/usr/bin/env python3
import json, pathlib, sys
args = sys.argv[1:]
assert args[2:5] == ['-process', 'Drakan.exe', '-readOnly']
assert args[5] == '-noanalysis'
assert args[args.index('-postScript')+1] == 'InvestigateFileLoader.java'
pathlib.Path(args[args.index('-postScript')+2]).write_text(json.dumps({'magic_hex':'53525343', 'executable_sha256':'23630f48e20e8a9f42026501165ae1df407cfcee545a784ec930a4c25ee70648'}))
''')
        mock.chmod(0o755)

    def tearDown(self):
        self.temp.cleanup()

    def test_protocol_and_mock_report(self):
        requests = [
            {'jsonrpc':'2.0','id':1,'method':'initialize','params':{'protocolVersion':'2024-11-05'}},
            {'jsonrpc':'2.0','method':'notifications/initialized'},
            {'jsonrpc':'2.0','id':2,'method':'tools/list'},
            {'jsonrpc':'2.0','id':3,'method':'tools/call','params':{'name':mcp.TOOL,'arguments':{}}},
            {'jsonrpc':'2.0','id':4,'method':'tools/call','params':{'name':mcp.TOOL,'arguments':{'path':'/etc'}}},
            {'jsonrpc':'2.0','id':5,'method':'missing'},
        ]
        payload = '\n'.join(json.dumps(x) for x in requests) + '\n{invalid\n'
        run = subprocess.run([sys.executable, str(SERVER), '--project-dir', str(self.project), '--project', 'Disposable', '--ghidra-home', str(self.home)], input=payload, text=True, capture_output=True, check=True, timeout=10)
        messages = [json.loads(line) for line in run.stdout.splitlines()]
        self.assertEqual(len(messages), 6)
        self.assertEqual(messages[0]['result']['serverInfo']['name'], 'dragonrider-loader')
        self.assertEqual(messages[1]['result']['tools'][0]['name'], mcp.TOOL)
        self.assertEqual(json.loads(messages[2]['result']['content'][0]['text'])['magic_hex'], '53525343')
        self.assertEqual(messages[3]['error']['code'], -32602)
        self.assertEqual(messages[4]['error']['code'], -32601)
        self.assertEqual(messages[5]['error']['code'], -32700)
        self.assertEqual(run.stderr, '')

    def test_project_guard(self):
        with self.assertRaises(ValueError):
            mcp.project_check('/tmp', 'Disposable')
        with self.assertRaises(ValueError):
            mcp.project_check(self.project, '../Disposable')
        (self.project / 'Disposable.rep' / 'bad').symlink_to('/etc')
        with self.assertRaises(ValueError):
            mcp.project_check(self.project, 'Disposable')

    def test_busy_lock(self):
        import fcntl
        with (self.project / '.Disposable.dragonrider-mcp.lock').open('w') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaisesRegex(ValueError, 'in use'):
                mcp.run_report(self.project, 'Disposable', self.home)

    def test_project_rejects_hardlinked_files(self):
        marker = self.project / 'Disposable.gpr'
        link = self.root / 'marker-link'
        os.link(marker, link)
        with self.assertRaisesRegex(ValueError, 'hardlinked'):
            mcp.project_check(self.project, 'Disposable')
        link.unlink()
        data = self.project / 'Disposable.rep' / 'data'
        data.write_text('sample')
        os.link(data, self.root / 'data-link')
        with self.assertRaisesRegex(ValueError, 'hardlinked'):
            mcp.project_check(self.project, 'Disposable')

    def test_rejects_wrong_executable_hash(self):
        mock = self.home / 'support' / 'analyzeHeadless'
        mock.write_text(mock.read_text().replace(mcp.RETAIL_SHA256, '0' * 64))
        with self.assertRaisesRegex(ValueError, 'does not match US retail baseline'):
            mcp.run_report(self.project, 'Disposable', self.home)

    def test_large_request(self):
        payload = 'x' * (mcp.MAX_REQUEST + 1) + '\n' + json.dumps({'jsonrpc':'2.0','id':1,'method':'ping'}) + '\n'
        run = subprocess.run([sys.executable, str(SERVER), '--project-dir', str(self.project), '--project', 'Disposable', '--ghidra-home', str(self.home)], input=payload, text=True, capture_output=True, check=True, timeout=10)
        msgs = [json.loads(x) for x in run.stdout.splitlines()]
        self.assertEqual(msgs[0]['error']['code'], -32600)
        self.assertEqual(msgs[1]['result'], {})


if __name__ == '__main__':
    unittest.main()
