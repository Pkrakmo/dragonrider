#!/usr/bin/env python3
"""Experimental stdio MCP bridge for one read-only Ghidra loader report.

Only use disposable projects; this is a narrow interface, not an OS sandbox.
"""
import argparse
import fcntl
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import tempfile

MAX_REQUEST = 65536
MAX_REPORT = 262144
ROOT = Path(__file__).resolve().parent
SCRIPT = ROOT / "scripts" / "InvestigateFileLoader.java"
TOOL = "investigate_file_loader"
RETAIL_SHA256 = '23630f48e20e8a9f42026501165ae1df407cfcee545a784ec930a4c25ee70648'


def project_check(project_dir, name):
    if not re.fullmatch(r"[A-Za-z0-9_-]+", name):
        raise ValueError("Invalid project name")
    directory = Path(project_dir).resolve(strict=True)
    tmp = Path('/tmp').resolve(strict=True)
    if directory == tmp or not directory.is_relative_to(tmp) or not directory.is_dir():
        raise ValueError("Project directory must be a dedicated directory under /tmp")
    gpr = directory / (name + '.gpr')
    rep = directory / (name + '.rep')
    if gpr.is_symlink() or rep.is_symlink() or not gpr.is_file() or not rep.is_dir():
        raise ValueError("Expected a non-symlink .gpr file and .rep directory")
    if gpr.stat().st_nlink != 1:
        raise ValueError("Project contains a hardlinked file")
    # A project copy with links back into the persistent database is not disposable.
    for base, dirs, files in os.walk(rep, followlinks=False):
        for entry in dirs + files:
            path = Path(base) / entry
            if path.is_symlink():
                raise ValueError("Project contains a symlink")
            if path.is_file() and path.stat().st_nlink != 1:
                raise ValueError("Project contains a hardlinked file")
    return directory


def run_report(directory, name, ghidra_home):
    directory = project_check(directory, name)
    headless = Path(ghidra_home).resolve(strict=True) / 'support' / 'analyzeHeadless'
    if not headless.is_file() or not os.access(headless, os.X_OK):
        raise ValueError('Missing executable analyzeHeadless')
    lock_path = directory / ('.' + name + '.dragonrider-mcp.lock')
    fd = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'r+') as lock:
        if not stat.S_ISREG(os.fstat(lock.fileno()).st_mode):
            raise ValueError('Invalid lock file')
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as e:
            raise ValueError('Disposable project is in use by another bridge') from e
        with tempfile.TemporaryDirectory(prefix='dragonrider-mcp-', dir='/tmp') as td:
            run = Path(td)
            report = run / 'report.json'
            env = os.environ.copy()
            env.update(XDG_CONFIG_HOME=str(run / 'config'), XDG_CACHE_HOME=str(run / 'cache'))
            env['JAVA_TOOL_OPTIONS'] = (env.get('JAVA_TOOL_OPTIONS', '') + ' -Duser.home=' + td).strip()
            args = [str(headless), str(directory), name, '-process', 'Drakan.exe', '-readOnly', '-noanalysis',
                    '-scriptPath', str(ROOT / 'scripts'), '-postScript', SCRIPT.name, str(report),
                    '-log', str(run / 'ghidra.log'), '-scriptlog', str(run / 'script.log')]
            proc = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL, env=env, start_new_session=True)
            try:
                code = proc.wait(timeout=180)
            except subprocess.TimeoutExpired:
                os.killpg(proc.pid, signal.SIGKILL)
                proc.wait()
                raise ValueError('Ghidra timed out')
            if code != 0:
                raise ValueError('Ghidra failed; no report returned')
            if not report.is_file() or report.is_symlink() or report.stat().st_size > MAX_REPORT:
                raise ValueError('Ghidra report missing or exceeds limit')
            with report.open('r', encoding='utf-8') as f:
                data = json.load(f)
            if not isinstance(data, dict):
                raise ValueError('Invalid report')
            digest = data.get('executable_sha256')
            if not isinstance(digest, str) or digest.lower() != RETAIL_SHA256:
                raise ValueError('Report executable SHA-256 does not match US retail baseline')
            return data


def error(ident, code, message):
    return {'jsonrpc': '2.0', 'id': ident, 'error': {'code': code, 'message': message}}


def dispatch(req, directory, name, ghidra_home):
    if not isinstance(req, dict) or req.get('jsonrpc') != '2.0' or not isinstance(req.get('method'), str):
        return error(None, -32600, 'Invalid Request')
    has_id = 'id' in req
    ident = req.get('id')
    if has_id and (isinstance(ident, bool) or not isinstance(ident, (str, int, type(None)))):
        return error(None, -32600, 'Invalid Request')
    method = req['method']
    if not has_id:
        return None
    params = req.get('params', {})
    if not isinstance(params, dict):
        return error(ident, -32602, 'Invalid params')
    if method == 'initialize':
        result = {'protocolVersion': '2024-11-05', 'capabilities': {'tools': {}},
                  'serverInfo': {'name': 'dragonrider-loader', 'version': '0.1.0'}}
    elif method == 'ping':
        result = {}
    elif method == 'tools/list':
        result = {'tools': [{'name': TOOL, 'description': 'Read-only report of function 0x0045EDC0 in a disposable Drakan.exe project.',
                            'inputSchema': {'type': 'object', 'properties': {}, 'additionalProperties': False}}]}
    elif method == 'tools/call':
        if params.get('name') != TOOL or params.get('arguments', {}) != {}:
            return error(ident, -32602, 'Unknown tool or invalid arguments')
        try:
            data = run_report(directory, name, ghidra_home)
            result = {'content': [{'type': 'text', 'text': json.dumps(data, ensure_ascii=True)}], 'isError': False}
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            result = {'content': [{'type': 'text', 'text': 'Report failed: ' + str(exc)}], 'isError': True}
    else:
        return error(ident, -32601, 'Method not found')
    return {'jsonrpc': '2.0', 'id': ident, 'result': result}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--project-dir', required=True, help='Dedicated disposable project directory under /tmp')
    parser.add_argument('--project', required=True, help='Existing disposable project name')
    parser.add_argument('--ghidra-home', default=os.environ.get('GHIDRA_HOME'), required=not bool(os.environ.get('GHIDRA_HOME')))
    opts = parser.parse_args()
    try:
        project_check(opts.project_dir, opts.project)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    while True:
        line = sys.stdin.buffer.readline(MAX_REQUEST + 1)
        if not line:
            break
        if len(line) > MAX_REQUEST:
            while not line.endswith(b'\n') and line:
                line = sys.stdin.buffer.readline(MAX_REQUEST + 1)
            response = error(None, -32600, 'Request too large')
        else:
            try:
                response = dispatch(json.loads(line), opts.project_dir, opts.project, opts.ghidra_home)
            except (ValueError, UnicodeDecodeError):
                response = error(None, -32700, 'Parse error')
        if response is not None:
            print(json.dumps(response, ensure_ascii=True, separators=(',', ':')), flush=True)


if __name__ == '__main__':
    main()
