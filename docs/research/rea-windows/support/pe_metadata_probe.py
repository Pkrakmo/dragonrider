#!/usr/bin/env python3
"""Version 1: hash-gated PE32 metadata inventory; standard library only."""
import datetime
import hashlib
import json
from pathlib import Path
import platform
import struct
import subprocess
import sys

VERSION = "1"
EXPECTED = "23630f48e20e8a9f42026501165ae1df407cfcee545a784ec930a4c25ee70648"

def inspect(path):
    with path.open("rb") as stream:
        data = stream.read(16 * 1024 * 1024 + 1)
    if len(data) > 16 * 1024 * 1024:
        raise ValueError("Input exceeds 16 MiB bound")
    digest = hashlib.sha256(data).hexdigest()
    if digest != EXPECTED:
        raise ValueError("Canonical hash mismatch: " + digest)

    def span(offset, size):
        if offset < 0 or size < 0 or offset + size > len(data):
            raise ValueError("Out-of-file read")
        return data[offset:offset + size]

    def unpack(fmt, offset):
        return struct.unpack(fmt, span(offset, struct.calcsize(fmt)))

    if span(0, 2) != b"MZ":
        raise ValueError("Missing DOS signature")
    pe = unpack("<I", 0x3c)[0]
    if span(pe, 4) != b"PE\0\0":
        raise ValueError("Missing PE signature")
    machine, nsections = unpack("<HH", pe + 4)
    optional_size = unpack("<H", pe + 20)[0]
    opt = pe + 24
    span(opt, optional_size)
    if optional_size < 112 or unpack("<H", opt)[0] != 0x10b:
        raise ValueError("Expected PE32 optional header")
    if unpack("<I", opt + 92)[0] < 2:
        raise ValueError("Missing import directory")
    entry = unpack("<I", opt + 16)[0]
    base = unpack("<I", opt + 28)[0]
    sections = []
    for index in range(nsections):
        off = opt + optional_size + index * 40
        row = span(off, 40)
        name = row[:8].split(b"\0", 1)[0].decode("ascii")
        virtual_size, rva, raw_size, raw_offset = unpack("<IIII", off + 8)
        span(raw_offset, raw_size)
        sections.append(dict(name=name, rva=rva, virtual_size=virtual_size,
                             raw_offset=raw_offset, raw_size=raw_size))

    def mapped(rva, size):
        matches = [s for s in sections
                   if s["rva"] <= rva and rva + size <= s["rva"] + s["raw_size"]]
        if len(matches) != 1:
            raise ValueError("RVA has no unique raw-backed section")
        s = matches[0]
        return s["raw_offset"] + rva - s["rva"], s["rva"] + s["raw_size"]

    def rread(rva, size):
        off, _ = mapped(rva, size)
        return span(off, size)

    def cstring(rva):
        off, end = mapped(rva, 1)
        value = span(off, min(1024, end - rva)).split(b"\0", 1)
        if len(value) != 2:
            raise ValueError("Unterminated or oversized string")
        return value[0].decode("ascii")

    imp_rva, imp_size = unpack("<II", opt + 104)
    imports = []
    terminated = False
    for index in range(min(imp_size // 20, 4096)):
        descriptor = struct.unpack("<IIIII", rread(imp_rva + index * 20, 20))
        if not any(descriptor):
            terminated = True
            break
        oft, _, _, name_rva, first_thunk = descriptor
        thunk = oft or first_thunk
        _, thunk_end = mapped(thunk, 4)
        named = ordinal = 0
        thunk_terminated = False
        for item in range(min((thunk_end - thunk) // 4, 65536)):
            value = struct.unpack("<I", rread(thunk + item * 4, 4))[0]
            if value == 0:
                thunk_terminated = True
                break
            rread(first_thunk + item * 4, 4)
            if value & 0x80000000:
                ordinal += 1
            else:
                rread(value, 2)
                cstring(value + 2)
                named += 1
        if not thunk_terminated:
            raise ValueError("Unterminated thunk table")
        imports.append(dict(dll=cstring(name_rva), entries=named + ordinal,
                            named=named, ordinal=ordinal))
    if not terminated:
        raise ValueError("Unterminated import descriptors")
    return dict(sha256=digest, size=len(data), machine=hex(machine),
                image_base=hex(base), entry_rva=hex(entry),
                entry_va=hex(base + entry), sections=sections,
                import_descriptors=len(imports),
                import_entries=sum(x["entries"] for x in imports), imports=imports)

def main():
    if len(sys.argv) != 2:
        raise ValueError("Usage: pe_metadata_repro.py /private/path/Drakan.exe")
    result = inspect(Path(sys.argv[1]))
    result.update(parser_version=VERSION, python_version=platform.python_version(),
                  observed_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                  objdump_version=subprocess.run(
                      ["objdump", "--version"], check=True, capture_output=True,
                      text=True, timeout=10).stdout.splitlines()[0])
    print(json.dumps(result, indent=2, sort_keys=True))

if __name__ == "__main__":
    main()

