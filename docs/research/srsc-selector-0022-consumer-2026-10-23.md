# Candidate `(0x0022,0,0)` consumer

**Input:** unpatched US retail `research/binaries/us/Drakan.exe`, SHA-256
`23630f48e20e8a9f42026501165ae1df407cfcee545a784ec930a4c25ee70648`.
**Methods:** Ghidra 12.1.4 read-only `-process -noanalysis` on the existing
`Drakan_US_Retail` project, GNU objdump 2.45.1-5.fc43 against the pinned
executable, and a Python scan of the private US SRSC inventory with per-file
size/SHA-256 checks. **Confidence:** high for the pinned instructions and
measured inventory; low for entry-point and runtime interpretation. No
decompiled code was copied into the implementation.

## Observed

In the existing Ghidra database, the bounded `TraceSrscRecords.java` probe
lists a direct call at `0x0040E3CA` to the three-word lookup at `0x0045F0D0`.
The xref has no containing function for the caller in that database. On the
hash-pinned raw executable, GNU objdump independently places the call in a
code region beginning at `0x0040E3B0`; the instructions push zero, zero, then
`0x22`, set `ECX` to a caller-provided object, and call the lookup. Under the
lookup's observed 12-byte stack argument convention, the requested tuple is
`(0x0022,0,0)`. A nonzero lookup result returns early from this code region.

After the successful lookup branch, this code calls `0x0045F370` with the
address of a local dword. The helper's pinned instructions pass a four-byte
request to the bounded read helper `0x0045F2D0`; the caller then reads that
dword and loops over it. Each loop calls the existing length-prefixed text
reader `0x0045F430` with a 512-byte destination capacity. The resulting
buffers are passed to two indirect calls through a table at object offset
`+0x1dc`; the targets and meaning of the strings are unknown. This path reads
a count and length-prefixed byte sequences after selecting the candidate
tuple; it does not establish a general payload grammar.

The full pinned `.text` disassembly contains 26 direct relative calls to
`0x0045F0D0`, including `0x0040E3CA`, and no direct unconditional jumps to that
lookup. It contains no direct calls or direct unconditional jumps to the
candidate region start `0x0040E3B0`. This does not exclude a computed, indirect,
table-driven, or runtime-written entry.

The fresh inventory scan checked recorded file sizes and SHA-256 values for
all 178 examined US SRSC containers (38,926 records across eight extensions).
None contains the exact selector tuple `(0x0022,0,0)`. This means only that the
tuple was absent from these hash-identified retail files; it does not prove
the code is unreachable, unused, or associated with a particular missing
resource.

## Reproduce

```sh
sha256sum research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x0040E3B0 --stop-address=0x0040E600 research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x0045F370 --stop-address=0x0045F430 research/binaries/us/Drakan.exe
python3 tools/research/verify_srsc_selector_0022.py research/binaries/us/Drakan.exe research/installed/us research/exports/srsc-records/us.json
python3 -m unittest discover -s tools/research -p 'test_verify_srsc_selector_0022.py' -v
```

The verifier hashes the executable once and disassembles a temporary copy of
those exact bytes, checks 14 instruction anchors, including the zero-register setup and both indirect call sites, and confirms the 26 direct lookup
calls and absence of direct jumps to the two selected addresses, then scans the
manifest inputs from one hash/size-verified snapshot each. Six synthetic tests
cover instruction parsing, malformed table/payload bounds, executable pinning,
source mutation during disassembly, stale hashes, malformed sizes, and duplicate
inventory paths. The Ghidra trace used
the existing project read-only with analysis disabled; its caller information
remains dependent on that database's xrefs.
