# SRSC record measurements

**Date:** 2026-10-17. **Source:** unpatched US retail extraction at
`research/installed/us`; files and generated per-file metadata remain private.
**Method:** raw-byte measurements with Python 3.14.7 using
`tools/research/analyze_srsc_records.py`; no Ghidra database was accessed.
**Confidence:** high for the measured arithmetic on this particular extraction;
low for any broader format rule or interpretation. The extraction has not been
proved complete or unmodified. The private JSON contains each examined file's
path and SHA-256, allowing the inputs to be identified precisely.

## Observed

The script selects regular non-symlink files with a 12-byte `SRSC` header,
version `0x0100`, nonzero count and table fitting the file, with a table start
at least 12 bytes in. It does not include other files or claim to validate SRSC.
It measured 178 such files, and skipped no matching complete headers for these
bounds. These contain 38,926 records, interpreting each as 14 bytes.

For each record, interpreting bytes 6–9 and 10–13 as little-endian unsigned
32-bit integers `a` and `b` respectively:

- All 38,926 satisfy `12 <= a <= a + b <= table offset`; none has `b == 0`.
- In all 178 files, the first record has `a == 12`, the last has
  `a + b == table offset`, and the table ends at EOF.
- All 38,748 adjacent pairs satisfy `a[i] + b[i] == a[i+1]` in table order.
  Thus these candidate ranges partition the bytes between header and table in
  each scanned file, without gaps or overlaps.
- Reading the first 2 bytes and next 4 bytes as a pair gives three repeated
  occurrences beyond the first within the same file: one in `Dragon.rrc` and
  two in `Rift Crystal.ssd`. Therefore treating that pair as a unique key
  would not hold even for this sample.

For a bounded, independently identifiable example, `Dragon.rrc`, SHA-256
`fb1e403bd33b370cc64fe1ac296b3cf889e524ff2279eca2a27b65911f0ca72a`,
has table offset 3,689,295 and count 559. Its first record is
`40 00 00 11 00 00 0c 00 00 00 01 03 00 00`: `a = 12`, `b = 769`.
The second has `a = 781`, `b = 67410`; 12 + 769 = 781. The other duplicate
example, `Rift Crystal.ssd`, has SHA-256
`de113fdd43cc366b5be9f981541c1819fe3a8512dc785bccc74edb1abaf402ec`.
Independent `sha256sum` confirmed both hashes.

## Inferred and unknown

The arithmetic strongly suggests `a` and `b` describe a payload location and
length in the sampled files. Later independent executable analysis confirms
seek and read-budget uses on selected paths; see `srsc-record-behavior.md`.
The sample arithmetic alone does not establish how the game consumes
records, the meaning of the first six bytes, uniqueness or ordering rules, valid
zero-length entries, gaps, alternate versions, or requirements for any other
edition or file. Do not turn the sampled contiguity or EOF conditions into
rejection rules without further evidence. Correlate record access in the
executable and examine independent files before implementing record semantics.

## Reproduce

```sh
python3 tools/research/analyze_srsc_records.py research/installed/us research/exports/srsc-records/us.json
python3 tools/research/analyze_srsc_records.py research/installed/us research/exports/srsc-records/us-repeat.json
cmp research/exports/srsc-records/us.json research/exports/srsc-records/us-repeat.json
python3 -m unittest discover -s tools/research -p 'test_*.py' -v
```

The two outputs compared identical; all four research-tool tests passed,
including synthetic contiguous, duplicate, noncontiguous, out-of-range,
trailing-data and truncated-table cases. These are tests of measurement, not
proof of original loader behavior. Raw retail samples are not included in tests.
