# SRSC reader status and limits

DragonRider's reader implements the evidenced subset of the unpatched US
retail SRSC structure; it is not a complete format specification. The source,
hash, instructions and limits of the executable analysis are in
`srsc-record-behavior.md` and `riot-file-loading.md`.

The 12-byte header comprises `SRSC`, little-endian version `0x0100`, a
little-endian 32-bit table offset, and a nonzero little-endian 16-bit count.
Each table entry occupies 14 bytes: three little-endian 16-bit comparison
values, a little-endian 32-bit seek position, and a little-endian 32-bit read
budget. The game uses the first three values for lookup on one path; their
individual meanings are unknown. It uses the latter two for seeking and
limiting reads on the investigated paths.

The C++ reader checks that the header, table and every offset/length range fit
the supplied byte span. It rejects invalid magic, unsupported version, zero
record count, truncated data, and out-of-file ranges with an error. Range
checks are a DragonRider input-safety policy rather than a demonstrated
original-loader check. For an independently supplied table, the reader checks
that all declared entries fit before allocating the result and validates each
payload range against the separately supplied file size; extra table bytes are
ignored. Synthetic tests exercise all truncations of a two-entry table and a
large count with a short table. Duplicate selectors, gaps, overlaps, zero-length ranges
and data after the table are accepted where they fit the file; this does not
claim the original game accepts each such arrangement. The inspector checks
record ranges when `--records` is requested and displays at most 50 entries.
It reads the bounded table rather than the entire file, without a 128 MiB
input limit. Size changes during inspection are detected; unchanged-size
concurrent modifications are not guaranteed to be detected.

Unknowns include individual selector meanings, payload formats, duplicate
lookup behavior outside the paths traced in [SRSC lookup order](srsc-lookup-order.md), alternate versions and editions, offsets at
or above 2 GiB in the original loader, and the contents' validity. The US
samples and tests do not establish universal contiguity or table-at-EOF rules.
The `--texture INDEX` option exposes evidenced selector-`0x0040` header fields
including the raw little-endian dwords at payload offsets 14, 18 and 34, and
checks raw-row bounds for the traced nonpositive branch. The meaning and
effect of those dwords depend on the loader path and device behavior.
`--texture-rows`
also decodes raw and storage-word-1 zlib base rows with bounded input and
output; it does not interpret pixels or additional blocks. See
`selector-0040-behavior.md`, `texture-pipeline-behavior.md`,
`texture-pixel-samples.md`, and ADRs 0003–0005.

`--palette INDEX` validates the count and four-byte entries for records with
selector words 0 and 2 equal to `0x0030` and zero. It preserves zero counts
and reports, but does not validate, trailing data. The lookup gate and runtime
namespace are not enforced by this structural inspection; see
`texture-palette-behavior.md`, `texture-palette-samples.md`, and ADR 0006.

`--indexed-check TEXTURE_INDEX PALETTE_INDEX` summarizes an explicitly chosen
8-bit texture and palette in one file, excluding stride padding. A reported
out-of-range index is relative to that choice, not proof that the original
runtime used the palette or rejected the texture. See ADR 0007.

`--record-0102 INDEX` reads only the bounded prefix and ten following bytes
of a selected first-selector-`0x0102` record. The prefix remains raw bytes,
and its checksum and raw following fields are diagnostic only. The remainder
is opaque; selector correlations, runtime gates and references are not
validated. See [ADR 0019](../decisions/0019-srsc-0102-prefix-inspection.md).

`--record-0102-array INDEX` additionally checks the observed two-dword and
four-byte-unit framing, subject to a one-million-entry limit. Its checksum
covers only those raw units; following bytes remain opaque. Runtime resource
matching and the meaning of the units are not established by inspection. See
[ADR 0020](../decisions/0020-srsc-0102-array-inspection.md).
