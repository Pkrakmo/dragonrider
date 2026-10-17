# Level cell texture candidates

**Date:** 2026-10-17. **Inputs:** unpatched US retail `Drakan.exe`, SHA-256
`23630f48e20e8a9f42026501165ae1df407cfcee545a784ec930a4c25ee70648`;
installed-US levels and candidate containers verified against their private
inventory hashes; and the retail installer cabinet, SHA-256
`d6b78b161eb5ed494ae76dae6c157b29c10822dc50b087708ec0de4bd6e08fc8`.
**Method:** Ghidra 12.1.4, disposable project, `-process -readOnly -noanalysis`,
`TraceLevelTextureSelection.java`, private run `level-texture-selection-ZNaJZg5O`;
independent GNU objdump 2.45.1, Python 3.14.7 and Unshield 1.6.2. The Ghidra
import reports the executable hash. No game or installer was executed.
**Confidence:** high for the specified static path, sample counts and listing
comparison; the combined installer destination, runtime source state, actual
file opens and other editions remain unverified.

## Observed

On the level path, `0x00437074`–`0x004370bc` copies the supplied level path,
finds its last backslash, truncates after it, and sets the current directory.
For each directory entry, `0x00437103` reads a length-prefixed byte sequence
into a 256-byte buffer; `0x00437122` calls `GetFullPathNameA` on it. The
result and entry value are passed to the source manager. The manager's reuse,
allocation and collision branches are documented in
[level source IDs](level-source-ids.md). The original API calls and their error
handling do not define DragonRider's safe path policy.

The selected texture path `0x0043586a`–`0x004358d4` searches source object IDs
using a cell dword's high half, conditionally opens a source using index 3
(which conditionally appends `.txd`), and selects a record with `0x0045f230`.
That function calls `0x0045fa10`, which compares record selector words 0 and
1 to `0x0040` and the low half of the dword, respectively, and selects the
first match. Selector word 2 is not tested by this search. See the
[texture trace](selector-0040-behavior.md). A match in a file is not proof that
this path was reached or an open succeeded.

Unshield 1.6.2 lists the cabinet's group and directory names using spaces.
Replacing spaces with underscores in each listed directory component, while
leaving filenames unchanged, yields a unique listing path with the same size
for **178/178** SRSC inventory entries. This confirms the name conversion for
these listed entries; size and path alone do not independently prove bytes were
extracted correctly. The inventory hashes verify the bytes used in the scan.
Unshield also lists six components and six file groups. Its component-filtered
listing reports that the action is not implemented in version 1.6.2, so this
check does not establish component-to-destination mappings or a shared runtime
destination.

## Candidate comparisons

The research script makes *lexical keys only* from each level's inventory path
and embedded name. It accepts restricted relative ASCII names, recognizes a
single trailing NUL, collapses `..` only within the inventory root, and applies
the observed conditional suffix. It never opens an embedded name. It compares
keys with inventory entries, opens only unique inventory-listed candidates
whose resolved paths remain under the supplied root, verifies their SHA-256,
and validates every candidate SRSC range. Case folding and these checks are
research policy, not an emulation of Windows `GetFullPathNameA`.

Under the exact extracted layout, **52/164** directory entries have one
candidate and **112** have none. The **41** referenced level/source pairs
include **15** with one candidate and **26** without. Their cell dword
occurrences comprise **190,423** unique selector matches and **559,331**
without a candidate, plus **335,828** negative dwords. No matched candidate
has a missing or multiple selector for these references.

As a separate hypothesis, remove the first extraction group component and
normalize spaces and underscores in directory components for both sides of
the comparison. This models groups sharing a destination; it is **not** a
verified installer layout. Under this policy, **154/164** directory entries
have one candidate and **10** have none. All **41/41** referenced level/source
pairs have exactly one candidate across **14** hash-verified files. All
**749,754** nonnegative dword occurrences have exactly one matching selector
pair in those candidate files; there are no missing or multiple matches.
This includes repeated fields even where the retail code could reuse a cached
result. The remaining **335,828** dwords are negative. The independent Python
scan agrees with the C++ diagnostic for each candidate pair.

These counts support the association as a useful research hypothesis, not an
actual runtime resolution, filesystem policy, visual correctness or evidence
that the ten unmatched, unreferenced directory entries are missing required
assets. `GetFullPathNameA`, the installer destinations, collisions, aliases,
other paths and the game state could alter the outcome.

## Reproduction

```sh
sha256sum research/binaries/us/Drakan.exe research/extracted/us/Setup/data1.cab
unshield -V
unshield c research/extracted/us/Setup/data1.cab
unshield g research/extracted/us/Setup/data1.cab
unshield -c 'Multi-player Files' l research/extracted/us/Setup/data1.cab
python3 tools/research/verify_unshield_listing.py research/extracted/us/Setup/data1.cab research/exports/asset-inventory/us.json
objdump -d -Mintel --start-address=0x437074 --stop-address=0x437144 research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x45f230 --stop-address=0x45f26b research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x45fa10 --stop-address=0x45facb research/binaries/us/Drakan.exe
python3 tools/research/measure_level_texture_candidates.py research/installed/us research/exports/asset-inventory/us.json --inspector build/debug/dragonrider_inspect
python3 tools/research/measure_level_texture_candidates.py research/installed/us research/exports/asset-inventory/us.json --overlay-hypothesis --inspector build/debug/dragonrider_inspect
python3 -m unittest discover -s tools/research -p 'test_*.py'
```

For Ghidra, use the disposable-project procedure in
[the block trace](level-0001-blocks.md), substitute `TraceLevelTextureSelection.java`,
and use fresh logs. Close any GUI using the project and serialize access.
