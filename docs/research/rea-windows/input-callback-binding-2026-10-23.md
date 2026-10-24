# Input callback ownership across EXE and retail RFL

## Scope and confidence

Date: 2026-10-23. Observed static linkage for the US retail pair:

| Input | Bytes | SHA-256 |
| --- | --- | --- |
| Drakan.exe | 552960 | `23630f48e20e8a9f42026501165ae1df407cfcee545a784ec930a4c25ee70648` |
| Dragon.rfl | 1724416 | `9b6496b65e962cf35dd1e18f424f2c8af08ceade78331dcc0b6da332ce844ac3` |

Both hashes were verified locally. The module was extracted from the owned
retail cabinet into private storage and made read-only. Neither input nor the
installer was executed. Ghidra 12.1.4/OpenJDK 25.0.4.1 and GNU objdump 2.42
were used on Ubuntu; two independent raw-disassembly checks covered the EXE
provisioning and RFL binding paths. Python 3.12.3 decoded PE data.

High confidence in the conditional static chain below. It assumes this module
was selected, its interface initialized, and loading/provisioning and input
initialization reached successfully. **Actual module selection was not
observed.** The generic loader accepts a selected path; the empty resource
string discussed in the [earlier RFL investigation](../srsc-0102-runtime.md)
does not establish a default loaded module.

## Observed host-to-module bridge

| Step | Evidence |
| --- | --- |
| RFL interface | Export `GetRFLInterface` at `0x10015650` returns object `0x1017aeb8`. Constructor `0x10015520` installs table `0x1016b794`; slot 0 points to `0x100155a0`, which returns host-function storage `0x1017aec0`. Constructor reachability is documented in the earlier RFL investigation. |
| EXE loader | Resolves `GetRFLInterface` using string `0x47d3cc`; calls the resolved export at `0x437be7`, stores the object at `0x483bf4`, calls object slot 0 at `0x437bf2`, and passes its return to `0x408a70` at `0x437bf5`. |
| Provisioning | At `0x408aed`, `0x408a70` writes getter `0x408860` into supplied storage +4. |
| Getter | `0x408860..0x408865` returns the address `0x483928`, without dereferencing it. |
| Input alias | EXE `0x40786b` writes `0x47fb20` into `0x483af4`; `0x483928 + 0x1cc = 0x483af4`. |
| RFL initialization | Interface slot +8 is `0x10013600`. Its call at `0x1001361f` invokes `[0x1017aec4]`, stores the return at `0x1017ae98` at `0x10013625`, and subsequently calls `0x1000e900(1)` at `0x10013789`. Earlier resource failure can return before binding. |

Thus the RFL receiver `[ [0x1017ae98] + 0x1cc ]` is the EXE input object
`0x47fb20` under those conditions. This establishes pointer provenance rather
than matching offsets by appearance alone.

## Observed binding and temporary capture

The EXE input object's table `0x47539c` has slot +0x50 -> `0x406810` and
slot +0x5c -> `0x406850`. These setters store their stack argument in receiver
fields +0x5c4 and +0x5c8 respectively and return with `ret 4`.
Initialization clears both fields at `0x405909`/`0x405913`.

RFL `0x1000e900` first calls receiver slot +4 at `0x1000e90d` (EXE helper
`0x406220`; slot +8 instead points to state-clear helper `0x4059d0`).
Its nonzero argument path installs:

| Input field | Target | RFL call site | Contract established on EXE side |
| --- | --- | --- | --- |
| +0x5c4 | `0x1000c6c0` | `0x1000e92a`, slot +0x50 | `(mapping, code, status, third_event_value)` |
| +0x5c8 | `0x10014d50` | `0x1000e93f`, slot +0x5c | `(kind, code, x, y)` |

See [event contracts](input-event-consumers-2026-10-23.md). Its zero argument
path calls `0x1000e8a0`, clears the two bindings at `0x1000e957`/`0x1000e969`,
and continues other logic. This is not a proof of complete module teardown.

EXE `0x406750..0x4067ea` temporarily saves field +0x5c4 and mode +0x5bc,
sets mode 1 and callback `0x4067f0`, saves the three device flags at +0x34,
+0x120 and +0x20c, and ORs each with 1. It clears global `0x47f420` and invokes
receiver slot 0 at `0x4067b1` (poll helper `0x405a60`). After that call returns,
it restores all saved flags, mode and callback and returns `0x47f420`.

`0x4067f0..0x406806` stores its second stack argument to that global only when
its third argument is nonzero, then returns 1. Therefore the capture result is
the last delivered nonzero-status code in that polling call, or zero if none;
it is not necessarily the first event. Reentrant/concurrent use and exceptional
nonreturning paths are unverified. The other callback field is not replaced.

## Bounded implications and unknowns

The observations support separate host event normalization, callback ownership,
module action mapping and temporary capture in a portable design. They do not
justify copying the original ABI or large dispatch body into the engine.

Ghidra recovered `0x1000c6c0..0x1000e12f`, a large conditional action dispatch;
its full gameplay semantics remain unknown. The smaller target is covered in
[the pointer callback report](input-pointer-callback-2026-10-23.md).
All decompilation and raw logs remain private; only independently written
behavioral summaries are committed.

## Reproduction

Use the environment in [lifecycle reproduction](lifecycle-reproduction-2026-10-23.md).
Set `DR_EXE` and `DR_RFL` to private inputs and verify the exact hashes above
with `sha256sum` before analysis. Map VAs using each PE's own ImageBase/sections;
do not apply the EXE metadata probe to the RFL.

```sh
objdump -d -Mintel --start-address=0x437b74 --stop-address=0x437c08 "$DR_EXE"
objdump -d -Mintel --start-address=0x408a70 --stop-address=0x408b02 "$DR_EXE"
objdump -d -Mintel --start-address=0x408860 --stop-address=0x408866 "$DR_EXE"
objdump -d -Mintel --start-address=0x407850 --stop-address=0x407880 "$DR_EXE"
objdump -s --start-address=0x47d3cc --stop-address=0x47d3dc "$DR_EXE"
objdump -d -Mintel --start-address=0x406750 --stop-address=0x406860 "$DR_EXE"
objdump -s --start-address=0x47539c --stop-address=0x47541c "$DR_EXE"
objdump -d -Mintel --start-address=0x10015520 --stop-address=0x10015660 "$DR_RFL"
objdump -s --start-address=0x1016b794 --stop-address=0x1016b7a0 "$DR_RFL"
objdump -d -Mintel --start-address=0x10013600 --stop-address=0x10013900 "$DR_RFL"
objdump -d -Mintel --start-address=0x1000e900 --stop-address=0x1000e98c "$DR_RFL"
```

For Ghidra, [InspectPinnedRetailFunctions.java](support/InspectPinnedRetailFunctions.java)
accepts only the two hashes above. A fresh privately owned RFL project was
imported once, querying `0x10013600`; subsequent `-process Dragon.rfl -readOnly
-noanalysis` queried `0x1000e900 0x1000c6c0 0x10014d50`. Both runs completed
successfully. The existing EXE project was processed separately with
`InspectWindowLifecycle.java 0x406750 0x4067f0 0x408a70 0x408860`, also successful.
Never access the same project concurrently. Redirect all output privately.

The import had not defined `0x10013600`; the script created it after checking
that the address was not inside another function. The later RFL query similarly
created `0x10014d50`. EXE capture/getter functions also needed explicit recovery.
Read-only processing discards those transient definitions. These gaps make
uncorroborated database xrefs insufficient for completeness claims.

Included script SHA-256:
`810925dfd295631f75d224ad1210fd05ad26ccb106ae17bb3d182854e4a654ba`.
