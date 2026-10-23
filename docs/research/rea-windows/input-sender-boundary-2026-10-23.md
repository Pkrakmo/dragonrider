# Sender construction and the -2 dispatch boundary

## Scope and evidence

Date: 2026-10-23. Static US retail Drakan.exe SHA-256
`23630f48e20e8a9f42026501165ae1df407cfcee545a784ec930a4c25ee70648`,
verified before analysis. No original program was executed. Ghidra
12.1.4/OpenJDK 25.0.4.1 queries and independent GNU objdump 2.42/raw PE checks
agree on the selected constructor, table and dispatch boundaries. The private
EXE project was processed sequentially with `-readOnly -noanalysis`; all
queries completed successfully and the functions were already defined.

This extends [the 0x28 producer](input-clear-producer-2026-10-23.md), whose
call uses host field +0x1ac, virtual slot +0x60 and arguments
`(-2,payload,10,-1)`. Confidence is high in the conditional target resolution
and selected branch, not in actual transport or end-to-end delivery.

## Observed pointer provenance

| Step | Evidence |
| --- | --- |
| Host receiver | `0x457f24` supplies ECX=0x483928; a nonzero argument selects call `0x40a7b0` at `0x457f2d`. |
| Replace object | `0x40a7b0` preserves that receiver in EDI, conditionally destroys/frees its existing +0x1ac object, then requests 0x6e bytes at `0x40a7e6`. |
| Construct | A nonnull allocation is passed to `0x457f60` at `0x40a800`; the null branch zeros EAX at `0x40a807`. |
| Store | Join `0x40a809` stores EAX to receiver +0x1ac, which is 0x483ad4 on this call path. It is **not** an unconditional zero store. |
| Table | Constructor `0x457f84` installs table 0x475e14. Raw dword at 0x475e74, its slot +0x60, is 0x456a80. |
| Alias | After construction returns, wrapper reloads 0x483ad4, calls `0x44dfb0(0,0)`, then copies 0x483ad4 to global 0x483bf0 at `0x457f46`. |

Thus the producer's virtual call resolves to **0x456a80**, conditional on this
construction path completing and the object/table remaining unchanged. Both
host field +0x1ac and the record dispatcher's global 0x483bf0 can identify the
same object. Allocation/constructor failure, replacement, callee mutations and
other callers remain separate conditions; class identity alone does not prove
runtime pointer contents. The constructor's remaining subobjects were not fully
audited.

## Observed -2 branch of 0x456a80

The function consumes four stack arguments `(selector,payload,length,flags)`
and returns with `ret 0x10`. For selector -2:

1. `0x456ac0` loads `A=sender[+0x46]` without a null check on A.
2. Require `A[+0x78]` nonnull and its signed dword +0x170 greater than zero
   (`0x456ac3..0x456ad6`). Rejection reaches return-zero at `0x456c42`.
3. `0x456aeb` calls `0x453b50` with receiver A[+0x78] and argument
   `A[+0x64]+length+0x1c`. Its result is not checked. Its effects are untraced.
4. After that call, reload sender +0x46 and its +0x78 at `0x456af0` and
   `0x456af9`, without repeating the null/count gate.
5. `0x456b01` calls `0x453be0(reloaded_receiver,payload,length,flags)`.
   The wrapper returns that result unchanged; it does not normalize a byte.

This branch does not use the ordinary individual-selector path's later flag
substitutions. In particular, producer flags -1 reach 0x453be0 as -1.
Receiver lifetime across the preparatory call is an unverified precondition.

## Observed fan-out helper: 0x453be0..0x453c32

The helper initializes EAX and loop index to zero. With positive signed count
at receiver +0x170, each iteration reads a dword identifier from the array
at receiver +0x168 and calls global 0x483bf0's slot +0x60 at `0x453c15`,
passing `(identifier,payload,length,flags)`. It reloads the global receiver and
array pointer each iteration, and reloads the count after each call.

Under the established alias/table conditions, these calls reenter 0x456a80
with the array identifiers. Their values are not validated in this helper;
do not assume they exclude special selector values or prove recursion ends.
Array ownership, positive capacity and stable count are also unproved here.

At `0x453c28`, the helper tests **full EAX** from the final call as signed,
then normalizes to 1 for nonnegative or 0 for negative. It does not aggregate
all results or stop on an earlier negative result. With no iterations, its
initial EAX=0 yields return 1. This is the observed return rule, not proof
that every target accepted or received the payload. Exact return-width and
error semantics of all reentered branches are outside this slice.

## Remaining boundary and implications

Construction, aliasing and fan-out are now linked, but this is not the same as
proving insertion into the 0x148-byte records consumed by 0x451610. The next
bounded question is the individual-target path and the downstream transport
boundary at 0x4508d0, followed separately by receiving/record insertion.
The producer's local callback clear still precedes these optional delivery
operations. No network traffic or original runtime execution was performed.

Portable design should keep local state transitions, sender selection, fan-out
result aggregation and delivery acknowledgement separate. Do not infer all-target
success from the original helper's last-result sign test.

## Reproduction

Verify the EXE hash and use the pinned environment and included script from
[lifecycle reproduction](lifecycle-reproduction-2026-10-23.md). Keep raw output
and decompilation private.

```sh
sha256sum "$DR_EXE"
objdump -d -Mintel --start-address=0x457f20 --stop-address=0x457f92 "$DR_EXE"
objdump -d -Mintel --start-address=0x40a7b0 --stop-address=0x40a833 "$DR_EXE"
objdump -s --start-address=0x475e74 --stop-address=0x475e78 "$DR_EXE"
objdump -d -Mintel --start-address=0x456a80 --stop-address=0x456b0b "$DR_EXE"
objdump -d -Mintel --start-address=0x456c42 --stop-address=0x456c4b "$DR_EXE"
objdump -d -Mintel --start-address=0x453be0 --stop-address=0x453c33 "$DR_EXE"
```

Ghidra queries, serialized: `InspectWindowLifecycle.java 0x40a7b0 0x457f60`,
then `0x456a80`, then `0x453be0`, always with `-process Drakan.exe -readOnly
-noanalysis`. Function bodies reported were 0x40a7b0..0x40a832,
0x457f60..0x458267, 0x456a80..0x456c4a and 0x453be0..0x453c32.
Only the selected paths above were independently checked; no complete
constructor, protocol or transport semantics are claimed.
