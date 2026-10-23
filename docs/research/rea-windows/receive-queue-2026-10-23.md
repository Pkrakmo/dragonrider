# Receive interface, queue insertion and consumer ownership

## Scope and evidence

Date: 2026-10-23. Static US retail Drakan.exe SHA-256
`23630f48e20e8a9f42026501165ae1df407cfcee545a784ec930a4c25ee70648`.
Hash verified; no original program run and no messages received experimentally.
Ghidra 12.1.4/OpenJDK 25.0.4.1 and independent GNU objdump 2.42/raw PE checks
agree on the paths below. Ghidra queries ran sequentially in the existing
private EXE project with `-readOnly -noanalysis`, all successfully.

Confidence is high in conditional ownership, interface arguments, insertion
and rollback. It is not a proof of allocation safety, thread lifetime, runtime
delivery, or the behavior of a particular external transport provider.

## Ownership and shared locking

Let S be sender global 0x483bf0, M=S[+0x46], W=M[+0x88], and C=W[+0x36].
The [sender report](input-sender-boundary-2026-10-23.md) establishes S's
conditional construction and aliasing.

- Call `0x450ba3` constructs W through `0x453650`; `0x450bb0` stores it at
  manager +0x88.
- Constructor `0x453650` initializes a critical section at W+0x1e, installs
  table 0x475dec, allocates a 0x2c-byte container, calls `0x4519c0` at
  `0x4536b5`, and stores the result at W+0x36 at `0x4536be`.
- Table 0x475dec's first entry is worker body `0x4537d0`. That body calls
  producer `0x4538b0` at `0x453862` after its wait and lock checks.
- Consumer `0x451610` obtains C through `0x4507d0`. With manager +0x10
  nonzero, that getter locks W+0x1e and returns W[+0x36]. Its paired
  `0x450800` calls LeaveCriticalSection on W+0x1e.

Helper `0x460670..0x46067e` calls EnterCriticalSection, returns 1 and pops one
stack argument. It **does not inspect that argument**. The worker's supplied
half-interval and consumer's -1 argument therefore do not establish a timed
lock operation. The worker calls LeaveCriticalSection at `0x453868` after
producer return. WaitForSingleObject calls govern its loop; runtime scheduling,
event signaling, exceptions and reentrant callback behavior remain unproved.

## Container and record fields

The constructor initializes both list endpoints to -1 and the numeric
counts/pointers below to zero. Descriptive names are inferred from operations.

| C offset | Observed use |
| --- | --- |
| +0x04 | Record-array base |
| +0x08 | Allocated record capacity |
| +0x0c | Logical record-slot count/high-water mark |
| +0x10 / +0x14 / +0x18 | Free-index array / capacity / count |
| +0x1c | Active record count |
| +0x20 / +0x24 | Head / tail index, -1 when absent |
| +0x28 | Next insertion sequence value |

Each record has stride **0x148**:

| Record offset | Observed use |
| --- | --- |
| +0 / +4 / +8 | Active marker / previous index / next index |
| +0x0c | Locally assigned insertion sequence |
| +0x10 | Interface output dword; later third module-dispatch argument |
| +0x14 | Interface in/out dword, initially M[+0x70] |
| +0x18..+0x143 | Payload storage, 0x12c (300) bytes |
| +0x144 | Interface in/out length, initialized to 0x12c |

These local sequence values are distinct from the sender's payload +1 counter.
No comparison or equivalence between the two is established.

## Count query and receive attempt

Producer `0x4538b0..0x453a84` first calls `0x456820(S)` at `0x4538c3`.
That helper initializes a local count to zero. When M[+0x10] is nonzero,
`0x456846` calls M[+0x7c] slot +0x44 with
`(interface,M[+0x70],&count)`. It returns **the output dword**, explicitly
loaded at `0x45687d`, not the local address suggested by Ghidra's inferred
pointer type. Disabled state returns zero.

A signed-negative interface status can conditionally notify S's slot +0x88
with `(7,&separate_zero_local,4,0)` at `0x456877`, depending on the reloaded
manager/mode. The separate local is not the count. The count is still returned
afterward; failure does not itself force it to zero in this helper.

Producer returns when the initial signed count is nonpositive. Otherwise it
uses that count as a bound on this invocation's receive attempts:

1. Reuse an index from C's free-index array, or call `0x453a90(C+4,1)` at
   `0x4538f9` to extend the record array.
2. Mark the reserved record active, set its links to -1, and increment C+0x1c
   before attempting reception (`0x453912..0x453922`).
3. Initialize record +0x14 from M+0x70 and record +0x144 to 0x12c.
4. At **`0x45397a`**, invoke M[+0x7c] slot **+0x64**, with arguments
   `(interface,&record[+0x10],&record[+0x14],2,record+0x18,&record[+0x144])`.

The output buffer is therefore the same record payload later dispatched to the
module. The call is not a separately observed copy from an intermediate buffer.
Payload validity and interface adherence to the supplied capacity are not proved
by these instructions.

## Successful insertion and failure rollback

On a **signed-nonnegative** interface result, assign the old C+0x28 value to
record +0x0c and increment that counter. Link the record after the current
tail C+0x24, updating previous/next links and the tail; an empty-list case
sets head C+0x20 (`0x453a43`). The tail update is at `0x453a23`. Repeat until
the initial count bound is exhausted. Thus this success test includes positive
results, not only zero.

On a **signed-negative** result, mark the reserved record inactive, reset
both links, decrement active count C+0x1c, return its index to the free-index
array through `0x451940` at `0x453a78`, and stop this invocation. No local
special handling of a reported larger buffer size, payload-buffer growth or
immediate retry is visible in this function. A later worker invocation remains
a separate event.

## Storage growth and limits

`0x453a90` grows record capacity in increments of 100 under ordinary
nonoverflowing arithmetic and allocates/reallocates `capacity*0x148` bytes.
It updates capacity before allocation, stores the GlobalLock result without
a null/status test, increments logical slot count and returns the old index.
`0x451940` grows free-index capacity by 50, stores its allocation result
unchecked, then appends the supplied index and increments count.

No local negative-request, overflow, allocation-failure recovery or index-value
validation is established in these helpers. The producer's subsequent index
tests do not by themselves guarantee a valid record pointer. These observations
limit the proof; they are not a complete memory-safety assessment or an observed
failure. A new portable implementation should validate these conditions explicitly.

## Connection to module dispatch

The already checked `0x451610` consumes this same C, selects an active record,
and passes record payload +0x18, length +0x144 and field +0x10 to the module
slot +0x28 when the third field is nonzero and first payload byte >0x1d.
See [the clear-dispatch bridge](input-clear-dispatch-2026-10-23.md).

Consequently, a suitable received record beginning with 0x28 is structurally
eligible for the RFL clear-dispatch path. Its state gates still apply. The
[send boundary](transport-interface-2026-10-23.md) and this receive boundary
do not prove that a specific locally emitted payload is delivered here, that
all messages are accepted, or that the transport is reliable or ordered.

## Reproduction

Verify the canonical hash and keep raw outputs private. Selected raw windows:

```sh
objdump -d -Mintel --start-address=0x450b7d --stop-address=0x450bc0 "$DR_EXE"
objdump -d -Mintel --start-address=0x453650 --stop-address=0x453728 "$DR_EXE"
objdump -s --start-address=0x475dec --stop-address=0x475df0 "$DR_EXE"
objdump -d -Mintel --start-address=0x4537d0 --stop-address=0x4538a5 "$DR_EXE"
objdump -d -Mintel --start-address=0x4538b0 --stop-address=0x453a85 "$DR_EXE"
objdump -d -Mintel --start-address=0x456820 --stop-address=0x456887 "$DR_EXE"
objdump -d -Mintel --start-address=0x4507d0 --stop-address=0x450811 "$DR_EXE"
objdump -d -Mintel --start-address=0x460670 --stop-address=0x46067f "$DR_EXE"
objdump -d -Mintel --start-address=0x453a90 --stop-address=0x453b48 "$DR_EXE"
objdump -d -Mintel --start-address=0x451940 --stop-address=0x4519ec "$DR_EXE"
objdump -p "$DR_EXE"
```

Use existing-project `InspectWindowLifecycle.java` queries for 0x4507d0,
0x450800, 0x4519c0, 0x453650, 0x4538b0, 0x456820, 0x4537d0, 0x460670,
0x453a90 and 0x451940, serialized with `-process Drakan.exe -readOnly -noanalysis`.
All completed. Import identities were checked against the PE import table:
IAT 0x4750ac=LeaveCriticalSection, 0x4750c0=WaitForSingleObject,
0x4750dc=EnterCriticalSection; allocation API identities likewise checked.
Decompiler `void`/pointer artifacts were resolved using raw returns and stack
arguments. No external implementation is needed for these conclusions.
