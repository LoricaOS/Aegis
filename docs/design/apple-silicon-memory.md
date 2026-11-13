# Diagnostic V4: reservation-aware memory intake

Status: **host/QEMU qualified; native candidate report reached on J514s/T6030**.
V3 has already demonstrated controlled EL1 and bounded 4 KiB translation on
J514s/T6030. V4 adds a metadata report after that transition, not a general
allocator, full kernel entry, or claim that all Apple memory is understood.

## Rule

`kernel/arch/arm64/boot_memory.c` is a pure, bounded intake function. It reads
the original DTB, including its reservation map, rather than relying on the
legacy peripheral reader's partial/early query results.

It validates the complete v17 structure stream and header/block bounds before
publishing a plan. Supported physical-memory bindings are root memory nodes
with one- or two-cell addresses/sizes, the FDT reservation table, static
`/reserved-memory` children with explicit matching cell counts and empty
`ranges`, and the chosen initrd start/end pair.

- RAM is rounded inward to whole 4 KiB pages.
- Reservations are rounded outward, sorted and unioned.
- The entire image footprint (including tables/stacks), original DTB, boot
  framebuffer and initrd are excluded.
- Static firmware reservations remain excluded even if disabled, reusable,
  or marked `no-map`. Nothing is reclaimed. An explicitly disabled static
  zero-size tuple describes no pages; see the placeholder rule below.
- Active dynamic reservations, translated reserved-memory buses, restrictive
  Linux usable-memory bindings, unsupported widths, overflow, malformed
  metadata and exhausted fixed capacities refuse the plan.
- Failure clears every output except the error code. No partial candidate
  list escapes. An empty candidate list can be a valid successful result.

The result is a **metadata-derived candidate list**, not an authorization to
touch those pages. This is not a complete validator for every possible
device-tree binding. The native handoff's binding coverage, firmware ownership,
loader lifetime, and eventual shared allocator interface still need review.

## Diagnostic

```sh
make -f Makefile.appleprobe memory
make -f Makefile.appleprobe test-memory
```

V4 remains separate under `build/appleprobe-v4/`. Default builds and plain
USB helper modes still select V2. V2/V3 normal images retain their exact
native-tested hashes.

V4 normal Image SHA256 (with bounded context and inactive-placeholder rule;
native report confirmed by the owner's screen capture):
`7404c2c81565159e6546a0814efa350c667ee7ddcfbfb8098ce2d093a47912e3`.

The diagnostic retains V3's narrow mappings, caches off and DAIF masked.
It does not map, read, write, allocate or probe candidate addresses. It
prints byte totals, counts and up to eight half-open candidate ranges.
The full bounded plan remains in image-owned BSS for debugger inspection.

Stages:

| Stage | Meaning |
| --- | --- |
| 8 | Existing EL1/paging self-check completed |
| 9 | Strict memory intake in progress |
| 10 | Candidate report complete; no allocation |
| 11 | Intake refused; error displayed, candidate report cleared |

Both outcomes halt intentionally. A refusal is useful evidence, not reason to
drop an unfamiliar reservation or weaken a bound.

## Bounded failure context

The intake accepts an optional, separate `boot_memory_failure` output.
The plan layout and fail-closed clearing rule are unchanged. This 40-byte
diagnostic record contains four u32 values (source, reason, DTB byte offset,
tuple index), followed by three u64 values (raw base, raw size, exclusive
physical limit). These are rejected input values, never usable ranges.

It is cleared on entry and remains zero on success or non-range/non-capacity
errors. On a range/request/capacity refusal it records only the first failed
check, before normalization. No DTB strings, unbounded copies, dereferences
through decoded addresses, or allocation are involved.

| Source ID | Input |
| --- | --- |
| 1 | Invalid request physical limit |
| 2 | FDT memreserve entry |
| 3 | Root memory `reg` tuple |
| 4 | Static reserved-memory `reg` tuple |
| 5 | Chosen initrd range |
| 6 | Image footprint |
| 7 | Original DTB footprint |
| 8 | Boot framebuffer footprint |
| 9 | Derived candidate (capacity error context) |

| Reason ID | Failed check |
| --- | --- |
| 1 | Zero size |
| 2 | Base at or above physical limit |
| 3 | Size exceeds `limit - base` |
| 4 | Fixed range-array capacity exhausted |
| 5 | Invalid request field/limit |

Offsets identify the original DTB byte containing the tuple's address
(or initrd-start value). Request/derived offsets are zero. Indices are
zero-based tuples within a `reg`, entries within the reservation map, or
the bank index for derived candidates. The framebuffer console prints all
seven fields on refusal; the same fixed record remains in image-owned BSS
as `apple_probe_memory_failure`. Passing a null diagnostic output produces
the identical acceptance decision and complete plan.

## Inactive static placeholders

The pinned loader input DTB contains `/reserved-memory/uat-handoff@30` with
`reg = <0 0x30 0 0>` and `status = "disabled"` (and other inactive UAT
placeholders). A zero-size inactive tuple names no physical pages; treating
it as an allocatable range or rounding it outward would both be wrong.

The intake now consumes a zero-size static `reg` tuple without appending
anything **only** if the node or an ancestor is explicitly `disabled` and
the raw base is below the validated physical limit. Full property length,
cell-width and structural validation still applies. Every nonempty tuple
in the same node is reserved as before. This rule is binding-based, not a
GPU/node-name allowlist.

Absent/active/unknown status does not permit an empty tuple. Empty RAM
banks, nonterminal memreserve entries with zero size, active dynamic
reservations, malformed `reg` values and out-of-range bases still refuse
the plan. Disabled nonempty firmware reservations are never reclaimed.

## Validation

- `test/boot_memory_test.py`: 22 host methods compile the real C intake with
  warnings as errors. Fixtures cover independent page-set subtraction,
  200 deterministic randomized models, high addresses, overlap/rounding,
  complete reservation-table placement, initrd/static exclusions, unsupported
  bindings, malformed headers/tree and fail-closed capacity errors.
  Every parse also checks that omitting diagnostics gives the identical plan.
  New cases check every range source, original offsets/tuple indices, raw
  values, request errors and reason precedence without leaking partial plans.
  Placeholder tests cover both cell widths, mixed empty/nonempty tuples,
  disabled ancestors, unrelated disabled siblings, active/unknown statuses,
  malformed values, out-of-range bases and unchanged nonempty exclusions.
- `test/apple_memory_test.py`: eleven actual QEMU executions after EL1/paging:
  successful reports and dynamic-reservation refusal from incoming EL1/EL2,
  range refusal with exact binary/console failure context from EL1/EL2, plus
  a successful load above 1 TiB. An independent interval-subtraction oracle
  checks the actual guest report. Pixel guards remain checked.
  The matching base-`0x30` empty tuple succeeds when disabled and refuses with
  source 4/reason 1 when enabled, from both incoming EL1 and EL2.
- Existing V2 25-case and V3 11-case execution suites and five mapper host
  methods pass again. V2/V3 Image SHA256 values remain unchanged.
- The resident-debug transport's six host tests and QEMU EL1 execution also
  pass again; its native-tested image hash is unchanged.

Evidence for the added context: `build/evidence/apple-memory-failure-test.log`
and `build/evidence/apple-failure-regression.log`. Placeholder-rule evidence:
`build/evidence/apple-memory-placeholder-test.log` and
`build/evidence/apple-placeholder-regression.log`.
The full-kernel ARM64/x86 and Lorica boot suites were not rerun for this
standalone diagnostic change; the new intake is not wired into their builds.

## Native result and next check

The one-shot native V4 run in
`build/appleprobe-v4/usb-20261113T022854Z-83417` reached the display and
reported: **“refused - invalid range. no candidates - no allocator.
halted - mmu on caches off daif masked.”**
That run used the previous Image SHA256
`802c9829296e299f8f1ce6bb2bca72647d93cd2607d1dc7bedf584aeabdcb708`,
which did not include detailed failure context.

That was a fail-closed refusal, not successful native memory qualification.
That image did not identify the failed range. A later context-enabled run
identified the rejected tuple below; neither run authorized removing a
nonempty reservation or relaxing a physical bound.
The separate resident-m1n1 USB transport test in `apple-silicon-debug.md`
has passed, but did not rerun or fix V4. Failure context was then prepared,
offline tested and used in the subsequent native run below.
It remains a one-way native diagnostic, not a resident USB-logging guest.

The subsequent context-enabled native run
`build/appleprobe-v4/usb-20261113T034016Z-86229`, using Image SHA256
`3cb9653ef77258dd9bee972fedfad8b2d6db1851174b0da79be2c300c7147a7c`,
also refused. The owner reported source 4, reason 1, DTB byte offset `0x277c`,
tuple index 0, raw base `0x30`, and size 0. The owner corrected the initially
abbreviated physical limit to include its nonzero `4`; this is consistent
with the expected exclusive 42-bit limit `0x0000040000000000`, not zero.
The unchanged raw tuple in the pinned input DTB strongly identifies the
inactive UAT placeholder above; the exact post-loader native node/status
was not captured over USB. Native USB loss after vectoring remains expected.

The next native run, `build/appleprobe-v4/usb-20261113T034603Z-87390`,
used Image SHA256
`7404c2c81565159e6546a0814efa350c667ee7ddcfbfb8098ce2d093a47912e3`.
The owner's screen capture confirms a completed V4 candidate report with
eight candidate ranges, followed by:

```
CANDIDATES ONLY - NO ALLOCATOR OR RECLAIM
HALTED - MMU ON / CACHES OFF / DAIF MASKED
```

This is native success for report-only metadata intake after the inactive
placeholder change. It is not physical validation of candidate pages,
firmware-ownership/lifetime qualification, or permission to allocate/reclaim
them. The final result is evidenced by the screen capture, not USB: the
host capture again ended on the expected serial disconnect after vectoring.
No complete native plan/DTB readback or native allocation test was performed.
No automatic retry, allocator activation, or reservation reclamation followed.

Use explicit `--check-v4` for offline payload preparation. It performs no target
requests. Only `--arm-v4` can wait for and send the one-shot RAM payload.
The existing identity, pinned source/artifact hashes, global boot lock,
padding and single-chainload checks remain enforced.

Coordinate power-off and arm before asking the owner to select the existing
Fedora USB-debug path. Do not modify the DH/Fedora selectors or installed
images. Capture the V4 totals/ranges or the exact refusal reason from the
display. USB disconnection after vectoring is not a native result by itself.
