# Diagnostic V3: controlled EL1 and bounded 4 KiB translation

Status: **host/QEMU tests pass; native normal EL1/4 KiB paging pass confirmed
by the owner. Root/TCR transcription discrepancies are reconciled below**.
The V2 native result established incoming EL2, SCTLR.M/C/I clear, and CPU
support for both 4 KiB and 16 KiB stage-1 granules. This justifies a small
4 KiB experiment, not a final Apple GPU/DMA or global PAGE_SIZE decision.

## Build and qualification boundary

```sh
make -f Makefile.appleprobe translation
make -f Makefile.appleprobe test-translation
```

Artifacts are separate under `build/appleprobe-v3/`. The default
`make -f Makefile.appleprobe` still builds V2. Its normal image remains
byte-for-byte equal to native-tested SHA256
`76a935a8383383c711ed9c96e845700f1f8e075d3da0982a758d050572723d11`.
V1/V2 images and their hardware-run manifests remain preserved.

V3 normal Image:

- SHA256 `b0d2fa25c244bc3fa88a3e22064bfe2ef45827208ba62e9dc926bc8439fa0490`.
- 18951 initialized bytes, 790528 bytes declared runtime footprint.
- Linux Image flags declare 4 KiB pages; 2 MiB-aligned relocation is retained.
- No runtime ELF relocations, unresolved symbols, GOT, or general RAM allocator.

These are build identities. The native result and its evidence limitations
are recorded below. No boot selector or installed image was changed.

## Transition

The existing MMU-off admission and normal console run first. V3 then preserves
its request in image-owned data, clears the visible panel for phase output,
and enters a controlled EL1 environment:

- An incoming EL1 proceeds directly, after checking its off-state contract.
- An incoming EL2 sets HCR.RW, clears VHE/stage-2 translation, initializes
  architectural EL1 control/stack/vector state, and ERETs to EL1h with DAIF
  masked. The inherited EL2 fatal table remains available if a trap routes up.
- No GIC/AIC or implementation-specific CPU register is accessed.
- EL1 SCTLR state is shown before activation. IRQ/FIQ are not enabled.

This is a diagnostic entry adapter, not a call into the existing Limine entry,
not the real kernel's trap/VM initialization, and not a second Apple-only OS.

## Mapping rule

The pure C builder uses a fixed pool of 48 table pages (192 KiB) **inside the
loaded image's writable data**. It creates only 4 KiB leaves for these ranges:

| Range | Attribute / EL1 permission |
| --- | --- |
| Diagnostic text and vectors | Normal noncacheable, read-only, executable |
| Diagnostic rodata | Normal noncacheable, read-only, execute-never |
| Diagnostic data, tables, and both stacks | Normal noncacheable, read/write, execute-never |
| DTB | Normal noncacheable, read-only, execute-never |
| Boot framebuffer | Device-nGnRnE, read/write, execute-never |

All leaves deny EL0 access and are UXN. No block mapping, whole-RAM mapping,
QEMU device address fallback, firmware reclamation or user process exists.
The byte ranges are rounded to page boundaries and checked for conflicts.
Neighbouring bytes in those same pages are necessarily covered; drawing
still stays inside the validated framebuffer geometry. The loader must own
the payload footprint and supply a valid framebuffer/DTB handoff. This is
not yet a complete reserved-memory validation/subtraction implementation.

The builder rejects unknown granule/PA encodings, unaligned section or pool
bounds, a pool outside RW image data, range overflow, unsupported sizes and
page-rounded overlaps. A failed/partial build leaves result.root zero and
is never activated.

TCR uses 48-bit TTBR0 VAs, the CPU's supported IPS (up to 48-bit descriptors),
4 KiB tables, noncacheable walks and disabled TTBR1. MAIR is `0x44`:
Attr0 normal NC and Attr1 Device-nGnRnE. The data cache stays off throughout;
instruction cache is disabled/invalidated before enabling translations.
DSB/ISB/TLBI sequencing precedes SCTLR.M.

After activation the diagnostic reads back SCTLR, TTBR0, TCR and MAIR, checks
them against the intended state, then performs architectural AT probes:

- Code read resolves to its identity PA; code write is denied.
- Table/data write resolves to its identity PA.
- DTB read resolves; DTB write is denied.
- Framebuffer write resolves.
- VA zero is unmapped.

Only after these checks does it print the final pass/halt and set stage 8.
Caches and interrupts remain off/masked. No exception-recovery path is added.

## Evidence

`test/apple_mmu_test.py`: five host methods compile and inspect the actual C
builder. Independent software walks verify the exact leaves, attributes,
absence of extra mappings, table counts, high physical addresses with a
42-bit native-like PA limit, maximum declared sizes, stale-map removal, and
invalid-input rejection.

`test/apple_translation_test.py`: eleven QEMU execution cases:

- Incoming EL1 and EL2, two low load bases, both framebuffer formats.
- Normal execution, intentional unmapped reads, and intentional NX execution.
- The same paths above 1 TiB, including native-sized framebuffer geometry.

The high-address test uses anonymous, demand-backed QEMU RAM with
`reserve=off`, not preallocated terabytes, ACPI hotplug, or firmware execution.
It tests code/stack/table/DTB/framebuffer addresses above 1 TiB, **not** Apple's
memory controller or display processor.

Tests read actual guest state and independently walk every installed table.
They assert exact mapped-page coverage and permissions, actual AT/readback
results, and fatal registers after paging is live. Negative variants check
translation-fault FAR/PC for zero reads and instruction permission faults
when branching into an RW/XN table page. These deliberately faulting variants
are separate artifacts and cannot pass the normal USB helper hash check.

The V2 25-case execution suite and seven FDT host methods also pass unchanged.
The full-kernel ARM64/x86 suites were not rerun for these diagnostic-only
files; no shared kernel VM source was modified.

Logs: `build/evidence/appleprobe-v3-test.log` and
`build/evidence/appleprobe-v2-test.log`. The normal high-address pixel preview
is `build/appleprobe-v3/translation-preview.png` (QEMU, not a Mac photo).

## Physical test

The helper requires explicit `--check-v3` / `--arm-v3` modes. Plain `--check`
and `--arm` still select V2. Only the qualified normal V3 hash is admitted;
the Image is padded to its declared footprint before RAM chainloading.

Keep the established recovery entries and debug cable. Arm before asking
the owner to enter the Fedora USB-debug path; do not replace an ESP selector
or initiate a reboot while the owner is using DH.

Hardware acceptance requires `EL1 READY`, control-register readback,
the AT checks, and `HALTED - MMU ON / CACHES OFF / DAIF MASKED`. A native
fatal report is a separate result to investigate, not permission to retry
blindly or weaken the mapping rule. Future steps include native trap/FIQ/AIC
qualification, validated free-memory intake and eventual shared-kernel entry.

## First native V3 observation

The owner supplied an assistant-generated transcription from another thread,
then directly checked disputed fields on the screen. The reported success
sequence was:

```text
ENTERING CONTROLLED EL1 STATE
EL1 READY - DAIF STILL MASKED
ENABLING 4K IDENTITY MAP - CACHES OFF
PASS - EL1 / 4K / RO CODE AND DTB
PASS - ZERO VA UNMAPPED
NO ALLOCATOR - RESERVATIONS NOT RECLAIMED
HALTED - MMU ON / CACHES OFF / DAIF MASKED
```

Run manifest:
`build/appleprobe-v3/usb-20261113T014300Z-81337/manifest.json`.
It identifies the normal Image above, 790528 bytes of declared image memory,
and a 5207495-byte combined RAM payload with SHA256
`d59a73edfe63e0eb01acd16d60dc9be91f97f9536687acb4a3745a9496cd50ef`.

This is an **owner-reported native success-path pass**, including the EL1
transition and the enabled-translation readback/AT predicates required by the
final pass line. It is not a full kernel boot, general allocator, cache-on
qualification, native interrupt test or intentionally induced native fault.
The stopped PC and report have not been independently read back.

The original transcription had discrepancies:

- `ROOT=0x0000100076880000` does not match the PA page extracted from the
  supplied `DATA WRITE PAR=0x4400010007688b00` (`0x10007688000`).
  They cannot both be exact if the diagnostic's identity check passed.
- The supplied TCR is `0x380903510`, while this build constructs
  `0x380903010` for IPS=3 and requires exact readback equality before
  printing its pass line. The discrepancy is in the walk-cache fields.
- Some other addresses/header text also differ from fixed formatter output.

The owner subsequently confirmed that ROOT ends in `8000`, not the extra-zero
ending in the transcription, that DATA WRITE PAR appears correct, and that
TCR AFTER is `0x...380903010`. The two checks therefore reconcile:

- Masking attribute/status bits from `DATA WRITE PAR=0x4400010007688b00`
  yields normalized root PA `0x0000010007688000`, consistent with the owner's
  root-ending correction. This full normalization is derived from PAR plus
  the correction, not a claim that every digit was independently re-read.
- Confirmed TCR AFTER `0x0000000380903010` matches the builder's requested
  noncacheable-walk value for IPS=3.

No repeated photo/OCR pass is required to establish this normal-path
milestone. The remaining transcribed values are not all independently
verified, and no stopped-PC or full RAM-report readback was performed.
No MMU constants, addresses or cache settings were changed to accommodate
the initial transcription. Every new payload must still derive its actual
ranges and CPU capabilities at boot.

The host transport disconnected immediately after vectoring and returned a
SerialException, as in the earlier runs. That exit code/capture is not the
hardware-success evidence; the owner's visible console report is.
