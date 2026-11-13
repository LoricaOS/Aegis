# Native diagnostic V2: console and fatal vectors

Status: **25 QEMU execution cases pass; normal V2 console confirmed on the
native Mac. Fatal-exception handling remains QEMU-validated only.**
V1's native badge pass remains recorded separately in
`apple-silicon-native-entry.md`. Nothing in this document upgrades that
hardware result to a full kernel boot.

## Scope

V2 retains the same Linux ARM64 Image transport, exact J514s/T6030 admission,
MMU/data-cache-off requirements, and bounded simplefb intake. It does not
initialize any peripheral driver, enable interrupts or translations, allocate
free RAM, or reclaim a firmware reservation.

The console prints:

- Incoming exception level, SCTLR and MMFR0.
- Raw TGran4/TGran16/TGran64 fields, without selecting a CPU page size.
- Image base/footprint, DTB address/size, and framebuffer base/pitch/geometry.
- Advertised memory banks, explicitly labeled **not free-memory ranges**.

Only a top-left panel is cleared. Text clips at the panel boundary; it does
not scroll or touch the rest of the firmware framebuffer. A bounded,
append-only 8192-byte RAM transcript is available at
`apple_probe_console_text`; this is not a persistent log or a USB service.

The memory-bank list uses the existing FDT reader for diagnostics only.
Its result must not be used as an allocator-ready memory map. Complete
reservation validation/subtraction remains future work.

## Fatal path

After BSS and the normal stack are initialized, the entry installs a
2048-byte-aligned vector table into VBAR_EL1 or VBAR_EL2 to match CurrentEL.
Every slot reports fatally. No slot returns or attempts to skip a faulting
instruction. DAIF remains masked throughout.

The assembly stub captures the original SP without writing through it, uses
a separate 16 KiB emergency stack, and passes vector index, ESR, ELR, FAR,
SPSR, original SP and current EL to C. A reentry flag stops a second fault
from recursively invoking the renderer.

The fatal console replaces the panel with register values and the boot stage.
FAR is explicitly marked potentially stale for non-address faults. A fault
before framebuffer initialization is only observable in the RAM report;
faults before our vector table is installed still cannot be diagnosed here.
If rendering itself faults, the stub stops rather than promise visible text.

This is a diagnostic stop path, not the shared kernel's future trap/interrupt
implementation, and not an exception-recovery mechanism.

## Validation

`make -f Makefile.appleprobe test` builds the normal image and **separate**
BRK, data-abort and bad-SP images in distinct build directories. Only the
normal image's exact hash is admitted by `tools/apple-probe-usb.sh`.

The 25 synthetic QEMU cases cover:

- Normal relocated entry at two physical bases, both framebuffer formats,
  native-sized geometry, and normal entry at EL1 and EL2.
- Rejection without pixel changes for wrong platform identity, unknown format,
  image overlap, invalid dimensions/pitch/capacity, disabled/duplicate
  framebuffer, zero base and address overflow.
- BRK #0x41 at EL1 and EL2: vector 4, BRK exception class, exact exception PC
  and immediate, saved DAIF, original stack pointer.
- An address-size data abort at EL1 and EL2: exact exception PC and FAR.
- BRK #0x43 with interrupted SP=0 at EL1 and EL2: successful fatal reporting
  proves the handler did not require a valid interrupted stack.
- A native-sized EL2 fatal-rendering case.

Checks read the guest's actual report and text buffers and pixel arena,
including guard bytes, not just host process exit codes. Real-pixel previews
are generated as `build/appleprobe/console-preview.png` and
`build/appleprobe/fault-preview.png`. These are QEMU images, not Mac photos.
The synthetic DTB includes a high-address bank only to test formatting;
QEMU is not emulating Apple's memory controller or display processor.

The production ELF has no runtime relocations or unresolved symbols, and
the linker enforces vector alignment/size and rejects a GOT. The loader
continues to package the raw Image with explicit BSS/stack zero padding.

V2 normal Image SHA256:
`76a935a8383383c711ed9c96e845700f1f8e075d3da0982a758d050572723d11`.
Initialized length 14199 bytes; declared memory footprint 579984 bytes.
The prior native-tested V1 image and ELF were preserved in
`build/appleprobe-v1/`; the original hardware run payload/manifest also remain.

No full-kernel source was changed for V2: the new code is linked only by
`Makefile.appleprobe`. Kernel capability/smoke suites were not rerun for these
diagnostic-only changes. The seven FDT host regression methods still pass.

## Native normal-entry result

The owner transcribed the V2 console after the one-shot run
`build/appleprobe/usb-20261113T010753Z-78811/`. Its manifest identifies the
normal Image hash above and combined RAM payload SHA256
`c1218b67ec57f7a777901e543fbc8235117e73b9ab85c8578becd8eab723230f`.
The console reached `HALTED - MMU OFF / DAIF MASKED`, not a fatal report.
This confirms the native normal path, register reads, console and RAM-bank
display. It does not validate native fault delivery or an enabled MMU.

| Field | Owner-reported value |
| --- | --- |
| EL | 2 |
| SCTLR | `0x0000000030900180` |
| MMFR0 | `0x110012120f100003` |
| TGran4 / TGran16 / TGran64 | `0` / `1` / `0xf` |
| Image base | `0x0000010007c00000` |
| Image footprint | `0x8d990` = 579984 bytes |
| DTB base | `0x0000010007c90000` |
| DTB size | `0x3217a` = 205178 bytes |
| Framebuffer stride | `0x2f40` = 12096 bytes |
| Framebuffer dimensions / format | 3024 × 1890 / X2R10G10B10 |
| Main advertised RAM bank | base `0x10001fac000`, size `0x459488000` |
| Additional advertised bank | base `0x1045b464000`, size `0x4000` |

SCTLR.M, C and I are all clear. Architectural MMFR0 decoding reports 4 KiB
and 16 KiB stage-1 translation support, no 64 KiB support, and PARange=3
(42-bit physical addresses). CPU support alone does not select the final
platform VM layout or establish GPU/DMA compatibility.

The image ends at `0x10007c8d990`; the DTB starts `0x2670` bytes later and
ends at `0x10007cc217a`. These two reported allocations do not overlap.
The actual DTB again exceeds the old 128 KiB reader limit.

The manually supplied framebuffer-base line was
`FB BASE=0X000001646002880`, which has only 15 hexadecimal digits whereas
the formatter always prints 16. Treat it as an unresolved transcription
discrepancy, **not** a canonical address or a value to hardcode into mappings.
Each payload must read the actual framebuffer address from its own DTB.

## Next gate

Use the normal V2 candidate, not an intentionally faulting test image.
Repeat a one-shot RAM chainload only after the owner is ready and the helper
is armed. Native exception handling still needs its own qualification;
normal entry is not evidence of fault delivery.

Do not implement a 4 KiB or 16 KiB MMU setup from the QEMU values in these
previews. The native feature fields now justify an initial **4 KiB diagnostic
translation test**, reusing the existing architecture's geometry without
globally changing PAGE_SIZE. That is not the final Apple GPU memory decision.

Keep the next transitions individually observable: establish controlled EL1
state from the incoming EL2, then test a narrowly bounded identity map for
the diagnostic, its stacks/tables, DTB and framebuffer. No whole-RAM cacheable
mapping, allocator, reservation reclamation, peripheral fallback, or interrupt
unmasking belongs in that first test. Reuse the fatal console and verify
cache attributes and maintenance at each handoff.
