# J514s/T6030 entry diagnostic V2 — not a native kernel port

For the new, separately built **V3 EL1/4 KiB translation experiment**, see
`docs/design/apple-silicon-translation.md`. Its normal paging path passed
on the Mac; owner-checked root/TCR corrections reconcile the initial
transcription. Native fatal handling remains unqualified.
Default build/USB modes still select native-tested V2;
`translation` / `test-translation` and `--check-v3` / `--arm-v3` are explicit.

The separate **V4 report-only memory intake** is documented in
`docs/design/apple-silicon-memory.md`. Host/QEMU tests pass; its Mac run is
still pending. Use `memory` / `test-memory` and explicit `--check-v4` /
`--arm-v4`; candidate ranges are not allocated or reclaimed.

`make -f Makefile.appleprobe` builds `build/appleprobe/Image` and a symbolized
`probe.elf`. This is a RAM-only diagnostic adapter, not an Apple-only copy
of the kernel, a bootloader installer, or a runnable LoricaOS image.

The default kernel builds do not link these files. Shared FDT intake is reused
from `../fdt.c`; no firmware implementation or Linux driver was imported.

## Contract and behavior

- Linux ARM64 Image header; little-endian, unspecified translation granule.
- A 2 MiB-aligned physical load base, x0 pointing to an 8-byte-aligned DTB
  in readable RAM, EL1 or EL2, MMU and data cache off.
- No MMU/cache transitions. If the incoming state is outside this contract,
  the entry stops before setting up a stack or touching display memory.
- The loader must reserve the entire header `image_size` (including BSS,
  parser buffer and separate 16 KiB normal/fatal stacks), load the Image without DTB/framebuffer/
  firmware overlap, and provide the usual executable cache coherency.
- PC-relative code/data references; the link rejects a GOT, and the final ELF
  has no runtime relocations or unresolved symbols. Tests execute at two
  different physical load bases.
- The entry masks DAIF and does not change exception level. It records EL,
  SCTLR, MMFR0 and DTB address in `apple_probe_report`.
- Only root identities containing both `apple,j514s` and `apple,t6030`
  proceed. No generic QEMU/Pi peripheral fallback is invoked.
- A single simple-framebuffer with supported XRGB8888 or XRGB2101010
  geometry is required. Address overflow, alignment, pitch, bounded dimensions,
  capacity, disabled status, duplicate framebuffers and overlap with the
  loaded image or DTB cause a stop.
- A clipped black/white diagnostic console is drawn at (16,16), at most
  1400 × 1100 pixels; the rest of the framebuffer is untouched. It uses
  original 5x7 glyphs, with 24 × 32 cells on the native-sized screen.
- The report shows EL, SCTLR, MMFR0, raw CPU granule fields, image/DTB ranges,
  framebuffer geometry and up to 16 advertised RAM banks. These are **not**
  free-memory ranges; reservations remain unreclaimed and no allocator runs.
- A matching EL1/EL2 vector table is installed before C entry. All slots are
  fatal, with syndrome/PC/address/saved-state/interrupted-SP capture and a
  separate emergency stack. There is no exception return. IRQ/FIQ stay masked.
- Fatal text replaces the console panel, preserving the RAM transcript.
  A fault before console initialization has only a RAM report. A second fault
  during reporting stops without recursively trying to render again.
- Then the CPU waits with interrupts masked. This is not a shutdown or return
  to the loader. A firmware watchdog, if still active, could reset the machine.

No allocator or DMA submission runs. Firmware reservations are not reclaimed.
The memory-map/CPU/timer/AIC/PAN/capability initialization required for the real
kernel remains separate work.

The shared reader currently captures at most 512 KiB of meaningful FDT
structure/strings, even if the header includes a larger padded total size.
An oversized meaningful tree is rejected; this diagnostic does not silently
truncate it.

Failure stages (inspect via a debugger if the screen stays unchanged):

| stage | meaning |
| --- | --- |
| 0 | C entry not reached |
| 1 | C entry and register capture |
| 2 | FDT captured |
| 3 | J514s/T6030 identity accepted |
| 4 | framebuffer validated and nonoverlapping |
| 5 | normal console report complete and stores synchronized |
| 255 | fatal report completed; no exception return |

## Evidence

`make -f Makefile.appleprobe test` runs a headless QEMU machine with no disks
or network. A **test-only** loader stub supplies x0 and deliberately forged
J514s identity in a synthetic DTB. It is not an Apple emulator.

The success cases check text readback, glyph rendering, pixel values and
all bytes outside a guarded console panel for two load addresses, two formats
and the live 3024 × 1890 boot geometry. The test has 25 execution cases.
Rejected inputs require no arena changes for
wrong identity, unsupported format, image overlap, zero/oversized dimensions,
short/misaligned stride, insufficient capacity, disabled/duplicate framebuffer,
zero base and address overflow. Separate test images deliberately raise BRK,
an address-size data abort, and BRK with SP=0, at both EL1 and EL2. Tests assert
the actual vector, syndrome, exception PC, saved state and interrupted SP.
Normal hardware images inject no fault.

These establish code execution, relocation and bounded framebuffer writes in
QEMU. **V1 passed one native Mac entry test by owner-visible confirmation**;
see `docs/design/apple-silicon-native-entry.md` for the exact evidence boundary.
**The normal V2 console now also passed on the Mac.** Its fatal-exception
path has only been tested in QEMU; see `docs/design/apple-silicon-console.md`
for the transcribed hardware report and remaining boundary.
Before repeating hardware testing, review the direct-loader contract and RAM
placement, ensure its DTB still declares the boot framebuffer, and arrange a
known recovery path. Do
not substitute the active desktop display mode or a previous boot's addresses.
Do not overwrite DH/Fedora/macOS boot selectors to try this artifact.

Current V2 artifact: 14199 initialized bytes, header `image_size` 579984 bytes.
SHA256:
`76a935a8383383c711ed9c96e845700f1f8e075d3da0982a758d050572723d11`.
These numbers identify this build, not a promise of cross-toolchain
bit-for-bit reproducibility.
