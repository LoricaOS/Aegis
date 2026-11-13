# First native J514s/T6030 diagnostic entry

Date: 2026-11-13 UTC (2026-11-12 local). One owner-observed hardware pass.

## Result

The owner reported:

> yes, it just shows "AEGIS" then freezes, it doesn't shutdown or anything,
> it has the bootloader icon in the middle and "AEGIS" top left.

This is the intended observable result of the entry diagnostic: a small
AEGIS badge over the inherited framebuffer and then a wait loop with
interrupts masked. The remainder of the bootloader artwork is not cleared.

The badge's code path requires reaching C, accepting J514s/T6030 root
identity, parsing a supported simple framebuffer, checking geometry and
image/DTB non-overlap, and drawing into it. This establishes native
diagnostic entry and firmware-framebuffer access on the M3 Pro.

It does **not** establish a full Aegis kernel boot, scheduler, allocator,
MMU setup, exception delivery, timer/AIC, secondary CPUs, user processes,
storage, GPU rendering, networking or suspend. It is one pass, not yet a
repeatability qualification. The final wait-loop PC and in-memory stage/
register report have not been independently read back.

## Artifact identity

| Item | Identity |
| --- | --- |
| Diagnostic Image | 5571 initialized bytes; 546320 bytes declared memory footprint |
| Image SHA256 | `2e7c8c815b5f1433a58fc5dc8e10c0af9da474b8e3bc816a8c807af58a12ef98` |
| m1n1 revision | `ba130ffbeeadaa35215ed88b07ebcee3199d0be7` |
| Raw stage-2 SHA256 | `59550fd89d026b27926ce785ca2390f01381a9aa2f480cd765ff3ce307bec2a0` |
| Staged DTB SHA256 | `d57b0c45d4fbacc332f3c4984d24ed96594a64fc6a5d45f965979b470ea5c743` |
| Combined RAM payload | 4963287 bytes |
| Combined payload SHA256 | `00106ac9cedf34fd250277629639993fd26c29534aea08cbd63a69609353b0a4` |

The run manifest is under ignored
`build/appleprobe/usb-20261113T001928Z-76981/manifest.json`.
Root-owned transport artifacts are intentionally private.

## Transport and failure accounting

`tools/apple-probe-usb.sh` packages the existing pinned stage 2, the known
J514s DTB, two chosen-property config lines, and the raw diagnostic Image.
The Image is zero-padded to its declared memory footprint before concatenation:
this loader's final uncompressed-kernel path copies `image_size`, not the
flat initialized file length.

Config:

```text
chosen.asahi,m3-defaults=0
chosen.bootargs=aegis.appleprobe=1
```

The owner selected the established Fedora USB-debug entry. This was a
temporary RAM chainload, not Fedora Linux booting the diagnostic. No normal
boot selector was replaced, no ESP was mounted, and no partition operation
was performed. No initramfs or biometric policy was supplied to the diagnostic.
The existing loader performs its usual hardware/firmware handoff; the
diagnostic itself initializes no peripheral driver.

The first connected attempt stopped before sending the payload because the
helper incorrectly looked for ADT `target-type` under `/chosen`. A read-only
query confirmed it at the ADT root (`J514s`); the helper was corrected. The
following single chainload passed target identity/video checks and sent the
hash-checked payload. The chainloader parked inherited firmware blobs to
avoid its live-heap overlap rather than overwriting them.

After the vector command, the serial device disconnected. The host capture
was empty and the transport process exited with a SerialException. This is
**not** a captured successful kernel log, and that process's exit code is
not a boot-success signal. The hardware-pass evidence is the owner's
observation of the diagnostic-specific AEGIS badge.

## Next gate

Expand visible diagnostics to show the captured EL/SCTLR/MMFR0 and memory
handoff, and add deliberate fault capture before moving into MMU setup.
Keep interrupts masked until FIQ/IRQ and critical-section semantics are
implemented together. Do not reuse QEMU or Pi 5 peripheral addresses.

Normal DH/Fedora/macOS boot targets remain available after powering off the
halted diagnostic. Repeating the test requires a deliberately armed loader;
do not issue blind proxy retries after the one-shot handoff.
