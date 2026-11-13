# Apple Silicon bring-up: baseline and next hardware gate

## Status

The ARM64 QEMU baseline is reproduced locally. Native diagnostics now cover
entry/console, EL1/4 KiB translation, and reservation-aware memory intake.
An explicit RAM-only bridge has also reached the **real ARM64 kernel's
shared-init checkpoint on J514s/T6030**, with existing per-CPU/PAN/vector/
uaccess setup and a scanned `shared-complete` report. See
`apple-silicon-kernel-bridge.md` for pinned artifacts and qualification limits.
A subsequent **native `memory-complete` checkpoint** initialized the existing
PMM/VMM/KVA on an explicit 8 MiB image-owned arena and passed bounded
allocation/map/write/readback/release checks. See
`apple-silicon-memory-integration.md`. This is not yet a full boot: broad DRAM
ownership, general Apple interrupt/device support and userland are not qualified.
A subsequent **native `timer-complete` checkpoint** delivered one physical-timer
FIQ and returned through the real kernel vectors, with the timer then disabled.
Its host/QEMU evidence and native record are in `apple-silicon-timer.md`.
A subsequent **native `sched-complete` checkpoint** ran two kernel threads
through 32 cooperative yield/resume rounds each, checking integer/FP/TLS
state. See `apple-silicon-scheduler.md` for its native record and limits.
A subsequent **native `preempt-complete` checkpoint** delivered 19 timer FIQs
and resumed two non-yielding threads 10/8 times with integer/FP/TLS checks
passed. See `apple-silicon-preemption.md` for its native record and limits.
A subsequent **native `user-complete` checkpoint** ran a capless ELF at EL0,
completed five real syscalls and verified kernel/RX/NX, capability and bad-pointer
denials. See `apple-silicon-userspace.md` for the native record and session handoff.
Arbitrary kernel preemption, SMP, libc/init and RAM-rootfs boot remain unqualified.
Do not put the QEMU ISO or Pi 5 native image into the Mac's boot path and
expect it to work.

First target: the owner's 14-inch M3 Pro MacBook Pro, J514s/T6030.
Keep one shared ARM64 implementation with separate platform backends.
Do not fork the kernel into an Apple-only implementation.

## Recovered handoff

Source bases:

| Repository | Base |
| --- | --- |
| Aegis | `5e0d385b8b6aa6b8fdda28119e98511d1ee59037` |
| LoricaOS | `b302c30e5cef02d7e7860d84e1745385df3abcce` |
| coreutils dependency | `9858f3634ed71ef841b8ea7b007949262f8d1041` |

The downloaded `apple-silicon-wip` handoff patches were hash-checked before
import. Aegis patch SHA256:
`353e8daff33e73450ed41f78d46ed89a30bbd7a9572abb85b009ae9667baf607`.
LoricaOS patch SHA256:
`fb6d44fbf52a62416b2fbbd47947856cc90d39874a3668366142a19ea16f3b5d`.
The handoff originals were not modified.

Recovered fixes: null-safe boot-time VFS caller checks, ARM64 dup and
process-group syscall translation, regression fixtures, serialized Limine
fetching, shared musl spawn/DNS patches, and a repeatable server-image test.
User processes still pass the original capability/DAC checks.

Local follow-ups:

- The FDT test uses a headless no-default-devices QEMU machine rather than
  accidentally depending on host network-option ROMs. Its temporary paths
  are isolated per run.
- The musl host model selects GNU C11 explicitly. GCC 16 defaults to C23,
  which changes upstream musl 1.2.5's old-style function-pointer semantics.
  This fixes the host test's language mode, not the production spawn code.
- `fdt_root_compatible()` queries only the root's complete compatible list,
  rejects malformed/duplicate root properties, and cannot mistake a child
  device for machine identity. It validates the bounded root property prefix,
  **not** every descendant, memory reservation, or physical MMIO range.
  It is a foundation for platform intake, not a live platform selector.

## Local evidence

The development host is x86-64 CachyOS. No system packages were installed.
Signed Arch packages were downloaded, checked with the host pacman keyring,
and extracted under ignored `build/host-tools/root`. Python dependencies
live in `build/host-tools/venv`.

Versions: AArch64 GCC 16.2.0, binutils 2.47, QEMU 11.1.3,
edk2-aarch64 202608, kconfiglib 14.1.0 and pexpect 4.9.0.
These differ from the original handoff; identical artifact hashes are not
expected. `build/host-tools/packages.urls` records package URLs.

Checks run:

- `make -f Makefile.arm64 iso build/arm64/aegis-arm64-test.iso dist -j8`
- `make -f Makefile.arm64 test` with the local EDK2 image and
  `QEMU_TIMEOUT=60`: 44 syscall/capability passes, forbidden service grants
  refused, VirtIO entropy mixed, and the expected no-init smoke halt.
- `make CC=gcc LD=ld NM=nm OBJCOPY=objcopy test`: x86 capability suite,
  Limine kernel smoke and Multiboot2 kernel smoke passed under QEMU.
  This uses host GCC/binutils, not an x86_64-elf cross compiler.
- `bash tools/test-fdt.sh`: QEMU DTB extraction, crafted-length-overflow
  regression, and root-identity/loader-expansion tests passed.
- `fakeroot bash tools/build-arm64-server.sh`: 80 programs including all
  62 coreutils; no reported skipped programs. fakeroot preserves uid/gid 0
  in the image without granting any runtime authority.
- `python3 tools/test-arm64-server.py --timeout 120`: guest account setup,
  authenticated stsh, `uname -m`, version file and `/bin` listing passed.
- `python3 -B tools/test-musl-aegis.py references/musl-1.2.5.tar.gz`:
  exact-source patch checks, spawn host model and recipe/cache checks passed.

Kernel logs: `build/evidence/arm64-{build,test}.log`,
`build/evidence/x86-{build,test}.log`, `build/evidence/fdt-test.log`.
LoricaOS logs: `build/evidence/arm64-server-{build,test}.log`,
`build/evidence/musl-host-test.log`, `build/arm64-server/qemu-session.log`.

An additional host check fed the root-identity reader the already-staged DH
J514s DTB (91,529 bytes). This is a workstation artifact, not a fresh capture
or hardware test. It must match `apple,j514s`, `apple,t6030`,
`apple,arm-platform`, but not `apple,j516s` or `linux,dummy-virt`.
The tested DTB's SHA256 is
`d57b0c45d4fbacc332f3c4984d24ed96594a64fc6a5d45f965979b470ea5c743`.

## First native milestone

Prefer an isolated, RAM-only diagnostic Image entry adapter using the
existing tested direct-boot transport. Preserve the current DH/Fedora/macOS
boot paths. Do not replace a normal selector or alter partitions for this
milestone.

The Linux ARM64 Image contract is a candidate transport, **not** the current
Aegis entry contract:

- Linux Image: DTB physical pointer in x0, x1–x3 zero, interrupts masked,
  MMU off, and a documented EL1/EL2/cache handoff.
- Aegis Limine: bootloader responses, a higher-half mapping and live
  translation tables. `start.c` currently programs 4 KiB geometry.
- Pi 5 native: board-specific entry and PL011/GIC assumptions. Do not copy
  its UART accesses, CPU-start path or MMIO layout to a Mac.

First diagnostic acceptance: validated J514s/T6030 identity, preserved boot
arguments and memory reservations, a known framebuffer/logging channel,
repeatable visible entry, then a controlled halt. No scheduler, secondary
CPUs, DMA submissions, storage, networking or SEP access.

Before enabling the MMU, determine the actual CPU granule support and the
loader's placement/reservation contract. Do not globally change PAGE_SIZE
because Linux happens to run with 16 KiB pages. GPU UAT geometry is separate.

Before enabling interrupts, implement the Apple timer/FIQ and interrupt
critical-section semantics coherently. The existing vectors hang on FIQ,
and IRQ helpers mask IRQ only. AIC support alone is insufficient.

## Live inventory and next physical gate

Collected a **read-only, allowlisted** live inventory while DH Linux ran:
root model/compatible, RAM banks and reserved ranges, framebuffer range and
format, exported CPU identification, kernel page size, and active-image
metadata. The granule feature registers were not exported through sysfs.
Findings are in `apple-silicon-inventory.md`. The kernel's live OF view can
also contain runtime changes; it is not identical to the loader's original
FDT. Neither is the staged DTB a substitute for the actual handoff.

Do not export the complete raw DT, random seeds, calibration, SEP state,
serial numbers or identity keybags into the repository. A Linux register
snapshot also does not prove what register state our own entry will receive.

The bounded entry diagnostic is built and tested on synthetic QEMU RAM. Its
shared reader accepts the loader-expanded tree size, and recognizes the
boot framebuffer's 10-bit pixel format. It does not initialize the real kernel.
The first physical RAM-only chainload produced the AEGIS badge on the Mac,
confirmed by the owner. It intentionally stops afterward; at that V1 milestone
CPU register values and exception delivery had not yet been read back.
The baseline
stage did not access the Mac; the subsequent inventory used read-only SSH
commands and did not modify boot selectors, mount the DH ESP, or load drivers.

The next diagnostic, V2, adds a readable CPU/memory console and EL1/EL2 fatal
vectors with an independent emergency stack. Its 25 QEMU execution cases pass,
including bad-stack fault reporting. The normal console has now also passed
on the Mac: incoming EL2, MMU/data cache off, with MMFR0 reporting both 4 KiB
and 16 KiB support. V2 did not enable translations; native fatal handling
remains unqualified. See `apple-silicon-console.md`. Begin with a controlled EL1
transition and bounded 4 KiB diagnostic mapping, not an unreviewed call into
the existing Limine initialization path or a global page-size rewrite.

V3 now implements that bounded experiment in a separate build. Five host
table tests and eleven QEMU execution cases pass, including execution above
1 TiB and fatal handling after paging is enabled. The owner confirmed the
native EL1/4 KiB pass/halt screen and corrected root/TCR errors in an
assistant-generated transcription; those two discrepancies are reconciled.
Default V2 builds and hashes remain unchanged; V3 has explicit build targets
and USB-helper modes. See `apple-silicon-translation.md`.

For hardware references, pin exact revisions and inspect per-file licenses.
The Linux tree is not wholesale MIT code. Preserve Aegis's C-only build and
no-ambient-authority model. Respect applicable repository instructions; no
m1n1 implementation was imported or modified during this stage.
