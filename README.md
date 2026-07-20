# Aegis

A clean-slate, capability-based, POSIX-compatible kernel for **x86-64 and
arm64**. Written entirely in C. On arm64 it runs on QEMU virt and boots
natively on the Raspberry Pi 5.

Aegis enforces a security model with **no ambient authority** — no process,
including root, holds power it was not explicitly granted. `uid=0` is cosmetic;
authority comes only from unforgeable capability tokens validated at the syscall
boundary.

Aegis is **just the kernel**. It embeds no userland: at boot it mounts the root
filesystem the bootloader/OS provides and execs `/bin/vigil` as init (panicking
"no init found" if there is none, exactly like Linux). An operating system built
on Aegis supplies its own userland, root filesystem, and boot image — see
[LoricaOS](https://github.com/LoricaOS/LoricaOS) for the reference OS.

## Build

Requires an `x86_64-elf` cross toolchain (gcc/ld/objcopy/nm) and `nasm`, or an
`aarch64-linux-gnu-*` toolchain for the arm64 build; and — for the smoke-test
ISO — `xorriso` plus the vendored Limine in `tools/`. No Rust toolchain is
needed: the kernel, capability core included, builds with a C cross-compiler
alone (a prerequisite for LoricaOS self-hosting).

```
make                     # build/aegis.elf  (x86-64)
make iso                 # build/aegis.iso  (kernel-only, bootable via Limine)
make test                # boot the kernel alone; expect the "no init found" panic
make version             # print the version (from the VERSION file)
make clean

make -f Makefile.arm64        # the aarch64 aegis.elf (QEMU virt / UEFI)
make -f Makefile.pi5native    # the firmware-direct image for a real Raspberry Pi 5
```

The version is the single value in `VERSION` — stamped into the kernel, not
derived from git, so builds are reproducible anywhere.

## Releases

Each tagged version publishes a stripped `aegis.elf`. An OS targeting Aegis
fetches the kernel image for the version it wants; kernel and OS versions are
independent by design.

## Architecture

- `kernel/arch/x86_64` — boot, IDT/GDT/TSS, LAPIC/IOAPIC, SMP, paging
- `kernel/arch/arm64` — EL2→EL1 boot (Limine + native Pi 5), GICv2/v3, timer,
  PSCI SMP, device-tree reader, Pi 5 drivers (RP1, Broadcom PCIe, VideoCore)
- `kernel/core`, `kernel/mm`, `kernel/sched`, `kernel/proc`, `kernel/signal`
- `kernel/cap` — capability subsystem (plain C; migrated from an earlier `no_std` Rust core)
- `kernel/syscall` — POSIX-ish syscall dispatch
- `kernel/fs` — VFS, ext2, ramfs, procfs, initrd, pipes, memfd
- `kernel/tty`, `kernel/drivers`, `kernel/net`
