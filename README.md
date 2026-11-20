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

You don't need a specific Linux distribution. Use GNU Make 4.3 or later,
GCC and GNU binutils for the target, and NASM for x86. The build prefers
`x86_64-elf-*` for x86 and `aarch64-linux-gnu-*` (then `aarch64-elf-*`) for
ARM64. If no cross compiler is present, it uses the native tools on Linux
when the host matches the target. On macOS, use `gmake` and an ELF
cross-toolchain. Override with `CROSS_COMPILE=<prefix>` (empty for native
tools) or set `CC`, `LD`, `OBJCOPY`, and `NM` on the make command line.

Configuration uses `kconf` if installed. Otherwise, install the public Python
package `kconfiglib` once and point make at that interpreter:

```sh
python3 -m venv .venv-kconfig
.venv-kconfig/bin/python -m pip install kconfiglib
make PYTHON=.venv-kconfig/bin/python
```

Use the same `PYTHON=...` for subsequent commands or activate the environment.
Neither Python nor pip is required when using `kconf`; no Rust toolchain is
required in either case.

ISO targets also need `xorriso` and Git (to fetch pinned Limine on first use).
Boot tests need QEMU and e2fsprogs (`mke2fs` and `debugfs` on `PATH`); ARM64
QEMU tests also need AAVMF/EDK2 firmware (`QEMU_EFI` if it isn't installed
at a default location). The x86 test scripts use GNU `timeout` for some
optional test targets.

```
make                     # build/aegis.elf  (x86-64)
make iso                 # build/aegis.iso  (kernel-only, bootable via Limine)
make test                # capability suite + Limine and Multiboot2 smoke boots
make version             # print the version (from the VERSION file)
make clean

make -f Makefile.arm64        # the aarch64 aegis.elf (QEMU virt / UEFI)
make -f Makefile.pi5native    # the firmware-direct image for a real Raspberry Pi 5
```

### Tested x86-64 toolchains

Clean builds passed `make test` (the capability suite and both smoke boots)
under QEMU/TCG with these native Linux GCC versions:

| Build host | GCC | QEMU |
| --- | --- | --- |
| Debian 13 | 14.2.0 | 10.0.13 |
| CachyOS | 15.3.0 | 11.1.3 |
| CachyOS | 16.2.1 | 11.1.3 |

These are tested combinations, not minimum requirements or KVM results.

For a local release check, repeat `make test` in clean checkouts on a stable
and a rolling Linux host. Record `gcc --version`, `ld --version`, and
`qemu-system-x86_64 --version`. This uses no CI minutes. When diagnosing a
boot-test difference, keep the ISO fixed and compare accelerators separately
from the build toolchain. Use a clean build when switching compiler or flags.

The kernel version comes from `VERSION`, not Git.

## Scheduler

Aegis uses the same equal-weight, virtual-runtime fair scheduler on x86-64 and
arm64. It balances runnable work across per-CPU queues while preferring a task's
last CPU for cache locality. The previous round-robin scheduler remains
available for comparison and recovery with the `sched=rr` kernel command-line
option; the active policy is reported by `/proc/scheduler`.

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
