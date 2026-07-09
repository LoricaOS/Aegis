# Contributing to Aegis

Aegis is a standalone, clean-slate x86-64 / arm64 kernel — just the kernel. It embeds
no userland: at boot it mounts the root filesystem the bootloader/OS provides and
execs `/bin/vigil` as init (panicking "no init found" if there is none, like Linux). It
publishes a versioned `aegis.elf` that an OS consumes; the reference OS is
[LoricaOS](https://github.com/LoricaOS/LoricaOS).

Thanks for wanting to help. A few things make this codebase what it is — please read
them before opening a PR.

## The one rule that overrides everything: never weaken the security model

Aegis enforces **no ambient authority** (see [SECURITY.md](SECURITY.md)). Authority
comes only from unforgeable capability tokens validated at the syscall boundary.

Any change that lets a process act without a capability it was granted — or that makes a
capability ambient, inheritable-by-default, or forgeable — will be rejected, however
convenient it is. **When in doubt, fail closed** (`ENOCAP` / `EFAULT`). A new syscall
validates its capabilities before doing anything observable.

## Build & test

You need an `x86_64-elf` cross toolchain (gcc/ld/objcopy/nm) + `nasm`, plus `xorriso`
and Limine (`tools/fetch-limine.sh`) for the smoke-test ISO. **No Rust/cargo** — the
capability core is plain C (`kernel/cap/cap.c`); the kernel builds with a C toolchain
alone (a prerequisite for LoricaOS self-hosting).

```
make          # build/aegis.elf  (the shipped artifact)
make iso      # build/aegis.iso  — kernel-only smoke-test ISO, bootable via Limine
make test     # boot the kernel alone; the "no init found" panic is SUCCESS
make dist     # the stripped, release aegis.elf
```

`make iso` / `make test` are a **smoke test only** — there is no userland here, so a
clean boot ends at the "no init found" panic (exactly like Linux with no init). Real
boots happen in LoricaOS. For arm64: `make -f Makefile.arm64 test`.

## House style

- **Match the surrounding code.** This is a pure C kernel. No new abstractions without a
  second caller — no interface with one implementation, no factory for one product, no
  config for a value that never changes.
- **Fail closed at the trust boundary.** The syscall surface (`kernel/syscall/sys_*.c`)
  is the line; validate capabilities and user pointers there.
- **Fix root causes, not symptoms.** One guard in the shared function beats a guard in
  every caller.
- **Keep kernel identifiers named "Aegis"** — the `aegis.elf` artifact, the
  `/etc/aegis/*` capability paths, "the Aegis kernel". The OS on top is "LoricaOS"; do
  not rebrand kernel internals.

## Layout

```
kernel/arch/x86_64/   boot, SMP, IDT/ISR, context switch, LAPIC, paging
kernel/arch/arm64/    the arm64 port (GICv3, generic timer, PSCI SMP, TTBR1 direct map)
kernel/syscall/       the syscall surface (sys_*.c) — the trust boundary
kernel/cap/           the capability core (cap.c) + policy loader
kernel/mm/            PMM, VMM, uaccess (copy_to/from_user + exception table)
kernel/sched/         scheduler, processes, fork/exec, wait queues
kernel/net/           netdev, eth, IP/TCP/UDP, sockets
kernel/drivers/       NVMe, xHCI, PS/2, framebuffer, HDA, NICs, ...
```

## Pull requests

- One logical change per PR; explain *why*, not just *what*.
- Make sure `make` and `make test` pass — and `make -f Makefile.arm64 test` if you
  touched shared or arm64 code.
- Sign off your commits with a real name and email.

By contributing, you agree that your contributions are licensed under the project's
[MIT License](LICENSE).
