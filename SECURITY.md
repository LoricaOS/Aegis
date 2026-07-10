# Security Policy

Aegis is a capability-secure, clean-slate x86-64 / arm64 kernel. Security is not a
feature here — it is the entire reason the kernel exists. This document explains the
security model, its current maturity, and how to report a vulnerability.

## The model — what Aegis promises

Aegis enforces **no ambient authority**. No process — including one running as
`uid=0` — holds any power it was not explicitly granted. `uid=0` is cosmetic; real
authority comes only from unforgeable **capability tokens** validated at the syscall
boundary (`cap_check` against the per-process capability table in `kernel/cap/`).

A process can act on a resource only if it holds a capability for it. Capabilities are
not ambient, not inheritable-by-default, and not forgeable. When the kernel is unsure,
it fails closed (`ENOCAP` / `EFAULT`).

> **A capability bypass — any path that lets a process act without a capability it was
> granted, or that makes a capability ambient, inheritable-by-default, or forgeable —
> is the highest-severity class of bug in this project.** It is a regression in the one
> thing the kernel exists to do.

## Current maturity — please read this

**Aegis is v1 software. It is NOT production-hardened. Do not rely on it to isolate
untrusted code or protect real secrets yet.**

The trusted computing base is plain C. Like any C kernel this young, it very likely
contains memory-safety bugs (out-of-bounds accesses, use-after-free, integer overflow)
that a determined attacker could turn into arbitrary code execution in the kernel —
which would defeat the capability model from below. The capability *design* is sound
and enforced at the syscall boundary; the *implementation* has not been audited or
fuzzed to a production standard.

In short:
- The **model** (no ambient authority) is the product, and it is enforced deliberately.
- The **implementation** is young. Treat Aegis as a research/hobby kernel, not a
  hardened isolation boundary.

## Reporting a vulnerability

Please report security issues **privately** — do not open a public issue for an
unfixed vulnerability.

- Preferred: a GitHub private security advisory on this repository.
- Or email: **execxd@icloud.com**

Please include the affected version or commit, a description, and a proof-of-concept if
you have one. We are especially interested in, in priority order:

1. **Capability bypasses** — a process obtaining or exercising authority it was never
   granted. This is the top priority.
2. Anything that makes a capability ambient, inheritable-by-default, or forgeable.
3. Memory-safety bugs in the syscall surface (`kernel/syscall/*`), `uaccess`
   (`copy_to`/`copy_from_user` and its exception table), and the capability core
   (`kernel/cap/`).

There is no bug-bounty program — this is an open-source project. Fixes are credited in
the release notes unless you prefer to remain anonymous.

## Supported versions

Only the latest released `aegis.elf` and the `main` branch are supported. Fixes land on
`main` and ship in the next release.
