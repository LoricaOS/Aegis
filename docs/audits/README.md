# Security audits

Historical record of security audits against the Aegis kernel. One file per
audit, named `YYYY-MM-DD-<scope>.md` so the directory sorts chronologically.

**These are historical documents, not issue trackers.** Each file records what
an audit found *at the time it ran*. Every file here carries a STATUS block at
the top stating whether its findings are resolved and, if so, the commits that
resolved them. Read that block before reading anything else — a closed audit's
CRITICAL section describes a kernel that no longer exists.

Open, unfixed vulnerabilities do not belong here. Per `SECURITY.md`, report
those privately via a GitHub security advisory; they land here only once fixed.

| Audit | Scope | Findings | Status |
|---|---|---|---|
| [2026-07-30](2026-07-30-kernel-security-audit.md) | Whole kernel — syscall/uaccess, net, fs, ELF/exec, MM/VMA, scheduler/SMP, block/NVMe/virtio/GPT, arch fault/entry | 41 (2 CRIT, 11 HIGH, 10 MED, 17 LOW) | **Resolved** in `a696dc5..f7849da` |

## Related

- `SECURITY.md` — the security model, current maturity, and how to report a
  vulnerability.
- `test/audit-poc/` — standalone host reproductions for the arithmetic findings,
  each running the vulnerable and fixed logic side by side. Plain `cc`, no cross
  toolchain or QEMU needed.
- `test/init.c`, `test/exectgt.c` — the in-tree boot tests, which include
  regression cases for the findings that are reachable from userspace.
