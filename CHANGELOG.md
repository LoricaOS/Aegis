# Changelog

Releases before 1.6.0 predate this file; see the git tags and
`docs/audits/` for their record.

## 1.6.0

This release also carries the 2026-09-07 boot checkpoint that was paused in the
working tree before this work (tracked now as
`docs/audits/2026-09-07-security-followup.md`): the earlier 42-finding
remediation plus the console-delegation correction. Its own status block still
applies — **filesystem identity checks and their mmap integration remain open**
(see "Next work, in order" in that file), so this is not a complete
remediation of the earlier scan either. Everything below was validated against
that combined tree.

**No-ambient-authority release.** Independent children no longer inherit usable
capability or session authority, and the teardown/syscall paths that could leak
or resurrect authority are closed. This changes userland-visible behaviour, so
LoricaOS needs the matching release (see `docs/design/process-authority-inheritance.md`).

### Security

- An audit of capability enforcement, user-memory access, process lifecycle and
  network input produced 11 findings; all are fixed, with a regression suite
  each (`test/cap_authority_test.py`, `process_authority_test.py`,
  `process_lifecycle_test.py`, `socket_uaccess_test.py`, `tcp_audit_test.py`,
  `fs_security_test.py`, `tty_pgrp_authority_test.py`).
- Capability publication is now transactional: exec, admin elevation and
  de-escalation share an epoch/busy protocol, so a stale derivation can no
  longer resurrect dropped or pre-exec authority.
- Malformed policy lines fail closed instead of being reinterpreted.
- Administration de-escalation is monotonic — drop may remove authority but
  never issue it.
- `AUTH` now authorises read-only opens of the exact resolved shadow/admin
  credential inodes, without a general DAC or uid-0 bypass.
- `TIOCSPGRP` needs baseline `IPC`/READ instead of process-inspection authority,
  keeping job control scoped to the caller's session.
- Networking: passive TCP rings are attached at the final handshake ACK rather
  than per SYN (320 KiB per half-open slot before); broadcast TCP is rejected;
  closing-state FINs validate sequence position; a peer that never sends its
  own FIN can no longer pin a `FIN_WAIT_2` slot forever; `TIME_WAIT` re-ACKs a
  retransmitted FIN.
- Lifecycle: children belong to the parent thread group; `waitpid` returns
  `ECHILD`; `SIGCHLD` is delivered to a live group member instead of a
  zombie/stopped leader.
- Framebuffer console text is serialised and bounds-checked (fixed a
  concurrent-writer fault one row past the shadow buffer).
- `execve` of a path that exists nowhere reports `ENOENT` again instead of
  `EACCES`; the "refuse to exec from a non-ext2 mount" rule had collapsed both
  cases, so `posix_spawn` and shell lookups diagnosed a missing binary as a
  permission error. `sys_spawn` already propagated the real error.

### Added

- **Syscall 521 `sys_admin_self`** — explicit, single-threaded, verified-
  credential self-elevation for the trusted authenticator, so an admin tool can
  be re-executed in place without inheriting a session. Old kernels return
  `ENOSYS`.

### Changed

- **Independent `fork`/`vfork`/`clone` children inherit constraints, never
  usable caps, authenticated/admin flags or bound identity.** `CLONE_THREAD`
  keeps a coherent same-principal snapshot.
- `sys_spawn` without a mask issues fresh unauthenticated destination policy;
  a masked spawn remains the explicit `CAP_DELEGATE`-gated route.
- `sys_admin_session` accepts only selector 0 (drop) and 1 (parent elevation);
  anything else is `EINVAL`.
- Exec supplies `AT_SECURE=1` for any image still eligible for later in-place
  elevation.

See `docs/design/hardening-validation.md` for the exact build/boot evidence and
its limits.

### Build

- `VERSION` is now a prerequisite of every object in all three makefiles. It was
  only expanded into `CFLAGS`, so bumping it left every `.o` untouched and
  `make dist` shipped a kernel still stamped with the previous version.
- The release asset is the **stripped** image (`make dist`), which is what
  `AGENTS.md` documents. CI previously uploaded the unstripped `build/aegis.elf`;
  at 3.1 MiB it overflowed the 3 MiB ESP slot the OS embeds it in. Stripped, the
  x86 image is ~0.59 MiB.
