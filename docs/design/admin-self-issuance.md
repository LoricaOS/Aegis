# Explicit administrative SELF issuance

Implemented for the LoricaOS migration on the Aegis `1.5.1` source baseline.
This is fresh credential-backed authority issuance to the caller, not a
session-delegation API or an inheritance exception.

## ABI and compatibility

* `sys_admin_self()` is syscall **521**, with no arguments
  (`AEGIS_SYS_ADMIN_SELF` in `kernel/cap/cap.h`).
* `sys_admin_session(0)` still drops the caller's administrative authority.
* `sys_admin_session(1)` still requests legacy direct-parent elevation, with
  its existing checks and race protocol.
* Every other selector to syscall 517 returns `EINVAL`, including 2.

SELF deliberately does **not** use selector 2 of syscall 517. Deployed kernels
treated every nonzero selector as parent elevation: using 2 would silently
elevate the wrong principal before a new caller could detect incompatibility.
An old kernel instead rejects the new syscall 521 with `ENOSYS`, without
changing authority. Login must fail closed on any error, never fall back to
517 or launch the operation without successful SELF issuance.

## Issuer and caller contract

Trusted installed `/bin/login` must:

1. Verify the separate administrative credential and an allowlisted operation.
2. Use its existing AUTH issuer to bind the verified administrative principal
   to uid/gid 0/0 with `sys_auth_session(0, 0)`.
3. Complete the existing checked `sys_setgid(0)` / `sys_setuid(0)` transitions.
4. Call syscall 521, check success, and exec the allowed operation **in the
   same process**, without an intervening fork/spawn.

The kernel requires all of the following at snapshot and commit:

* A live user caller with `ADMIN_AUTH` and `WRITE`.
* `authenticated` and bound `auth_uid == 0 && auth_gid == 0`.
* Numeric `uid == 0 && gid == 0`.
* No active persistent capability ceiling and no `authority_busy` transaction.
* No other live user task in the caller's thread group. Stopped tasks count
  as live; zombies do not. The task-list scan is authoritative, not the
  leader's cached thread count. A sole live nonleader is permitted.

Raw uid zero, a missing binding, a mismatched binding, or a merely authenticated
ordinary principal does not authorize issuance. Existing trusted-path policy
continues to restrict ADMIN_AUTH to `/bin/login`; this change grants it to no
shell or administrative operation program. The credential verifier and
operation allowlist are LoricaOS responsibilities, not kernel password logic.

## Publication and revocation

Under `sched_lock`, SELF checks eligibility and snapshots the caller's epoch,
executable path, authenticated state, session and thread-group identity. It
derives the current executable's policy with authenticated state and
`admin_session = 1` outside the lock. No provisional authority flag, cap table,
or busy reservation is published.

Under the same lock, SELF rechecks epoch, path, session, thread-group identity,
live ADMIN_AUTH rights, binding, numeric identity, ceiling, busy state and
absence of live siblings. Only then does it atomically publish the derived
cap table, set `admin_session`, clear `admin_session_firstboot`, and advance
the epoch. Existing epoch writers cover AUTH, exec (including same-path exec),
drop, session changes and competing elevation; live numeric identity checks
also cover uid/gid writers that do not advance the epoch.

An invalidated request returns `EPERM`; it never retries or restores authority
removed by a concurrent drop. Active ceilings are rejected, not widened.
Existing monotonic drop, sentinel validation, parent-mode races, exec policy,
AUTH/SETUID behavior, filesystem/TTY rules and child inheritance are unchanged.

## Validation scope

`python3 test/cap_authority_test.py` executes the production SELF, legacy
admin-session, AUTH, identity-transition and exec publication functions/blocks
with host scheduler/filesystem stubs and deterministic policy-I/O race hooks.
It covers initial denials, both legacy selectors, invalid selectors, exact
pre-commit nonpublication, successful same-process exec, ceiling preservation,
live siblings, drop/exec/auth/session races, live-state revalidation and
competing issuance. `test/process_authority_test.py` checks the unchanged
production process-authority paths.

These host checks do not replace SMP stress, a kernel boot, or the installed
LoricaOS credential/allowlist and administrative-operation workflow.
