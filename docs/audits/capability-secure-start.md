# Capability authority and secure startup

## Kernel policy

Exec and spawn write `AT_SECURE=1` when **any** of these conditions holds:

- The final image has no persistent capability ceiling.
- The image gains a capability kind or right compared with its predecessor
  (the spawning parent for spawn).
- The image gains direct admin-session authority.

A ceiling-confined image with no authority gain may receive `AT_SECURE=0`.
Spawn uses the child's final ceiling, including an explicitly supplied spawn
mask or an inherited ceiling, not the parent's ceiling alone. Exec preserves
the existing ceiling. This changes startup mode, not fork inheritance policy.

## Why an image with no initial gain can still require secure startup

An unattenuated process can be elevated in place by a credential-checking login
child through `sys_admin_session`. That operation can grant both policy caps
and an admin-session flag; the flag itself authorizes some operations even if
the executable's policy supplies no additional caps.

Previously exec could freeze `AT_SECURE=0`, publish its new authority state,
and then receive a login child's elevation while the kernel was still loading
the interpreter or building the initial stack. Capability comparison at exec
time alone missed that grant. Rechecking later only moves the race: authority
can change after auxv is written. Holding a transaction marker until the last
kernel return also does not establish when a userspace loader has finished
processing its environment.

The conservative rule therefore selects secure startup **before any later
in-place elevation**, for every unattenuated exec/spawn image. A persistent
ceiling excludes that path: `sys_admin_session` rejects elevation of a
ceiling-confined target, including attempts that would restore only the direct
session flag. Gains at the exec/spawn boundary still independently require
secure startup.

This rule does not delay a legitimate elevation or introduce a loader
handshake. The separate authority epoch/transaction checks continue to prevent
an obsolete policy derivation from committing after exec, drop, or another
authority-state change.

## Drop is attenuation, not issuance

`sys_admin_session(0)` never restores capabilities from an executable pathname.
An already unelevated process (neither credential-backed nor first-boot admin
flag set) keeps its table unchanged and performs no policy I/O. Its authority
epoch still advances, canceling any outstanding elevation request.

An actual drop snapshots the held capability rights before revocation, clears
the admin flags and old table, then derives nonadmin policy outside the
scheduler lock. The result is bounded by both the held rights and any
persistent ceiling. A resulting rights mask must also have been authorized by
one old slot: separate slots cannot be combined into newly usable authority.
Consequently an empty independent child's inherited path cannot recover
baseline/service authority, and a mask or policy reload cannot make drop grow
the live table. Repeated drops remain no-ops rather than policy refreshes.

## Compatibility and guarantee limits

The kernel supplies an auxiliary-vector flag. It does **not** filter the
environment itself, guarantee that an interpreter/libc honors the flag, undo
code already loaded into a running image, or sanitize an application's own
configuration and plugin mechanisms.

Depending on the OS interpreter/libc, secure mode may ignore library-search
overrides such as `LD_LIBRARY_PATH`, suppress preloading through `LD_PRELOAD`,
or restrict other loader/libc environment features. Development wrappers,
profiling/injection tools, and application-local dependency lookup that rely
on those overrides may consequently behave differently for ordinary
unattenuated programs, even when no elevation occurs. Exact behavior is
loader-specific; no deployed LoricaOS loader was verified for this change.
Normal kernel argument/environment copying is unchanged.

The compatibility cost is deliberate: an image eligible for a later in-place
authority grant must not start with an auxv value that advertises insecure
startup merely because it lacks elevated authority at the instant of exec.

## Focused validation

`test/cap_authority_test.py` executes production authority syscall functions,
exec authority blocks, and the actual exec/spawn secure-auxv writes with host
stubs. Its passing suite includes:

- Elevation after auxv freezes, before simulated user entry, with and without
  additional policy capabilities: the written value remains `AT_SECURE=1`.
- Ceiling-confined exec with no gain: `AT_SECURE=0`, and late elevation denied.
- A capability gain within an exec ceiling: `AT_SECURE=1`.
- Unattenuated spawn, final masked/inherited ceiling cases, capability/right
  gains, and direct admin-session gains.
- Empty/partially masked tables remain bounded across drop, policy widening,
  duplicate-kind rights slots, first-boot flags, and repeated no-op drops.

This is deterministic host regression coverage, not a userspace-loader
integration test or a full-kernel SMP proof.
