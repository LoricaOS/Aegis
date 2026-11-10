# Process authority inheritance

Status: implemented with approval. Independent children inherit constraints,
not usable capability or latent session authority. This enforces the
no-default-inheritance rule in `AGENTS.md`; it is an intentional change to
the old fork/vfork and spawn authority behavior.

## Implemented rule

| Creation path | Initial authority |
| --- | --- |
| `fork`, fork-style `clone`, `vfork` | Empty cap table; authenticated/admin/firstboot flags zero; bound uid/gid `AUTH_ID_NONE` |
| `CLONE_THREAD` | Coherent snapshot of the existing principal's caps, sessions, bound identity and constraints |
| Unmasked `sys_spawn` | Fresh unauthenticated destination policy; no parent session or bound identity |
| Masked `sys_spawn` | Explicit parent-held/destination-policy intersection; persistent ceiling; no session flags |

`init_child_authority` applies the fork/clone rule while holding `sched_lock`.
Spawn snapshots authority under the same publication lock, then performs
policy I/O and mask handling outside it. Ordinary uid/gid and POSIX process
state keep their existing meanings; uid zero does not confer authority.

An existing active ceiling is always preserved or narrowed. Empty initial
caps on ordinary fork do **not** synthesize an empty active ceiling: exec
can still issue fresh baseline and trusted destination-policy caps, bounded
by any inherited restriction. An explicitly empty spawn mask, by contrast,
intentionally installs an empty active ceiling, even across future exec.

No syscall numbers, legacy argument interpretations, hidden fork/vfork
registers, mutable "next fork" setting, or new bootstrap grants were added.

## Explicit delegation and fresh issuance

The existing `sys_spawn(path, argv, ..., cap_mask)` interface is the supported
explicit delegation route:

* A non-null mask requires `CAP_KIND_CAP_DELEGATE`.
* Each requested kind/right subset must be held by the parent's coherent
  snapshot and survive destination policy plus the inherited ceiling.
* The parent's authenticated/admin flags may qualify that explicit policy
  intersection; the child receives selected live caps, never those flags.
* The final intersection becomes a persistent ceiling on later exec/spawn
  and independent descendants. An inherited restriction cannot be removed.
* Bound uid/gid are retained only if the mask's SETUID grant survives all
  filters with WRITE, the right checked by `sys_setuid`/`sys_setgid`. Otherwise
  they are `AUTH_ID_NONE`, including for all unmasked spawns.

The retained identity only permits a verified bound identity transition.
It does not authenticate the child, elevate it, or preserve admin authority.
Later exec therefore cannot regenerate excluded or session-qualified grants
merely because its parent was authenticated/elevated.

Unmasked spawn and exec remain **fresh trusted-policy issuance**, not parent
capability delegation. Service and baseline grants can exist independently
of the caller's cap table. The policy parser/anchor rules are unchanged.
An in-process credential-checker can authenticate and then exec in place;
its own authenticated/bound identity state still survives that exec. This
does not cause its subsequently forked children to inherit that state.

`CAP_KIND_CAP_GRANT` remains reserved, not an implemented child-grant API.
Runtime grant syscall 363 remains removed. There is no arbitrary-PID injection
route or supported explicit session-delegation API.

## Bootstrap and first boot

`proc_spawn` continues to give PID 1 its seven explicit bootstrap grants:
VFS_OPEN, VFS_WRITE, VFS_READ, IPC, PROC_READ, THREAD_CREATE and POWER.
Fork -> exec startup does not need a new inheritance exception: exec itself
is ungated and destination policy can issue fresh authority.

AUTH-gated credential-checkers and the anchored admin authenticator remain
authority sources, not cosmetic uid operations. The anchored first-boot setup
policy and `/etc/aegis/configured` marker remain the bounded account-database
bootstrap exception. A child never inherits a parent's firstboot flag; any
setup exception must come from the child's own qualifying destination policy.

## Threads and vfork are not sandboxes

`CLONE_THREAD` tasks share an address space and security principal. Their
authority remains a snapshot rather than a redesigned shared authority object;
this change makes no isolation claim between threads.

A vfork child has no inherited usable caps or session flags, but it still
borrows the parent's address space and can alter its memory before the parent
resumes. Emptying the cap table does not isolate a malicious vfork child from
the parent. **Do not advertise vfork as a sandbox.**

## Required LoricaOS migration

This repository contains no production userland. Full LoricaOS compatibility
has not been tested or assumed. The kernel rule is implemented now; an old OS
must not silently rely on the previous inheritance behavior.

1. Audit init/service launch, login -> shell, elevated shell -> commands,
   installer/setup, shell pipelines, libc fork/posix_spawn/vfork, and
   language-runtime subprocess creation.
2. Account for child-side work before exec. Inherited descriptors remain
   present, but capability-gated read/write/open/socket operations now fail
   without grants. Ungated descriptor cleanup and exec/exit are not equivalent
   to a generally privileged pre-exec child.
3. Use masked spawn for the bounded direct grants it can express. Callers must
   actually hold CAP_DELEGATE and the requested rights; a shell cannot delegate
   an authority it does not possess merely because a destination policy names it.
4. Redesign login/admin launch flows that relied on implicit session propagation.
   Existing masked spawn does not delegate authenticated/admin session state.
   It is not a complete replacement for arbitrary forked execution or every
   old elevated-shell workflow. Any new explicit session-delegation ABI needs
   a separately reviewed, scoped design; there is no compatibility fallback here.
5. Validate real login, first boot, administrative commands, service supervision,
   pipelines and multithreaded subprocess creation before claiming OS support.

Focused host tests execute production child-initialization, spawn delegation,
cap-check, ceiling and policy-issuance logic with mocked locks/user-copy and
policy lookup. They do not replace boots with the actual LoricaOS userland.

Full x86-64 and AArch64 builds and in-tree QEMU boot tests subsequently passed,
including ring-3 checks for empty children, non-granting admin drops, fresh
policy issuance, persistent ceilings and secure startup. See the
[validation record](hardening-validation.md) for exact commands and limits.
Those test-fixture boots do not remove the LoricaOS migration requirement.
