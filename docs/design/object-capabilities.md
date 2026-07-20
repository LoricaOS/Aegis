# Design: object-designating file capabilities for Aegis

Status: **accepted — direction locked 2026-07-20** (the three design decisions in
§6 are resolved; ready to start step 1 in §5).
Scope: the capability model in `kernel/cap/` and the file-authority path in
`kernel/fs/` + `kernel/syscall/sys_file.c`. Does **not** touch the Linux syscall
ABI, the monolithic architecture, or the uid-0-is-cosmetic model.

---

## 1. The problem this closes

Aegis enforces *no ambient authority*: authority comes only from unforgeable
capability tokens checked at the syscall boundary (`cap_check` against the
per-process cap table). That posture is correct and is the reason the kernel
exists. This proposal fixes **one structural weakness in how the file-authority
subset of those capabilities is expressed**, while the ABI window is still open
(LoricaOS is the only consumer and is aware the system is morphing).

### The weakness, stated precisely

A capability is `{uint32_t kind; uint32_t rights}` (`kernel/cap/cap.h`). `kind`
names an **operation** — `CAP_KIND_VFS_OPEN` = "may call `sys_open`" — not an
**object**. This is the `capabilities(7)` family (operation flags), not the
seL4/Fuchsia/Capsicum family (references that name what you may act on). The
README leans toward the latter; `cap.h` implements the former.

Consequences visible today:

- `CAP_KIND_VFS_OPEN` is **all-or-nothing across the filesystem**: any holder can
  open any path that isn't specifically fenced off.
- The high-value objects are fenced off by **minting a kind per protected path**:
  `CAP_KIND_AUTH` (inode-scoped gate on `/etc/shadow` + `/etc/aegis/admin`,
  enforced post-symlink in `vfs_open`), `CAP_KIND_INSTALL` (the `/apps` +
  `/etc/aegis` protected trees), plus `sys_vfs_confine` (process-wide unveil).
  These *work* — but they are a growing set of special cases, not one mechanism.

### What this is NOT (correcting the Linux-comparison framing)

The Linux comparison (`~/AEGIS_LINUX_COMPARISON.md` §2) calls this "reimplementing
`capabilities(7)`'s road to `CAP_SYS_ADMIN` = the new root." That overstates it,
and the distinction decides the design:

- The **failure** that made `CAP_SYS_ADMIN` "the new root" was *convergence*:
  unrelated powers piling into one broad bucket because there was no object to key
  on. **Aegis is not doing this.** The maintenance reflex has been the opposite —
  split authority into narrow least-authority kinds (`CAP_KIND_MOUNT` was minted
  specifically so mounting a tmpfs need not require `DISK_ADMIN`; `NET_LISTEN` was
  split from `NET_ADMIN`). There is no Aegis bucket that everything converges on.
- `CAP_KIND_AUTH` is **not** "the first junk-drawer patch" (the doc's claim). It is
  a narrow, inode-scoped gate — object-scoping done crudely, the *opposite* of
  junk-drawer accretion.

So we have the *structural shape* that made Linux vulnerable, but **not** the
disease. What is genuinely worth fixing is narrower and real: **the general file
caps are coarse, and the object-scoping we already do is a set of special cases
rather than one general mechanism.** This proposal generalizes it.

### Operation caps stay as they are — on purpose

`POWER` (reboot), `NET_ADMIN`, `SETUID`, `THREAD_CREATE`, `DISK_ADMIN`, … name
authorities with **no object to designate**. Even seL4 has authorities like this.
They are correctly operation-flags and this proposal does not change them. The
redesign applies **only to file authority** (`VFS_OPEN/READ/WRITE`, and the
special-case kinds `AUTH`/`INSTALL` it can subsume).

---

## 2. Prior art (web-verified 2026-07-20)

Three object-capability systems, ranked by applicability to Aegis (Linux-ABI,
monolithic, POSIX fds):

### Capsicum (FreeBSD) — the primary reference

The closest match: **Unix file descriptors *are* capabilities**, in a real
POSIX kernel.
- Rights on an fd are reduced — never expanded — by `cap_rights_limit(2)`
  (monotonic attenuation). This is exactly the one-way property `sys_vfs_confine`
  already has.
- In *capability mode* (`cap_enter(2)`) there is **no global namespace**: `open()`
  by absolute path is forbidden; you may only derive new fds from fds you already
  hold via the `*at()` calls (`openat`, `connectat`, `accept`, `recvmsg` fd
  passing, `dup`). A directory fd becomes the root of a subtree you can reach.
- Rights **inherit down**: an fd `openat`'d from a directory fd that lacks
  `CAP_WRITE` is itself unwritable. `CAP_LOOKUP` is the right that lets a directory
  fd be used as a lookup root for `openat`/`linkat`/`unlinkat`.

Aegis is one `openat`-that-honors-`dirfd` away from this model, and already has the
fd-passing transport (`SCM_RIGHTS`).

### seL4 — the revocation model

- Maintains a **capability derivation tree (CDT)** tracking which caps were minted
  from which originals.
- **`mint`** creates a copy with a *subset* of rights (+ an optional *badge*
  identifying the grant); a minted cap supports one level of further derivation.
- **`revoke`** recursively removes *every* capability derived from a selected one —
  the mature answer to "take authority back." This is the piece Capsicum/Unix fds
  lack (you can only close *your* fd).

### Zircon (Fuchsia) — the pragmatic staging

- Handles are capabilities; `zx_handle_duplicate` produces a handle with *strictly
  lesser* rights (attenuation again).
- Notably, **revocation is still "ongoing work"** — Zircon ships object-caps with
  only close-the-handle semantics. Proof that object-capabilities are shippable
  *before* a full revocation tree, and that revocation can be staged.

**Takeaways for Aegis:** monotonic attenuation is universal — adopt it. Directory-
fd-rooted authority (Capsicum) is the file-cap mechanism. Recursive revocation
(seL4 CDT) is the eventual endpoint but (Zircon) may be staged behind
close-the-fd.

Sources: seL4 Reference Manual (capability derivation / revoke / mint / badge);
Capsicum: *Practical Capabilities for UNIX*, Watson et al., USENIX Security 2010,
+ `rights(4)`, `cap_enter(2)`, `cap_rights_limit(2)`; Fuchsia `concepts/kernel/rights`,
`zx_handle_duplicate`.

---

## 3. The design

**A directory fd can be a subtree capability.** It carries an inode root, a rights
mask, and a "confined" flag; `openat`/`*at` relative to it are (a) unable to escape
the subtree and (b) rights-attenuated. Delegation is `SCM_RIGHTS` fd passing;
attenuation is a new `cap_rights_limit`-analog; revocation is staged.

### 3.1 What an fd gains

`vfs_file_t` (the per-fd struct in `fd_table_t.fds[]`) gains, for directory fds
only:

```c
/* Directory-fd capability scope. Zero/absent = an ordinary directory fd with no
 * capability semantics (today's behavior). Set = this fd is a subtree root. */
uint64_t cap_root_inode;   /* subtree root; lookups may not ascend above it     */
uint32_t cap_rights;       /* CAP_RIGHTS_* ceiling for anything derived from it  */
uint8_t  cap_confined;     /* 1 = *at() via this fd cannot escape the subtree    */
```

This is `proc->vfs_scope` (process-wide unveil) generalized to **per-fd and
delegable**. Nothing changes for fds without `cap_confined`. The two **compose**:
a lookup must satisfy both the process-wide `vfs_confine` scope *and* the
directory-fd capability's subtree — both only ever remove authority, so their
intersection is the reachable set, and neither can widen the other.

### 3.2 `openat` honors `dirfd` (the core change)

Today `sys_openat` ignores `dirfd` and forwards to `sys_open` (path-only). New
behavior:

- `dirfd == AT_FDCWD` or absolute path → **unchanged** (ABI-compatible; existing
  programs keep working). Still gated by the process's `VFS_OPEN` cap + any
  process-wide `vfs_confine` scope. **This is the default (decision 1):** a confined
  process keeps coarse `VFS_OPEN` for absolute paths — POSIX-friendly, doesn't break
  absolute-path programs. A hard `cap_enter`-style mode that forbids global `open()`
  entirely (Capsicum-faithful) is left as opt-in future work, added only if a
  consumer wants that strictness.
- `dirfd` is a **capability directory fd** (`cap_confined`) → resolve the path
  *relative to `cap_root_inode`*, reject any resolution (incl. `..` and symlinks)
  that ascends above the root (reuse the post-symlink inode check that `AUTH`
  already uses), and clamp the resulting fd's rights to `min(cap_rights, requested)`.

Escape-proofing reuses machinery that already exists: `path_canonicalize` (collapses
`.`/`..`/`//`) and the inode-based post-symlink gate in `vfs_open` that makes
`/etc/../etc/shadow` and symlink tricks fail for `AUTH`.

### 3.3 Attenuation — `cap_rights_limit` analog

A new Aegis-private syscall (unused Aegis number, e.g. next after `vfs_confine`
518) monotonically narrows a directory fd's `cap_rights` and may set `cap_confined`.
One-way, like `vfs_confine`; never widens. This is `seL4_CNode_Mint` /
`cap_rights_limit` / `zx_handle_duplicate`-with-lesser-rights for Aegis.

`cap_rights` uses the existing 3-bit `CAP_RIGHTS_{READ,WRITE,EXEC}` set
(decision 2) — enough to express readable/writable/executable subtrees. Capsicum's
finer rights (`LOOKUP`, `CREATE`, `UNLINK`, …) are added only when a consumer needs
the distinction, not up front.

```
sys_cap_rights_limit(int fd, uint32_t new_rights, int confine)
    → fd->cap_rights   &= new_rights;     // never adds a bit
    → fd->cap_confined |= (confine != 0); // one-way
```

### 3.4 Delegation — already solved

Passing a directory-fd capability to another process is `SCM_RIGHTS` over an
`AF_UNIX` socket — the transport already exists (`UNIX_PASSED_FD_MAX`,
`sys_sendmsg`). A received capability fd carries its `cap_root_inode` /
`cap_rights` / `cap_confined` with it, and the receiver can only *further* attenuate
(§3.3), never widen. This is the delegable-object property the current
`{kind, rights}` caps lack.

### 3.5 Revocation — staged (Zircon → seL4)

- **Phase 1 (ship first):** close-the-fd. Authority ends when the last holder
  closes the capability fd — the fd refcount already gives us this. Matches Zircon's
  current reality; adequate for the delegations LoricaOS does today.
- **Phase 2 (only if needed):** seL4-style recursive revoke. Track derivations
  (which capability fd each was `cap_rights_limit`'d / `SCM_RIGHTS`-passed from) and
  add `sys_cap_revoke(fd)` that invalidates the whole subtree of derived caps.
  Deferred until a concrete need appears — do not build the CDT speculatively.

### 3.6 How the special-case kinds collapse

- **`CAP_KIND_AUTH`** stops being a per-secret kind: `/etc/shadow` + `/etc/aegis`
  live under a subtree that is simply not reachable without a directory-fd
  capability rooted at (or above) it. `login` receives that capability instead of
  holding a global "may read shadow" flag.
- **`CAP_KIND_INSTALL`** similarly becomes "holds a writable capability fd rooted at
  `/apps` + `/etc/aegis`" rather than a global "may mutate those trees" flag —
  handed to herald at install time.
- **`CAP_KIND_VFS_OPEN`** remains as the coarse "may use the file syscalls at all"
  gate for the unconfined/legacy path, but least-authority programs run *confined*
  and reach only what their directory-fd capabilities name.

Net effect: the file-cap kind count **shrinks** over time instead of growing — the
opposite trajectory to the one the Linux comparison warned about.

---

## 4. What does not change

- **The Linux syscall ABI.** `openat` stays `openat`; unconfined absolute-path opens
  behave exactly as today. The only new syscalls are Aegis-private (rights-limit,
  later revoke), in the Aegis-private number range — same pattern as `vfs_confine`.
- **Operation caps** (`POWER`, `NET_ADMIN`, `SETUID`, …) — unchanged; they have no
  object to name.
- **`uid 0` is cosmetic; no ambient authority; fail closed.** This proposal only
  *removes* ambient reach (a confined process reaches less), so it cannot weaken the
  model — same additive/monotonic property that made `vfs_confine` safe to ship.

---

## 5. Staging

1. **`openat` honors `dirfd`** for ordinary directory fds (no capability semantics
   yet) — pure ABI-correctness fix, unblocks everything below. (Small.)
2. **Directory-fd capability fields + confined `*at` resolution** (§3.1–3.2) +
   `sys_cap_rights_limit` (§3.3). Opt-in, additive; nothing regresses. KTEST: a
   confined dir-fd cannot `openat("../etc/shadow")`, cannot exceed its rights.
3. **Migrate `AUTH`/`INSTALL` to subtree capabilities** (§3.6), one at a time, in
   lockstep with LoricaOS (`login`, `herald`). Retire each kind only once its
   consumers use the capability form.
4. **Revocation Phase 2** (§3.5) — only if a concrete revoke requirement appears.

Each step is independently shippable and independently verifiable (x86 + arm64
KTEST + KASAN), consistent with how the rest of `v1.2.2-hardening` landed.

---

## 6. Decisions (locked 2026-07-20)

1. **Confinement default → coarse default + opt-in hard mode.** Confined processes
   keep coarse `VFS_OPEN` for absolute paths (POSIX-friendly, no breakage). A hard
   `cap_enter`-style mode forbidding global `open()` is opt-in future work, built
   only if a consumer wants that strictness. (§3.2)
2. **Rights granularity → keep the 3-bit `READ/WRITE/EXEC` set.** Capsicum's finer
   rights (`LOOKUP`/`CREATE`/`UNLINK`/…) are added only when a consumer needs the
   distinction. (§3.3)
3. **Revocation → Phase-1 close-the-fd; defer the seL4 CDT.** Recursive revocation
   is built only if a concrete revoke requirement appears. (§3.5)

Step 1 (§5 — `openat` honors `dirfd`) is ready to start.
