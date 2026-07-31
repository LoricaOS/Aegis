# Aegis Kernel Security Audit — Findings

> ## STATUS: RESOLVED — historical record
>
> **Every finding in this document has been fixed.** All 41 — C1, C2, H1–H11,
> M1–M10, L1–L17 — were individually re-verified against the source before being
> acted on, then fixed and tested. This file is kept as the record of what was
> found and why each fix looks the way it does; it is **not** a list of open
> issues. Do not read the CRITICAL/HIGH sections below as describing the current
> kernel.
>
> Fixed in `a696dc5..f7849da` (branch `feat/kconfig`), 2026-07-30/31:
>
> | Commit | Findings |
> |---|---|
> | `610d0dd` | H1, H3, M3, M5 — mm/VMA |
> | `68dd988` | C1 (syscall half), M2 — syscall boundary |
> | `32ed216` | C1 (backend), C2, H4, H5, H6, H7, H8, H10 (gate), M7, M8, M9 — fs |
> | `dfd11e3` | H11, M9 (driver half) — virtio/blk |
> | `324e015` | H2 — AF_UNIX SCM_RIGHTS |
> | `2f2a46e` | H9, H10 (walk), M1 — arch/sched/tty |
> | `7f51866` | M4, M6, M10 — exec/proc |
> | `e320c50` | regression tests + standalone PoCs (`test/audit-poc/`) |
> | `001c149` | L1–L17 |
>
> **Verification.** x86_64: clean `-Werror`, 22/22 KTEST, three ISOs boot.
> aarch64: clean `-Werror`, 23/23 KTEST, two ISOs boot (the arm64 build itself
> was broken and was fixed in `f7849da`). Eleven of the arithmetic findings have
> standalone host reproductions in `test/audit-poc/` that run the vulnerable and
> fixed logic side by side. C1 was additionally demonstrated by building a
> deliberately-unpatched kernel and triggering the panic; M4 was verified end to
> end by booting a genuinely dynamic init, both accepting the real musl linker
> and refusing a non-root-owned one.
>
> **Caveats recorded honestly.** H7, H11, M1, M3, M7 and M9 have no runtime test
> — they need a many-port USB controller, a malicious virtio device, a second
> login session, an SMP data race, a memfd `ftruncate` and a crafted GPT
> respectively. They are verified by source reading and clean compilation only.
> H2 likewise: triggering it deadlocks the machine by definition, so it would
> present as a timeout rather than a failure.

**Date:** 2026-07-30 (pass 1), 2026-07-30 (pass 2 — scheduler/drivers/arch/misc)
**Scope:** Aegis kernel source (cloned at `../aegis/`) — direct source audit plus nine parallel
deep-audit passes: pass 1 (syscall/uaccess, net, fs, ELF/exec, MM/VMA); pass 2
(scheduler/SMP/PCB lifetime, block/NVMe/virtio/GPT, arch fault/entry, misc subsystems).
**Method:** Every finding below was confirmed by direct code reading; the headline findings were
verified line-by-line. Severity reflects reachability × impact. No patches were applied — this
is a hit list for the dev session.

> All `file:line` references are relative to the Aegis kernel tree (`../aegis/kernel/...`).
> "Stock-reachable" means no crafted media / special privileges beyond a normal reader-capable
> process. "Crafted-media" means an attacker must mount a malicious ext2/FAT image.
> "Privileged-precondition" means a non-trivial cap (e.g. `DISK_ADMIN`) is required — still a
> real cap-boundary break if it grants more than the named authority.

---

## Severity legend

| Level   | Meaning                                                            |
|---------|-------------------------------------------------------------------|
| CRIT    | Kernel memory corruption / RCE primitive, stock-reachable          |
| HIGH    | UAF / deadlock / privilege gap / system-wide hang                 |
| MED     | Local DoS, info leak, confinement bypass, latent escalation       |
| LOW     | Hardening, latent footgun, off-by-one, correctness                |

---

## CRITICAL

### C1 — `readlink(path, buf, 0)` → uint32 underflow → kernel stack OOB read+write
**Severity:** CRIT — stock-reachable by any `CAP_KIND_VFS_READ` process
**Files:** `fs/ext2.c:1138-1139` (root cause), reached via `syscall/sys_meta.c:292,313,315`

```c
// sys_meta.c:292
uint32_t bufsiz = (uint32_t)arg3;          // attacker passes 0
...
// sys_meta.c:313
char kbuf[256];
if (bufsiz > sizeof(kbuf)) bufsiz = sizeof(kbuf);   // 0 > 256 is FALSE — bufsiz stays 0
int n = g_rootfs->readlink(resolved, kbuf, bufsiz);  // forwards 0 unchanged

// ext2.c:1135-1147
uint32_t tlen = inode.i_size;              // e.g. 8 for "/bin/sh -> busybox"
if (tlen == 0) return 0;
if (tlen >= bufsiz)                         // 8 >= 0 → TRUE
    tlen = bufsiz - 1;                      // 0 - 1 = 0xFFFFFFFF  (uint32 underflow)
...
for (i = 0; i < tlen; i++)                  // ~4 billion iterations
    buf[i] = (char)src[i];                  // src = on-stack inode → reads up the stack
buf[tlen] = '\0';                           // writes past the 256-byte kbuf
```

**Failure scenario:** Any process holding `CAP_KIND_VFS_READ` calls
`readlink("/bin/sh", buf, 0)` against a stock fast symlink (`i_size <= 60`, the common case —
e.g. the shipped `/bin/sh -> busybox`). The downward-only clamp at `sys_meta.c:313` never
rejects `0`; the `/proc/self/exe` branch above it is safe (clamps `len` to `bufsiz` → 0), but
the ext2 path forwards `0`. `tlen = bufsiz - 1` underflows to `0xFFFFFFFF`, and the copy loop
reads `src` (the on-stack `ext2_inode_t`) past its bounds and writes `buf` (the caller's
256-byte `kbuf`) past its bounds — corrupting the kernel stack frame and saved return address.

- **Stock system:** kernel stack corruption → panic (unprivileged DoS).
- **Crafted mounted ext2:** the inline symlink target (first 60 bytes = `inode.i_block`) is
  attacker-chosen, so the first 60 bytes of the stack overwrite are controlled → RCE primitive.

**Fix (one line, per-site):** reject `bufsiz == 0` at the top of
`ext2_read_symlink_target_impl` **and** in `sys_readlink` before the clamp:
```c
if (bufsiz == 0) return -EINVAL;   // ext2 path
```
Also consider clamping/rejecting in `sys_readlink` itself as defense-in-depth.

---

### C2 — FAT LFN `seq == 0` → 13-byte stack underflow write
**Severity:** CRIT (crafted-media) — `fs/fat.c:173-176` (`walk_dir`)

```c
171    if ((e[11] & ATTR_LFN) == ATTR_LFN) {
172        if (e[0] & 0x40) { kmemset(lfn, 0, sizeof lfn); have_lfn = 1; }
173        int seq = e[0] & 0x1F, base = (seq - 1) * 13;   /* seq==0 → base = -13 */
174        for (int k = 0; k < 13 && base + k < 259; k++) { /* signed compare passes for -13..-1 */
175            uint16_t ch; kmemcpy(&ch, e + LFN_POS[k], 2);
176            lfn[base + k] = (ch == 0 || ch == 0xFFFF) ? 0 : (char)(ch & 0xFF); /* lfn[-13..-1] */
```

`lfn` is `char lfn[260]` on the stack (line 160). A crafted FAT dirent with LFN attr (`0x0F`)
and `e[0] & 0x1F == 0` (e.g. `e[0] = 0x40`, the "last fragment" bit with seq zeroed) makes
`base = -13`; the signed `base + k < 259` guard passes, writing 13 attacker-controlled bytes
below `lfn` into adjacent stack locals (`sec[512]`, `have_lfn`, `cl`) and saved state.
Corrupting `cl` (the cluster pointer) redirects the directory walk to attacker-chosen clusters,
compounding with H4. Triggered by mounting/readdir on a crafted FAT image.

**Fix:** reject `seq == 0` (and `seq > 20`) before computing `base`.

---

## HIGH

### H1 — `sys_mremap` integer overflow → VMA-invariant corruption → double-free / UAF
**Severity:** HIGH — stock-reachable by a baseline-capability process
**File:** `syscall/sys_memory.c:934-983`

`mremap` is the one memory syscall that skipped the `USER_ADDR_MAX` / `MM_MAX_RANGE_PAGES`
bounds that `mmap`/`munmap`/`mprotect`/`brk` all enforce.

```c
946    uint64_t osz = (old_size + 4095UL) & ~4095UL;
947    uint64_t nsz = (new_size + 4095UL) & ~4095UL;     // no USER_ADDR_MAX check, no cap
970    uint64_t ext = old_addr + osz, glen = nsz - osz;
971    for (uint64_t va = ext; va < ext + glen; va += 4096UL) {   // ext+glen can wrap → loop skipped
972        if (vma_find(proc, va) || vmm_phys_of_user_raw(proc->pml4_phys, va))
973            return SYS_ERR(ENOMEM);
974    }
978    if (vma_insert(proc, ext, glen, prot, VMA_MMAP) != 0) ...
```

**Scenario:** `mremap(old_addr=0x10000, old_size=0x1000, new_size=0xFFFFFFFFFFFFE000, MAYMOVE)`.
`osz=0x1000`, `nsz=0xFFFFFFFFFFFFE000` (no wrap on round-up). `ext=0x11000`,
`glen=0xFFFFFFFFFFFFE000`, `ext+glen = 0xF000` (64-bit wrap) → scan loop `va < 0xF000` with
`ext=0x11000` does **not execute**. `vma_insert`'s successor-overlap test
`(base+len) > table[idx].base` is `0xF000 > X` → false for any higher mapping, so the overlap
check is bypassed. The new entry merges with the predecessor into a single VMA
`[0x10000, 0xF000)` that wraps the whole address space and **overlaps every existing VMA** —
breaking the sorted/non-overlapping invariant `vma_find`'s binary search and teardown depend on.
`munmap` of any page in that wrapped VMA frees a frame another live VMA still owns →
`pmm_free_page` of a still-mapped frame → UAF / heap corruption. Also corrupts
`proc->mmap_base` (`:980-981`).

**Fix:**
```c
if (nsz == 0 || nsz > USER_ADDR_MAX - old_addr || ext + glen < ext)
    return SYS_ERR(EINVAL);
```
and cap the grow scan with `MM_MAX_RANGE_PAGES` (see H3).

---

### H2 — AF_UNIX SCM_RIGHTS recursive `unix_lock` deadlock
**Severity:** HIGH — trivially reachable by any process that can create AF_UNIX sockets
**Files:** `net/unix_socket.c:339-356`, `:937-986`; allowed by `syscall/sys_socket.c:34-39`

`unix_sock_free` and `unix_sock_recv_fds` call `ops->close(priv)` on each staged passed-fd
**while holding `unix_lock`**:

```c
// unix_socket.c:341
irqflags_t fl = spin_lock_irqsave(&unix_lock);
...
// :353-356  (still under unix_lock)
for (uint8_t i = 0; i < us->passed_fd_count; i++) {
    if (us->passed_fds[i].ops && us->passed_fds[i].ops->close)
        us->passed_fds[i].ops->close(us->passed_fds[i].priv);
}
```

`scm_fd_passable` permits AF_UNIX socket fds (`sys_socket.c:36-38`); their `close` is
`unix_vfs_close` (`unix_socket.c:171-175`) → `unix_sock_free` → re-acquires the non-recursive
ticket lock (`core/spinlock.h:28-34`) → permanent IRQs-disabled hard lockup on the same CPU.

**Triggers:**
1. `socketpair`→(A,B); `socketpair`→(C,D). `sendmsg(A, SCM_RIGHTS, fd=C)` stages C on B.
   Close B without receiving → `unix_sock_free(B)` → refcount 0 → cleanup closes staged C →
   `unix_vfs_close(C)` → `unix_sock_free(C)` → `spin_lock_irqsave(&unix_lock)` → **deadlock**.
2. Receive side: stage a unix-socket fd on a peer, then `recvmsg` with a full fd table →
   `unix_sock_recv_fds` installs 0 fds and runs the cleanup close loop at `:978-981` under
   `unix_lock` → same deadlock.

Timer stops being serviced on the locked core; other unix-socket users spin on `unix_lock` →
system hang. No memory-safety escape, but trivially reachable permanent DoS.

**Fix:** capture the to-close fd list under `unix_lock`, release the lock, then close. (The
file already does this for ring-buffer `kva_free_pages` for exactly this reason — TLB
shootdowns must not run under the lock; `ops->close` can recurse the same way.)

---

### H3 — `sys_mremap` unbounded grow scan → unpreemptible core-wedge DoS
**Severity:** HIGH (DoS) — `syscall/sys_memory.c:971-974`

The scan loop has no per-page ceiling. With a huge non-wrapping `glen` (e.g.
`new_size = 0x7FFFFFFFFFFF0000`), the loop runs ~2³⁵ iterations, each doing a locked
`vma_find` (spinlock + binary search) and a locked 4-level `vmm_phys_of_user_raw` walk. Syscalls
run with `IF=0` (`IA32_SFMASK` clears IF on entry), so this cannot be preempted, interrupted, or
killed — a permanent wedge of that core from any process, no capability required. The comment
block at `sys_memory.c:40-58` explicitly calls out this exact class for
`munmap`/`mprotect`/`brk` and caps them with `MM_MAX_RANGE_PAGES`; `mremap` was missed. Once the
scan crosses `0x800000000000` into the kernel half, `vmm_phys_of_user_raw` returns 0 for the
physmap's 2 MB huge-page PDEs (`PTE_PS` → return 0, `vmm.c:950`), so the scan sees those kernel
pages as "free" and keeps going rather than terminating early.

**Fix:** cap the grow scan with `MM_MAX_RANGE_PAGES` (or drive it off the VMA table instead of
per-page).

---

### H4 — ext2 directory `i_size` not validated → infinite loop holding `ext2_lock`
**Severity:** HIGH (crafted-media → system-wide FS hang)
**Files:** `fs/ext2.c:1032` (`ext2_readdir`), `fs/ext2_dir.c:63` (`ext2_dir_add_entry`),
`fs/ext2_dir.c:194` (`ext2_dir_remove_entry`), `fs/ext2.c:2498` (`ext2_readdir`)

```c
/* ext2_readdir, ext2.c:1030-1037 */
uint32_t bytes_walked = 0;
while (bytes_walked < inode.i_size) {        /* i_size crafted = 0xFFFFFFFF */
    uint32_t blk = ext2_block_num(&inode, file_block_idx);
    if (blk == 0) {
        bytes_walked += s_block_size;         /* 0xFFFFF000 + 0x1000 → wraps to 0 */
        file_block_idx++;
        continue;                            /* 0 < 0xFFFFFFFF still true → infinite */
    }
```

`ext2_read` caps regular-file `i_size` against `ext2_max_file_size()` (`ext2.c:834`), but the
directory walkers do **not**. With a crafted directory inode `i_size = 0xFFFFFFFF` and sparse
`i_block[]`, `bytes_walked`/`pos` (uint32) increments by `s_block_size` until it wraps past
`0xFFFFF000` back to 0, which is still `< 0xFFFFFFFF` — a tight infinite spin. `ext2_block_num`
returns 0 for all out-of-range `file_block_idx` (triple-indirect unsupported, line 811), so every
iteration is the cheap `continue` path. The whole loop runs under `ext2_lock`, so on SMP every
other CPU touching the filesystem deadlocks. Trigger: `getdents`/create/unlink on a crafted
directory on mounted attacker media.

> **Note:** `ext2_walk_impl` (`ext2.c:1264`) is **not** affected — it does `if (blk == 0) break;`
> (line 1267) rather than `continue`. Both ext2 sub-audits initially mis-rated this as
> "bounded/terminating"; the uint32 wrap makes it genuinely infinite.

**Fix:** apply the `ext2_max_file_size()` cap to directory inodes after `ext2_read_inode` in
each walker.

---

### H5 — FAT cluster/chain/BPB validation gaps (DoS + arbitrary-LBA I/O)
**Severity:** HIGH (crafted-media) — `fs/fat.c`

- **H5a — cyclic cluster chain → infinite loop** (`fat.c:163,192`, also `fat_read:344,348,359`,
  `fat_free_chain:436-443`, `find_free_slot:468-488`, `dir_end_slot:556-568`,
  `fat_write:670-703`): the only terminators are `cl < 2` or `cl >= FAT_EOC` (`0x0FFFFFF8`); no
  visited-set, no iteration cap. A 2-cycle chain (FAT[100]=101, FAT[101]=100) reachable from the
  root directory loops forever in `walk_dir`/`fat_read`/`fat_free_chain`/`fat_write`. Any
  `open`/`readdir`/`stat` walking that directory hangs the kernel path resolver.
  **Fix:** iteration cap + visited-set on chain walks.

- **H5b — BPB fields unvalidated → geometry underflow/overflow** (`fat.c:245-272`): `reserved`,
  `fat_size` (upper bound), `total`, and `s_root_cluster` (line 255) are never validated. A
  crafted BPB with `total < s_data_lba` makes `s_total_clusters` underflow to ~0xFFFFFFFF;
  `s_root_cluster` may be 0/1 or beyond the volume. `s_data_lba = reserved + nfats*fat_size` can
  overflow uint32. All subsequent `cluster_lba`/`fat_next` calls compute out-of-range LBAs.
  **Fix:** validate BPB fields and bound `s_root_cluster`.

- **H5c — `cluster_lba` uint32 overflow → arbitrary-LBA disk I/O** (`fat.c:83-85`, `:88-95`,
  `:123-127`): `first_cluster` is taken straight from a dirent with no masking and no
  `>= s_total_clusters` check. A value like `0x0FFFFFF0` passes the `cl < FAT_EOC` gate, but
  `(cl-2) * s_spc` with `s_spc` up to 255 overflows uint32 → arbitrary LBA; `fat_read_lba`
  (`fat.c:78-81`) does no LBA bounds check and forwards `s_dev->lba_offset + lba` to the block
  device. Gives attacker-controlled on-disk read **and write** at arbitrary sectors.
  (`fat_next`'s `cl*4` does *not* overflow for `cl < FAT_EOC`; the real overflow is in
  `cluster_lba`.)
  **Fix:** mask `first_cluster` to 28 bits and range-check against `s_total_clusters`; add an LBA
  bounds check in `fat_read_lba`/`fat_write_lba`.

- **H5d — `lastname[16]` static-buffer overflow from a long path component** (`fat.c:226-227`,
  `resolve`'s `parent_cluster_out` branch): `n` can be up to 255, so
  `kmemcpy(lastname, comp, n+1)` copies up to 256 bytes into the 16-byte
  `static char lastname[16]` — a 240-byte overflow into file-scope BSS (the FAT geometry statics
  `s_dev`/`s_bps`/`s_spc`/`s_fat_lba`/`s_data_lba`/`s_root_cluster`/`s_total_clusters` at lines
  47-56 are the likely adjacent symbols). Reachable from `fat_lookup_parent` on the VFS O_CREAT
  path with a >15-char final component — a **path-resolution** buffer overflow, not strictly
  on-disk metadata.
  **Fix:** bound the `kmemcpy` to `sizeof(lastname)`.

---

### H6 — `vfs_scope_allows` 255-byte truncation → confinement bypass
**Severity:** HIGH (confinement) — `fs/vfs.c:90-114`

```c
96     char abs[256];
99         for (; path[i] && i < sizeof(abs) - 1; i++) abs[i] = path[i];   /* truncates to 255 */
105    abs[i] = '\0';
107    char canon[256];
108    path_canonicalize(abs, canon, sizeof(canon));    /* canonicalizes the TRUNCATED prefix */
110    uint32_t L = proc->vfs_scope_len;
112        if (canon[k] != proc->vfs_scope[k]) return 0;
113    return (canon[L] == '\0' || canon[L] == '/');    /* matches on the truncated prefix */
```

The scope check copies only the first 255 bytes of `path` into `abs`, canonicalizes that
truncated string, and prefix-matches; the backend (`g_rootfs->open(path, …)`) receives the full
untruncated path. A scoped process can pass a >255-char path whose truncated prefix canonicalizes
inside the scope but whose real suffix escapes via `..`. The shadow/admin/passwd/group and
`/bin`,`/sbin`,`/apps` inode gates (`vfs.c:315-349`) still protect crown-jewel files, so this
bypasses confinement only for non-cap-gated files outside the scope.

**Fix:** bound the scope check to the full path, not a 255-byte truncation (canonicalize the full
path, or reject paths longer than the buffer).

---

### H7 — `procfs gen_usbnet` unbounded write into a 4096-byte kva page
**Severity:** HIGH (hardware-attacker) — `fs/procfs.c:749-953`, dispatched by
`procfs_open_global` at `procfs.c:1319-1324`

```c
749    static uint32_t gen_usbnet(char *buf, uint32_t bufsz) {
752        char *p = buf;
753        (void)bufsz;                       /* bufsz discarded — no end pointer, no bound checks */
...
910        for (pn = 1; pn <= h.adopted_max_ports; pn++) {   /* ~100-130 B/iter, unbounded */
```

`pfs_strcpy`/`pfs_u64_dec`/`pfs_u64_hex` (`procfs.c:54-99`) are unbounded. `procfs_open_global`
allocates exactly one 4096-byte page (`kva_alloc_pages(1)`, line 1320) and calls `gen(buf, 4096)`.
Unlike `gen_maps`/`gen_mounts`/`gen_tasks`/`gen_status`, `gen_usbnet` never consults `bufsz` and
has no `(end - p)` margin guard. A host controller reporting many ports drives `*p++` past the
4096-byte buffer into the next kva page — a kernel heap OOB write.

**Threat-model caveat:** the trigger is a malicious/many-port USB host controller (hardware
attacker), not on-disk media; exploitability hinges on whether the xHCI driver caps
`h.adopted_max_ports` (not in the audited files).

**Fix:** use the `end`-bounded `pfs_b*` helpers that `gen_status` already uses.

---

### H8 — GPT partition bounce buffer OOB write/read (4K-native drives) → ring-0 / BSS leak
**Severity:** HIGH (privileged-precondition: `DISK_ADMIN` + 4K-native drive) —
`fs/gpt.c:110-150` (write at `:148`, read at `:127`)

```c
static uint8_t s_part_bounce[4096];  /* sized for one 4K native sector */   // gpt.c:108

static int gpt_part_write(blkdev_t *dev, uint64_t lba, uint32_t count, const void *buf)
{
    ...
    if (lba + count > dev->block_count) return -1;       // only guard: partition range
    uint32_t native_bs = p->parent->block_size;          // 4096 on a 4K-native drive
    if (native_bs == 512) return p->parent->write(...);
    uint64_t byte_count = (uint64_t)count * 512ULL;       // up to 128*512 = 65536
    uint32_t sub_off    = (uint32_t)(byte_start % native_bs);
    if (p->parent->read(p->parent, p->lba_offset + nat_lba, 1, s_part_bounce) < 0) return -1;
    __builtin_memcpy(s_part_bounce + sub_off, buf, byte_count);   // 65536 into 4096 → 60 KiB OOB
    return p->parent->write(p->parent, p->lba_offset + nat_lba, 1, s_part_bounce);
}
```

The comment at `gpt.c:100-106` claims "at most one native sector is ever needed per call because
ext2 block sizes ≤ native block size" — an **unenforced assumption about callers**. It is violated
by `sys_blkdev_io`, which chunks at `max_chunk = sizeof(s_bounce)/bs = 65536/512 = 128` sectors
(`sys_disk.c:142`). So `gpt_part_write`/`gpt_part_read` receive `count` up to 128 → `byte_count`
up to 65536, and `memcpy` 60 KiB past the 4096-byte static `s_part_bounce` into kernel BSS.

- **Write direction (`:148`):** the overflow bytes are fully attacker-controlled (they are the
  user's `s_bounce`, filled via `copy_from_user` in `sys_blkdev_io`). Adjacent BSS in the same
  translation unit includes `s_devs[]` (`blkdev_t` with `read`/`write` **function pointers**) and
  `s_parts[]`. Corrupting a function pointer and then triggering that partition's read/write yields
  a ring-0 call to an attacker-chosen address — a `DISK_ADMIN` → ring-0 cap-boundary break at
  runtime (no reboot needed).
- **Read direction (`:127`):** `memcpy(buf, s_part_bounce + sub_off, byte_count)` copies up to 60 KiB
  of kernel BSS (function pointers / kernel addresses → KASLR defeat) into `sys_blkdev_io`'s
  `s_bounce`, which is then `copy_to_user`'d to the caller. `DISK_ADMIN` authorizes raw disk
  access, not kernel-memory disclosure.

**Precondition:** `CAP_KIND_DISK_ADMIN` (admin_session tier) **and** a 4K-native namespace (NVMe
accepts `lbads=12`, `nvme.c:598-604`; a controller can report this). `DISK_ADMIN` is already
high-privilege (≈ raw-disk root), so this is a runtime cap-boundary break to ring-0 / a kernel
info leak, not a from-unprivileged foothold — but it is a clean kernel memory-corruption
primitive the cap model does not intend to grant.

**Fix:** before the `memcpy`, reject a request whose byte span exceeds one native sector:
`if (sub_off + byte_count > native_bs) return -1;` (or loop over native sectors instead of
assuming one suffices). Apply to both read and write.

---

### H9 — VGA ANSI CSI cursor-position signed-overflow → kernel OOB write (unprivileged console)
**Severity:** HIGH — stock-reachable by any user with the text console as an fd (server ISO)
**File:** `arch/x86_64/vga.c:69-80` (parse), `:158` (OOB write); reached via
`fs/kbd_vfs.c:40-41`

```c
// vga.c:68-80  (_vga_dispatch_csi, cmd 'H'/'f')
int row = 0, col = 0, i = 0;
while (i < s_esc_len && s_esc_buf[i] >= '0' && s_esc_buf[i] <= '9')
    row = row * 10 + (s_esc_buf[i++] - '0');   // signed int overflow → negative
if (row > 0) row--;
...
s_row = (row < VGA_ROWS) ? row : VGA_ROWS - 1;  // negative row passes '< 25' → stored as-is
s_col = (col < VGA_COLS) ? col : VGA_COLS - 1;

// vga.c:158  (vga_putchar, next printable byte)
vga[s_row * VGA_COLS + s_col] = vga_cell(c, VGA_ATTR);   // vga[-80] etc. → write before FB
```

`s_esc_len` is capped at 15 (`vga.c:128`), so the 10-digit string `"4294967295"` fits. The
accumulator reaches `429496729*10 + 5 = 4294967295 = 0xFFFFFFFF = -1` as `int32`, so `row = -1`;
`row > 0` is false (no decrement); `-1 < VGA_ROWS(25)` is true → `s_row = -1`. The next printable
byte writes `vga[-1*80 + 0]` = `vga[-80]`, i.e. `VGA_PHYS - 160` (`0xFFFFFFFF800B8000 - 160`) —
160 bytes **before** the framebuffer, into kernel memory. Other row values target other negative
offsets (down to ~2 GB below the FB in 160-byte windows; `s_col` gives 2-byte granularity).

**Reachability (confirmed):** on the x86_64 text-console (server ISO) profile, userspace console
output reaches this parser via `console_tty_write_out` (`kbd_vfs.c:32-46`), which calls
`vga_write_string(tmp)` **unconditionally on `vga_available`** (it deliberately bypasses
`printk_quiet` to preserve echo). A logged-in user on tty1 (console inherited as fd 0/1/2) runs
`printf '\033[4294967295H X'` (or `cat`s a file containing it) → kernel OOB write. Outcome:
`0xFFFFFFFF800B7F60` is in the kernel direct-map of low RAM → either silent low-memory corruption
(constrained 16-bit `char|attr` value) or, for larger negative offsets, an unmapped #PF in kernel
mode → **deterministic kernel panic**. The shared framebuffer parser `drivers/fb.c` is **not**
vulnerable (it uses `uint32_t row/col`, `fb.c:512`, which wraps and is caught by the clamp).

**Fix:** clamp `row`/`col` to `>= 0` before the range test, or parse into `uint32_t` and clamp
like `fb.c`:
```c
if (row < 0) row = 0;  if (row >= VGA_ROWS) row = VGA_ROWS - 1;
if (col < 0) col = 0;  if (col >= VGA_COLS) col = VGA_COLS - 1;
```

---

### H10 — `/proc/stackshot` (and `/proc/trace`, `/proc/dmesg`) unprivileged → scheduler freeze + lockless UAF/leak
**Severity:** HIGH — stock-reachable (`CAP_KIND_VFS_OPEN` is baseline, inherited by every process)
**Files:** `fs/procfs.c:1085-1091` (`gen_stackshot`), `:1118` (registry, mode 0444),
`:1316-1334` (`procfs_open_global` — **no cap check**); `sched/sched.c:1172-1234`
(`dump_all_tasks`)

`/proc/stackshot` is a world-readable 0444 global file opened through `procfs_open_global`, which
has **no capability gate** (the only `cap_check` in procfs.c is `procfs_check_access` for
`/proc/<pid>/`, line 965). `VFS_OPEN` is granted to init at `proc.c:409` and inherited by every
descendant, so any unprivileged process can open it. `gen_stackshot` calls `dump_all_tasks`, which:

```c
// sched.c:1181-1228
irqflags_t fl = arch_irq_save();
int locked = spin_trylock(&sched_lock);          // non-blocking
if (!locked) printk("[STACKSHOT] WARN: sched_lock busy; walk may be inconsistent\n");
aegis_task_t *t = cur;
do {
    ... printk(...) per task; print_backtrace_from(...) ...
    t = t->next;                                  // LOCKLESS if trylock failed
} while (t != cur && ++n < 256);
```

**Two failure modes, both reachable from userspace:**

**(a) Global scheduler freeze (deterministic DoS) — when `spin_trylock` succeeds.** The walk holds
`sched_lock` with `IF=0` across the *entire* loop, and every iteration calls `printk`, which
acquires `printk_lock` and busy-waits on the UART TX-ready bit at serial baud. Up to 256 tasks ×
multiple lines × 12-frame backtraces = kilobytes of serial output = **seconds** holding
`sched_lock`. Every other CPU spinning on `sched_lock` does so with `IF=0`, so no CPU takes timer
interrupts or schedules. One unprivileged `open("/proc/stackshot")` freezes the whole machine for
seconds. No race required.

**(b) UAF / info-leak / panic — when `spin_trylock` fails.** The walk proceeds **lockless** (only
`arch_irq_save` on this CPU; other CPUs still mutate the list). A concurrent `sys_waitpid` reaper
on another CPU unlinks a zombie and frees its PCB (`sys_process.c:1170` unlink under `sched_lock`,
then `kva_free_pages(child, 2)` at `:1263` after dropping the lock — `kva_free_pages` unmaps PTEs
**and returns the VA to the freelist for reuse**). The lockless `t = t->next` can follow a stale
pointer into that freed VA: if still unmapped → reading `t->is_user`/`t->sp`/`t->next` **#PFs in
kernel mode → panic**; if reused by a concurrent fork's `kva_alloc_pages` → reads the new
occupant's memory as a TCB, `t->sp` passes the `>= 0xFFFFFFFF80000000 && !(sp&7)` guard, then
`s[6]`/`s[4]` and `print_backtrace_from(s[4], 12)` **dump kernel stack/pointer contents to the
serial log**, readable back via `/proc/dmesg` (also world-readable, no cap gate) → kernel-address
info-leak.

**Trigger:** spawn many children exiting in a tight loop (keeps `sched_lock` contended so `trylock`
fails, and produces a steady stream of reaps), open `/proc/stackshot` from another process, read
`/proc/dmesg`. Outcome ranges from a kernel panic (DoS) to leaking kernel addresses.

**Fix:** remove `/proc/stackshot`, `/proc/trace`, `/proc/dmesg` from the world-readable procfs
root (gate behind an admin/debug cap). When invoked from procfs (not the wedged-CPU
SysRq/panic path at `serial.c:107`), `dump_all_tasks` should use a blocking
`spin_lock_irqsave(&sched_lock)` instead of `spin_trylock` so the list walk can never run against
a mutating list — the trylock fallback is only appropriate for the SysRq/panic path where
`sched_lock` may be held by a stuck CPU.

---

### H11 — virtio `used`-ring descriptor id not bounds-checked → OOB read of kernel memory
**Severity:** HIGH (device/host-attacker precondition) — `drivers/virtqueue.c:99-131`

```c
// virtqueue.c:108
*id = (uint16_t)vq->used->ring[slot].id;     // device-writable, NOT bounds-checked
...
// virtqueue.c:115-131  virtq_free_chain — head == the device-supplied id
uint16_t cur = head, guard;
for (guard = 0; guard < vq->size; guard++) {
    uint16_t next     = vq->desc[cur].next;   // OOB read if cur >= vq->size
    uint16_t has_next = (uint16_t)(vq->desc[cur].flags & VIRTQ_DESC_F_NEXT);
    if (cur < vq->size && vq->nfree < vq->size)   // guard protects ONLY the free-stack push
        vq->free[vq->nfree++] = cur;
    if (!has_next) break;
    cur = next;                               // OOB garbage → more OOB reads
}
```

`vq->used->ring[slot].id` is a device-writable uint32 truncated to uint16, so a malicious virtio
device can return any `id` in `[0, 0xFFFF]`. `vq->desc` is a single 4096-byte DMA page holding
exactly 256 descriptors; `vq->size ≤ 256`. The `cur < vq->size` guard on line 125 protects only
the free-stack push — the `vq->desc[cur]` reads on lines 123-124 happen unconditionally first.
`virtio_blk` calls `virtq_free_chain(&s_blk_vq, cid)` unconditionally after `virtq_poll_used`
(`virtio_blk.c:124-125`), before checking status. A malicious device completing with
`used.id = 0xFFFF` makes `virtq_free_chain` read `desc[0xFFFF]` = byte offset ~1 MiB past the
descriptor DMA page: unmapped → kernel #PF/panic (DoS); mapped → silent OOB read of adjacent
kernel memory, with the OOB `next` driving further OOB reads for up to `vq->size` iterations.

**Precondition:** a malicious virtio-blk device / host (in scope for a microVM kernel under a
potentially-hostile hypervisor), not a local unprivileged user.

**Fix:** in `virtq_poll_used` (or at the top of `virtq_free_chain`), validate `*id < vq->size`
before indexing `desc`; if out of range, log and return without walking.

---

## MEDIUM

### M1 — TIOCSCTTY controlling-terminal hijack
**Severity:** MED (auth-bypass of ctty model, local DoS / terminal hijack)
**File:** `tty/tty.c:537-547`

`TIOCSCTTY` overwrites `tty->session_id`/`tty->fg_pgrp` with **no** check that the tty is
unclaimed or already the caller's — unlike the adjacent `TIOCSPGRP` (`tty.c:502-530`), which
correctly checks `tty->session_id == 0 || tty->session_id != proc->sid` *and* requires
`CAP_KIND_PROC_READ`+`PROC_WRITE` and `tty_pgrp_in_session`:

```c
// tty.c:537-547  (TIOCSCTTY — the bug)
if (cmd == TIOCSCTTY) {
    aegis_task_t *t = sched_current();
    if (!t || !t->is_user) return -1;
    aegis_process_t *proc = (aegis_process_t *)t;
    if (proc->sid != proc->pid) return -1; /* only a session leader */
    irqflags_t pf = spin_lock_irqsave(&tty_global_lock);
    tty->session_id = proc->sid;            // no check the tty is unclaimed/the caller's
    tty->fg_pgrp    = proc->pgid;
    spin_unlock_irqrestore(&tty_global_lock, pf);
    return 0;
}
```

Combined with `sys_setsid` (`syscall/sys_identity.c:221-231`) having **no capability gate**, the
chain is: unprivileged child of a login shell (has console/PTY on fd 0/1/2) → `setsid()` (no
gate) → session leader → `ioctl(STDIN_FILENO, TIOCSCTTY, 0)` → steals the controlling terminal
from the shell's session. The shell's `tty_find_controlling(sid)` returns NULL (loses ctty), the
shell receives `SIGTTIN` on next stdin read (stopped), and Ctrl-C/SIGTSTP redirect to the
attacker's pgrp. More serious on multi-user systems.

**Fix:** mirror `TIOCSPGRP`'s guard:
```c
if (tty->session_id != 0 && tty->session_id != proc->sid) return -1;  /* EPERM */
```
and optionally reject if the caller already owns a controlling terminal (match Linux `TIOCSCTTY`
semantics). Consider gating `sys_setsid` too.

---

### M2 — `sys_write`/`writev`/`pwrite64` ignore `copy_from_user` return → kernel-stack info leak to file
**Severity:** MED (kernel-memory-to-file disclosure) — `syscall/sys_io.c:131,219,442`

```c
uint8_t staging[4096];
while (total < arg3) {
    uint64_t chunk = arg3 - total;
    if (chunk > sizeof(staging)) chunk = sizeof(staging);
    copy_from_user(staging, (const void *)(uintptr_t)(arg2 + total), chunk);   /* return IGNORED */
    int r = f->ops->write(f->priv, staging, chunk);
```

`staging` is uninitialized kernel stack. `copy_from_user` is fault-tolerant (exception-table
fixup in `arch/x86_64/arch_smap.c` / `idt.c:334-340`): on a partial fault it returns
bytes-not-copied and leaves the tail of `staging` untouched (stale kernel stack). The return is
ignored, so `f->ops->write` writes the full `chunk` — including the stale tail — to the file/pipe.

**Trigger:** a CLONE_VM sibling `munmap`s the page covering `buf + <fault offset>` while the
writer is blocked in a full pipe/AF_UNIX socket. The writer resumes, the next `copy_from_user`
faults, the fixup aborts the `rep movsb`, and `staging[fault_off..chunk]` retains prior
kernel-stack contents (kernel pointers → KASLR defeat; credential/arg snippets). Those bytes are
persisted to a file the caller has `VFS_WRITE` on, and the caller reads them back. `sys_pwrite64`
(line 442, `kbuf[4096]`) leaks to a file at an attacker-chosen offset; `sys_writev` (line 219)
likewise. `sys_sendto` (line 574) already checks the return — these three don't.

> A not-yet-faulted anonymous page does **not** trigger this — `idt.c:311-325` calls
> `mm_populate_fault` for kernel-mode #PF on a lazy user page and retries. The leak requires a
> genuinely unmapped page at copy time (the sibling-munmap race).

**Fix:** `if (copy_from_user(staging, ..., chunk)) return SYS_ERR(EFAULT);` (or short-write
`total` for a partial fault, matching `sys_sendto`).

---

### M3 — `vma_find` returns an unlocked pointer → SMP torn/stale read → cross-file data leak
**Severity:** MED (SMP data leak / wrong-frame map) — `mm/vma.c:107-122`

`vma_find` self-locks, does the binary search, **unlocks at line 120, then returns the raw
pointer** `&t[mid]`. On SMP, `IF=0` only masks interrupts on *this* CPU; a CLONE_VM sibling on
another CPU can take `vlock` and run `vma_remove` → `vma_shift_left` (`vma.c:77-83`), which
overwrites `t[mid]` with a different entry (or tears it mid-copy — `table[i] = table[i+1]` is a
non-atomic 48-byte struct copy).

Two callers read fields through the returned pointer *after* the lock is released:
- `mm_populate_fault` (`sys_memory.c:708-724`) snapshots `v->type`, `v->prot`, `v->file_ino`,
  `v->file_gen`, `v->file_off`, `v->file_size`, `v->base`, `v->len` from `v` after `vma_find`
  returns. A concurrent sibling `munmap` can shift a different VMA into that slot, so the fault is
  resolved using the **wrong file's** backing → populating the faulting page with a different
  file's contents (cross-file data leak / wrong-frame map), or computing a wild
  `fpos = foff + (va - vbase)` from a torn `base`/`len`.
- `sys_mremap` (`sys_memory.c:953`) reads `uint32_t prot = v->prot;` after `vma_find` and feeds
  it to `vma_insert`, so a torn/stale prot can be applied to the resized mapping.

**Fix:** return the entry by value (a `vma_entry_t` copy taken under the lock), or have those
callers take `vlock` and copy under it, rather than reading through the unlocked pointer.

---

### M4 — PT_INTERP interpreter loaded with no integrity/permission check
**Severity:** MED (latent privilege escalation) — `syscall/sys_exec.c:415-436` (also `:878-907`,
`proc/proc.c:130-156`)

The main binary gets an X_OK DAC check before loading:
```c
// sys_exec.c:182-186
int xperm = g_rootfs->check_perm(elf_ino, (uint16_t)proc->uid, (uint16_t)proc->gid, 1); // X_OK
if (xperm != 0) { ret = SYS_ERR(EACCES); goto done; }
```
The interpreter (PT_INTERP — the dynamic linker) gets **no such check** — it is opened and loaded
directly:
```c
// sys_exec.c:415-436
int vr = vfs_open(er.interp, 0, 0, &vf);   // no check_perm anywhere
...
int rr = vf.ops->read(vf.priv, interp_buf, 0, vf.size);
```
Worse, the capability policy is applied only to the **main binary's path**, never to the
interpreter (`sys_exec.c:364`). The interpreter's entry point becomes the actual RIP
(`sys_exec.c:686`: `has_interp ? interp_er.entry : er.entry`), so the interpreter runs first,
inside a process holding the main binary's granted caps.

**Scenario:** A privileged binary B (whose path has a cap policy granting elevated caps, e.g.
INSTALL/ADMIN) that the attacker can execute but not write, if B's `PT_INTERP` points at a
user-writable path P, lets the attacker write their own ELF to P and exec B. The kernel loads P as
the interpreter with no X_OK/trusted-location check, and P's code runs with B's granted caps —
the classic setuid-interpreter attack Linux defends against. Latent in a default install
(root-owned `/lib/ld*.so`), but no defense-in-depth exists. (The **shebang** interpreter *is*
X_OK-checked, because the shebang path replaces `path` and re-enters the lookup at
`reload_binary` `sys_exec.c:259-261` → `:175-196`. Only PT_INTERP escapes.)

**Fix:** X_OK-check `er.interp` (and require root-owned / trusted-dir) at all three sites; apply
cap policy to the interpreter path, or refuse `PT_INTERP` for policy-privileged binaries.

---

### M5 — `sys_brk` SMP race with concurrent `MAP_FIXED` → double-map panic
**Severity:** MED (kernel panic, requires CLONE_VM sibling) — `syscall/sys_memory.c:136-161`

```c
for (va = proc->brk; va < arg1; va += 4096UL) {                       /* 136 — pre-scan, no lock */
    if (vmm_phys_of_user_raw(proc->pml4_phys, va) != 0 ||
        vma_find(proc, va) != (vma_entry_t *)0)
        return proc->brk;                                             /* 139 */
}
for (va = proc->brk; va < arg1; va += 4096UL) {                       /* 141 — map loop */
    uint64_t phys = pmm_alloc_page();
    ...
    vmm_map_user_page(proc->pml4_phys, va, phys, ...);                /* 158 */
}
```

`vmm_map_user_page` panics on an already-present PTE (`vmm.c:622-625`:
`"[VMM] FAIL: vmm_map_user_page double-map"` → `panic_halt`). A sibling CLONE_VM thread can
`mmap(MAP_FIXED)` a page inside `[brk, arg1)` after this thread's pre-scan completes but before
the map loop reaches it (the mmap path and the brk path share no lock). The map loop then hits the
just-installed PTE and panics. `mmap`'s non-fixed path closed the analogous race with
`vma_insert`'s `-2` overlap rejection + atomic reservation; `brk` does neither.

**Fix:** hold `vma_lock` (or atomically reserve `[brk, arg1)` via `vma_insert` with `-2` retry,
like `sys_mmap`'s non-fixed path) across the pre-scan + map.

---

### M6 — ELF short-read not detected; `elf_size` trusts `vf.size` over bytes actually read
**Severity:** MED (info leak of recycled memory, crafted/corrupted media) —
`syscall/sys_exec.c:210-218` (also `:428-435`, `:820-825`, `:891-899`)

```c
int rr = vf.ops->read(vf.priv, ext2_buf, 0, vf.size);
if (vf.ops->close) vf.ops->close(vf.priv);
if (rr < 0) { ret = SYS_ERR(EIO); goto done; }
elf_data = (const uint8_t *)ext2_buf;
elf_size = vf.size;          // <- uses declared size, not bytes read (rr)
```

`ext2_buf` is allocated via `kva_alloc_pages`, which does **not** zero its frames
(`elf.c:263-272`: "kva_alloc_pages does not zero and pmm_free_page does not scrub"). For a
well-formed ext2 file, `ext2_read` clamps `len` to `i_size` and returns the full size, so
`rr == vf.size`. But `ext2_read` returns a **short read** (`return (int)bytes_read;` at
`ext2.c:896/904`) when it hits an out-of-range block number or a device read error partway. Then
`rr < vf.size`, the tail `[rr, vf.size)` of `ext2_buf` holds **uninitialized recycled PMM frames**
(another process's freed memory, kernel stacks, etc.), and `elf_load` is called with
`len = vf.size`. If a PT_LOAD's `[p_offset, p_offset+p_filesz)` extends into that tail,
`elf_load`'s copy loop (`elf.c:279-281`) copies those uninitialized bytes into the user-mapped
segment, which the user can then read — an **information leak of recycled kernel/user memory**.

**Trigger:** exec a file on a corrupted ext2 image whose inode block list contains an out-of-range
block number partway through, while the ELF header + phdrs sit in the first (readable) block and a
PT_LOAD's file bytes extend past the short-read boundary. Also reachable on a block-device I/O
error mid-read.

> The related `(vf.size + 4095ULL)/4096ULL` page-count expression (`sys_exec.c:205/422/814/885`)
> is **not** an overflow: ext2's on-disk `i_size` is 32-bit with no `i_size_high`, and
> `ext2_read` rejects `i_size > ext2_max_file_size()` (`ext2.c:834`), so `vf.size < 4 GiB`.

**Fix:** `if (rr < (int)vf.size && rr >= 0) { ...reject or zero-fill... }`, or zero the unused
tail, or pass `rr` as `len` to `elf_load`.

---

### M7 — `memfd_truncate` integer overflow bypasses `MEMFD_PAGES_MAX`
**Severity:** MED (cap circumvention + corrupted `st_size`) — `fs/memfd.c:201`

```c
uint32_t new_pages = (uint32_t)((size + 4095) / 4096);   /* size+4095 wraps when size ~ UINT64_MAX */
if (new_pages > MEMFD_PAGES_MAX) { ... return -ENOMEM; }
```

`sys_ftruncate` passes the user 64-bit `length` straight through. `ftruncate(fd, 0xFFFFFFFFFFFFF001)`
makes `size + 4095` wrap to a small value, so `new_pages = 0` passes the cap; `mf->size` is then
stored as `0xFFFFFFFFFFFFF001` with `page_count = 0` (line 278). No OOB results —
`memfd_vfs_read` clamps `len` to `mf->size - off` and the `page_idx < page_count` (0) check routes
all reads to the zero-fill branch — but the explicit 8 MiB size cap is circumvented and
`st_size` reports a corrupted value.

**Fix:** `if (size > MEMFD_PAGES_MAX * 4096ULL) return -ENOMEM;` before the addition.

---

### M8 — `fat_write` `off + done` uint32 wrap → size-field corruption
**Severity:** MED (crafted-media) — `fs/fat.c:700-702`

```c
uint32_t ns = off + done;                       /* both uint32; can wrap */
patch_entry(ino, first, ns > d.size ? ns : d.size);
```

A wrapped `ns` records a size smaller than what was written, leaving the size field inconsistent
with the cluster chain. Combined with H5c (unvalidated cluster numbers), a crafted pre-existing
file with a huge `d.size` and a short/cyclic chain can drive further corruption.

**Fix:** widen `ns` to 64-bit or bound `off + done` against `d.size`/volume size.

---

### M9 — GPT parser trusts on-disk LBA fields without bounding to the device
**Severity:** MED (crafted-media; virtio-blk/AHCI lack the LBA range check NVMe has) —
`fs/gpt.c:235, 278, 282-283`

```c
// gpt.c:278
s_parts[idx].lba_offset = e->start_lba;                 /* no check vs dev->block_count */
// gpt.c:282-283
uint64_t native_count = e->end_lba - e->start_lba + 1;   /* attacker-controlled, can wrap */
s_devs[idx].block_count = native_count * (dev->block_size / 512u);
...
// gpt.c:235 — partition_entry_lba also unbounded
if (dev->read(dev, hdr.partition_entry_lba + ei, 1, s_entry_chunk) < 0) { ... }
```

`start_lba`, `end_lba`, and `partition_entry_lba` are read straight off the disk image and used
to (a) read the entry array and (b) set the partition's `lba_offset`, with no check that they lie
within `[0, dev->block_count)` or within `first_usable_lba..last_usable_lba`. NVMe rejects the
resulting out-of-range reads in `nvme_io_validate` (`nvme.c:711-714`), but **virtio-blk and AHCI
have no LBA range check** (`virtio_blk.c:142-174`, `ahci.c:213-262` — neither references
`dev->block_count`), so an attacker-crafted GPT on those transports forwards arbitrary,
device-supplied LBAs straight to the hardware. No kernel-memory corruption (the data is
device-supplied), but the kernel fails to enforce the device-size boundary the capability model
promises, and `native_count` can wrap to a small `block_count`, defeating the partition bounds
check's intent.

**Fix:** in `gpt_scan`, reject entries where `e->start_lba < first_usable_lba ||
e->end_lba > last_usable_lba || e->start_lba >= dev->block_count || e->end_lba >= dev->block_count`;
bound `hdr.partition_entry_lba` similarly before the read loop. Independently, virtio-blk/AHCI
should gain the `lba+count > block_count` check NVMe already has.

---

### M10 — User-process kernel stacks have no guard page (x86_64 + arm64)
**Severity:** MED (defense-in-depth / kernel-bug amplifier) — `proc/proc.c:103`,
`syscall/sys_process.c:493,902`; contrast `sched/sched.c:313-318` (kernel tasks — guard present)

Kernel-task stacks allocate a guard page; user-process kernel stacks do not.

```c
// sched.c:313-318  (kernel tasks — guard present)
uint8_t *stack_region = kva_alloc_pages(STACK_PAGES + 1);
uint64_t guard_phys   = kva_page_phys(stack_region);
vmm_unmap_page((uint64_t)(uintptr_t)stack_region);
pmm_free_page(guard_phys);
uint8_t *stack = stack_region + 4096UL;   /* usable stack starts above the guard */

// proc.c:103  (user processes — no guard)
uint8_t *kstack = kva_alloc_pages(STACK_PAGES);
// sys_process.c:493,902  (fork/clone child stacks — no guard)
uint8_t *kstack = kva_alloc_pages(4);
```

A user-process kernel stack that grows past its 16 KiB bottom does not hit an unmapped guard page
(no #PF on x86, no EL1 data-abort on arm64). Because `kva_alloc_pages` returns contiguous mapped
pages, the overflow silently writes into whatever kva allocation is immediately below (another
process's PCB/stack, kernel data) instead of tripping a clean #DF/panic — exactly the failure mode
the `sched.c` guard exists to prevent. This converts a future kernel stack-overflow bug (e.g. the
8 KB `saved[]` array in L6, or deep recursion) from "safe panic" into "silent kernel-memory
corruption." `proc.c` is arch-agnostic, so the gap exists on both x86_64 and arm64.

**Reachability caveat:** normal syscall depth is well within 16 KiB (deepest documented chain
~4.4 KiB for `pipe_write_fn`), and syscalls run with `IF=0` so timer IRQs do not nest on top. So a
user cannot trivially overflow the stack without a kernel bug or pathological nesting — the
finding is the inconsistency and the lost safety barrier, not a one-syscall DoS.

**Fix:** mirror `sched.c:313-318` in `proc.c:103` and `sys_process.c:493/902` —
`kva_alloc_pages(STACK_PAGES + 1)`, unmap+free the lowest page, point `stack_base`/
`kernel_stack_top` one page up.

---

## LOW

### L1 — `procfs_stat` skips `procfs_check_access` → minor existence info leak
**File:** `fs/procfs.c:1453` — `stat` on `/proc/<pid>/*` without `CAP_KIND_PROC_READ` reveals
existence/size info. Generators are otherwise unbounded by `bufsz` but safe given the 4096 buffer
+ 256-byte `exe_path`.

### L2 — `sys_ppoll` signed overflow / unvalidated `tv_nsec`
**File:** `syscall/sys_poll.c:47` — `ts.tv_sec * 1000` signed-overflow (UB) near
`INT64_MAX/1000`; `tv_nsec` not range-checked (contrast `sys_nanosleep`). Wraps negative →
`ms < 0` clamp → 0-timeout (silent return instead of wait). DoS/correctness. (The same
`tv_sec * 1000` pattern in `sys_select`/`sys_pselect6` uses a `uint64_t` cast → wraps, not UB.)

### L3 — `stat_copy_path` / `copy_path_from_user` `bufsz==0` underflow (latent)
**Files:** `syscall/sys_file.c:224,941` — `for (i = 0; i < bufsz - 1; i++)` with `bufsz` uint32:
`bufsz==0` → `0xFFFFFFFF` iterations, OOB stack/heap write. **Not reachable today** — every
caller passes a compile-time `sizeof > 0`. Latent footgun for any future runtime-`bufsz` caller.

### L4 — `sys_open` path normalization silent >254-byte segment truncation
**File:** `syscall/sys_file.c:110-111` — a path segment >254 bytes is silently truncated during
normalization, so two distinct paths can normalize to the same key. Defense-in-depth only (the
authoritative check is the inode-based `path_under_protected` / `vfs_open_ex` install gate).

### L5 — `sys_munmap` / `sys_brk` bound off-by-one vs `sys_mmap`
**Files:** `syscall/sys_memory.c:861-864` (`munmap`), `:91` (`brk`) clamp to
`0x00007FFFFFFFFFFF` (`USER_ADDR_MAX`); `sys_mmap` (`:382-384`) clamps to `0x800000000000`. So
the last user page `[0x7FFFFFFFFFF000, 0x800000000000)` is mappable by `mmap(MAP_FIXED)` but
**not unmunmapable** (`0x800000000000 > 0x7FFFFFFFFFFF` → `EINVAL`) — leaked until exit.
**Fix:** unify bounds to `0x800000000000`.

### L6 — 8 KB stack array on a 16 KB kernel stack in the shebang path
**File:** `syscall/sys_exec.c:247` — `char *saved[EXECVE_MAX_ARGV]` with `EXECVE_MAX_ARGV = 1024`
(`sys_impl.h:84`) → 8192 bytes. Coexists with `path[256]`, `shebang_interp[256]`,
`shebang_arg[256]`, `script_path[256]`, two `elf_load_result_t` (~1 KB) and the callee chain
(`resolve_path` → `vfs_open` → `ext2_walk` → `ext2_read_inode` → device reads). Any user can
trigger this via a `#!` script. Thin margin → potential kernel stack overflow / double-fault.
**Fix:** allocate `saved` from the kva arg buffer (which already exists for argv) instead of the
kernel stack.

### L7 — `eventfd2` unvalidated `initval`
**File:** `fs/eventfd.c:188` — `eventfd2(0xFFFFFFFFFFFFFFFF, 0)` sets `count = UINT64_MAX`,
defeating the write-side overflow check (`1 > EFD_VALMAX - count` wraps to false) and breaking
the counter invariant. No memory-safety impact.

### L8 — `procfs pfs_parse_pid` uint32 overflow
**File:** `fs/procfs.c:1261-1272` — `/proc/4294967297/maps` → pid 1. Non-exploitable:
`procfs_check_access` still requires `CAP_KIND_PROC_READ` for non-self targets.

### L9 — `sys_mount` errno confusion
**File:** `syscall/sys_mount.c:67-70` — maps a `copy_path_from_user` `-ENAMETOOLONG` return to
`SYS_ERR(EFAULT)`. Not a security hole; a path-too-long is misreported as a bad pointer.

### L10 — Stale `uaccess_user.h` comment
**File:** `mm/uaccess_user.h:7-17` — claims `copy_from_user`/`copy_to_user` have "NO fault-fixup
table" and that a kernel-mode #PF on an unmapped user pointer "panics the kernel." False as of
current code: the copy IS fault-tolerant via `__ex_table` (`arch_smap.c:171-202`) and the #PF
fixup path (`idt.c:334-340`). Security-relevant because it leads developers to believe ignored
`copy_from_user` returns are panic-prone (they are not — they leak, per M2). Correct the comment.

### L11 — SMAP/PAN disabled kernel-wide (latent)
**Files:** `arch/x86_64/arch_smap.c` (`arch_smap_enabled = 0`), `arch/arm64/arch.c:32`
("PAN not enabled yet"); `CR4.SMAP` never set. The net code is written *assuming* SMAP is on —
UDP and AF_UNIX read/write paths bounce through a kernel stack buffer ("With SMAP enabled, the
kernel cannot access them directly", `unix_socket.c:139-156`). The TCP `read()` path does
**not** bounce: `sock_vfs_read` (`net/socket.c:56-119`) hands the user `buf` straight to
`tcp_conn_recv`, which does `__builtin_memcpy(d, &c->rbuf[hoff], first)` (`net/tcp.c:1349`)
directly into user memory. With SMAP off this works; if SMAP/PAN were ever enabled (as the TODOs
say is intended), this path would #PF in ring 0 and panic. Not exploitable now, but fix for
consistency before SMAP is turned on.

### L12 — `vfork_freeze` silently skips at >16 concurrent vforks
**File:** `sched/sched.c:163-178` — `VFORK_FROZEN_MAX = 16`; with `MAX_PROCESSES = 256`, an
attacker creating ≥17 thread groups that `vfork` simultaneously overflows the 16-slot set; the
17th group's freeze is silently dropped, so its siblings run concurrently with the vfork child
that shares their PML4, corrupting the child's exec setup — exactly the corruption the freeze
exists to prevent. The comment accepts this as "never-hit," but it is reachable from hostile
userspace. **Fix:** grow `VFORK_FROZEN_MAX` with `MAX_PROCESSES`, or fail the 17th `vfork` with
`EAGAIN` instead of silently skipping the freeze.

### L13 — virtio queue size accepted without power-of-two validation
**File:** `drivers/virtio_core.c:195,220` — `qsz` is capped to 256 but not validated to be a
power of two as the spec requires. `VQ_MASK(vq) = vq->size - 1` (`virtqueue.c:22`) is only a valid
modulo when `size` is a power of two. With a non-power-of-two `qsz` (e.g. 3), `ai & (size-1)` and
the device's `idx % size` diverge, so the driver reads used-ring slots the device did not intend
— driver/device desynchronization (stalled I/O / DoS) with a malicious device. All indices stay
`< size ≤ 256` and rings are sized `VIRTQ_SIZE=256`, so no OOB. **Fix:**
`if (dev_max == 0 || (dev_max & (dev_max - 1))) return -1;`.

### L14 — NVMe MDTS/MPSMIN shift can zero `s_max_xfer` → all disk I/O fails (DoS)
**File:** `drivers/nvme.c:556-558,124` — `mps_min = 4096u << ((cap >> 48) & 0xF)` (up to
`4096<<15 = 0x80000000`) and `mdts` (from the Identify response) are device-controlled. With
`MPSMIN=15` and `mdts=1`, `mps_min << 1` overflows uint32 to 0, so `s_mdts_max=0`,
`s_max_xfer=0`; every subsequent `nvme_io_validate` rejects (`bytes64 > s_max_xfer`) and all disk
I/O fails. The overflow can only shrink `s_max_xfer` (capped by `bounce_bytes` otherwise), so
DoS-only, not OOB. A malicious controller can DoS anyway, hence LOW. **Fix:** compute
`s_mdts_max` in uint64 and reject/clamp when the shift would exceed the bounce budget.

### L15 — RNG has no readiness gate; seed is timing-only on virtio-rng-less systems
**File:** `core/random.c` — `random_init` (`:218-265`) seeds the entire 256-bit ChaCha20 key +
64-bit nonce from only four `arch_get_cycles()` reads and one `arch_get_ticks()` read.
`random_get_bytes` (`:196-213`) never blocks and has no "not yet seeded" state — the pool is
considered seeded the moment `random_init` returns. Linux blocks `getrandom` until the CRNG is
ready; Aegis does not. Mitigations present (hence LOW): `virtio_rng_init` mixes 64 bytes of
host entropy via `random_add_entropy` before `proc_spawn_init` (`main.c:439,571`), and the
PIT/keyboard ISRs call `random_add_interrupt_entropy` (`pit.c:109`, `kbd.c:507`) throughout the
window between `random_init` (`main.c:351`) and init spawn. Residual exposure: on a deterministic
VM **without** virtio-rng (or bare metal that boots before meaningful interrupt entropy
accumulates), the first `getrandom`/`AT_RANDOM` draws from a CSPRNG seeded only from a handful of
cycle-counter samples — the classic early-boot entropy-starvation hole, with no readiness gate to
fall back on. **Fix:** require a minimum entropy-count threshold before serving bytes (block or
mix until `s_entropy_count >= N`), and fold any available HW RNG (virtio-rng, RDRAND if present)
into the initial seed unconditionally.

### L16 — `#DF` IST stack is a single 4 KiB page (x86_64)
**File:** `arch/x86_64/tss.c:19-24` — the #DF handler runs on this 4 KiB IST stack and, via
`isr_common_stub` → `isr_dispatch` (vector 8), calls `printk` repeatedly, `panic_backtrace`
(RBP-chain walk), and `panic_bluescreen` (framebuffer writes). 4 KiB is tight for that call chain;
overflowing it has no guard page below and produces a triple fault (silent reboot) instead of a
diagnosable panic. #DF is already fatal and not user-reachable (IDT gates are DPL=0, so
`int $8` from ring 3 raises #GP not #DF), so this is a diagnostics-reliability issue, not a
privilege issue. **Fix:** allocate 2 pages for the #DF IST and keep the lower one as a guard, or
trim the #DF path to a minimal printk before halting.

### L17 — Kernel-mode #PF demand-paging/COW does not gate on the faulting RIP
**File:** `arch/x86_64/idt.c:291-326` (and `arch/arm64/traps.c:235-251`) — when a kernel-mode #PF
hits a present-but-COW or not-present user page, the handler populates/breaks-COW and retries
**before** the exception-table lookup, with no check that the faulting RIP is a registered uaccess
site. The intended user is `copy_*_user` into lazy/COW buffers, but the path accepts *any* kernel
RIP faulting on *any* user address. A genuine kernel pointer-confusion bug that happens to land in
the user half is thus silently resolved (page populated / share broken, faulting instruction
retried) instead of reaching the exception-table check or panicking — masking kernel bugs rather
than catching them. **Fix:** require the faulting RIP to be a registered uaccess site before
populating/breaking-COW from kernel mode; otherwise fall through to the exception-table/panic path.

---

## Audited and found GUARDED (no issue) — for the record

- **Capability model core** (`cap.c`, `cap_policy.c`): no ambient-authority bypass found. Every
  privileged syscall gates the correct cap (MOUNT, DISK_ADMIN, FB, NET_SOCKET/IPC/ADMIN,
  PROC_READ, POWER, SETUID, AUTH, ADMIN_AUTH, INSTALL, CAP_QUERY). `cap_check` fail-closed
  (`-ENOCAP = -EPERM`). `sys_setuid`/`setgid` are bound-identity (no give-away). `sys_admin_session`
  re-derives parent caps under `sched_lock` with re-find-after-policy-read (avoids the freed-PCB
  write). Trusted-path anchoring (`/bin /sbin /apps` + dynamic anchors, `path_under_protected`
  inode check) is sound.
- **Signal delivery / sigreturn** (`signal.c`, `sys_signal.c`): sigframe sanitization correct on
  both arches — RIP canonical-user check, RFLAGS mask `0xCD5|0x202`, PSTATE `0xF0000000`; no
  kernel-PC/IOPL/EL1 injection. `sigset` size==8 enforced; handler/restorer user-addrs validated.
- **ELF parser** (`proc/elf.c`): program-header arithmetic overflow-safe throughout; BSS fully
  zeroed; W^X enforced; double-map preempted by per-page overlap check; entry-point bounded
  (closes SYSRET-non-canonical-#GP-at-CPL0); `kva_alloc_pages` NULL handled.
- **ext2 block-number trust**: every block from `i_block[]`, indirect blocks, and BGD fields
  reaches disk only through `cache_get_slot` (`ext2_cache.c:107`), which rejects
  `>= s_blocks_count`; the `ext2_read` fast path re-checks `blk < s_blocks_count`
  (`ext2.c:869,886`). ext2 mount geometry validated (`ext2.c:446-500`). Directory-entry walkers
  guard `rec_len < 8`, `block_pos + rec_len > s_block_size`, `name_len + 8 > rec_len`.
- **IP/TCP/UDP/eth parsing**: no integer-overflow or buffer-overflow in header handling, options
  parsing, or reassembly (deliberately none — IP fragments dropped `ip.c:354`, out-of-order TCP
  dropped). Ring writes gated by `space = (SIZE-1) - used`. UDP payload capped to 1500. ARP table
  mutation under `arp_table_lock`; unsolicited replies rejected.
- **epoll**: duplicate-ADD rejected, `nwatches` capped, `epoll_wait` re-validates user buffer each
  iteration, `maxevents * sizeof` computed in uint64. No UAF / double-registration.
- **fd_table.c**: iterators bounded by `PROC_MAX_FDS`; `fd_table_assert_live` + `FD_TABLE_POISON`
  + atomic refcount prevent double-free/UAF on close (stale use panics).
- **ramfs.c**: `ramfs_write_fn` clamps `len` to `RAMFS_MAX_SIZE - base`; names bounded by
  `rfs_name_ok`/`rfs_strcpy`.
- **futex.c**: 4-byte align + `user_ptr_valid` on uaddr/addr2; per-address-space quota; lost-wakeup
  guards correct.
- **sys_disk.c**: DISK_ADMIN cap + overflow-safe bounds (`count > block_count || lba > block_count - count`),
  fail-closed, `bs > s_bounce` rejected.
- **COW fork** (`vmm.c:1420-1580`): reuse-in-place refcount check + PTE flip under continuous
  `vmm_window_lock`; `pmm_lock` taken in canonical `vmm_window_lock > pmm_lock` order; no TOCTOU.
- **Scheduler / PCB lifetime** (pass 2): every `proc_find_by_pid_locked` caller holds `sched_lock`
  across the dereference and any write (`sys_setpgid`, `sys_getpgid`, `sys_exit` thread-count
  decrement, `sys_cap_query`, `sys_admin_session`, procfs walkers) — no use-after-lock-drop UAF.
  `sys_waitpid` reaper is correct (unlink+capture under lock, drop, spin on `on_cpu` to confirm
  the dying task's `ctx_switch` published `on_cpu=-1` before freeing the stack; `leader_not_reapable`
  prevents reaping a group leader while a sibling runs; WNOHANG vs concurrent exit covered by
  `sched_block_locked`). Lost-wakeup / `wake_pending` machinery sound. TLB shootdown
  (`arch/x86_64/tlb.c`) handles late/aliased IPIs; shootdowns called outside `sched_lock`.
  `setpgid`/`setsid`/`getpgid` pgrp/session mutation under `sched_lock`. Fork-count/pid accounting
  bounded by `MAX_PROCESSES=256`.
- **Block layer / NVMe / virtio_blk / AHCI** (pass 2): `blkdev` registry serialized on
  `blkdev_lock`, name walks bounded by `name[16]`. NVMe `nvme_io_validate` solid (64-bit
  `count*block_size`, NLB underflow guard, 64-bit `lba+count` range check, QD1 synchronous so no
  CID-reuse race, PRP bounded by `NVME_BOUNCE_PAGES`). virtio_blk/AHCI chunking overflow-safe
  (`nsec ≤ 8`/`64`, `nbytes ≤ 4096`, `npages ≤ 8`) — the only gap is the missing LBA range check
  (→ M9). GPT CRC/header validation solid (`header_size` 92..512, `num_partition_entries ≤ 128`,
  `partition_entry_size == 128` before the array read). No driver can present `block_size > 4096`
  to bypass `sys_blkdev_io` (NVMe clamps `lbads` 9..12; `sys_disk.c:138` rejects `bs > s_bounce`).
- **Arch fault / entry / syscall dispatch** (pass 2): exception-table coverage complete — the only
  direct user-VA deref is the `rep movsb` in `__uaccess_copy` (`arch_smap.c:171-202`, both load+store
  registered) and the arm64 `ldr`/`str` pair (`uaccess.S:36-49`); `vmm_write_user_*` walk page
  tables through a kernel window, never dereferencing the user VA. SYSRET `rcx` always canonical
  user; IRETQ/ERET sigreturn sanitizes `cs/ss/spsr/rip/rflags`; fork/clone/`proc_enter` force
  `CS=USER_CS`, `SS=USER_DS`, `RFLAGS=0x202` / `SPSR=0` EL0t; `isr.asm:271-273` forces `SS.RPL=3`
  on every ring-3 iretq. `IA32_SFMASK=0x700` clears IF/TF/DF on SYSCALL; all IDT gates are
  interrupt gates (IF=0 on entry); all return paths restore IF=1. No runtime KASLR leak (no
  syscall returns a kernel pointer; `ARCH_GET_FS` returns the user-constrained FS base). Syscall
  dispatch is a `switch` (out-of-range → `ENOSYS`), not a table index — no OOB. `#DF` is IST-gated,
  excluded from the ring-3 signal path, and not user-reachable (DPL=0 gates; `int $8` from ring 3 →
  #GP, not #DF).
- **Misc subsystems** (pass 2): keyboard scancode tables bounded (`sc < SC_TABLE_SIZE` gate,
  `kbd.c:489`); E0-prefixed keys use a `switch`; `kbd_*inject` ring bounded. ISIG `fg_pgrp`
  redirection can't reach init (`signal_send_pgrp` excludes `pid != 1`, `signal.c:577`), so the
  `sys_kill` PID-1 POWER gate isn't bypassable via ISIG. `drivers/fb.c` CSI parser uses `uint32_t`
  + clamp (safe — contrast the VGA bug H9). shm / `MAP_SHARED` memfd refcounting consistent
  (`ref-on-map` + `ref-drop-on-unmap`, `VMM_FLAG_SHARED` vs `SHARED_OWNED` distinguished; no
  double-free/UAF; `memfd_truncate` shrink bounded, OOM-mid-grow leaves `page_count` at
  `old_count`). `sys_reboot` POWER-gated for both cmd=0/1; no bypass path. First-boot marker
  re-checked on every `cap_policy_is_firstboot` call (clears `g_first_boot` the moment
  `/etc/aegis/configured` appears); firstboot tier grants only to the anchored `configure` binary;
  `admin_session_firstboot` dropped at exec. Cap delegation can only restrict, never escalate
  (`CAP_DELEGATE` required, `kind <= CAP_KIND_MAX`, parent must hold the cap with ≥ requested
  rights, child grant intersected with computed baseline+policy; runtime cap-grant syscall
  removed). PTY refcounting with read-side pinning sound (no slot-reuse UAF). RNG is a single
  global CSPRNG (no per-process fork-reserved-state leakage); rekey/refill avoids keystream reuse.

---

## Recommended fix order (hit list)

> Re-ranked after pass 2. Items marked **[stock]** are reachable by an unprivileged process with
> only baseline caps; **[priv]** need a non-trivial cap; **[media]** need crafted mounted media;
> **[device]** need a malicious device/host.

1. **C1** [stock] — `readlink` `bufsiz==0` underflow (`ext2.c:1138` + `sys_meta.c`): one-line
   reject. *Stock-reachable kernel stack corruption.*
2. **H9** [stock] — VGA ANSI CSI signed-overflow OOB write (`vga.c:69-80,158`): clamp `row`/`col`
   `>= 0` (or use `uint32_t` like `fb.c`). *Unprivileged console write → kernel OOB write / panic.*
3. **H10** [stock] — `/proc/stackshot` (and `/proc/trace`, `/proc/dmesg`) unprivileged scheduler
   freeze + lockless UAF/leak (`procfs.c:1118,1316` + `sched.c:1182`): gate behind a cap; use
   blocking `spin_lock_irqsave` from the procfs path.
4. **H1** [stock] — `mremap` overflow → UAF (`sys_memory.c:934`): add `USER_ADDR_MAX` + overflow
   checks.
5. **H2** [stock] — SCM_RIGHTS `unix_lock` deadlock (`unix_socket.c:339,937`): close staged fds
   after dropping the lock.
6. **H8** [priv] — GPT partition bounce OOB write/read (`gpt.c:127,148`): bound
   `sub_off + byte_count` to `native_bs`. *DISK_ADMIN → ring-0 / BSS leak on 4K-native drives.*
7. **H3** [stock] — `mremap` unbounded scan (`sys_memory.c:971`): `MM_MAX_RANGE_PAGES` cap.
8. **C2** [media] — FAT LFN `seq==0` underflow (`fat.c:173`): reject `seq==0`/`seq>20`.
9. **H4** [media] — ext2 dir `i_size` infinite loop (`ext2.c:1032` + `ext2_dir.c`): cap to
   `ext2_max_file_size()`.
10. **H5** [media] — FAT chain/BPB/cluster/`lastname` (`fat.c`): iteration cap + visited-set, BPB
    validation, 28-bit cluster mask + range check, bound `lastname` copy.
11. **M2** [stock] — ignored `copy_from_user` returns (`sys_io.c:131,219,442`): check the return.
12. **M1** [stock] — TIOCSCTTY hijack (`tty.c:537`): mirror `TIOCSPGRP`'s guard.
13. **M3** [stock, SMP] — `vma_find` unlocked pointer (`vma.c:107`): return by value /
    lock-and-copy.
14. **M4** — PT_INTERP integrity (`sys_exec.c:415`): X_OK-check + cap policy on interpreter.
15. **M5** [stock, SMP] — `brk`/`MAP_FIXED` race (`sys_memory.c:136`): lock across scan+map.
16. **H6** — `vfs_scope_allows` truncation (`vfs.c:90`): bound to full path.
17. **H7** [device-ish] — `gen_usbnet` unbounded write (`procfs.c:749`): `end`-bounded helpers.
18. **H11** [device] — virtio `used`-ring `id` not bounds-checked (`virtqueue.c:108`): validate
    `*id < vq->size` before indexing `desc`.
19. **M9** [media] — GPT trusts on-disk LBA (`gpt.c:235,278`): bound to `dev->block_count` /
    usable range; add LBA range checks to virtio-blk/AHCI.
20. **M10** — user-process kernel stacks have no guard page (`proc.c:103`, `sys_process.c:493,902`):
    mirror `sched.c:313-318`.
21. **M6–M8, L1–L17** — hardening / correctness / latent (incl. L15 RNG readiness gate, L17
    kernel-#PF RIP gating, L6 8 KB `saved[]` stack array which M10 would make survivable).⏎
