#ifndef AEGIS_LIMITS_H
#define AEGIS_LIMITS_H
/*
 * limits.h — the one place for kernel capacity ceilings.
 *
 * Aegis sizes nearly everything as `static T pool[N]` with N a per-subsystem
 * #define scattered across that subsystem's header. Several N are dangerously
 * low for the "run real software / SSH / a browser tab / a desktop session"
 * ambition (TCP_MAX_CONNS=32 is the single most limiting), and the dedup'd
 * concepts (MAX_CPUS vs SMP_MAX_CPUS, STACK_SIZE in two files, PAGE_SIZE under
 * three names) drift. This header centralises the COUNT ceilings and the truly
 * global constants so a bump is one edit and the duplicates collapse to one.
 *
 * SHIP-STRUCTURE-NOW, TUNE-LATER (lead Gate 2):
 *   - This commit ships the STRUCTURE (centralized names + the dedups below) at
 *     CURRENT values — it changes NO ceiling. Every numeric increase is a
 *     SEPARATE measured commit the lead applies after the dev box reports real
 *     `size build/aegis.elf` section sizes against the 8 MB BSS cap. The
 *     proposed targets live ONLY in comments here (and the spec's measure-gated
 *     table); the live `#define`s equal today's values.
 *
 * MIGRATION MODEL:
 *   - This header is the AUTHORITY. Each subsystem header KEEPS its public
 *     macro name (TCP_MAX_CONNS, SOCK_TABLE_SIZE, …) but DEFINES it as the
 *     value from here, e.g. in tcp.h: `#include "../limits.h"` then
 *     `#define TCP_MAX_CONNS AEGIS_TCP_MAX_CONNS`. Call sites are untouched.
 *   - DO NOT bump a ceiling without checking the _Static_assert it feeds. Three
 *     asserts are load-bearing:
 *       * proc.c:41   sizeof(aegis_process_t) <= 2*4096
 *       * pipe.c:12   sizeof(pipe_t) == 4096
 *       * the 8 MB kernel BSS cap (vmm maps pd_hi[0..3]); every `static pool[N]`
 *         bump adds N*sizeof(elem) to BSS — the big arrays (fd tables are
 *         kva-allocated, not BSS; but sock/tcp/unix/proc pools ARE BSS).
 *   - aegis_process_t SIZE SENSITIVITY: the PCB embeds caps[CAP_TABLE_SIZE] and
 *     mmap_free[MMAP_FREE_MAX] and exe_path[256] inline. Bumping MMAP_FREE_MAX
 *     grows the PCB by 16 B/entry; CAP_TABLE_SIZE by sizeof(cap_slot_t)/entry.
 *     PROC_MAX_FDS does NOT (fd_table is a pointer to a kva page) — and A3 makes
 *     fd_table_alloc size-agnostic so PROC_MAX_FDS becomes a free one-number
 *     change in the later measured commit.
 *
 * Pure #define header. Include from each subsystem header that owns a ceiling.
 */

/* ── Process / fd / thread ceilings (CURRENT values — tuning deferred) ────── */

/* MAX_PROCESSES (sys_impl.h): global process table. Each process slot costs
 * ~2.9 KB of BSS (the PCB is inline, not just a pointer), so 64 -> 256 adds
 * ~0.55 MB BSS. This briefly overflowed the old 6 MB map; now that the BSS
 * ceiling is 8 MB (vmm maps pd_hi[0..3], window relocated to pd_hi[4]) it fits.
 * APPLIED 2026-06-15: 64 -> 256. */
#define AEGIS_MAX_PROCESSES   256

/* PROC_MAX_FDS (vfs.h): per-process fd table size. fd_table is kva-allocated
 * (NOT BSS); fd_table_alloc is size-agnostic. All fd use is linear scan / bounds
 * check (verified 2026-06-15: no fixed-width fd bitmap), so a bump is purely a
 * per-process kva cost, not BSS.
 * APPLIED 2026-06-15: 64 -> 256 (256*40=10240 -> 3 kva pages/table). */
#define AEGIS_PROC_MAX_FDS    256

/* ── Networking ceilings (CURRENT values — tuning deferred) ───────────────── */

/* TCP_MAX_CONNS (tcp.h): #1 most limiting; a browser tab needs more.
 * DONE 2026-06-15: the tcb RBUF/SBUF rings are now kva-allocated (allocated once
 * at boot, never freed; the tcb embeds only the two uint8_t ring pointers), so
 * the dominant ~24 KB/tcb BSS cost is gone — each tcb is now ~120 B of BSS plus
 * RBUF 16384 + SBUF 8192 = 24 KB of kva. With BSS no longer the constraint,
 * 64 -> 128: 128 conns = 3 MB kva at boot (no longer counted against the 8 MB
 * BSS ceiling). 256 is trivially reachable (6 MB kva) if ever needed.
 * APPLIED 2026-06-15: 32 -> 64 -> 128. */
#define AEGIS_TCP_MAX_CONNS   128

/* SOCK_TABLE_SIZE (socket.h): AF_INET socket descriptors. sock_t is NOT small —
 * it embeds per-socket buffers (e.g. the UDP rx ring), so 64 -> 128 is a real BSS
 * cost. Fits under the 8 MB ceiling. APPLIED 2026-06-15: 64 -> 128. */
#define AEGIS_SOCK_TABLE_SIZE 128

/* UNIX_SOCK_MAX (unix_socket.h): the whole GUI/IPC bus; 64 = 32 concurrent
 * connections. Each unix_sock_t carries UNIX_BUF_SIZE(4096) — so +32 entries is
 * ~256 KB BSS. Fits under the 8 MB ceiling. APPLIED 2026-06-15: 32 -> 64. */
#define AEGIS_UNIX_SOCK_MAX   64

/* UNIX_PASSED_FD_MAX (unix_socket.h): max fds carried in one SCM_RIGHTS send,
 * staged on the receiving socket until recvmsg installs them. Each
 * unix_passed_fd_t is 24 B (ops* + priv* + flags, 8-aligned); the array is
 * embedded in unix_sock_t, so the BSS cost is MAX * 24 * AEGIS_UNIX_SOCK_MAX.
 * The same MAX also sizes two stack scratch arrays in sys_sendmsg
 * (sender_fds[int] + staged[unix_passed_fd_t]). 16 -> 32 doubles the headroom
 * for multi-fd handoff (Lumen passes one memfd today, but peeled GUI apps and
 * SCM_RIGHTS-based service brokering can pass several at once) at a modest cost:
 * BSS 32*24*64 = 48 KB (was 24 KB); sendmsg stack 32*(4+24) = ~900 B. Well
 * under the 8 MB ceiling and a sane kernel-stack budget. Linux SCM caps at 253
 * and Serenity at 64/msg; 32 is the conservative middle. APPLIED: 16 -> 32. */
#define AEGIS_UNIX_PASSED_FD_MAX  32

/* ── Synchronisation (CURRENT values — tuning deferred) ───────────────────── */

/* FUTEX_MAX_WAIT (futex.c): GLOBAL waiter pool; threaded apps starve it. [BSS]
 * tiny. APPLIED 2026-06-15: 64 -> 256. */
#define AEGIS_FUTEX_MAX_WAIT  256

/* ── Truly-global constants (dedup, not bumps) ───────────────────────────── */

/* PAGE_SIZE: defined THREE times — pmm.h (PAGE_SIZE 4096UL), vma.c (PAGE_SIZE
 * 4096u), vmm.c (VMM_PAGE_SIZE 4096UL). All the same constant. Canonical here;
 * the three local defs are deleted and replaced by including this header.
 * (vmm.c's VMM_PAGE_SIZE uses → AEGIS_PAGE_SIZE.) */
#define AEGIS_PAGE_SIZE       4096UL

/* AEGIS_MAX_CPUS — generous compile-time ceiling on logical CPUs (the
 * Linux-NR_CPUS model: a high bound + per-CPU allocation for present CPUs).
 * 1024 is ~4x the largest real machines and a corrupt MADT can't exceed it.
 * The only per-CPU structures sized by this are SMALL (percpu_t, TSS, GDT,
 * the AP-entry dummy, the MADT cpu list — ~900 B/CPU combined ≈ 0.9 MB at
 * 1024, well within the kernel's 8 MB image window).  The big one — the 4 KB
 * per-CPU #DF (IST) stack — is NOT a static array of this size: it is
 * kva-allocated per CPU as each comes online (tss.c), so absent CPUs cost
 * nothing.  Bumping this number is cheap; only the small static arrays grow.
 *
 * MAX_CPUS (smp.h) and SMP_MAX_CPUS (acpi.h) both alias this. */
#define AEGIS_MAX_CPUS        1024

/* STACK_SIZE: identical (STACK_PAGES * 4096) in proc.c AND sched.c. Both
 * compute from STACK_PAGES=4 (16 KB kernel stack). Canonical pages count here;
 * both files derive STACK_SIZE from it. */
#define AEGIS_STACK_PAGES     4
#define AEGIS_STACK_SIZE      (AEGIS_STACK_PAGES * AEGIS_PAGE_SIZE)

/* User stack: top, page count, base. Single-sourced here — was duplicated as
 * USER_STACK_TOP_EXEC/NPAGES (sys_impl.h; exec + spawn paths) and
 * USER_STACK_TOP/NPAGES (proc.c; init). 256 KB because 16 KB overflowed on
 * deep recursion / the sntrup761 post-quantum KEX. Top 0x7FFFFFFF000 is page-
 * aligned (and therefore 16-byte aligned), as the SysV ABI entry requires. */
#define AEGIS_USER_STACK_TOP    0x7FFFFFFF000ULL
#define AEGIS_USER_STACK_PAGES  64ULL
#define AEGIS_USER_STACK_BASE   (AEGIS_USER_STACK_TOP - AEGIS_USER_STACK_PAGES * AEGIS_PAGE_SIZE)

/*
 * ── DEFERRED / FLAGGED (do NOT batch-bump in this thread) ─────────────────
 *
 * These are listed for completeness but each needs its own analysis; the spec
 * marks them DEFER. Centralise their NAMES here later, not their (changed)
 * values now:
 *   - MMAP_FREE_MAX (proc.h, 64) [PCB] — bumping grows the PCB 16B/entry; needs
 *     the proc.c sizeof assert recomputed. Leave at 64.
 *   - CAP_TABLE_SIZE (cap.h, 64) [PCB] — same PCB sensitivity; security-load-
 *     bearing; do NOT touch in a capacity pass.
 *   - EXT2_FD_POOL (32), CACHE_SLOTS (16→64 is a cheap perf win but ext2 is the
 *     fragile subsystem — its own thread).
 *   - PTY_MAX_PAIRS (16), UDP_BINDINGS_MAX (16), MEMFD_MAX (48),
 *     EPOLL_MAX_INSTANCES (8), RAMFS_MAX_FILES (32), RAMFS_MAX_SIZE (4096/file).
 *   - RAMFS_MAX_SIZE in particular breaks real /tmp use but bumping it changes
 *     the one-page-per-file invariant (ramfs.c) — a code change, not a #define.
 */

#endif /* AEGIS_LIMITS_H */
