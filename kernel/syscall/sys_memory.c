/* sys_memory.c — Memory management syscalls: brk, mmap, munmap, mprotect */
#include "sys_impl.h"
#include "printk.h"
#include "sched.h"
#include "proc.h"
#include "vmm.h"
#include "pmm.h"
#include "kva.h"        /* kva_alloc_pages — per-CPU file-fault bounce buffers */
#include "smp.h"        /* percpu_self — per-CPU bounce-buffer index           */
#include "vfs.h"
#include "vma.h"
#include "memfd.h"
#include "ext2_vfs.h"   /* ext2_vfs_ino_of — lazy file-backed mmap backing */
#include "ext2.h"       /* ext2_read — fault-time file page populate         */
#include "../lib/va_freelist.h"

/* Demand-paged file-backed mmap flag. DEFAULT ON; `nolazyfile` forces eager.
 * See proc.h. */
int g_lazyfile = 1;

/* Per-CPU bounce buffers for fault-time file-page reads (lazy file-backed
 * mmap). Previously a single global buffer + spinlock serialized EVERY file
 * demand-fault across all CPUs — directly on the big-port startup path (mmap a
 * large file, touch many pages). Each CPU now owns its own bounce page indexed
 * by cpu_id, so concurrent file faults on different CPUs proceed in parallel
 * with no lock at all: a slot is read/written only by its owning CPU, and the
 * demand-fault path runs with IF=0 (interrupt-gate #PF / IF=0 syscall context),
 * so there is no same-CPU re-entry on the buffer either.
 *
 * Lazily allocated on first use per CPU (MM_FAULT_CLUSTER KVA pages — the
 * fault-time readahead window); never freed — it lives for the system lifetime
 * exactly as the old static buffer did. A pointer array
 * (AEGIS_MAX_CPUS * 8 B = 8 KB BSS) is used instead of a static
 * per-CPU array, which at AEGIS_MAX_CPUS=1024 would burn megabytes of
 * the 8 MB kernel-BSS budget. cpu_id is a uint8_t (< 256 < AEGIS_MAX_CPUS), so
 * the index is always in bounds. */
static uint8_t *s_filebuf[AEGIS_MAX_CPUS];

/* MM_FAULT_CLUSTER — pages populated per file-backed fault (fault-time
 * readahead).  One #PF on a sequential mmap read used to mean one 4 KiB ext2
 * read (one device round-trip) per page; clustering reads 64 KiB in one ext2
 * call (which batches contiguous blocks into one NVMe command) and maps all
 * 16 pages, cutting both traps and device commands ~16x on the mmap-heavy
 * exec/port-startup paths. */
#define MM_FAULT_CLUSTER 16u

/*
 * sys_brk — syscall 12
 *
 * arg1 = requested new break address (0 = query current brk)
 *
 * Returns the new (or current) break address.
 * On OOM, returns the current break unchanged (Linux-compatible).
 * No capability gate — process expands its own address space only.
 *
 * arg1 is page-aligned upward before processing. proc->brk is always
 * page-aligned. musl's malloc passes exact byte offsets and expects the
 * kernel to return the actual (rounded-up) new break — this is correct.
 */
uint64_t
sys_brk(uint64_t arg1)
{
    aegis_process_t *proc = current_proc();

    if (arg1 == 0)
        return proc->brk;  /* query */

    /* Clamp to user address space */
    if (arg1 >= 0x00007FFFFFFFFFFFULL)
        return proc->brk;

    /* M2: reject shrink below the initial ELF brk — prevents freeing
     * ELF segment pages via brk manipulation. */
    if (arg1 < proc->brk_base)
        return proc->brk;

    /* Page-align upward so proc->brk is always page-aligned */
    arg1 = (arg1 + 4095UL) & ~4095UL;

    uint64_t old_brk = proc->brk;

    if (arg1 > proc->brk) {
        /* Grow: map pages [proc->brk, arg1) into this process's PML4.
         * Zero each page before mapping — Linux brk/sbrk guarantee that
         * new heap pages are zeroed.  musl's malloc reads free-list headers
         * from fresh pages without initialising them first; stale PMM data
         * (e.g. DIR.buf_pos/buf_end != 0) causes readdir to skip the
         * getdents64 refill path and crash on garbage dirent data. */
        uint64_t va;
        /* PRE-SCAN: vmm_map_user_page PANICs on an already-present PTE. A
         * MAP_FIXED mmap could have placed a page anywhere in this range, so
         * scan first. If any page is already mapped, abort the grow and
         * return the current break unchanged (brk failure convention).
         *
         * The vma_find check is load-bearing alongside the phys check: a
         * MAP_FIXED *lazy anonymous* region in [brk, arg1) has a VMA but NO
         * present PTE yet, so a phys-only scan is blind to it. Without this
         * check brk would map its heap frames over that reserved range and then
         * extend the heap VMA's len across it (line ~93), producing OVERLAPPING
         * VMAs — breaking vma_find's sorted/non-overlapping invariant (the
         * demand-fault hot path) and double-owning the frames (munmap of the
         * mmap region would then double-free pages brk also believes it owns).
         * Mirror sys_mmap's allocator pre-scan, which checks both. The scan range
         * [brk, arg1) is disjoint from the heap's own VMA [base, brk), so this
         * never false-positives on the heap itself. */
        for (va = proc->brk; va < arg1; va += 4096UL) {
            if (vmm_phys_of_user_raw(proc->pml4_phys, va) != 0 ||
                vma_find(proc, va) != (vma_entry_t *)0)
                return proc->brk;  /* range collides — leave brk unchanged */
        }
        for (va = proc->brk; va < arg1; va += 4096UL) {
            uint64_t phys = pmm_alloc_page();
            if (!phys) {
                /* OOM: unwind every page mapped THIS call so we neither leak
                 * frames nor leave half-mapped pages that would panic the
                 * next grow. proc->brk stays at the old value. */
                uint64_t v2;
                for (v2 = proc->brk; v2 < va; v2 += 4096UL) {
                    uint64_t p = vmm_phys_of_user_raw(proc->pml4_phys, v2);
                    if (p) {
                        vmm_unmap_user_page(proc->pml4_phys, v2);
                        pmm_free_page(p);
                    }
                }
                return proc->brk;  /* OOM — return current brk unchanged */
            }
            vmm_zero_page(phys);
            vmm_map_user_page(proc->pml4_phys, va, phys,
                              VMM_FLAG_PRESENT | VMM_FLAG_USER |
                              VMM_FLAG_WRITABLE);
        }
        proc->brk = arg1;

        /* Update heap VMA */
        if (proc->vma_table) {
            uint32_t vi;
            int found = 0;
            for (vi = 0; vi < vma_count_get(proc); vi++) {
                if (proc->vma_table[vi].type == VMA_HEAP) {
                    proc->vma_table[vi].len = proc->brk - proc->vma_table[vi].base;
                    found = 1;
                    break;
                }
            }
            if (!found) {
                if (vma_insert(proc, old_brk, proc->brk - old_brk,
                               0x01 | 0x02, VMA_HEAP) != 0) {
                    /* VMA table full: the grown range would be mapped but
                     * untracked (corrupts /proc/maps, defeats teardown). Roll
                     * back exactly like the OOM path above — unmap+free every
                     * page mapped THIS call ([old_brk, arg1)) and restore brk.
                     * brk failure convention (line 76, 60): return the current
                     * (unchanged) break, NOT -ENOMEM. */
                    uint64_t v2;
                    for (v2 = old_brk; v2 < proc->brk; v2 += 4096UL) {
                        uint64_t p = vmm_phys_of_user_raw(proc->pml4_phys, v2);
                        if (p) {
                            vmm_unmap_user_page(proc->pml4_phys, v2);
                            pmm_free_page(p);
                        }
                    }
                    proc->brk = old_brk;
                    return proc->brk;
                }
            }
        }
    } else if (arg1 < proc->brk) {
        /* Shrink: unmap and free pages [arg1, proc->brk) */
        uint64_t va;
        for (va = arg1; va < proc->brk; va += 4096UL) {
            uint64_t phys = vmm_phys_of_user(proc->pml4_phys, va);
            if (phys) {
                vmm_unmap_user_page(proc->pml4_phys, va);
                pmm_free_page(phys);
            }
        }
        proc->brk = arg1;

        /* Update heap VMA */
        if (proc->vma_table) {
            uint32_t vi;
            for (vi = 0; vi < vma_count_get(proc); vi++) {
                if (proc->vma_table[vi].type == VMA_HEAP) {
                    if (proc->brk <= proc->vma_table[vi].base) {
                        /* Removing the whole heap entry by its exact
                         * [base,len) — a full removal, never a split, so this
                         * cannot return -1. Cast to void deliberately. */
                        (void)vma_remove(proc, proc->vma_table[vi].base,
                                         proc->vma_table[vi].len);
                    } else {
                        proc->vma_table[vi].len = proc->brk -
                                                  proc->vma_table[vi].base;
                    }
                    break;
                }
            }
        }
    }

    return proc->brk;
}

/* ── mmap VA freelist helpers ─────────────────────────────────────────── */

/*
 * M2 audit fix: mmap_free_insert takes proc->mmap_free_lock for its full body.
 * Two threads sharing a VM (CLONE_VM) can race on the freelist — latent on
 * single-core, corrupting on SMP. The lock is per-process and does not nest with
 * any other kernel lock from here, so no ordering constraints at the insert site.
 * (The alloc side was inlined into sys_mmap's non-fixed path so the freelist
 * carve + bump scan + VMA reservation + mmap_base advance share ONE lock hold —
 * see the big comment there.)
 *
 * mmap_free_insert is a thin wrapper over the shared coalescing allocator in
 * kernel/lib/va_freelist.{h,c} (the same primitive backing the KVA freelist).
 * The mmap freelist is pure BYTES — base and len both byte quantities — so it
 * maps directly onto va_region_t {base,len} with no unit conversion. mmap_free_t
 * is already {uint64_t base; uint64_t len;}, byte-identical to va_region_t, so
 * the backing array casts in place.
 */
_Static_assert(sizeof(mmap_free_t) == sizeof(va_region_t),
               "mmap_free_t must alias va_region_t for the freelist view cast");

static void
mmap_free_insert(aegis_process_t *proc, uint64_t base, uint64_t len)
{
    irqflags_t fl = spin_lock_irqsave(&proc->mmap_free_lock);
    va_freelist_t vfl = { (va_region_t *)proc->mmap_free, MMAP_FREE_MAX,
                          proc->mmap_free_count };
    va_freelist_insert(&vfl, base, len);   /* WARN-on-overflow now inside */
    proc->mmap_free_count = vfl.count;
    spin_unlock_irqrestore(&proc->mmap_free_lock, fl);
}

/* (mmap_free_alloc was inlined into sys_mmap's non-fixed path so the freelist
 * carve, the bump scan, the VMA reservation, and the mmap_base advance all
 * happen under ONE mmap_free_lock hold — closing the concurrent-selection race.
 * mmap_free_insert above is still its own helper; sys_munmap calls it.) */

/*
 * sys_mmap — syscall 9
 *
 * Supports MAP_ANONYMOUS | MAP_PRIVATE, MAP_FIXED, and file-backed private mappings.
 *
 * MAP_FIXED (addr != 0, MAP_FIXED set): map at exact address; silently unmap
 * existing pages first.  addr must be page-aligned, below 0x800000000000.
 *
 * File-backed (fd != -1, MAP_ANONYMOUS not set): read file content into mapped
 * pages via VFS.  MAP_PRIVATE semantics — pages are independent of file after
 * mapping.  offset must be page-aligned.
 *
 * Each allocated page is zeroed before mapping — MAP_ANONYMOUS guarantee.
 * OOM rollback: already-mapped pages are unmapped and freed before returning -ENOMEM.
 * No capability gate — process expands its own address space only.
 */
uint64_t
sys_mmap(uint64_t arg1, uint64_t arg2, uint64_t arg3,
         uint64_t arg4, uint64_t arg5, uint64_t arg6)
{
    aegis_process_t *proc = current_proc();
    uint64_t addr  = arg1;
    uint64_t prot  = arg3;
    uint64_t flags = arg4;
    int64_t  fd    = (int64_t)arg5;
    uint64_t off   = arg6;

    uint64_t len = (arg2 + 4095UL) & ~4095UL;
    if (len == 0)
        return SYS_ERR(EINVAL);
    if (prot & ~(uint64_t)(PROT_READ | PROT_WRITE | PROT_EXEC))
        return SYS_ERR(EINVAL);
    /* W^X: reject simultaneous write+execute. Sequential W-then-X
     * transitions via mprotect remain allowed (dynamic linker). */
    if ((prot & PROT_WRITE) && (prot & PROT_EXEC))
        return SYS_ERR(EINVAL);
    int is_shared = (flags & MAP_SHARED) != 0;

    int file_backed = !(flags & MAP_ANONYMOUS) && fd != -1;
    if (!file_backed && !(flags & MAP_ANONYMOUS))
        return SYS_ERR(EINVAL);
    if (file_backed && (off & 0xFFFUL))
        return SYS_ERR(EINVAL);   /* EINVAL — offset not page-aligned */

    /* Read-only MAP_SHARED of a regular (non-memfd) file: Aegis keeps no page
     * cache for ext2, so a *true* shared file mapping is memfd-only. But a
     * READ-ONLY shared mapping needs no write-back, so an eager private copy is
     * observationally identical — downgrade it to private here so it works.
     * (Ladybird's Core::MappedFile maps fonts/HTML/resources PROT_READ
     * MAP_SHARED; without this every file:// resource load fails with EINVAL.)
     * A writable shared map of a non-memfd file still falls through to the
     * memfd-only EINVAL below — that genuinely needs a shared backing store.
     *
     * Moved BEFORE the allocator so the VMA type is known at reservation time
     * (the non-fixed path reserves its VMA up front under mmap_free_lock to
     * close the concurrent-selection race — see below). */
    if (is_shared && file_backed && !(prot & PROT_WRITE)) {
        extern const vfs_ops_t g_memfd_ops;
        if (!((uint32_t)fd < PROC_MAX_FDS &&
              proc->fd_table->fds[(uint32_t)fd].ops == &g_memfd_ops))
            is_shared = 0;  /* treat as MAP_PRIVATE: eager file copy below */
    }
    /* Lazy file-backed decision (cmdline `lazyfile`): a MAP_PRIVATE mapping of
     * an ext2 file is demand-paged — record the backing inode+offset+size, leave
     * pages not-present, and let mm_populate_fault read each file page on first
     * touch. Only ext2 (its read-by-inode lets the fault path re-read after the
     * fd is closed, with no per-VMA file refcount); other filesystems and
     * MAP_SHARED keep the eager path. Decided here so the VMA is reserved with
     * type VMA_FILE up front (the non-fixed path reserves before the copy). */
    uint32_t lazy_ino = 0;
    uint64_t lazy_fsize = 0;
    uint32_t lazy_gen = 0;
    int      lazy_file = 0;
    if (file_backed && !is_shared && g_lazyfile &&
        (uint32_t)fd < PROC_MAX_FDS && proc->fd_table->fds[(uint32_t)fd].ops) {
        uint32_t ino = ext2_vfs_ino_of(proc->fd_table->fds[(uint32_t)fd].ops,
                                       proc->fd_table->fds[(uint32_t)fd].priv);
        if (ino) {
            lazy_file  = 1;
            lazy_ino   = ino;
            lazy_fsize = proc->fd_table->fds[(uint32_t)fd].size;
            /* secfix M2: snapshot the inode generation now; the fault path
             * revalidates it so a recycled inode number cannot leak another
             * file's contents through this mapping. */
            lazy_gen   = ext2_inode_gen(ino);
        }
    }
    uint8_t vma_type = lazy_file ? VMA_FILE
                     : (is_shared && file_backed) ? VMA_SHARED : VMA_MMAP;

    int is_fixed = (flags & MAP_FIXED) && addr != 0;
    uint64_t base;
    /* reserved: the non-fixed path inserts its VMA up front (under
     * mmap_free_lock) so a concurrent thread's selection sees the range taken;
     * the trailing per-path vma_insert is then skipped. The fixed path keeps the
     * historical insert-at-end behaviour (explicit addr, no selection race). */
    int reserved = 0;

    if (is_fixed) {
        if (addr & 0xFFFUL)
            return SYS_ERR(EINVAL);   /* EINVAL — not page-aligned */
        if (addr >= 0x800000000000ULL || addr + len > 0x800000000000ULL ||
            addr + len < addr)
            return SYS_ERR(EINVAL);   /* EINVAL — out of user range */
        /* POSIX MAP_FIXED replaces any existing mapping in the target range.
         * Update the VMA table FIRST (it touches only the table, not the page
         * tables). If the replacement would split a straddled VMA and the
         * table is full, vma_remove returns -1 having changed nothing — abort
         * with -ENOMEM before any irreversible page teardown, so the existing
         * mapping survives intact. */
        if (vma_remove(proc, addr, len) != 0)
            return SYS_ERR(ENOMEM);   /* -ENOMEM: cannot record split */
        /* Now silently unmap+free existing pages so the subsequent map loop
         * does not hit an already-present PTE (which would panic_halt). Use
         * vmm_phys_of_user_raw so PROT_NONE pages (PRESENT cleared but phys
         * recorded by mprotect) are also caught. pmm_free_page is
         * refcount-decrementing, so a MAP_SHARED memfd frame is released
         * correctly without double-freeing — its other references survive. */
        uint64_t va;
        for (va = addr; va < addr + len; va += 4096UL) {
            uint64_t phys = vmm_phys_of_user_raw(proc->pml4_phys, va);
            if (phys) {
                vmm_unmap_user_page(proc->pml4_phys, va);
                pmm_free_page(phys);
            }
        }
        base = addr;
    } else {
        if (addr != 0)
            return SYS_ERR(EINVAL);   /* EINVAL — addr must be 0 */
        /* SMP: VA selection must be atomic against sibling CLONE_VM threads that
         * mmap concurrently — otherwise both pre-scan the same range clear and
         * both reserve it (overlapping VMAs / double-map). proc->mmap_free and
         * proc->mmap_base are PER-THREAD (copied at clone), so they need no lock;
         * the SHARED state is the vma_table, and the atomicity comes from
         * vma_insert itself: it self-locks the shared table lock and REJECTS a
         * strict overlap (returns -2). So the loop below pre-scans, then tries the
         * reservation via vma_insert; if a sibling grabbed the range in the gap
         * between scan and insert, vma_insert returns -2 and we re-select. No
         * outer lock is held (and none across the slow map/read path that
         * follows) — the earlier "hold a lock across the whole reservation"
         * attempt deadlocked pthread_create; this lock-free-retry form does not.
         *
         * Freelist-first then bump: a freelist range can collide with a page a
         * MAP_FIXED overwrote without de-listing (ld-musl reserves a lib span,
         * MAP_FIXEDs its segments, frees the slack — incomplete delist), so we
         * pre-scan and SKIP AHEAD on collision rather than fail (returning ENOMEM
         * here broke pthread_create thread-stack mmap in lib-heavy processes). */
        va_freelist_t vfl = { (va_region_t *)proc->mmap_free, MMAP_FREE_MAX,
                              proc->mmap_free_count };
        uint8_t from_free = va_freelist_alloc(&vfl, len, &base);
        proc->mmap_free_count = vfl.count;
        if (!from_free || base + len > USER_ADDR_MAX || base + len < base) {
            base = proc->mmap_base;
            from_free = 0;
        }
        int oom = 0;
        for (;;) {
            if (base + len > USER_ADDR_MAX || base + len < base) {
                oom = 1;
                break;
            }
            uint64_t sva, hit = 0;
            for (sva = base; sva < base + len; sva += 4096UL) {
                /* Occupied if a VMA reserves it OR a stray PTE is present.
                 * The VMA check is load-bearing for lazy anon mmap: a reserved-
                 * but-not-yet-faulted region has NO present PTE, so the phys
                 * scan alone is blind to it and would hand the range out twice,
                 * overlapping a live region (thread stack / lib BSS) and
                 * corrupting it. The phys check still catches stale-freelist /
                 * incomplete-delist pages with no backing VMA. */
                if (vma_find(proc, sva) ||
                    vmm_phys_of_user_raw(proc->pml4_phys, sva) != 0) { hit = sva; break; }
            }
            if (hit) {
                /* Occupied. Stale freelist range → bump from the monotonic
                 * mmap_base; bump collision → skip past the occupied page. */
                if (from_free) { base = proc->mmap_base; from_free = 0; }
                else           { base = hit + 4096UL; }
                continue;
            }
            /* Clear run — try to atomically reserve it. vma_insert self-locks the
             * shared table and rejects a strict overlap (-2) if a sibling grabbed
             * [base,len) since our scan; on -2 re-select and retry. -1 = table
             * full → ENOMEM. 0 = reserved. */
            int r = vma_insert(proc, base, len, (uint32_t)(prot & 0x07), vma_type);
            if (r == 0) {
                reserved = 1;
                if (base >= proc->mmap_base)
                    proc->mmap_base = base + len;
                break;
            }
            if (r == -2) {
                if (from_free) { base = proc->mmap_base; from_free = 0; }
                else           { base = base + 4096UL; }
                continue;   /* lost the race — re-select */
            }
            oom = 1;   /* r == -1: VMA table full */
            break;
        }
        if (oom) {
            printk("[MMAP] OOM: no free %lx-byte VA gap pid=%u mmap_base=%lx\n",
                   len, proc->pid, proc->mmap_base);
            return SYS_ERR(ENOMEM);  /* -ENOMEM — VA space / VMA table exhausted */
        }
    }

    /* PTE flags: NX by default; clear NX only for PROT_EXEC */
    uint64_t map_flags = VMM_FLAG_PRESENT | VMM_FLAG_USER | VMM_FLAG_NX;
    if (prot & PROT_WRITE)
        map_flags |= VMM_FLAG_WRITABLE;
    if (prot & PROT_EXEC)
        map_flags &= ~VMM_FLAG_NX;

    /* MAP_SHARED path: map memfd's physical pages directly.
     *
     * For the non-fixed path the VMA was already RESERVED up front (reserved=1);
     * a failure here must vma_remove that reservation (and unmap any pages mapped
     * so far). For the fixed path the VMA is inserted at the end as before. */
    if (is_shared && file_backed) {
        extern const vfs_ops_t g_memfd_ops;
        if ((uint32_t)fd >= PROC_MAX_FDS ||
            !proc->fd_table->fds[(uint32_t)fd].ops ||
            proc->fd_table->fds[(uint32_t)fd].ops != &g_memfd_ops) {
            if (reserved) vma_remove(proc, base, len);
            return SYS_ERR(EINVAL);  /* EINVAL: MAP_SHARED only for memfd */
        }

        uint32_t mid = (uint32_t)(uintptr_t)proc->fd_table->fds[(uint32_t)fd].priv;
        extern memfd_t *memfd_get(uint32_t id);
        memfd_t *mf = memfd_get(mid);
        if (!mf) { if (reserved) vma_remove(proc, base, len); return SYS_ERR(EINVAL); }
        /* Compare against page-rounded size so a memfd ftruncate'd to a
         * non-page-aligned length (e.g. 200x100x4 = 80000 bytes) can still
         * be mapped at the page-rounded length the caller passed. */
        uint64_t mf_pages_bytes = (uint64_t)mf->page_count * 4096UL;
        if (len > mf_pages_bytes) {
            if (reserved) vma_remove(proc, base, len);
            return SYS_ERR(EINVAL);  /* mapping larger than memfd */
        }

        uint32_t num_pages = (uint32_t)(len / 4096);
        uint64_t va;
        for (va = base; va < base + len; va += 4096UL) {
            uint32_t pi = (uint32_t)((va - base) / 4096);
            if (pi >= mf->page_count || !mf->phys_pages[pi]) {
                /* Unmap+unref the pages mapped so far this call, then drop the
                 * reservation. (Defensive: the len<=mf_pages_bytes guard above
                 * makes this branch unreachable for in-range pages.) */
                uint64_t v2;
                for (v2 = base; v2 < va; v2 += 4096UL) {
                    uint64_t p = vmm_phys_of_user_raw(proc->pml4_phys, v2);
                    if (p) { vmm_unmap_user_page(proc->pml4_phys, v2); pmm_free_page(p); }
                }
                if (reserved) vma_remove(proc, base, len);
                return SYS_ERR(EINVAL);
            }
            vmm_map_user_page(proc->pml4_phys, va, mf->phys_pages[pi], map_flags);
            /* This mapping now holds its own reference on the memfd frame.
             * Invariant: total refs = 1 (memfd) + live MAP_SHARED mappings.
             * Without this, munmap/exit would free a frame still owned by
             * the memfd and any other mapping (UAF). */
            pmm_ref_page(mf->phys_pages[pi]);
        }
        (void)num_pages;

        /* Fixed path only: insert the VMA now (non-fixed reserved it up front).
         * On table-full, roll back: unmap each page and pmm_free_page it —
         * which DECREMENTS the per-mapping reference taken via pmm_ref_page above
         * (ref-on-map invariant: total refs = 1 memfd + live mappings). The
         * memfd's own reference survives, so the frame is not freed out from
         * under it. */
        if (!reserved &&
            vma_insert(proc, base, len, (uint32_t)(prot & 0x07),
                       VMA_SHARED) != 0) {
            uint64_t v2;
            for (v2 = base; v2 < base + len; v2 += 4096UL) {
                uint64_t p = vmm_phys_of_user_raw(proc->pml4_phys, v2);
                if (p) {
                    vmm_unmap_user_page(proc->pml4_phys, v2);
                    pmm_free_page(p);  /* drops the per-mapping ref */
                }
            }
            return SYS_ERR(ENOMEM);  /* -ENOMEM */
        }

        /* mmap_base already advanced under the lock for the reserved (non-fixed)
         * path; only the fixed path could need it, and fixed never advances it. */
        return base;
    }

    /* Lazy file-backed mmap: record the backing inode in the VMA and leave the
     * pages not-present — mm_populate_fault reads each file page on first touch.
     * Avoids the eager whole-file copy at mmap time (137 .so × procs startup
     * wall). Non-fixed path already reserved the VMA as VMA_FILE (reserved=1);
     * the fixed path inserts it now. The VMA backing is set after the reserve. */
    if (lazy_file) {
        if (!reserved &&
            vma_insert(proc, base, len, (uint32_t)(prot & 0x07), VMA_FILE) != 0)
            return SYS_ERR(ENOMEM);   /* -ENOMEM: VMA table full */
        vma_set_file_backing(proc, base, lazy_ino, off, lazy_fsize, lazy_gen);
        return base;
    }

    /* Demand paging: anonymous private mmap is LAZY — record the VMA only and
     * leave pages not-present; mm_populate_fault() fills each on first touch
     * (the #PF handler and uaccess populate paths). This is the big win:
     * Ladybird churns ~12 GB of anon mmap, almost all untouched/reserved, so
     * eager alloc+zero of every page dominated startup. Non-ext2 / MAP_SHARED
     * file mappings stay eager (handled in the loop below). */
    uint64_t va;
    if (file_backed)
    for (va = base; va < base + len; va += 4096UL) {
        uint64_t phys = pmm_alloc_page();
        if (!phys) {
            /* OOM: unmap already-mapped pages, drop the reservation, -ENOMEM */
            uint64_t v2;
            for (v2 = base; v2 < va; v2 += 4096UL) {
                uint64_t p = vmm_phys_of_user(proc->pml4_phys, v2);
                if (p) {
                    vmm_unmap_user_page(proc->pml4_phys, v2);
                    pmm_free_page(p);
                }
            }
            if (reserved) vma_remove(proc, base, len);
            return SYS_ERR(ENOMEM);  /* -ENOMEM */
        }
        vmm_zero_page(phys);
        vmm_map_user_page(proc->pml4_phys, va, phys, map_flags);
    }

    /* File-backed: copy file content into the mapped pages */
    if (file_backed) {
        if ((uint32_t)fd < PROC_MAX_FDS &&
            proc->fd_table->fds[(uint32_t)fd].ops &&
            proc->fd_table->fds[(uint32_t)fd].ops->read) {
            vfs_file_t *f = &proc->fd_table->fds[(uint32_t)fd];
            uint64_t file_bytes = len;
            if (f->size > 0 && off < f->size) {
                uint64_t avail = f->size - off;
                if (file_bytes > avail)
                    file_bytes = avail;
            } else if (f->size > 0 && off >= f->size) {
                file_bytes = 0;
            }
            if (file_bytes > 0) {
                uint8_t chunk[4096];
                uint64_t copied = 0;
                while (copied < file_bytes) {
                    uint64_t want = file_bytes - copied;
                    if (want > 4096) want = 4096;
                    int rr = f->ops->read(f->priv, chunk,
                                          off + copied, want);
                    if (rr <= 0) break;
                    vmm_write_user_bytes(proc->pml4_phys,
                                         base + copied,
                                         chunk, (uint64_t)rr);
                    copied += (uint64_t)rr;
                }
            }
        }
    }

    /* Fixed path only: insert the VMA now (non-fixed reserved it up front under
     * mmap_free_lock). On table-full, roll back like the OOM path above —
     * unmap+free every private frame mapped for this request. Return -ENOMEM.
     * (For the reserved non-fixed path this is a no-op: the VMA is already in
     * the table with the correct prot/type, and mmap_base was already advanced
     * under the lock; lazy-anon thus completes with zero further work.) */
    if (!reserved &&
        vma_insert(proc, base, len, (uint32_t)(prot & 0x07), VMA_MMAP) != 0) {
        uint64_t v2;
        for (v2 = base; v2 < base + len; v2 += 4096UL) {
            uint64_t p = vmm_phys_of_user(proc->pml4_phys, v2);
            if (p) {
                vmm_unmap_user_page(proc->pml4_phys, v2);
                pmm_free_page(p);
            }
        }
        return SYS_ERR(ENOMEM);  /* -ENOMEM */
    }

    return base;
}

/* mm_populate_fault — demand-paging populate for a single user page.
 * Called from the #PF handler (user touches a lazy page) and from
 * uaccess_range_mapped (kernel about to read/write a lazy page). Returns 0 if
 * the page is now present (populated or already mapped), -1 if va is not a
 * populatable lazy page (→ the caller raises SIGSEGV / EFAULT).
 *
 * Lazy types: VMA_MMAP (anonymous private — zero page) and VMA_FILE (ext2
 * MAP_PRIVATE — read the backing file page, zero-fill the EOF tail). PROT_NONE
 * regions are never populated (guard pages → real fault). Runs with IF=0
 * (interrupt-gate #PF / syscall context). */
int
mm_populate_fault(aegis_process_t *proc, uint64_t va)
{
    if (!proc || !proc->pml4_phys)
        return -1;
    va &= ~0xFFFULL;
    vma_entry_t *v = vma_find(proc, va);
    if (!v || (v->type != VMA_MMAP && v->type != VMA_FILE))
        return -1;
    if ((v->prot & (PROT_READ | PROT_WRITE | PROT_EXEC)) == 0)
        return -1;                       /* PROT_NONE guard — real fault */

    /* Snapshot the VMA fields now: v points into the shared table, which a
     * sibling thread could shift (vma_insert/remove) after we drop out of
     * vma_find's lock. All reads below use the snapshot, not v. */
    uint8_t  vtype = v->type;
    uint32_t vprot = v->prot;
    uint32_t fino  = v->file_ino;
    uint32_t fgen  = v->file_gen;
    uint64_t foff  = v->file_off;
    uint64_t fsize = v->file_size;
    uint64_t vbase = v->base;
    uint64_t vlen  = v->len;

    /* Fast path: already present (re-entry, or a sibling thread populated it). */
    if (vmm_phys_of_user_raw(proc->pml4_phys, va))
        return 0;

    /* SMP: two CLONE_VM/CLONE_THREAD threads sharing one PML4 can fault the SAME
     * lazy page on different CPUs at once. Both pass the check above and both
     * allocate a frame — but vmm_try_map_user_page resolves the race atomically
     * under vmm_window_lock: exactly one thread installs its frame (returns 0),
     * the other observes the PTE already present (returns 1) and frees its frame.
     * No extra lock is needed — the window lock already serializes every PTE
     * mutation. For VMA_FILE the frame is FULLY populated (file data read in)
     * BEFORE this map, so the racing sibling never observes a half-filled page.
     * Reproducer: user/bin/mmfaultstress. */
    uint64_t phys = pmm_alloc_page();
    if (!phys)
        return -1;                       /* OOM → fault */
    vmm_zero_page(phys);

    /* VMA_FILE: cluster read — up to MM_FAULT_CLUSTER pages of the backing
     * file in ONE generation-validated ext2 read (see MM_FAULT_CLUSTER).
     * Bytes past EOF stay zero (file hole / partial last page).  `got` is the
     * number of file bytes read into buf; pages of the cluster beyond it are
     * not prefetched (they fault + zero-fill later if legitimately mapped). */
    uint32_t cluster = 1;
    uint32_t got     = 0;
    uint8_t *buf     = NULL;
    if (vtype == VMA_FILE && fino) {
        uint64_t fpos = foff + (va - vbase);
        /* Readahead window: clamp to the VMA end (never touch pages of a
         * neighboring mapping) — EOF is handled by the read length below. */
        uint64_t vma_pages_left = (vbase + vlen - va) >> 12;
        cluster = MM_FAULT_CLUSTER;
        if ((uint64_t)cluster > vma_pages_left)
            cluster = (uint32_t)vma_pages_left;
        if (cluster == 0)
            cluster = 1;
        if (fpos < fsize) {
            uint64_t avail = fsize - fpos;
            uint64_t want  = (uint64_t)cluster * 4096u;
            if (want > avail) want = avail;
            /* Per-CPU bounce buffer — no lock (see s_filebuf comment). The
             * fault path is IF=0, so this CPU can't be preempted mid-read and
             * no other CPU touches this slot. */
            uint32_t cpu = percpu_self()->cpu_id;
            buf = s_filebuf[cpu];
            if (!buf) {
                buf = kva_alloc_pages(MM_FAULT_CLUSTER);
                if (!buf) {            /* KVA exhausted — clean fault, no leak */
                    pmm_free_page(phys);
                    return -1;
                }
                s_filebuf[cpu] = buf;
            }
            /* secfix M2: generation-validated read. If the backing inode
             * number was recycled for a different file since mmap, fault
             * instead of leaking the new file's contents through this mapping
             * (the original open()'s DAC check no longer applies to it). */
            int g = ext2_read_validated(fino, buf, fpos, (uint32_t)want, fgen);
            if (g == EXT2_EGEN) {
                pmm_free_page(phys);
                return -1;               /* recycled inode → SIGSEGV */
            }
            got = (g > 0) ? (uint32_t)g : 0;
        }
    }

    uint64_t mf = VMM_FLAG_PRESENT | VMM_FLAG_USER | VMM_FLAG_NX;
    if (vprot & PROT_WRITE) mf |= VMM_FLAG_WRITABLE;
    if (vprot & PROT_EXEC)  mf &= ~VMM_FLAG_NX;

    for (uint32_t i = 0; i < cluster; i++) {
        uint64_t page_off = (uint64_t)i * 4096u;
        uint64_t frame;
        if (i == 0) {
            frame = phys;              /* pre-allocated + zeroed above */
        } else {
            /* Prefetch pages only while backed by read data — a page beyond
             * `got` is either past EOF or after a short read; let it fault
             * on its own later. Best-effort: OOM just ends the readahead. */
            if (page_off >= got)
                break;
            frame = pmm_alloc_page();
            if (!frame)
                break;
            vmm_zero_page(frame);
        }
        if (buf && page_off < got) {
            uint32_t n = (got - page_off) < 4096u ? (uint32_t)(got - page_off)
                                                  : 4096u;
            vmm_write_phys_bytes(frame, 0, buf + page_off, n);
        }
        int r = vmm_try_map_user_page(proc->pml4_phys, va + page_off, frame, mf);
        if (r != 0) {
            /* r==1: lost the populate race, page already present → free our
             * frame and move on (success for the faulting page).
             * r==-1: OOM allocating a page table → real fault for page 0,
             * end of readahead otherwise. */
            pmm_free_page(frame);
            if (i == 0)
                return (r == 1) ? 0 : -1;
            if (r == -1)
                break;
        }
    }
    return 0;
}

/*
 * sys_munmap — syscall 11
 *
 * arg1 = addr (must be page-aligned)
 * arg2 = length
 *
 * Frees physical pages for [addr, addr+len) and returns VA to the
 * per-process freelist for reuse by future mmap calls.
 * Returns 0 on success, -EINVAL if addr is not page-aligned.
 */
uint64_t
sys_munmap(uint64_t arg1, uint64_t arg2)
{
    if (arg1 & 0xFFFUL)
        return SYS_ERR(EINVAL);   /* EINVAL — not page-aligned */

    /* MEDIUM: reject zero length BEFORE page-rounding. Linux munmap(2) returns
     * EINVAL for length 0; without this, arg2==0 rounds to len==0 and we would
     * insert a zero-length freelist entry and call vma_remove(.,.,0) — both
     * meaningless. Check the raw arg2 so a sub-page nonzero length still maps
     * to a one-page unmap (page-rounded below), matching mmap's rounding. */
    if (arg2 == 0)
        return SYS_ERR(EINVAL);   /* EINVAL — zero length */

    uint64_t len = (arg2 + 4095UL) & ~4095UL;

    /* C7: reject kernel addresses and overflow — prevent kernel VAs from
     * being inserted into the mmap freelist. */
    if (arg1 >= 0x00007FFFFFFFFFFFULL ||
        arg1 + len > 0x00007FFFFFFFFFFFULL ||
        arg1 + len < arg1)
        return SYS_ERR(EINVAL);

    aegis_process_t *proc = current_proc();

    /* Update the VMA table FIRST. vma_remove only touches the table, so doing
     * it before the irreversible page teardown gives all-or-nothing semantics:
     * if unmapping the middle of a tracked region would split a VMA and the
     * table is full, vma_remove returns -1 having changed nothing, and we
     * return -ENOMEM with the mapping fully intact. (Linux munmap can also
     * fail with ENOMEM when the kernel runs out of VMA descriptors mid-split,
     * so this errno is POSIX-faithful.) Once the pages are freed there is no
     * way back, so the order matters. */
    if (vma_remove(proc, arg1, len) != 0)
        return SYS_ERR(ENOMEM);   /* -ENOMEM: cannot record split */

    /* Unmap and drop one reference on every actually-mapped frame in the
     * range. With ref-on-map in sys_mmap, a MAP_SHARED memfd frame carries
     * one reference per live mapping plus the memfd's own; pmm_free_page
     * here decrements — it only returns the frame to the allocator when the
     * memfd and every mapping have released it. A private frame is freed as
     * before (its lone 1->0 transition). No shared special-case: that would
     * leak the per-mapping reference taken in sys_mmap. */
    uint64_t va;
    for (va = arg1; va < arg1 + len; va += 4096UL) {
        /* H4: use vmm_phys_of_user_raw to find physical frames even when
         * PRESENT is cleared (PROT_NONE pages from mprotect). Without this,
         * munmap leaks physical frames for PROT_NONE pages. */
        uint64_t phys = vmm_phys_of_user_raw(proc->pml4_phys, va);
        if (phys) {
            /* SECURITY (H1): never free a VMM_FLAG_SHARED frame — it is
             * driver-owned RAM (e.g. the virtio-gpu framebuffer published by
             * sys_fb_map) that the process maps but does not own. Freeing it
             * returns live GPU/shared RAM to the allocator -> cross-context
             * corruption. Same guard the exit-teardown walks already apply
             * (vmm_free_user_pml4 / vmm_free_user_pages). Unmap only. */
            uint64_t pte = vmm_pte_of_user_raw(proc->pml4_phys, va);
            /* Clear the PTE first so the exit-time teardown
             * (vmm_free_user_pml4) won't see this frame and decrement a
             * second time for the same mapping. */
            vmm_unmap_user_page(proc->pml4_phys, va);
            if (!(pte & VMM_FLAG_SHARED))
                pmm_free_page(phys);
        }
    }

    /* Return VA range to freelist for reuse by future mmap calls. */
    mmap_free_insert(proc, arg1, len);

    return 0;
}

/*
 * sys_mprotect — syscall 10
 *
 * arg1 = addr (must be page-aligned)
 * arg2 = len (rounded up to page boundary)
 * arg3 = prot (PROT_NONE, PROT_READ, PROT_WRITE, PROT_EXEC combinations)
 *
 * Changes page permissions for [addr, addr+len). Unmapped pages are
 * silently skipped (matching Linux). W^X: NX is set by default; only
 * an explicit PROT_EXEC clears NX.
 */
uint64_t
sys_mprotect(uint64_t addr, uint64_t len, uint64_t prot)
{
    if (addr & 0xFFFUL)
        return SYS_ERR(EINVAL);   /* -EINVAL: not page-aligned */

    uint64_t rlen = (len + 4095UL) & ~4095UL;
    if (rlen == 0)
        return 0;  /* zero-length is a no-op */

    if (addr + rlen > USER_ADDR_MAX || addr + rlen < addr)
        return SYS_ERR(EINVAL);   /* -EINVAL: exceeds user space */

    /* W^X: reject simultaneous write+execute. Sequential W-then-X
     * transitions remain allowed (dynamic linker relocation pass). */
    if ((prot & PROT_WRITE) && (prot & PROT_EXEC))
        return SYS_ERR(EINVAL);   /* -EINVAL */

    /* Map PROT_* to VMM_FLAG_*.
     * x86 can't do write-only or exec-only; implicitly add READ. */
    uint64_t flags;
    if (prot == 0) {
        flags = 0;  /* PROT_NONE: clear PRESENT */
    } else {
        flags = VMM_FLAG_PRESENT | VMM_FLAG_USER | VMM_FLAG_NX;
        if (prot & PROT_WRITE)
            flags |= VMM_FLAG_WRITABLE;
        if (prot & PROT_EXEC)
            flags &= ~VMM_FLAG_NX;  /* clear NX for executable pages */
    }

    aegis_process_t *proc = current_proc();

    /* Update the VMA table FIRST so the page-protection change and its
     * bookkeeping are all-or-nothing. vma_update_prot only touches the table;
     * if a partial-overlap split cannot fit (table full) it returns -1 having
     * changed nothing, and we fail with -ENOMEM before any PTE is modified —
     * the protections and the table never desync. (Linux mprotect likewise
     * returns ENOMEM when it cannot allocate the VMA split, so the errno is
     * POSIX-faithful.)
     *
     * Ordering note re: the !any_mapped ENOMEM check below: a range with no
     * backing frames also has no overlapping VMA entry (a live VMA always has
     * frames — PROT_NONE pages keep their phys recorded, so they too count as
     * mapped), so for such a range vma_update_prot is a no-op (no overlap →
     * extra==0, no mutation). Running it first is therefore consistent with
     * returning ENOMEM afterward: nothing was changed in that case either. */
    if (vma_update_prot(proc, addr, rlen, (uint32_t)(prot & 0x07)) != 0)
        return SYS_ERR(ENOMEM);   /* -ENOMEM: cannot record split */

    uint64_t va;
    int any_mapped = 0;   /* did at least one page in the range have a mapping? */
    for (va = addr; va < addr + rlen; va += 4096UL) {
        /* vmm_set_user_prot returns -1 ONLY when the page has no backing
         * frame at any paging level (an absent PML4/PDPT/PD entry, or a PT
         * entry with neither PRESENT nor a stored phys). It performs no
         * allocation and has no other failure mode, so -1 unambiguously means
         * "this single page is a hole" — never OOM or a bad argument.
         *
         * A mid-range hole is legitimate: musl's dynamic linker mprotects an
         * ET_DYN object's whole [base, base+memsz) span — which spans the gap
         * between PT_LOAD segments — and sparse/file-backed mappings leave
         * holes too. POSIX mprotect must apply the new protection to the
         * pages that ARE mapped and not abort on the gap. So skip holes and
         * continue rather than failing the whole call (the previous code
         * returned EINVAL on the first hole, aborting these valid operations).
         *
         * PROT_NONE on an unmapped page also returns 0 (a harmless no-op);
         * it does not set any_mapped, which is correct — it changed nothing. */
        if (vmm_set_user_prot(proc->pml4_phys, va, flags) == 0)
            any_mapped = 1;
    }

    /* POSIX: if the range contains no mapped pages at all, it names no
     * mapping — fail with ENOMEM rather than silently succeeding. A request
     * that touched at least one mapped page succeeds (holes were skipped).
     * (flags == 0 / PROT_NONE on a wholly-unmapped range is a true no-op and
     * vmm_set_user_prot returns 0 for it, so any_mapped is set and we return
     * success — there is nothing to protect and nothing to report.) */
    if (!any_mapped) {
        /* No backing frames — but a lazy (unpopulated) anonymous VMA is still
         * a real mapping: mm_populate_fault will back it on first touch using
         * the prot just recorded by vma_update_prot. Only ENOMEM if NO VMA
         * covers the range (it truly names no mapping). This is the case musl
         * pthread_create hits: it mmaps the thread stack PROT_NONE, then
         * mprotects it RW before any page faults — under lazy anon that range
         * has zero frames, so a frame-only check spuriously returned ENOMEM and
         * pthread_create failed with EAGAIN. */
        int has_vma = 0;
        for (va = addr; va < addr + rlen; va += 4096UL) {
            if (vma_find(proc, va)) { has_vma = 1; break; }
        }
        if (!has_vma)
            return SYS_ERR(ENOMEM);   /* -ENOMEM: range has no mapping */
    }

    return 0;
}

/* ── sys_memfd_create ─────────────────────────────────────────────────── */

uint64_t sys_memfd_create(uint64_t name_ptr, uint64_t flags)
{
    (void)flags;
    aegis_process_t *proc = current_proc();
    if (cap_check(proc->caps, CAP_TABLE_SIZE, CAP_KIND_IPC, CAP_RIGHTS_READ) != 0)
        return SYS_ERR(ENOCAP);

    char name[32] = {0};
    if (name_ptr) {
        for (int i = 0; i < 31; i++) {
            /* Validate EACH byte before reading it: the name may straddle a
             * page boundary and walk into an unmapped/non-canonical page.
             * There is no fault fixup table, so an unchecked copy_from_user
             * would fault the kernel. Mirror the per-byte pattern used in
             * sys_open's path copy. Stop at NUL; leave name[] zero-filled. */
            if (!user_ptr_valid(name_ptr + (uint64_t)i, 1))
                break;
            uint8_t c;
            copy_from_user(&c, (const void *)(uintptr_t)(name_ptr + (uint64_t)i), 1);
            if (!c) break;
            name[i] = (char)c;
        }
    }

    int mid = memfd_alloc(name);
    if (mid < 0) return SYS_ERR(EMFILE);

    int fd = memfd_open_fd((uint32_t)mid, proc);
    if (fd < 0) {
        memfd_t *mf = memfd_get((uint32_t)mid);
        if (mf) { refcount_init(&mf->refcount, 0); mf->in_use = 0; }
        return SYS_ERR(EMFILE);
    }
    return (uint64_t)fd;
}

/* ── sys_ftruncate ────────────────────────────────────────────────────── */

uint64_t sys_ftruncate(uint64_t fd_arg, uint64_t length)
{
    aegis_process_t *proc = current_proc();
    memfd_t *mf = memfd_from_fd((int)fd_arg, proc);
    if (!mf) return SYS_ERR(EINVAL);  /* EINVAL: not a memfd */

    uint32_t mid = (uint32_t)(uintptr_t)proc->fd_table->fds[(int)fd_arg].priv;
    int rc = memfd_truncate(mid, length);
    return rc < 0 ? (uint64_t)(int64_t)rc : 0;
}
