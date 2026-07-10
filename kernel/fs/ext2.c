/* ext2.c — ext2 filesystem driver (mount, inode ops, block alloc, public API)
 *
 * Block cache lives in ext2_cache.c.
 * Directory helpers live in ext2_dir.c.
 * Shared state and internal declarations in ext2_internal.h.
 *
 * No libc, no malloc, no VLAs.
 */

#include "ext2_internal.h"
#include "spinlock.h"
#include "smp.h"   /* percpu_self()->cpu_id for the recursive lock owner */
#include "vfs.h"   /* vfs_open/vfs_file_t — ext2_anchors_reload reads /etc/aegis/anchors */

/* ext2_internal.h defines EIO/EINVAL/etc. but not EFBIG.  ext2_write needs
 * it to reject writes that would exceed the driver's max file size. */
#ifndef EFBIG
#define EFBIG        27
#endif

/* Maximum file size this driver supports — see ext2_max_file_size() below.
 * The on-disk ext2 inode stores only the low 32 bits of the size in i_size
 * (this driver does not implement the i_size_high / i_dir_acl 64-bit
 * extension), so files are inherently below 4 GiB. */
static uint64_t ext2_max_file_size(void);

spinlock_t ext2_lock = SPINLOCK_INIT;

/* ── Recursive ext2_lock ──────────────────────────────────────────────
 * The ext2 path-resolution / inode / permission / block-map helpers are
 * called BOTH from already-locked data paths (ext2_read/readdir/write) AND
 * directly from unlocked VFS/exec callers (vfs_open, sys_execve's ext2_open +
 * ext2_check_perm, fstat, etc.).  A non-recursive lock cannot serve both, so
 * historically the helpers ran lock-free — fine single-core, but on SMP the
 * unlocked callers raced the shared 16-slot block cache: cache_get_slot()
 * returns a pointer INTO a cache slot that another CPU's cache_evict() can
 * repurpose mid-use, so a concurrent stat/open while another core ran exec
 * tore the ELF/dir block → ld-musl dereferenced a garbage relocation pointer
 * (user CR2=<garbage>) or the path walk followed a corrupted inode/block
 * number into a kernel fault.  Making ext2_lock recursive lets every public
 * entry acquire it unconditionally while nested internal calls just bump a
 * depth counter.  Interrupts are disabled first so cpu_id is stable; the lock
 * owner is only ever set to / read as "mine" by the owning CPU, so the
 * lock-free owner check is sound (a stale read of another owner or -1 just
 * routes to the real spin_lock, which is always correct). */
static volatile int s_ext2_owner = -1;   /* cpu_id of the holder, -1 = free */
static int          s_ext2_depth = 0;     /* recursion depth (owner-only) */

/* Monotonic in-memory inode-generation counter (secfix M2). Every newly
 * allocated inode is stamped with a unique generation; lazy file mmap captures
 * it and revalidates at fault time so a recycled inode number (unlink → realloc
 * for a different, possibly more-privileged file) is detected and faulted
 * instead of silently leaking the new file's contents through the stale
 * mapping. Per-boot (mappings do not survive reboot); only ever read/written
 * under the recursive ext2 lock. Starts at 1 so it differs from the on-disk
 * generation 0 of files created at image-build time. */
static uint32_t     s_inode_gen_ctr = 1;

/* ext2_next_gen — allocate the next unique inode generation. ext2 lock held. */
static uint32_t ext2_next_gen(void)
{
    s_inode_gen_ctr++;
    if (s_inode_gen_ctr == 0)        /* skip 0 on the (boot-length) wrap */
        s_inode_gen_ctr = 1;
    return s_inode_gen_ctr;
}

irqflags_t ext2_lock_acquire(void)
{
    irqflags_t fl = arch_irq_save();              /* irqs off → cpu_id stable */
    int cpu = (int)percpu_self()->cpu_id;
    if (s_ext2_owner == cpu) {
        s_ext2_depth++;                            /* recursive re-entry */
        return fl;
    }
    spin_lock(&ext2_lock);                         /* irqs already off */
    s_ext2_owner = cpu;
    s_ext2_depth = 1;
    return fl;
}

void ext2_lock_release(irqflags_t fl)
{
    if (--s_ext2_depth == 0) {
        s_ext2_owner = -1;
        spin_unlock(&ext2_lock);
    }
    arch_irq_restore(fl);
}

/* Public, recursive-lock-acquiring wrappers for the cache-touching helpers
 * (bodies are the *_impl forms further below).  Every caller uses these public
 * names: internal-under-lock callers re-enter recursively (cheap depth bump),
 * external-unlocked callers (vfs_open / sys_execve / fstat) acquire fresh — so
 * all shared block-cache access is serialized. */
static int      ext2_read_inode_impl(uint32_t ino, ext2_inode_t *out);
static int      ext2_write_inode_impl(uint32_t ino, const ext2_inode_t *inode);

/* Current wall-clock Unix seconds for inode timestamps. 0 until the NTP daemon
 * sets the epoch offset, but still advances across a boot — enough for make/git
 * to see a rewritten file as newer (mtime always 0 was silently breaking
 * incremental builds and `ls -l`). */
void arch_clock_gettime(uint64_t *sec, uint64_t *nsec);
static uint32_t ext2_now(void)
{
    uint64_t s = 0, n = 0;
    arch_clock_gettime(&s, &n);
    return (uint32_t)s;
}
static uint32_t ext2_block_num_impl(const ext2_inode_t *inode, uint32_t file_block);
static uint32_t ext2_ind_get(uint32_t blk, uint32_t idx);
static int      ext2_read_symlink_target_impl(uint32_t ino, char *buf, uint32_t bufsiz);
static int      ext2_walk_impl(const char *path, uint32_t *inode_out,
                               int follow_final, int *touched);
static void     icache_clear(void);   /* parsed-inode cache; defined below */

int ext2_read_inode(uint32_t ino, ext2_inode_t *out)
{
    irqflags_t fl = ext2_lock_acquire();
    int r = ext2_read_inode_impl(ino, out);
    ext2_lock_release(fl);
    return r;
}

int ext2_write_inode(uint32_t ino, const ext2_inode_t *inode)
{
    irqflags_t fl = ext2_lock_acquire();
    int r = ext2_write_inode_impl(ino, inode);
    ext2_lock_release(fl);
    return r;
}

uint32_t ext2_block_num(const ext2_inode_t *inode, uint32_t file_block)
{
    irqflags_t fl = ext2_lock_acquire();
    uint32_t r = ext2_block_num_impl(inode, file_block);
    ext2_lock_release(fl);
    return r;
}

int ext2_read_symlink_target(uint32_t ino, char *buf, uint32_t bufsiz)
{
    irqflags_t fl = ext2_lock_acquire();
    int r = ext2_read_symlink_target_impl(ino, buf, bufsiz);
    ext2_lock_release(fl);
    return r;
}

static int ext2_walk(const char *path, uint32_t *inode_out, int follow_final,
                     int *touched)
{
    irqflags_t fl = ext2_lock_acquire();
    int r = ext2_walk_impl(path, inode_out, follow_final, touched);
    ext2_lock_release(fl);
    return r;
}

/* ------------------------------------------------------------------ */
/* Shared globals — accessed by ext2_cache.c and ext2_dir.c via extern */
/* ------------------------------------------------------------------ */

blkdev_t *s_dev;
ext2_superblock_t s_sb;
uint32_t s_block_size;
uint32_t s_num_groups;
ext2_bgd_t s_bgd[32];   /* support up to 32 block groups */
int s_mounted = 0;

/* Per-group allocation resume-hints (block + inode bitmaps).  The bitmap scan
 * in ext2_alloc_block/ext2_alloc_inode used to restart at bit 0 on every call,
 * so the k-th allocation in a group scanned past the k-1 already-set bits —
 * O(n²) per group, the dominant CPU cost when writing a large file or
 * extracting an install (thousands of sequential allocations).  The hint
 * records the next bit to try; the scan resumes there and only wraps to
 * [0, hint) if the tail is full, so a freed low bit is still found (correctness
 * preserved) while sequential allocation is amortized O(1).  Reset at mount. */
static uint32_t s_blk_hint[32];
static uint32_t s_ino_hint[32];

/* Largest file this driver can address, derived from the mounted block size:
 * direct (12) + single-indirect (ppb) + double-indirect (ppb*ppb) data blocks,
 * where ppb = block_size/4.  This is ≈67 MiB at 1 KiB blocks and ≈4 GiB at
 * 4 KiB blocks.  Capped one block below 4 GiB because i_size is a 32-bit field
 * and every derived byte offset / file_block must stay within uint32.  The old
 * fixed 256 MiB cap truncated large downloads (e.g. a 279 MB herald package)
 * even though 4 KiB-block filesystems can address far more.  Triple-indirect is
 * not implemented, so this is the true ceiling. */
static uint64_t ext2_max_file_size(void)
{
    uint64_t ppb    = (uint64_t)s_block_size / 4u;
    uint64_t blocks = 12u + ppb + ppb * ppb;
    uint64_t bytes  = blocks * (uint64_t)s_block_size;
    uint64_t cap    = (uint64_t)0xFFFFFFFFu - (uint64_t)s_block_size;
    return bytes < cap ? bytes : cap;
}

/* Inode of /etc/shadow on the mounted ext2 volume.  Populated at mount
 * time and used by vfs_open to enforce CAP_KIND_AUTH after symlink
 * resolution — the pre-resolution string check in sys_open is
 * insufficient because symlinks and ".." can alias the path.
 * 0 = not found (live boot without ext2 shadow). */
static uint32_t s_shadow_ino = 0;

uint32_t ext2_get_shadow_ino(void) { return s_shadow_ino; }

/* Inode of /etc/aegis/admin — the admin-elevation credential hash.  Gated for
 * READS the same way /etc/shadow is (CAP_KIND_AUTH, even for uid=0): it is the
 * sole gate on admin_session / CAP_KIND_INSTALL, so a baseline process must not
 * be able to read it and crack the hash offline.  Recorded at mount; compared
 * against the resolved inode in vfs_open so symlinks/".." cannot alias it.
 * This is a per-FILE gate, NOT a gate on all of /etc/aegis (caps.d/, anchors,
 * etc. must stay readable).  0 = not present on this volume. */
static uint32_t s_admin_ino = 0;

uint32_t ext2_get_admin_ino(void) { return s_admin_ino; }

/* Inodes of the install-protected trees, recorded at mount. Mutations under
 * these (resolved through symlinks / "..") require CAP_KIND_INSTALL. 0 = the
 * tree is absent on this volume (no protection to enforce).
 *
 * /bin and /sbin are protected for a security-critical reason: the cap-policy
 * trusted-path anchor (cap_policy_lookup) DERIVES policy capabilities from any
 * executable under /bin, /sbin, or /apps. If those trees were writable by an
 * ordinary user, that user could overwrite /bin/login (→ AUTH+SETUID) or drop
 * a /bin/reboot (→ POWER) and forge authority by filename — exactly the
 * privilege-by-filename attack the anchor exists to stop. The trusted-for-
 * granting tree and the write-protected tree MUST be the same set. */
static uint32_t s_apps_ino = 0;
static uint32_t s_etc_aegis_ino = 0;
static uint32_t s_bin_ino = 0;
static uint32_t s_sbin_ino = 0;
/* Dynamic install-anchor set: extra trusted-path / install-protected dirs beyond
 * the hardcoded builtins above. Registered from /etc/aegis/anchors (one absolute
 * path per line) by ext2_anchors_reload() — called at boot after mount and by
 * sys_install_commit() when herald installs a package that writes outside /apps
 * (e.g. an engine library closure under /lib/<app>). Both the cap-policy
 * trusted-path anchor (cap_policy.c, matched by path prefix) and this fs
 * write-protection (matched by inode) derive from the SAME anchors file,
 * refreshed together — preserving the load-bearing "trusted-for-granting ==
 * write-protected" invariant. The anchors file lives under /etc/aegis (itself a
 * builtin protected tree), so only CAP_KIND_INSTALL (herald) can extend the set. */
#define EXT2_ANCHOR_MAX 16
static uint32_t s_anchor_ino[EXT2_ANCHOR_MAX];
static int      s_anchor_count = 0;

static int
ext2_ino_is_anchor(uint32_t ino)
{
    int j;
    for (j = 0; j < s_anchor_count; j++)
        if (s_anchor_ino[j] == ino)
            return 1;
    return 0;
}

/* ------------------------------------------------------------------ */
/* Filesystem clean/dirty state (superblock s_state)                   */
/* ------------------------------------------------------------------ */
/* ext2's s_state records whether the volume was cleanly unmounted.  We clear
 * EXT2_VALID_FS at mount (mark it "in use") and restore it only on an orderly
 * shutdown (ext2_mark_clean, from sys_reboot after ext2_sync), so the next
 * mount can DETECT an unclean shutdown — power loss or a crash — and warn.
 * Detection only: there is no journal or in-kernel fsck.  This matches the
 * standard ext2 semantics, so the image stays e2fsck-compatible.
 *
 * s_state lives at byte offset 58 of the 1024-byte superblock (LBA 2, two
 * 512-byte sectors).  Patch it with a read-modify-write of those two sectors
 * so the rest of the superblock — which this driver keeps only a truncated
 * in-memory copy of (ext2_superblock_t) — is preserved.  The superblock block
 * is never held in the block cache, so a direct device RMW is coherent.
 * Caller holds ext2_lock. */
static void ext2_super_write_state(uint16_t state)
{
    uint8_t sb_buf[1024];
    if (!s_dev)
        return;
    if (s_dev->read(s_dev, 2, 2, sb_buf) < 0)
        return;
    sb_buf[58] = (uint8_t)(state & 0xffu);
    sb_buf[59] = (uint8_t)((state >> 8) & 0xffu);
    s_dev->write(s_dev, 2, 2, sb_buf);
    s_sb.s_state = state;
}

void ext2_mark_clean(void)
{
    irqflags_t fl = ext2_lock_acquire();
    if (s_mounted && s_dev)
        ext2_super_write_state((uint16_t)(s_sb.s_state | EXT2_VALID_FS));
    ext2_lock_release(fl);
}

/* ------------------------------------------------------------------ */
/* ext2_mount                                                          */
/* ------------------------------------------------------------------ */

int ext2_mount(const char *devname)
{
    irqflags_t fl = ext2_lock_acquire();
    uint32_t i;

    /* Initialise cache slots to age 0 (unused) */
    for (i = 0; i < CACHE_SLOTS; i++) {
        s_cache[i].block_num = 0;
        s_cache[i].dirty = 0;
        s_cache[i].age = 0;
    }

    /* Reset per-group allocation resume-hints for this mount. */
    for (i = 0; i < 32; i++) {
        s_blk_hint[i] = 0;
        s_ino_hint[i] = 0;
    }

    /* Drop any parsed inodes cached from a previous mount. */
    icache_clear();

    int ret = -1;

    s_dev = blkdev_get(devname);
    if (!s_dev)
        goto mount_out;  /* silent — no NVMe on -machine pc */

    /* Superblock is at byte offset 1024 from partition start.
     * blkdev uses 512-byte sectors: LBA 2 = byte 1024. */
    uint8_t sb_buf[1024];
    if (s_dev->read(s_dev, 2, 2, sb_buf) < 0)
        goto mount_out;

    /* Copy superblock from start of buffer */
    uint8_t *src = sb_buf;
    uint8_t *dst = (uint8_t *)&s_sb;
    for (i = 0; i < sizeof(ext2_superblock_t); i++)
        dst[i] = src[i];

    if (s_sb.s_magic != EXT2_MAGIC)
        goto mount_out;

    /* The whole driver assumes block size <= 4096: every cache slot is a
     * fixed 4096-byte buffer (cache_slot_t.data[4096] in ext2_internal.h)
     * and cache_get_slot reads s_block_size/512 sectors into it.  A larger
     * block (s_log_block_size > 2 → > 4096 bytes) would overflow that buffer
     * and clobber adjacent cache slots, so reject it at mount time. */
    if (s_sb.s_log_block_size > 2) {   /* block size > 4096 unsupported */
        printk("[EXT2] FAIL: invalid log_block_size %u\n",
               (unsigned)s_sb.s_log_block_size);
        goto mount_out;
    }
    s_block_size = 1024u << s_sb.s_log_block_size;
    /* s_inode_size must be a power of two in [128, block_size].  The inode-read
     * path computes in_block = (index * inode_size) % s_block_size and copies a
     * fixed 128 bytes from cache_slot.data + in_block; a non-power-of-two size
     * (e.g. 900) makes in_block land near the end of the slot so the 128-byte
     * read runs past it into the adjacent cache slot (OOB read).  Requiring a
     * power of two <= block_size also guarantees block_size % inode_size == 0,
     * so every inode lies wholly within one block — true for any real ext2. */
    if (s_sb.s_rev_level >= 1) {
        uint32_t isz = s_sb.s_inode_size;
        if (isz < 128 || isz > s_block_size || (isz & (isz - 1)) != 0) {
            printk("[EXT2] FAIL: invalid inode_size %u (block_size=%u)\n",
                   (unsigned)isz, (unsigned)s_block_size);
            goto mount_out;
        }
    }

    /* Validate the divisor fields BEFORE any division.  s_blocks_per_group is
     * the divisor just below; s_inodes_per_group divides in ext2_read_inode /
     * ext2_alloc_inode.  A crafted (or corrupt) image with either == 0 would
     * otherwise trigger a divide-by-zero #DE kernel fault mid-mount.  Reject
     * the mount instead (the kernel falls back to the RAM rootfs).  Also reject
     * s_first_data_block > 1: the BGD-block computation below only handles the
     * standard values (1 for 1 KiB blocks, 0 otherwise); a larger value would
     * read the group descriptors from the wrong block. */
    if (s_sb.s_blocks_per_group == 0 || s_sb.s_inodes_per_group == 0 ||
        s_sb.s_first_data_block > 1) {
        printk("[EXT2] FAIL: bad superblock geometry "
               "(blocks_per_group=%u inodes_per_group=%u first_data_block=%u)\n",
               (unsigned)s_sb.s_blocks_per_group,
               (unsigned)s_sb.s_inodes_per_group,
               (unsigned)s_sb.s_first_data_block);
        goto mount_out;
    }

    /* Each group's inode/block bitmap is exactly one block (<= 4096 bytes), so a
     * group can describe at most 8 * block_size objects.  The allocators and the
     * unlink/rmdir bitmap-clear index bitmap[bit/8] directly from a one-block
     * cache slot; an unbounded inodes_per_group/blocks_per_group (a crafted image
     * can set either to e.g. 2^20) drives that index far past the slot — an OOB
     * read+write into adjacent cache slots (kernel BSS).  Reject at mount. */
    if (s_sb.s_inodes_per_group > 8u * s_block_size ||
        s_sb.s_blocks_per_group > 8u * s_block_size) {
        printk("[EXT2] FAIL: per-group count exceeds one bitmap block "
               "(inodes_per_group=%u blocks_per_group=%u block_size=%u)\n",
               (unsigned)s_sb.s_inodes_per_group,
               (unsigned)s_sb.s_blocks_per_group,
               (unsigned)s_block_size);
        goto mount_out;
    }

    s_num_groups = (s_sb.s_blocks_count + s_sb.s_blocks_per_group - 1)
                   / s_sb.s_blocks_per_group;
    if (s_num_groups > 32)
        s_num_groups = 32;

    /* BGD table is at the block immediately after the superblock.
     * For 1024-byte blocks: superblock is in block 1, BGD at block 2.
     * For larger blocks:    superblock is in block 0, BGD at block 1. */
    uint32_t bgd_block = (s_sb.s_first_data_block == 1) ? 2 : 1;

    uint8_t *bgd_buf = cache_get_slot(bgd_block);
    if (!bgd_buf)
        goto mount_out;

    uint32_t bgd_bytes = s_num_groups * sizeof(ext2_bgd_t);
    src = bgd_buf;
    dst = (uint8_t *)s_bgd;
    for (i = 0; i < bgd_bytes; i++)
        dst[i] = src[i];

    s_mounted = 1;

    /* Unclean-shutdown detection: if the volume still has EXT2_VALID_FS set it
     * was cleanly unmounted; if not, a previous run left it dirty (crash / power
     * loss) — warn.  Then clear VALID to mark the volume in use; ext2_mark_clean()
     * restores it on orderly shutdown.  Preserves the EXT2_ERROR_FS bit so the
     * state stays e2fsck-meaningful. */
    if (!(s_sb.s_state & EXT2_VALID_FS))
        printk("[EXT2] WARN: %s was not cleanly unmounted (s_state=%u)\n",
               devname, (unsigned)s_sb.s_state);
    ext2_super_write_state((uint16_t)(s_sb.s_state & ~(uint16_t)EXT2_VALID_FS));

    /* Record the inode of /etc/shadow for post-resolution capability
     * enforcement in vfs_open.  Must happen after s_mounted=1 so
     * ext2_open_ex can walk the directory tree. */
    {
        uint32_t shadow_ino = 0;
        if (ext2_open_ex("/etc/shadow", &shadow_ino, 1) == 0)
            s_shadow_ino = shadow_ino;
        uint32_t admin_ino = 0;
        if (ext2_open_ex("/etc/aegis/admin", &admin_ino, 1) == 0)
            s_admin_ino = admin_ino;
    }

    /* Record the install-protected tree inodes (same rationale as shadow:
     * enforce on the resolved inode, not the path string). */
    {
        uint32_t ino = 0;
        if (ext2_open_ex("/apps", &ino, 1) == 0)
            s_apps_ino = ino;
        ino = 0;
        if (ext2_open_ex("/etc/aegis", &ino, 1) == 0)
            s_etc_aegis_ino = ino;
        ino = 0;
        if (ext2_open_ex("/bin", &ino, 1) == 0)
            s_bin_ino = ino;
        ino = 0;
        if (ext2_open_ex("/sbin", &ino, 1) == 0)
            s_sbin_ino = ino;
        /* Dynamic anchors (e.g. /lib/<app> from installed packages) are recorded
         * post-mount by ext2_anchors_reload() — they require reading a file
         * (/etc/aegis/anchors), which can't be done under the mount lock. */
    }

    printk("[EXT2] OK: mounted %s, %u blocks, %u inodes\n",
           devname, s_sb.s_blocks_count, s_sb.s_inodes_count);
    ret = 0;
mount_out:
    ext2_lock_release(fl);
    return ret;
}

/* ------------------------------------------------------------------ */
/* Parsed-inode cache                                                  */
/* ------------------------------------------------------------------ */
/* ext2_read_inode_impl re-parsed each inode out of the 16-slot block cache
 * on every call: a CACHE_SLOTS linear scan in cache_find() plus a
 * sizeof(ext2_inode_t) byte copy.  Path resolution touches the same inodes
 * repeatedly — every component of every open/stat reads its parent directory
 * inode and the target inode — so a small parsed-inode cache eliminates that
 * rescan+parse for hot inodes.
 *
 * Coherence: keyed by inode number.  EVERY mutation of an inode's on-disk
 * bytes flows through ext2_write_inode_impl — it is the sole writer of the
 * inode-table blocks (verified: every other cache_mark_dirty site touches a
 * bitmap, directory data, or an indirect/data block, never an inode-table
 * block) — and it updates the matching cache entry in lockstep.  So a cached
 * copy always equals what a fresh block-cache parse would return.  The
 * superblock-state RMW in ext2_mark_clean() writes the superblock block only,
 * not inode tables, so it does not perturb this invariant.
 *
 * Locking: the only callers of ext2_{read,write}_inode_impl are the public
 * wrappers, which hold the recursive ext2_lock, so the cache is accessed
 * serialized-per-fs and needs no separate lock.  Cleared at mount.  LRU via a
 * 64-bit age (same scheme as the block cache: monotonic, never wraps in
 * practice).
 *
 * Negative caching (caching "inode is free → ENOENT") from the Serenity design
 * is intentionally NOT implemented: Aegis's read path never consults the inode
 * allocation bitmap — a non-existent name resolves to ENOENT at the directory-
 * entry layer (ext2_walk), so ext2_read_inode is only ever called for inodes
 * that exist.  A negative inode cache would have no hit path here, so it is
 * omitted rather than added as dead/speculative state. */
#define ICACHE_SLOTS 32
typedef struct {
    uint32_t     ino;    /* 0 = slot unused (inode 0 is invalid in ext2) */
    uint64_t     age;    /* LRU recency; only meaningful when ino != 0 */
    ext2_inode_t inode;
} icache_slot_t;
static icache_slot_t s_icache[ICACHE_SLOTS];
static uint64_t      s_icache_age = 0;

static void icache_clear(void)
{
    int i;
    for (i = 0; i < ICACHE_SLOTS; i++) {
        s_icache[i].ino = 0;
        s_icache[i].age = 0;
    }
}

/* Insert or update the cached copy of inode `ino`.  Caller holds ext2_lock. */
static void icache_put(uint32_t ino, const ext2_inode_t *src)
{
    if (ino == 0)
        return;
    int i, slot = -1, free_slot = -1, lru = 0;
    for (i = 0; i < ICACHE_SLOTS; i++) {
        if (s_icache[i].ino == ino) { slot = i; break; }   /* update in place */
        if (s_icache[i].ino == 0 && free_slot < 0) free_slot = i;
        if (s_icache[i].age < s_icache[lru].age) lru = i;
    }
    if (slot < 0)
        slot = (free_slot >= 0) ? free_slot : lru;

    const uint8_t *s = (const uint8_t *)src;
    uint8_t *d = (uint8_t *)&s_icache[slot].inode;
    uint32_t b;
    for (b = 0; b < sizeof(ext2_inode_t); b++)
        d[b] = s[b];
    s_icache[slot].ino = ino;
    s_icache[slot].age = ++s_icache_age;
}

/* Copy the cached inode for `ino` into `out` if present.  Returns 1 on hit
 * (bumping recency), 0 on miss.  Caller holds ext2_lock. */
static int icache_get(uint32_t ino, ext2_inode_t *out)
{
    int i;
    for (i = 0; i < ICACHE_SLOTS; i++) {
        if (ino != 0 && s_icache[i].ino == ino) {
            const uint8_t *s = (const uint8_t *)&s_icache[i].inode;
            uint8_t *d = (uint8_t *)out;
            uint32_t b;
            for (b = 0; b < sizeof(ext2_inode_t); b++)
                d[b] = s[b];
            s_icache[i].age = ++s_icache_age;
            return 1;
        }
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* ext2_read_inode (internal)                                          */
/* ------------------------------------------------------------------ */

static int ext2_read_inode_impl(uint32_t ino, ext2_inode_t *out)
{
    if (ino == 0) return -EIO;   /* inode 0 is reserved/invalid in ext2 */
    if (icache_get(ino, out))
        return 0;                /* parsed-inode cache hit */
    uint32_t group       = (ino - 1) / s_sb.s_inodes_per_group;
    uint32_t index       = (ino - 1) % s_sb.s_inodes_per_group;
    if (group >= s_num_groups || group >= 32) {
        return -1;
    }
    uint32_t inode_size  = (s_sb.s_rev_level >= 1)
                           ? (uint32_t)s_sb.s_inode_size : 128u;
    uint32_t inode_table_block = s_bgd[group].bg_inode_table;
    uint32_t byte_offset = index * inode_size;
    uint32_t block_offset = byte_offset / s_block_size;
    uint32_t in_block    = byte_offset % s_block_size;

    uint8_t *data = cache_get_slot(inode_table_block + block_offset);
    if (!data)
        return -1;

    uint8_t *src = data + in_block;
    uint8_t *dst = (uint8_t *)out;
    uint32_t i;
    for (i = 0; i < sizeof(ext2_inode_t); i++)
        dst[i] = src[i];

    icache_put(ino, out);   /* warm the parsed-inode cache */
    return 0;
}

/* ------------------------------------------------------------------ */
/* ext2_write_inode (internal)                                         */
/* ------------------------------------------------------------------ */

static int ext2_write_inode_impl(uint32_t ino, const ext2_inode_t *inode)
{
    uint32_t group       = (ino - 1) / s_sb.s_inodes_per_group;
    uint32_t index       = (ino - 1) % s_sb.s_inodes_per_group;
    if (group >= s_num_groups || group >= 32) {
        return -1;
    }
    uint32_t inode_size  = (s_sb.s_rev_level >= 1)
                           ? (uint32_t)s_sb.s_inode_size : 128u;
    uint32_t inode_table_block = s_bgd[group].bg_inode_table;
    uint32_t byte_offset = index * inode_size;
    uint32_t block_offset = byte_offset / s_block_size;
    uint32_t in_block    = byte_offset % s_block_size;

    uint8_t *data = cache_get_slot(inode_table_block + block_offset);
    if (!data)
        return -1;

    uint8_t *dst = data + in_block;
    const uint8_t *src = (const uint8_t *)inode;
    uint32_t i;
    for (i = 0; i < sizeof(ext2_inode_t); i++)
        dst[i] = src[i];

    cache_mark_dirty(inode_table_block + block_offset);
    icache_put(ino, inode);   /* keep the parsed-inode cache coherent */
    return 0;
}

/* ------------------------------------------------------------------ */
/* ext2_block_num (internal)                                           */
/* ------------------------------------------------------------------ */

static uint32_t ext2_block_num_impl(const ext2_inode_t *inode,
                        uint32_t file_block)
{
    uint32_t ptrs_per_block = s_block_size / 4;

    if (file_block < 12)
        return inode->i_block[file_block];

    if (file_block < 12 + ptrs_per_block) {
        uint32_t indirect = inode->i_block[12];
        if (indirect == 0)
            return 0;
        uint8_t *data = cache_get_slot(indirect);
        if (!data)
            return 0;
        uint32_t off = file_block - 12;
        uint32_t entry;
        uint8_t *p = data + off * 4;
        entry  = (uint32_t)p[0];
        entry |= (uint32_t)p[1] << 8;
        entry |= (uint32_t)p[2] << 16;
        entry |= (uint32_t)p[3] << 24;
        return entry;
    }

    /* Double indirect: i_block[13] → block of pointers → block of pointers */
    if (file_block < 12 + ptrs_per_block + ptrs_per_block * ptrs_per_block) {
        uint32_t dind = inode->i_block[13];
        if (dind == 0) return 0;
        uint8_t *outer = cache_get_slot(dind);
        if (!outer) return 0;
        uint32_t idx       = file_block - 12 - ptrs_per_block;
        uint32_t outer_off = idx / ptrs_per_block;
        uint32_t inner_off = idx % ptrs_per_block;
        uint8_t *op = outer + outer_off * 4;
        uint32_t ind;
        ind  = (uint32_t)op[0];
        ind |= (uint32_t)op[1] << 8;
        ind |= (uint32_t)op[2] << 16;
        ind |= (uint32_t)op[3] << 24;
        if (ind == 0) return 0;
        uint8_t *inner = cache_get_slot(ind);
        if (!inner) return 0;
        uint8_t *ip = inner + inner_off * 4;
        uint32_t entry;
        entry  = (uint32_t)ip[0];
        entry |= (uint32_t)ip[1] << 8;
        entry |= (uint32_t)ip[2] << 16;
        entry |= (uint32_t)ip[3] << 24;
        return entry;
    }

    return 0;   /* triple indirect not supported */
}

/* ext2_open moved below ext2_is_dir — now a thin wrapper around ext2_open_ex */

/* ------------------------------------------------------------------ */
/* ext2_read                                                           */
/* ------------------------------------------------------------------ */

int ext2_read(uint32_t inode_num, void *buf, uint64_t offset, uint32_t len)
{
    if (!s_mounted)
        return -1;
    irqflags_t fl = ext2_lock_acquire();

    ext2_inode_t inode;
    if (ext2_read_inode(inode_num, &inode) < 0) {
        ext2_lock_release(fl);
        return -1;
    }

    /* S9: Reject inodes whose i_size exceeds what this driver can address
     * (guards against corrupt/malicious ext2 images claiming an absurd size). */
    if ((uint64_t)inode.i_size > ext2_max_file_size()) {
        ext2_lock_release(fl);
        return -EIO;
    }

    if (offset >= inode.i_size) {
        ext2_lock_release(fl);
        return 0;
    }

    if (offset + len > inode.i_size)
        len = (uint32_t)(inode.i_size - offset);

    uint8_t *out = (uint8_t *)buf;
    uint32_t bytes_read = 0;

    /* offset < i_size (a 32-bit on-disk field) is guaranteed by the EOF check
     * above, so the low 32 bits below are lossless even though offset is u64. */
    uint32_t offset32 = (uint32_t)offset;

    while (bytes_read < len) {
        uint32_t cur_off = offset32 + bytes_read;
        uint32_t file_block = cur_off / s_block_size;
        uint32_t in_block   = cur_off % s_block_size;
        uint32_t can_copy   = s_block_size - in_block;
        if (can_copy > len - bytes_read)
            can_copy = len - bytes_read;

        uint32_t blk = ext2_block_num(&inode, file_block);
        if (blk == 0) {
            /* sparse block — fill zeros */
            uint32_t i;
            for (i = 0; i < can_copy; i++)
                out[bytes_read + i] = 0;
        } else if (in_block == 0 && can_copy == s_block_size &&
                   blk < s_sb.s_blocks_count && cache_find(blk) < 0) {
            /* Multi-block fast path: this and the following blocks are
             * full-block reads.  Gather a run of blocks that are consecutive
             * ON DISK and not in the cache (a cached block may be dirty — its
             * cached copy is authoritative), then issue ONE device read for
             * the whole run straight into the caller's buffer.  With the
             * NVMe multi-page bounce this turns a 64 KiB sequential read from
             * 16 serialized device round-trips into 1.  Bypassing the cache
             * also stops bulk data evicting the hot indirect/bitmap blocks
             * from its 16 slots.  Runs are capped so one request can never
             * exceed the block layer's per-command ceiling. */
            uint32_t max_run = (len - bytes_read) / s_block_size;
            uint32_t run_cap = EXT2_READ_RUN_BYTES / s_block_size;
            if (max_run > run_cap) max_run = run_cap;
            uint32_t run = 1;
            while (run < max_run) {
                uint32_t nb = ext2_block_num(&inode, file_block + run);
                if (nb != blk + run || nb >= s_sb.s_blocks_count ||
                    cache_find(nb) >= 0)
                    break;
                run++;
            }
            uint32_t spb = s_block_size / 512;
            s_cache_dev_reads++;
            if (s_dev->read(s_dev, (uint64_t)blk * spb, run * spb,
                            out + bytes_read) < 0) {
                ext2_lock_release(fl);
                return (int)bytes_read;
            }
            bytes_read += run * s_block_size;
            continue;
        } else {
            uint8_t *data = cache_get_slot(blk);
            if (!data) {
                ext2_lock_release(fl);
                return (int)bytes_read;
            }
            __builtin_memcpy(out + bytes_read, data + in_block, can_copy);
        }
        bytes_read += can_copy;
    }

    ext2_lock_release(fl);
    return (int)bytes_read;
}

/* ------------------------------------------------------------------ */
/* ext2_inode_gen / ext2_read_validated  (secfix M2)                   */
/* ------------------------------------------------------------------ */

/* Return the current generation stamp of an inode, or 0 on error. Used by lazy
 * file mmap to capture the backing inode's identity at mmap time. */
uint32_t ext2_inode_gen(uint32_t inode_num)
{
    if (!s_mounted)
        return 0;
    irqflags_t fl = ext2_lock_acquire();
    ext2_inode_t inode;
    if (ext2_read_inode(inode_num, &inode) < 0) {
        ext2_lock_release(fl);
        return 0;
    }
    uint32_t g = inode.i_generation;
    ext2_lock_release(fl);
    return g;
}

/* Generation-validated read for the lazy file-fault path. Holds the (recursive)
 * ext2 lock across the generation check AND the read so a concurrent unlink +
 * inode reallocation cannot slip between them (TOCTOU). Returns the byte count
 * (>=0) on a generation match, or EXT2_EGEN (-2) if the backing inode's
 * generation no longer equals expect_gen — i.e. the inode number was recycled
 * for a different file; the caller must fault rather than read the new file's
 * contents through the stale mapping. */
int ext2_read_validated(uint32_t inode_num, void *buf, uint64_t offset,
                        uint32_t len, uint32_t expect_gen)
{
    if (!s_mounted)
        return -1;
    irqflags_t fl = ext2_lock_acquire();
    ext2_inode_t inode;
    if (ext2_read_inode(inode_num, &inode) < 0) {
        ext2_lock_release(fl);
        return -1;
    }
    if (inode.i_generation != expect_gen) {
        ext2_lock_release(fl);
        return EXT2_EGEN;                 /* inode recycled — fault, don't leak */
    }
    int r = ext2_read(inode_num, buf, offset, len);  /* recursive lock OK */
    ext2_lock_release(fl);
    return r;
}

/* ------------------------------------------------------------------ */
/* ext2_file_size                                                       */
/* ------------------------------------------------------------------ */

int ext2_file_size(uint32_t inode_num)
{
    if (!s_mounted)
        return -1;

    ext2_inode_t inode;
    if (ext2_read_inode(inode_num, &inode) < 0)
        return -1;

    return (int)inode.i_size;
}

/* ------------------------------------------------------------------ */
/* ext2_statfs — filesystem totals for /proc/mounts                    */
/* ------------------------------------------------------------------ */

int ext2_statfs(uint64_t *total_kb, uint64_t *free_kb)
{
    if (!s_mounted)
        return -1;

    irqflags_t fl = ext2_lock_acquire();
    /* s_block_size is at least 1024 (1024 << s_log_block_size), so the
     * 1K-unit conversion factor is always >= 1. */
    uint64_t bs_kb = (uint64_t)(s_block_size / 1024u);
    *total_kb = (uint64_t)s_sb.s_blocks_count * bs_kb;
    *free_kb  = (uint64_t)s_sb.s_free_blocks_count * bs_kb;
    ext2_lock_release(fl);
    return 0;
}

/* ------------------------------------------------------------------ */
/* ext2_devname — name of the mounted block device                     */
/* ------------------------------------------------------------------ */

const char *ext2_devname(void)
{
    if (!s_mounted || !s_dev)
        return (const char *)0;
    return s_dev->name;
}

/* ------------------------------------------------------------------ */
/* ext2_readdir — index-based directory iteration                      */
/* ------------------------------------------------------------------ */

int ext2_readdir(uint32_t dir_inode, uint64_t index,
                 char *name_out, uint8_t *type_out)
{
    if (!s_mounted) return -1;
    irqflags_t fl = ext2_lock_acquire();
    ext2_inode_t inode;
    if (ext2_read_inode(dir_inode, &inode) < 0) {
        ext2_lock_release(fl);
        return -1;
    }
    if ((inode.i_mode & EXT2_S_IFMT) != EXT2_S_IFDIR) {
        ext2_lock_release(fl);
        return -1;
    }

    uint64_t count = 0;
    uint32_t file_block_idx = 0;
    uint32_t bytes_walked = 0;

    while (bytes_walked < inode.i_size) {
        uint32_t blk = ext2_block_num(&inode, file_block_idx);
        if (blk == 0) {
            bytes_walked += s_block_size;
            file_block_idx++;
            continue;
        }
        uint8_t *data = cache_get_slot(blk);
        if (!data) {
            ext2_lock_release(fl);
            return -1;
        }
        uint32_t block_pos = 0;
        while (block_pos + 8 <= s_block_size) {
            ext2_dirent_t *de = (ext2_dirent_t *)(data + block_pos);
            if (de->rec_len < 8 || block_pos + de->rec_len > s_block_size)
                break;
            /* name_len must fit inside the entry record (rec_len already
             * validated >= 8 above, so rec_len - 8 cannot underflow).
             * Promote to uint32_t for the compare.  A crafted entry with
             * name_len > rec_len - 8 would otherwise read past the 4096
             * cache buffer and leak those bytes to userspace via getdents. */
            if ((uint32_t)de->name_len + 8u > (uint32_t)de->rec_len) {
                block_pos += de->rec_len;
                continue;
            }
            if (de->inode != 0) {
                if (count == index) {
                    uint8_t nlen = de->name_len;
                    uint32_t k;
                    for (k = 0; k < nlen; k++) name_out[k] = de->name[k];
                    name_out[nlen] = '\0';
                    if (de->file_type == EXT2_FT_DIR)
                        *type_out = 4u;   /* DT_DIR */
                    else if (de->file_type == EXT2_FT_SYMLINK)
                        *type_out = 10u;  /* DT_LNK */
                    else
                        *type_out = 8u;   /* DT_REG */
                    ext2_lock_release(fl);
                    return 0;
                }
                count++;
            }
            block_pos += de->rec_len;
        }
        bytes_walked += s_block_size;
        file_block_idx++;
    }
    ext2_lock_release(fl);
    return -1;
}

/* ------------------------------------------------------------------ */
/* ext2_is_dir — returns 1 if inode is a directory, 0 otherwise       */
/* ------------------------------------------------------------------ */

int ext2_is_dir(uint32_t ino)
{
    if (!s_mounted) return 0;
    ext2_inode_t inode;
    if (ext2_read_inode(ino, &inode) < 0) return 0;
    return ((inode.i_mode & EXT2_S_IFMT) == EXT2_S_IFDIR) ? 1 : 0;
}

/* ------------------------------------------------------------------ */
/* ext2_check_perm — POSIX DAC permission check (no root bypass)      */
/* ------------------------------------------------------------------ */

int ext2_check_perm(uint32_t ino, uint16_t proc_uid, uint16_t proc_gid, int want)
{
    ext2_inode_t inode;
    if (ext2_read_inode(ino, &inode) < 0)
        return -EIO;

    uint16_t mode = inode.i_mode;
    uint16_t perm;

    if (inode.i_uid == proc_uid) {
        perm = (mode >> 6) & 7;
    } else if (inode.i_gid == proc_gid) {
        perm = (mode >> 3) & 7;
    } else {
        perm = mode & 7;
    }

    if ((perm & want) == (uint16_t)want)
        return 0;
    return -EACCES;
}

/* ------------------------------------------------------------------ */
/* ext2_read_symlink_target — read symlink target from inode           */
/* ------------------------------------------------------------------ */

static int ext2_read_symlink_target_impl(uint32_t ino, char *buf, uint32_t bufsiz)
{
    ext2_inode_t inode;
    if (ext2_read_inode(ino, &inode) < 0)
        return -EIO;

    if ((inode.i_mode & EXT2_S_IFMT) != EXT2_S_IFLNK)
        return -EINVAL;

    uint32_t tlen = inode.i_size;
    if (tlen == 0)
        return 0;
    if (tlen >= bufsiz)
        tlen = bufsiz - 1;

    if (inode.i_size <= 60) {
        /* Fast symlink — target stored in i_block[] */
        uint8_t *src = (uint8_t *)inode.i_block;
        uint32_t i;
        for (i = 0; i < tlen; i++)
            buf[i] = (char)src[i];
        buf[tlen] = '\0';
        return (int)tlen;
    }

    /* Slow symlink — target in first data block */
    uint32_t blk = inode.i_block[0];
    if (blk == 0)
        return -EIO;
    uint8_t *data = cache_get_slot(blk);
    if (!data)
        return -EIO;

    uint32_t i;
    for (i = 0; i < tlen; i++)
        buf[i] = (char)data[i];
    buf[tlen] = '\0';
    return (int)tlen;
}

/* ------------------------------------------------------------------ */
/* ext2_open_ex — path walk with symlink following                     */
/* ------------------------------------------------------------------ */

/* Core resolution walk. If `touched` is non-NULL, it is set to 1 whenever the
 * resolution passes through (or ends at) a protected tree inode (/apps,
 * /etc/aegis, /bin, /sbin) — symlink- and ".."-safe, and set even when the
 * final component doesn't resolve (e.g. an O_CREAT target), so callers can gate
 * creates too. */
static int ext2_walk_impl(const char *path, uint32_t *inode_out, int follow_final,
                     int *touched)
{
    if (!s_mounted)
        return -1;

    char resolved[512];
    uint32_t depth = 0;
    uint32_t plen, i;

    /* Copy path into resolved buffer */
    plen = 0;
    while (path[plen] != '\0' && plen < 510)
        plen++;
    for (i = 0; i < plen; i++)
        resolved[i] = path[i];
    resolved[plen] = '\0';

restart_walk:
    {
        const char *p = resolved;
        uint32_t current_ino = EXT2_ROOT_INODE;

        /* skip leading slashes */
        while (*p == '/')
            p++;

        /* Root dir itself */
        if (*p == '\0') {
            *inode_out = current_ino;
            return 0;
        }

        while (*p != '\0') {
            /* Extract next component */
            char component[256];
            uint32_t clen = 0;
            while (*p != '\0' && *p != '/') {
                if (clen < 255)
                    component[clen++] = *p;
                p++;
            }
            component[clen] = '\0';

            /* Skip trailing slashes */
            while (*p == '/')
                p++;

            int is_final = (*p == '\0');

            /* ".." — clamp to root */
            if (component[0] == '.' && component[1] == '.' && component[2] == '\0') {
                current_ino = EXT2_ROOT_INODE;
                continue;
            }

            /* Read current directory inode */
            ext2_inode_t dir_inode;
            if (ext2_read_inode(current_ino, &dir_inode) < 0)
                return -1;

            /* Must be a directory */
            if ((dir_inode.i_mode & EXT2_S_IFMT) != EXT2_S_IFDIR)
                return -1;

            /* Search directory entries for component */
            int found = 0;
            uint32_t child_ino = 0;
            uint32_t pos = 0;

            while (pos < dir_inode.i_size) {
                uint32_t file_block = pos / s_block_size;
                uint32_t blk = ext2_block_num(&dir_inode, file_block);
                if (blk == 0)
                    break;
                uint8_t *data = cache_get_slot(blk);
                if (!data)
                    return -1;
                uint32_t block_pos = pos % s_block_size;
                while (block_pos < s_block_size) {
                    ext2_dirent_t *de =
                        (ext2_dirent_t *)(data + block_pos);
                    if (de->rec_len < 8 || block_pos + de->rec_len > s_block_size)
                        break;
                    if (de->inode == 0) {
                        block_pos += de->rec_len;
                        pos += de->rec_len;
                        continue;
                    }
                    /* name_len must fit inside the record (rec_len already
                     * validated >= 8 above, so rec_len - 8 can't underflow).
                     * Skip malformed entries to avoid an OOB read past the
                     * 4096 cache buffer during the name compare. */
                    if ((uint32_t)de->name_len + 8u > (uint32_t)de->rec_len) {
                        block_pos += de->rec_len;
                        pos += de->rec_len;
                        continue;
                    }
                    if (de->name_len == (uint8_t)clen) {
                        uint32_t k;
                        int match = 1;
                        for (k = 0; k < clen; k++) {
                            if (de->name[k] != component[k]) {
                                match = 0;
                                break;
                            }
                        }
                        if (match) {
                            child_ino = de->inode;
                            found = 1;
                            break;
                        }
                    }
                    block_pos += de->rec_len;
                    pos += de->rec_len;
                }
                if (found)
                    break;
                if (!found) {
                    uint32_t block_end = (file_block + 1) * s_block_size;
                    if (pos < block_end)
                        pos = block_end;
                }
            }

            if (!found)
                return -1;

            /* Flag if this resolved component is a protected-tree root. Covers
             * intermediate dirs (so /apps/<id>/file flags on "apps") and the
             * final component (so renaming/chmod'ing /apps itself flags). */
            if (touched && child_ino != 0 &&
                (child_ino == s_apps_ino || child_ino == s_etc_aegis_ino ||
                 child_ino == s_bin_ino  || child_ino == s_sbin_ino ||
                 ext2_ino_is_anchor(child_ino)))
                *touched = 1;

            /* Check if resolved inode is a symlink */
            ext2_inode_t child_node;
            if (ext2_read_inode(child_ino, &child_node) < 0)
                return -1;

            if ((child_node.i_mode & EXT2_S_IFMT) == EXT2_S_IFLNK) {
                /* Final component and no-follow requested: return the symlink inode */
                if (is_final && !follow_final) {
                    *inode_out = child_ino;
                    return 0;
                }

                /* Follow the symlink */
                depth++;
                if (depth > SYMLINK_MAX_DEPTH)
                    return -ELOOP;

                char target[256];
                int tlen = ext2_read_symlink_target(child_ino, target, sizeof(target));
                if (tlen < 0)
                    return tlen;

                /* Build new path: target + "/" + remaining */
                char newpath[512];
                uint32_t np = 0;
                uint32_t ti;

                for (ti = 0; ti < (uint32_t)tlen && np < 510; ti++)
                    newpath[np++] = target[ti];

                /* Append remaining path if any */
                if (*p != '\0') {
                    if (np < 510)
                        newpath[np++] = '/';
                    while (*p != '\0' && np < 510)
                        newpath[np++] = *p++;
                }
                newpath[np] = '\0';

                /* Copy newpath into resolved */
                for (i = 0; i < np; i++)
                    resolved[i] = newpath[i];
                resolved[np] = '\0';

                goto restart_walk;
            }

            current_ino = child_ino;
        }

        *inode_out = current_ino;
        return 0;
    }
}

int ext2_open_ex(const char *path, uint32_t *inode_out, int follow_final)
{
    return ext2_walk(path, inode_out, follow_final, (int *)0);
}

int ext2_path_under_protected(const char *path)
{
    if (!s_mounted || (s_apps_ino == 0 && s_etc_aegis_ino == 0 &&
                       s_bin_ino == 0 && s_sbin_ino == 0 && s_anchor_count == 0))
        return 0;
    uint32_t ino = 0;
    int touched = 0;
    /* follow_final=1: a final symlink pointing into a protected tree is
     * treated as protected, matching what the real (symlink-following) open
     * would write. We ignore the return value — `touched` is set even if the
     * final component doesn't exist (O_CREAT) or resolution fails late. */
    ext2_walk(path, &ino, 1, &touched);
    return touched;
}

/* Re-read /etc/aegis/anchors and record each listed dir's inode into the dynamic
 * anchor set (s_anchor_ino). One absolute path per line; blank/relative lines are
 * ignored. Idempotent and additive — an anchor never un-registers without a
 * reboot (uninstall-time removal is future work; a stale anchor only over-protects
 * a path the package owns anyway). Called OUTSIDE the mount lock: it opens a file
 * (which re-enters ext2 read) and calls ext2_open_ex (which takes the lock), then
 * publishes results under a brief lock. Safe when the file is absent (no anchors).
 *
 * Pairs with cap_policy_load()'s reading of the same file: sys_install_commit()
 * calls both so the path-trust set and the inode-protect set stay identical. */
void
ext2_anchors_reload(void)
{
    vfs_file_t f;
    char buf[1024];
    uint64_t fsize;
    int n = 0;
    int i;

    if (vfs_open("/etc/aegis/anchors", 0, 0, &f) != 0)
        return;
    fsize = f.size;
    if (fsize > sizeof(buf) - 1)
        fsize = sizeof(buf) - 1;
    if (f.ops->read)
        n = f.ops->read(f.priv, buf, 0, fsize);
    if (f.ops->close)
        f.ops->close(f.priv);
    if (n <= 0)
        return;
    buf[n] = '\0';

    i = 0;
    while (i < n) {
        int start, end, len;
        /* skip leading whitespace / blank lines */
        while (i < n && (buf[i] == ' ' || buf[i] == '\t' ||
                         buf[i] == '\r' || buf[i] == '\n'))
            i++;
        start = i;
        while (i < n && buf[i] != '\n' && buf[i] != '\r')
            i++;
        end = i;
        while (end > start && (buf[end - 1] == ' ' || buf[end - 1] == '\t'))
            end--;
        len = end - start;
        if (len > 0 && len < 128 && buf[start] == '/') {
            char path[128];
            uint32_t ino = 0;
            int k;
            for (k = 0; k < len; k++)
                path[k] = buf[start + k];
            path[len] = '\0';
            if (ext2_open_ex(path, &ino, 1) == 0 && ino != 0) {
                irqflags_t fl = ext2_lock_acquire();
                if (!ext2_ino_is_anchor(ino) && s_anchor_count < EXT2_ANCHOR_MAX)
                    s_anchor_ino[s_anchor_count++] = ino;
                ext2_lock_release(fl);
            }
        }
    }
}

/* ------------------------------------------------------------------ */
/* ext2_open — thin wrapper around ext2_open_ex (follow all symlinks)  */
/* ------------------------------------------------------------------ */

int ext2_open(const char *path, uint32_t *inode_out)
{
    return ext2_open_ex(path, inode_out, 1);
}

/* ------------------------------------------------------------------ */
/* ext2_symlink — create a symbolic link                               */
/* ------------------------------------------------------------------ */

int ext2_symlink(const char *linkpath, const char *target)
{
    if (!s_mounted)
        return -1;
    irqflags_t fl = ext2_lock_acquire();

    uint32_t parent_ino;
    const char *basename;
    if (ext2_lookup_parent(linkpath, &parent_ino, &basename) != 0) {
        ext2_lock_release(fl);
        return -1;
    }

    /* Reject an existing name with EEXIST (POSIX symlink()).  Without this,
     * ext2_dir_add_entry below would append a SECOND dirent with the same name
     * (duplicate entry) and the freshly-allocated symlink inode (plus its data
     * block for a slow symlink) would leak.  ext2_open_ex takes no ext2_lock
     * (recursive lock anyway), so calling it here is deadlock-free.  Use
     * follow_final=0 so an existing symlink at linkpath is itself detected. */
    {
        uint32_t existing;
        if (ext2_open_ex(linkpath, &existing, 0) == 0) {
            ext2_lock_release(fl);
            return -EEXIST;
        }
    }

    /* Measure target length */
    uint32_t tlen = 0;
    while (target[tlen] != '\0')
        tlen++;

    uint32_t new_ino = ext2_alloc_inode(0);
    if (new_ino == 0) {
        ext2_lock_release(fl);
        return -1;
    }

    ext2_inode_t inode;
    uint32_t ci;
    for (ci = 0; ci < sizeof(inode); ci++)
        ((uint8_t *)&inode)[ci] = 0;
    inode.i_mode = EXT2_S_IFLNK | 0777;
    inode.i_size = tlen;
    inode.i_links_count = 1;

    if (tlen <= 60) {
        /* Fast symlink — target stored directly in i_block[] */
        uint8_t *dst = (uint8_t *)inode.i_block;
        for (ci = 0; ci < tlen; ci++)
            dst[ci] = (uint8_t)target[ci];
    } else {
        /* Slow symlink — allocate data block */
        uint32_t blk = ext2_alloc_block(0);
        if (blk == 0) {
            ext2_lock_release(fl);
            return -1;
        }
        inode.i_block[0] = blk;
        inode.i_blocks = s_block_size / 512;

        uint8_t *data = cache_get_slot(blk);
        if (!data) {
            ext2_lock_release(fl);
            return -1;
        }
        /* Zero the block first */
        for (ci = 0; ci < s_block_size; ci++)
            data[ci] = 0;
        /* Copy target */
        for (ci = 0; ci < tlen; ci++)
            data[ci] = (uint8_t)target[ci];
        cache_mark_dirty(blk);
    }

    inode.i_generation = ext2_next_gen();   /* secfix M2: unique per allocation */
    ext2_write_inode(new_ino, &inode);
    int r = ext2_dir_add_entry(parent_ino, new_ino, basename, EXT2_FT_SYMLINK);
    ext2_lock_release(fl);
    return r;
}

/* ------------------------------------------------------------------ */
/* ext2_readlink — read symlink target by path (no-follow final)       */
/* ------------------------------------------------------------------ */

int ext2_readlink(const char *path, char *buf, uint32_t bufsiz)
{
    if (!s_mounted)
        return -1;
    irqflags_t fl = ext2_lock_acquire();

    uint32_t ino;
    if (ext2_open_ex(path, &ino, 0) != 0) {
        ext2_lock_release(fl);
        return -1;
    }

    int r = ext2_read_symlink_target(ino, buf, bufsiz);
    ext2_lock_release(fl);
    return r;
}

/* ------------------------------------------------------------------ */
/* ext2_chmod — change permission bits                                 */
/* ------------------------------------------------------------------ */

int ext2_chmod(const char *path, uint16_t mode)
{
    if (!s_mounted)
        return -1;
    irqflags_t fl = ext2_lock_acquire();

    uint32_t ino;
    if (ext2_open_ex(path, &ino, 1) != 0) {
        ext2_lock_release(fl);
        return -1;
    }

    ext2_inode_t inode;
    if (ext2_read_inode(ino, &inode) < 0) {
        ext2_lock_release(fl);
        return -EIO;
    }

    /* Preserve type bits (upper 4), replace permission bits (lower 12) */
    inode.i_mode = (inode.i_mode & EXT2_S_IFMT) | (mode & 0x0FFF);
    ext2_write_inode(ino, &inode);
    ext2_lock_release(fl);
    return 0;
}

/* ------------------------------------------------------------------ */
/* ext2_chown — change owner and/or group                              */
/* ------------------------------------------------------------------ */

int ext2_chown(const char *path, uint16_t uid, uint16_t gid, int follow)
{
    if (!s_mounted)
        return -1;
    irqflags_t fl = ext2_lock_acquire();

    uint32_t ino;
    if (ext2_open_ex(path, &ino, follow) != 0) {
        ext2_lock_release(fl);
        return -1;
    }

    ext2_inode_t inode;
    if (ext2_read_inode(ino, &inode) < 0) {
        ext2_lock_release(fl);
        return -EIO;
    }

    inode.i_uid = uid;
    inode.i_gid = gid;
    ext2_write_inode(ino, &inode);
    ext2_lock_release(fl);
    return 0;
}

/* ------------------------------------------------------------------ */
/* ext2_utimes — set access/modification times (for utimensat/utimes)  */
/* atime/mtime are epoch seconds; EXT2_UTIME_KEEP leaves that field.    */
/* ctime is always bumped to now (the inode metadata just changed).     */
/* ------------------------------------------------------------------ */

int ext2_utimes(const char *path, uint32_t atime, uint32_t mtime, int follow)
{
    if (!s_mounted)
        return -1;
    irqflags_t fl = ext2_lock_acquire();

    uint32_t ino;
    if (ext2_open_ex(path, &ino, follow) != 0) {
        ext2_lock_release(fl);
        return -1;
    }

    ext2_inode_t inode;
    if (ext2_read_inode(ino, &inode) < 0) {
        ext2_lock_release(fl);
        return -EIO;
    }

    if (atime != EXT2_UTIME_KEEP) inode.i_atime = atime;
    if (mtime != EXT2_UTIME_KEEP) inode.i_mtime = mtime;
    inode.i_ctime = ext2_now();
    ext2_write_inode(ino, &inode);
    ext2_lock_release(fl);
    return 0;
}

/* ------------------------------------------------------------------ */
/* Block and inode allocation                                          */
/* ------------------------------------------------------------------ */

/* ext2_free_block — clear blk's bit in its group block bitmap and bump the
 * free-block counters.  No-op for blk 0 (sparse / unallocated).  Caller holds
 * ext2_lock.  Centralizes what ext2_unlink / ext2_rmdir used to open-code so
 * the indirect-block walk (ext2_free_inode_blocks) can reuse it. */
static void ext2_free_block(uint32_t blk)
{
    if (blk == 0 || blk < s_sb.s_first_data_block || blk >= s_sb.s_blocks_count)
        return;
    if (s_sb.s_blocks_per_group == 0)
        return;
    uint32_t grp = (blk - s_sb.s_first_data_block) / s_sb.s_blocks_per_group;
    if (grp >= s_num_groups)
        return;
    uint8_t *bitmap = cache_get_slot(s_bgd[grp].bg_block_bitmap);
    if (!bitmap)
        return;
    uint32_t bit = (blk - s_sb.s_first_data_block) % s_sb.s_blocks_per_group;
    bitmap[bit / 8] &= (uint8_t)~(1u << (bit % 8));
    cache_mark_dirty(s_bgd[grp].bg_block_bitmap);
    s_bgd[grp].bg_free_blocks_count++;
    s_sb.s_free_blocks_count++;
}

/* ext2_free_inode_blocks — free EVERY data block an inode references: the 12
 * direct blocks, the single-indirect tree (i_block[12] + the blocks it points
 * to), and the double-indirect tree (i_block[13] + its inner pointer blocks +
 * their data blocks).  The pointer (indirect) blocks themselves are freed too.
 * Clears the inode's i_block[] so a later write can't reuse a freed pointer.
 * Caller holds ext2_lock.  Before this, unlink/rmdir freed only i_block[0..11],
 * leaking all indirect-referenced blocks of files larger than 12 blocks. */
static void ext2_free_inode_blocks(ext2_inode_t *inode)
{
    uint32_t ppb = s_block_size / 4;
    uint32_t i;

    /* Direct */
    for (i = 0; i < 12; i++) {
        ext2_free_block(inode->i_block[i]);
        inode->i_block[i] = 0;
    }

    /* Single indirect: i_block[12] → block of data-block pointers. */
    uint32_t ind = inode->i_block[12];
    if (ind != 0) {
        for (i = 0; i < ppb; i++)
            ext2_free_block(ext2_ind_get(ind, i));
        ext2_free_block(ind);            /* the pointer block itself */
        inode->i_block[12] = 0;
    }

    /* Double indirect: i_block[13] → block of indirect-block pointers. */
    uint32_t dind = inode->i_block[13];
    if (dind != 0) {
        for (i = 0; i < ppb; i++) {
            uint32_t inner = ext2_ind_get(dind, i);
            if (inner == 0)
                continue;
            uint32_t j;
            for (j = 0; j < ppb; j++)
                ext2_free_block(ext2_ind_get(inner, j));
            ext2_free_block(inner);      /* inner pointer block */
        }
        ext2_free_block(dind);           /* outer pointer block */
        inode->i_block[13] = 0;
    }
}

/* ext2_alloc_block — scan block bitmaps for a free bit.
 * preferred_group: start scanning from this group (locality hint).
 * Returns allocated block number, or 0 on failure. */
uint32_t ext2_alloc_block(uint32_t preferred_group)
{
    uint32_t g, i;
    for (g = 0; g < s_num_groups; g++) {
        uint32_t grp = (g + preferred_group) % s_num_groups;
        if (s_bgd[grp].bg_free_blocks_count == 0)
            continue;
        uint8_t *bitmap = cache_get_slot(s_bgd[grp].bg_block_bitmap);
        if (!bitmap)
            continue;
        uint32_t blocks_in_group = (grp == s_num_groups - 1)
            ? (s_sb.s_blocks_count - grp * s_sb.s_blocks_per_group)
            : s_sb.s_blocks_per_group;
        /* Resume from the per-group hint; wrap once to cover [0, hint) so a
         * freed low bit is still found (correctness) — amortized O(1) for the
         * common sequential-allocation case. */
        uint32_t hint = s_blk_hint[grp];
        if (hint >= blocks_in_group)
            hint = 0;
        uint32_t scanned;
        for (scanned = 0; scanned < blocks_in_group; scanned++) {
            i = hint + scanned;
            if (i >= blocks_in_group)
                i -= blocks_in_group;
            if (!(bitmap[i / 8] & (1u << (i % 8)))) {
                bitmap[i / 8] |= (1u << (i % 8));
                cache_mark_dirty(s_bgd[grp].bg_block_bitmap);
                s_bgd[grp].bg_free_blocks_count--;
                s_sb.s_free_blocks_count--;
                s_blk_hint[grp] = i + 1;
                return grp * s_sb.s_blocks_per_group + i + s_sb.s_first_data_block;
            }
        }
    }
    return 0; /* no free block */
}

/* ext2_alloc_inode — scan inode bitmaps for a free bit.
 * preferred_group: start scanning from this group.
 * Returns allocated inode number (1-based), or 0 on failure. */
uint32_t ext2_alloc_inode(uint32_t preferred_group)
{
    uint32_t g, i;
    for (g = 0; g < s_num_groups; g++) {
        uint32_t grp = (g + preferred_group) % s_num_groups;
        if (s_bgd[grp].bg_free_inodes_count == 0)
            continue;
        uint8_t *bitmap = cache_get_slot(s_bgd[grp].bg_inode_bitmap);
        if (!bitmap)
            continue;
        uint32_t ipg = s_sb.s_inodes_per_group;
        uint32_t hint = s_ino_hint[grp];
        if (hint >= ipg)
            hint = 0;
        uint32_t scanned;
        for (scanned = 0; scanned < ipg; scanned++) {
            i = hint + scanned;
            if (i >= ipg)
                i -= ipg;
            if (!(bitmap[i / 8] & (1u << (i % 8)))) {
                bitmap[i / 8] |= (1u << (i % 8));
                cache_mark_dirty(s_bgd[grp].bg_inode_bitmap);
                s_bgd[grp].bg_free_inodes_count--;
                s_sb.s_free_inodes_count--;
                s_ino_hint[grp] = i + 1;
                return grp * s_sb.s_inodes_per_group + i + 1; /* 1-based */
            }
        }
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* Write path                                                          */
/* ------------------------------------------------------------------ */

/* ------------------------------------------------------------------ */
/* Write-side block mapping: allocate the data block backing file_block,   */
/* creating direct / single-indirect / double-indirect metadata as needed. */
/* ------------------------------------------------------------------ */

/* Zero an entire block in the cache and mark it dirty. */
static void ext2_zero_block(uint32_t blk)
{
    uint8_t *d = cache_get_slot(blk);
    uint32_t i;
    if (!d)
        return;
    for (i = 0; i < s_block_size; i++)
        d[i] = 0;
    cache_mark_dirty(blk);
}

/* Read a little-endian u32 pointer at index `idx` of pointer-block `blk`. */
static uint32_t ext2_ind_get(uint32_t blk, uint32_t idx)
{
    uint8_t *d = cache_get_slot(blk);
    uint8_t *p;
    if (!d)
        return 0;
    p = d + idx * 4;
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/* Write a little-endian u32 pointer at index `idx` of pointer-block `blk`. */
static void ext2_ind_set(uint32_t blk, uint32_t idx, uint32_t val)
{
    uint8_t *d = cache_get_slot(blk);
    uint8_t *p;
    if (!d)
        return;
    p = d + idx * 4;
    p[0] = (uint8_t)(val & 0xff);
    p[1] = (uint8_t)((val >> 8) & 0xff);
    p[2] = (uint8_t)((val >> 16) & 0xff);
    p[3] = (uint8_t)((val >> 24) & 0xff);
    cache_mark_dirty(blk);
}

/* Return the data block backing file_block, allocating it (and any indirect
 * blocks on the path) if absent. Newly allocated blocks are zeroed. Updates
 * inode->i_block[12]/[13] for the indirect roots. Returns 0 on allocation
 * failure (disk full) or beyond double-indirect range. Each cache_get_slot
 * result is used and released before the next, so LRU eviction is safe. */
static uint32_t ext2_bmap_alloc(ext2_inode_t *inode, uint32_t file_block)
{
    uint32_t ppb = s_block_size / 4;

    if (file_block < 12) {
        if (inode->i_block[file_block] == 0) {
            uint32_t b = ext2_alloc_block(0);
            if (b == 0)
                return 0;
            ext2_zero_block(b);
            inode->i_block[file_block] = b;
        }
        return inode->i_block[file_block];
    }

    /* Single indirect */
    if (file_block < 12 + ppb) {
        uint32_t off = file_block - 12;
        uint32_t data;
        if (inode->i_block[12] == 0) {
            uint32_t ib = ext2_alloc_block(0);
            if (ib == 0)
                return 0;
            ext2_zero_block(ib);
            inode->i_block[12] = ib;
        }
        data = ext2_ind_get(inode->i_block[12], off);
        if (data == 0) {
            data = ext2_alloc_block(0);
            if (data == 0)
                return 0;
            ext2_zero_block(data);
            ext2_ind_set(inode->i_block[12], off, data);
        }
        return data;
    }

    /* Double indirect */
    if (file_block < 12 + ppb + ppb * ppb) {
        uint32_t idx = file_block - 12 - ppb;
        uint32_t outer_off = idx / ppb;
        uint32_t inner_off = idx % ppb;
        uint32_t ind, data;
        if (inode->i_block[13] == 0) {
            uint32_t db = ext2_alloc_block(0);
            if (db == 0)
                return 0;
            ext2_zero_block(db);
            inode->i_block[13] = db;
        }
        ind = ext2_ind_get(inode->i_block[13], outer_off);
        if (ind == 0) {
            ind = ext2_alloc_block(0);
            if (ind == 0)
                return 0;
            ext2_zero_block(ind);
            ext2_ind_set(inode->i_block[13], outer_off, ind);
        }
        data = ext2_ind_get(ind, inner_off);
        if (data == 0) {
            data = ext2_alloc_block(0);
            if (data == 0)
                return 0;
            ext2_zero_block(data);
            ext2_ind_set(ind, inner_off, data);
        }
        return data;
    }

    return 0;   /* beyond double indirect — unsupported */
}

int ext2_write(uint32_t inode_num, const void *buf,
               uint32_t offset, uint32_t len)
{
    if (!s_mounted || len == 0)
        return 0;

    /* Reject writes that would overflow the driver's max file size BEFORE
     * touching the disk.  All byte offsets below are computed in 64-bit so
     * this comparison can never wrap; offset and len are each at most
     * UINT32_MAX, so (uint64_t)offset + len fits in 33 bits.  Capping the
     * end offset at EXT2_MAX_FILE_SIZE (< 4 GiB) guarantees every cur_offset,
     * file_block and the final i_size fit in uint32_t — the historical
     * uint32 wrap (offset + bytes_written rolling past 4 GiB and aliasing
     * file_block 0 / filesystem metadata) is structurally impossible. */
    uint64_t end_off  = (uint64_t)offset + (uint64_t)len;
    uint64_t max_size = ext2_max_file_size();
    if ((uint64_t)offset > max_size || end_off > max_size)
        return -EFBIG;

    irqflags_t fl = ext2_lock_acquire();

    ext2_inode_t inode;
    if (ext2_read_inode(inode_num, &inode) != 0) {
        ext2_lock_release(fl);
        return -1;
    }

    const uint8_t *src = (const uint8_t *)buf;
    uint32_t bytes_written = 0;
    uint32_t orig_size = inode.i_size;   /* save before write loop */

    while (bytes_written < len) {
        /* 64-bit accumulator: cannot wrap.  Bounded above by end_off which
         * we already capped at EXT2_MAX_FILE_SIZE, so the truncation to
         * uint32_t for file_block/in_block is always exact. */
        uint64_t cur_offset = (uint64_t)offset + (uint64_t)bytes_written;
        uint32_t file_block = (uint32_t)(cur_offset / s_block_size);
        uint32_t in_block   = (uint32_t)(cur_offset % s_block_size);
        uint32_t can_write  = s_block_size - in_block;
        if (can_write > len - bytes_written)
            can_write = len - bytes_written;

        uint32_t blk = ext2_block_num(&inode, file_block);
        if (blk == 0) {
            /* Allocate the backing block (direct, single- or double-indirect). */
            blk = ext2_bmap_alloc(&inode, file_block);
            if (blk == 0) {
                /* Allocation failed (disk full or beyond double-indirect):
                 * commit what was written so far as a partial write.  Bounded
                 * by EXT2_MAX_FILE_SIZE, so actual_end fits in uint32_t. */
                uint32_t actual_end = (uint32_t)((uint64_t)offset +
                                                 (uint64_t)bytes_written);
                inode.i_size = (actual_end > orig_size) ? actual_end : orig_size;
                inode.i_blocks = (uint32_t)(((uint64_t)inode.i_size + 511u) / 512u);
                ext2_write_inode(inode_num, &inode);
                ext2_lock_release(fl);
                return (bytes_written > 0) ? (int)bytes_written : -EIO;
            }
            /* ext2_bmap_alloc already zeroed the freshly allocated block. */
        }

        uint8_t *data = cache_get_slot(blk);
        if (!data)
            break;
        uint32_t wi;
        for (wi = 0; wi < can_write; wi++)
            data[in_block + wi] = src[bytes_written + wi];
        cache_mark_dirty(blk);
        bytes_written += can_write;
    }

    /* update inode size and 512-byte sector count.  end is bounded by
     * EXT2_MAX_FILE_SIZE (checked above), so the uint32_t store is exact. */
    uint32_t end = (uint32_t)((uint64_t)offset + (uint64_t)bytes_written);
    if (end > inode.i_size) {
        inode.i_size = end;
        inode.i_blocks = (uint32_t)(((uint64_t)inode.i_size + 511u) / 512u);
    }
    inode.i_mtime = inode.i_ctime = ext2_now();   /* content changed */
    ext2_write_inode(inode_num, &inode);
    ext2_lock_release(fl);
    return (int)bytes_written;
}

/* ext2_truncate — shrink a regular file to length 0 and free ALL its data
 * blocks.  The O_TRUNC open path used to only set i_size = 0 (in vfs.c), which
 * left every data + indirect + pointer block marked allocated forever — a leak
 * on every `> existing_ext2_file` truncate.  Directories are rejected (callers
 * never truncate a dir; that would orphan its entries). */
int ext2_truncate(uint32_t inode_num)
{
    if (!s_mounted)
        return -1;
    irqflags_t fl = ext2_lock_acquire();

    ext2_inode_t inode;
    if (ext2_read_inode(inode_num, &inode) != 0) {
        ext2_lock_release(fl);
        return -1;
    }
    if ((inode.i_mode & EXT2_S_IFMT) == EXT2_S_IFDIR) {
        ext2_lock_release(fl);
        return -1;
    }

    ext2_free_inode_blocks(&inode);   /* frees + zeroes i_block[] */
    inode.i_size   = 0;
    inode.i_blocks = 0;
    inode.i_mtime  = inode.i_ctime = ext2_now();
    ext2_write_inode(inode_num, &inode);

    ext2_lock_release(fl);
    return 0;
}

int ext2_create(const char *path, uint16_t mode)
{
    if (!s_mounted)
        return -1;
    irqflags_t fl = ext2_lock_acquire();

    uint32_t parent_ino;
    const char *basename;
    if (ext2_lookup_parent(path, &parent_ino, &basename) != 0) {
        printk("[EXT2] creat: lookup_parent failed for %s\n", path);
        ext2_lock_release(fl);
        return -1;
    }

    uint32_t new_ino = ext2_alloc_inode(0);
    if (new_ino == 0) {
        printk("[EXT2] creat: alloc_inode failed\n");
        ext2_lock_release(fl);
        return -1;
    }

    ext2_inode_t inode;
    uint32_t ci;
    for (ci = 0; ci < sizeof(inode); ci++)
        ((uint8_t *)&inode)[ci] = 0;
    inode.i_mode = EXT2_S_IFREG | (mode & 0x1FFu);
    inode.i_links_count = 1;
    inode.i_generation = ext2_next_gen();   /* secfix M2: unique per allocation */
    inode.i_atime = inode.i_mtime = inode.i_ctime = ext2_now();
    ext2_write_inode(new_ino, &inode);
    int r = ext2_dir_add_entry(parent_ino, new_ino, basename, EXT2_FT_REG_FILE);
    if (r != 0)
        printk("[EXT2] creat: dir_add_entry failed parent=%u ino=%u\n",
               parent_ino, new_ino);
    ext2_lock_release(fl);
    return r;
}

int ext2_unlink(const char *path)
{
    if (!s_mounted)
        return -1;
    irqflags_t fl = ext2_lock_acquire();

    uint32_t parent_ino;
    const char *basename;
    if (ext2_lookup_parent(path, &parent_ino, &basename) != 0) {
        ext2_lock_release(fl);
        return -1;
    }

    uint32_t ino;
    if (ext2_open(path, &ino) != 0) {
        ext2_lock_release(fl);
        return -1;
    }

    ext2_inode_t inode;
    if (ext2_read_inode(ino, &inode) != 0) {
        ext2_lock_release(fl);
        return -1;
    }

    /* Directories must go through ext2_rmdir — blindly unlinking one
     * orphans its contents and leaves the parent's link count wrong. */
    if ((inode.i_mode & EXT2_S_IFMT) == EXT2_S_IFDIR) {
        ext2_lock_release(fl);
        return -EISDIR;
    }

    if (inode.i_links_count > 0)
        inode.i_links_count--;

    if (inode.i_links_count == 0) {
        /* free ALL data blocks (direct + single/double indirect + pointer
         * blocks) — previously only i_block[0..11] were freed, leaking the
         * indirect blocks of any file larger than 12 blocks. */
        ext2_free_inode_blocks(&inode);
        /* free inode */
        uint32_t igrp = 0;
        if (s_sb.s_inodes_per_group > 0)
            igrp = (ino - 1) / s_sb.s_inodes_per_group;
        if (igrp < s_num_groups) {
            uint8_t *ibitmap = cache_get_slot(s_bgd[igrp].bg_inode_bitmap);
            if (ibitmap) {
                uint32_t ibit = (ino - 1) % s_sb.s_inodes_per_group;
                ibitmap[ibit / 8] &= (uint8_t)~(1u << (ibit % 8));
                cache_mark_dirty(s_bgd[igrp].bg_inode_bitmap);
                s_bgd[igrp].bg_free_inodes_count++;
                s_sb.s_free_inodes_count++;
            }
        }
        inode.i_blocks = 0;
        inode.i_dtime = 1; /* mark deleted */
    }
    ext2_write_inode(ino, &inode);
    int r = ext2_dir_remove_entry(parent_ino, basename);
    ext2_lock_release(fl);
    return r;
}

int ext2_mkdir(const char *path, uint16_t mode)
{
    if (!s_mounted)
        return -1;
    irqflags_t fl = ext2_lock_acquire();

    uint32_t parent_ino;
    const char *basename;
    if (ext2_lookup_parent(path, &parent_ino, &basename) != 0) {
        ext2_lock_release(fl);
        return -1;
    }

    /* Reject an existing name with EEXIST (POSIX). Without this, mkdir of an
     * existing directory would add a duplicate dirent; callers also rely on
     * EEXIST to treat "already there" as success (e.g. the herald tar
     * extractor's mkdir -p over /apps). ext2_open_ex takes no ext2_lock, so
     * calling it while we hold the lock is deadlock-free. */
    {
        uint32_t existing;
        if (ext2_open_ex(path, &existing, 0) == 0) {
            ext2_lock_release(fl);
            return -EEXIST;
        }
    }

    uint32_t new_ino = ext2_alloc_inode(0);
    if (new_ino == 0) {
        ext2_lock_release(fl);
        return -1;
    }

    uint32_t blk = ext2_alloc_block(0);
    if (blk == 0) {
        ext2_lock_release(fl);
        return -1;
    }

    ext2_inode_t inode;
    uint32_t ci;
    for (ci = 0; ci < sizeof(inode); ci++)
        ((uint8_t *)&inode)[ci] = 0;
    inode.i_mode = EXT2_S_IFDIR | (mode & 0x1FFu);
    inode.i_links_count = 2; /* "." + parent's ".." */
    inode.i_size = s_block_size;
    inode.i_blocks = s_block_size / 512;
    inode.i_block[0] = blk;
    inode.i_generation = ext2_next_gen();   /* secfix M2: unique per allocation */
    inode.i_atime = inode.i_mtime = inode.i_ctime = ext2_now();
    ext2_write_inode(new_ino, &inode);

    /* initialise "." and ".." entries in the new block */
    uint8_t *data = cache_get_slot(blk);
    if (!data) {
        ext2_lock_release(fl);
        return -1;
    }
    uint32_t zi;
    for (zi = 0; zi < s_block_size; zi++)
        data[zi] = 0;

    /* "." entry */
    ext2_dirent_t *dot = (ext2_dirent_t *)data;
    dot->inode     = new_ino;
    dot->rec_len   = 12;
    dot->name_len  = 1;
    dot->file_type = EXT2_FT_DIR;
    dot->name[0]   = '.';

    /* ".." entry */
    ext2_dirent_t *dotdot = (ext2_dirent_t *)(data + 12);
    dotdot->inode     = parent_ino;
    dotdot->rec_len   = (uint16_t)(s_block_size - 12);
    dotdot->name_len  = 2;
    dotdot->file_type = EXT2_FT_DIR;
    dotdot->name[0]   = '.';
    dotdot->name[1]   = '.';
    cache_mark_dirty(blk);

    /* increment parent link count for ".." back-reference */
    ext2_inode_t parent;
    if (ext2_read_inode(parent_ino, &parent) == 0) {
        parent.i_links_count++;
        ext2_write_inode(parent_ino, &parent);
    }

    /* update block group directory count */
    uint32_t grp = (new_ino - 1) / s_sb.s_inodes_per_group;
    if (grp < s_num_groups)
        s_bgd[grp].bg_used_dirs_count++;

    int r = ext2_dir_add_entry(parent_ino, new_ino, basename, EXT2_FT_DIR);
    ext2_lock_release(fl);
    return r;
}

/* ext2_rmdir — remove an empty directory.
 * Returns 0 on success, -20 (ENOTDIR) if path is not a directory,
 * -39 (ENOTEMPTY) if it holds anything besides "." and "..",
 * -1 on other failures. */
int ext2_rmdir(const char *path)
{
    if (!s_mounted)
        return -1;
    if (path[0] == '/' && path[1] == '\0')
        return -1; /* never the root */
    irqflags_t fl = ext2_lock_acquire();

    uint32_t parent_ino;
    const char *basename;
    if (ext2_lookup_parent(path, &parent_ino, &basename) != 0) {
        ext2_lock_release(fl);
        return -1;
    }

    uint32_t ino;
    if (ext2_open(path, &ino) != 0) {
        ext2_lock_release(fl);
        return -1;
    }

    ext2_inode_t inode;
    if (ext2_read_inode(ino, &inode) != 0) {
        ext2_lock_release(fl);
        return -1;
    }
    if ((inode.i_mode & EXT2_S_IFMT) != EXT2_S_IFDIR) {
        ext2_lock_release(fl);
        return -ENOTDIR;
    }

    /* Emptiness walk: any live dirent besides "." and ".." → ENOTEMPTY.
     * Inline (not ext2_readdir) because ext2_lock is already held.
     * Same rec_len/name_len bounds as the readdir walk. */
    {
        uint32_t file_block_idx = 0;
        uint32_t bytes_walked = 0;
        while (bytes_walked < inode.i_size) {
            uint32_t blk = ext2_block_num(&inode, file_block_idx);
            if (blk == 0) {
                bytes_walked += s_block_size;
                file_block_idx++;
                continue;
            }
            uint8_t *data = cache_get_slot(blk);
            if (!data) {
                ext2_lock_release(fl);
                return -1;
            }
            uint32_t block_pos = 0;
            while (block_pos + 8 <= s_block_size) {
                ext2_dirent_t *de = (ext2_dirent_t *)(data + block_pos);
                if (de->rec_len < 8 || block_pos + de->rec_len > s_block_size)
                    break;
                if ((uint32_t)de->name_len + 8u > (uint32_t)de->rec_len) {
                    block_pos += de->rec_len;
                    continue;
                }
                if (de->inode != 0) {
                    int is_dot = (de->name_len == 1 && de->name[0] == '.');
                    int is_dotdot = (de->name_len == 2 &&
                                     de->name[0] == '.' && de->name[1] == '.');
                    if (!is_dot && !is_dotdot) {
                        ext2_lock_release(fl);
                        return -ENOTEMPTY;
                    }
                }
                block_pos += de->rec_len;
            }
            bytes_walked += s_block_size;
            file_block_idx++;
        }
    }

    /* Free ALL the directory's data blocks (direct + indirect trees). */
    ext2_free_inode_blocks(&inode);

    /* Free the inode. */
    {
        uint32_t igrp = 0;
        if (s_sb.s_inodes_per_group > 0)
            igrp = (ino - 1) / s_sb.s_inodes_per_group;
        if (igrp < s_num_groups) {
            uint8_t *ibitmap = cache_get_slot(s_bgd[igrp].bg_inode_bitmap);
            if (ibitmap) {
                uint32_t ibit = (ino - 1) % s_sb.s_inodes_per_group;
                ibitmap[ibit / 8] &= (uint8_t)~(1u << (ibit % 8));
                cache_mark_dirty(s_bgd[igrp].bg_inode_bitmap);
                s_bgd[igrp].bg_free_inodes_count++;
                s_sb.s_free_inodes_count++;
            }
            if (s_bgd[igrp].bg_used_dirs_count > 0)
                s_bgd[igrp].bg_used_dirs_count--;
        }
    }
    inode.i_links_count = 0;
    inode.i_blocks = 0;
    inode.i_dtime = 1;
    ext2_write_inode(ino, &inode);

    /* Parent loses the child's ".." back-reference. */
    {
        ext2_inode_t parent;
        if (ext2_read_inode(parent_ino, &parent) == 0) {
            if (parent.i_links_count > 0)
                parent.i_links_count--;
            ext2_write_inode(parent_ino, &parent);
        }
    }

    int r = ext2_dir_remove_entry(parent_ino, basename);
    ext2_lock_release(fl);
    return r;
}

int ext2_rename(const char *old_path, const char *new_path)
{
    if (!s_mounted)
        return -1;
    irqflags_t fl = ext2_lock_acquire();

    uint32_t ino;
    if (ext2_open(old_path, &ino) != 0) {
        ext2_lock_release(fl);
        return -1;
    }

    uint32_t old_parent_ino;
    const char *old_basename;
    if (ext2_lookup_parent(old_path, &old_parent_ino, &old_basename) != 0) {
        ext2_lock_release(fl);
        return -1;
    }

    uint32_t new_parent_ino;
    const char *new_basename;
    if (ext2_lookup_parent(new_path, &new_parent_ino, &new_basename) != 0) {
        ext2_lock_release(fl);
        return -1;
    }

    ext2_inode_t inode;
    if (ext2_read_inode(ino, &inode) != 0) {
        ext2_lock_release(fl);
        return -1;
    }
    uint8_t ftype = ((inode.i_mode & EXT2_S_IFMT) == EXT2_S_IFDIR)
                    ? EXT2_FT_DIR : EXT2_FT_REG_FILE;

    /* If the destination name already exists, deal with it BEFORE adding the
     * new entry — otherwise ext2_dir_add_entry appends a SECOND dirent with the
     * same name (duplicate entry) and the old target's inode + blocks leak. */
    uint32_t dst_ino = 0;
    if (ext2_walk_impl(new_path, &dst_ino, 0 /*don't follow final*/, 0) == 0 &&
        dst_ino != 0) {
        if (dst_ino == ino) {
            /* Source and destination resolve to the same inode (e.g. a no-op
             * rename, or hard-link aliases): nothing to move. */
            ext2_lock_release(fl);
            return 0;
        }
        ext2_inode_t dst;
        if (ext2_read_inode(dst_ino, &dst) != 0) {
            ext2_lock_release(fl);
            return -1;
        }
        int dst_is_dir = ((dst.i_mode & EXT2_S_IFMT) == EXT2_S_IFDIR);
        int src_is_dir = (ftype == EXT2_FT_DIR);
        /* POSIX: a non-dir can't replace a dir and vice-versa. */
        if (dst_is_dir != src_is_dir) {
            ext2_lock_release(fl);
            return dst_is_dir ? -EISDIR : -ENOTDIR;
        }
        /* Replacing a directory: only if empty (no entries beyond . and ..).
         * Reuse ext2_rmdir for correctness (emptiness check, link counts, block
         * free); on failure (ENOTEMPTY) abort the rename without side effects. */
        if (dst_is_dir) {
            int rr = ext2_rmdir(new_path);
            if (rr != 0) {
                ext2_lock_release(fl);
                return rr;
            }
        } else {
            /* Replacing a regular file: drop its dir entry, then free its inode
             * + blocks if that was its last link (mirrors ext2_unlink). */
            ext2_dir_remove_entry(new_parent_ino, new_basename);
            if (dst.i_links_count > 0)
                dst.i_links_count--;
            if (dst.i_links_count == 0) {
                ext2_free_inode_blocks(&dst);
                uint32_t igrp = (s_sb.s_inodes_per_group > 0)
                    ? (dst_ino - 1) / s_sb.s_inodes_per_group : 0;
                if (igrp < s_num_groups) {
                    uint8_t *ib = cache_get_slot(s_bgd[igrp].bg_inode_bitmap);
                    if (ib) {
                        uint32_t ibit = (dst_ino - 1) % s_sb.s_inodes_per_group;
                        ib[ibit / 8] &= (uint8_t)~(1u << (ibit % 8));
                        cache_mark_dirty(s_bgd[igrp].bg_inode_bitmap);
                        s_bgd[igrp].bg_free_inodes_count++;
                        s_sb.s_free_inodes_count++;
                    }
                }
                dst.i_blocks = 0;
                dst.i_dtime = 1;
            }
            ext2_write_inode(dst_ino, &dst);
        }
    }

    /* Add the new name FIRST, then remove the old — so a failed add (e.g. the
     * destination directory is full) leaves the file reachable under its old
     * name instead of orphaning it. */
    int r = ext2_dir_add_entry(new_parent_ino, ino, new_basename, ftype);
    if (r != 0) {
        ext2_lock_release(fl);
        return r;
    }
    if (ext2_dir_remove_entry(old_parent_ino, old_basename) != 0) {
        ext2_lock_release(fl);
        return -1;
    }

    /* Directory moved to a different parent: fix its ".." back-reference and the
     * two parents' link counts (a child dir contributes 1 to its parent's
     * i_links_count via "..").  Same-parent moves need none of this. */
    if (ftype == EXT2_FT_DIR && new_parent_ino != old_parent_ino) {
        ext2_dir_remove_entry(ino, "..");
        ext2_dir_add_entry(ino, new_parent_ino, "..", EXT2_FT_DIR);
        ext2_inode_t op, np;
        if (ext2_read_inode(old_parent_ino, &op) == 0) {
            if (op.i_links_count > 0) op.i_links_count--;
            ext2_write_inode(old_parent_ino, &op);
        }
        if (ext2_read_inode(new_parent_ino, &np) == 0) {
            np.i_links_count++;
            ext2_write_inode(new_parent_ino, &np);
        }
    }

    ext2_lock_release(fl);
    return 0;
}
