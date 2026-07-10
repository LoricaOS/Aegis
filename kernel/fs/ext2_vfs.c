/* ext2_vfs.c — ext2 VFS adapter: per-fd state pool + vfs_ops_t callbacks.
 *
 * Extracted from vfs.c.  Provides the glue between the generic VFS layer
 * (vfs_file_t + vfs_ops_t) and the ext2 filesystem implementation (ext2.h). */

#include "ext2_vfs.h"
#include "ext2.h"
#include "uaccess.h"
#include <stdint.h>

/* ── ext2 fd pool ────────────────────────────────────────────────────── */

/* 256, not 32: a self-hosting `ld` holds ALL ~150 kernel object files open at
 * once during the link — 32 slots exhausted, ext2_pool_alloc returned NULL, and
 * vfs_open mapped that to ENOMEM, so ld failed with "cannot find X: Out of
 * memory" mid-link. Just a bigger static array (ext2_fd_priv_t is tiny). */
#define EXT2_FD_POOL 256
static ext2_fd_priv_t s_ext2_pool[EXT2_FD_POOL];

ext2_fd_priv_t *
ext2_pool_alloc(uint32_t ino)
{
    uint32_t i;
    for (i = 0; i < EXT2_FD_POOL; i++) {
        if (!s_ext2_pool[i].in_use) {
            s_ext2_pool[i].ino          = ino;
            s_ext2_pool[i].write_offset = 0;
            s_ext2_pool[i].in_use       = 1;
            s_ext2_pool[i].ref_count    = 1;
            return &s_ext2_pool[i];
        }
    }
    return (ext2_fd_priv_t *)0;
}

void
ext2_pool_free(ext2_fd_priv_t *p)
{
    if (!p) return;
    if (p->ref_count > 0)
        p->ref_count--;
    if (p->ref_count == 0)
        p->in_use = 0;
}

/* ext2_vfs_ino_of — if (ops,priv) is an ext2 file, return its inode number;
 * else 0. Used by lazy file-backed mmap to record the backing inode in the
 * VMA so the page-fault handler can read file pages on demand via ext2_read. */
uint32_t
ext2_vfs_ino_of(const vfs_ops_t *ops, void *priv)
{
    if (ops != &s_ext2_ops || !priv)
        return 0;
    return ((ext2_fd_priv_t *)priv)->ino;
}

/* ── ext2 vfs_ops_t implementations ──────────────────────────────────── */

static int
ext2_vfs_read_fn(void *priv, void *buf, uint64_t off, uint64_t len)
{
    ext2_fd_priv_t *p = (ext2_fd_priv_t *)priv;
    /* sys_read passes f->offset as off; forward directly. */
    return ext2_read(p->ino, buf, off, (uint32_t)len);
}

/* EXT2_WRITE_CHUNK — maximum bytes copied per write pass.
 * Matches NVMe single-transfer limit (one 4 KB block).  buf is a user-space
 * pointer passed from sys_write; copy_from_user transfers it to a kernel
 * bounce buffer before calling ext2_write, avoiding a SMAP violation. */
#define EXT2_WRITE_CHUNK 4096

static int
ext2_vfs_write_fn(void *priv, const void *buf, uint64_t len)
{
    ext2_fd_priv_t *p = (ext2_fd_priv_t *)priv;
    /* sys_write does not pass a file offset, so we maintain write_offset
     * in the priv struct for sequential writes.  This is correct for:
     *   - shell redirection (O_WRONLY|O_CREAT|O_TRUNC): write from 0.
     *   - append writes: each call advances write_offset by bytes written.
     * Concurrent writes to the same fd are not supported (single-process).
     *
     * buf is a user-space pointer (validated by sys_write before dispatch).
     * ext2_write accesses it in kernel mode, which SMAP forbids.  Copy into
     * a kernel bounce buffer first.  Loop in EXT2_WRITE_CHUNK slices to keep
     * the stack frame bounded. */
    /* Static bounce buffer — was stack-allocated, which put 4 KB (25% of
     * the 16 KB per-task kernel stack) in one frame with interrupts on
     * the same stack.  A single static is safe today: scheduling is
     * single-core (APs halt) and syscalls run with IF=0 (IA32_SFMASK),
     * so two tasks are never inside this function concurrently.
     * Revisit (lock or per-CPU buffer) if SMP scheduling lands. */
    static uint8_t s_kbuf[EXT2_WRITE_CHUNK];
    uint64_t done = 0;
    while (done < len) {
        uint64_t chunk = len - done;
        if (chunk > EXT2_WRITE_CHUNK)
            chunk = EXT2_WRITE_CHUNK;
        /* Cap chunk to the current page boundary so we never cross an
         * unmapped page (same guard as console_write_fn). */
        {
            uint64_t page_off = (uint64_t)(uintptr_t)((const uint8_t *)buf + done) & 0xFFFULL;
            uint64_t to_end   = 0x1000ULL - page_off;
            if (chunk > to_end)
                chunk = to_end;
        }
        copy_from_user(s_kbuf, (const uint8_t *)buf + done, (uint32_t)chunk);
        int n = ext2_write(p->ino, s_kbuf, p->write_offset, (uint32_t)chunk);
        if (n <= 0)
            return (done > 0) ? (int)done : n;
        p->write_offset += (uint32_t)n;
        done += (uint64_t)n;
    }
    return (int)done;
}

/* ext2_vfs_seek_fn — sync the write cursor with lseek. Reads already take
 * f->offset directly (ext2_vfs_read_fn), but writes track their own position,
 * so without this a seek-then-write (e.g. `as` seeking back to patch an ELF
 * header after writing sections) would write at the stale position and produce
 * a corrupt object file. */
static void
ext2_vfs_seek_fn(void *priv, uint64_t offset)
{
    ((ext2_fd_priv_t *)priv)->write_offset = (uint32_t)offset;
}

static void
ext2_vfs_close_fn(void *priv)
{
    ext2_pool_free((ext2_fd_priv_t *)priv);
}

static void
ext2_vfs_dup_fn(void *priv)
{
    ext2_fd_priv_t *p = (ext2_fd_priv_t *)priv;
    if (p)
        p->ref_count++;
}

static int
ext2_vfs_readdir_fn(void *priv, uint64_t index,
                    char *name_out, uint8_t *type_out)
{
    ext2_fd_priv_t *p = (ext2_fd_priv_t *)priv;
    return ext2_readdir(p->ino, index, name_out, type_out);
}

static int
ext2_vfs_stat_fn(void *priv, k_stat_t *st)
{
    ext2_fd_priv_t *p = (ext2_fd_priv_t *)priv;
    int sz = ext2_file_size(p->ino);
    if (sz < 0) return -1;
    ext2_inode_t inode;
    if (ext2_read_inode(p->ino, &inode) != 0) return -1;
    __builtin_memset(st, 0, sizeof(*st));
    st->st_dev     = 2;           /* device 2 = nvme0 */
    st->st_ino     = (uint64_t)p->ino;
    st->st_nlink   = inode.i_links_count ? inode.i_links_count : 1;
    st->st_mode    = (uint32_t)inode.i_mode; /* preserves type + permissions from disk */
    st->st_uid     = (uint32_t)inode.i_uid;
    st->st_gid     = (uint32_t)inode.i_gid;
    st->st_size    = (int64_t)sz;
    st->st_blksize = 4096;
    st->st_blocks  = (int64_t)(((uint64_t)sz + 511) / 512);
    st->st_atime   = (int64_t)inode.i_atime;
    st->st_mtime   = (int64_t)inode.i_mtime;
    st->st_ctime   = (int64_t)inode.i_ctime;
    return 0;
}

const vfs_ops_t s_ext2_ops = {
    .seekable = 1,
    .seek    = ext2_vfs_seek_fn,
    .read    = ext2_vfs_read_fn,
    .write   = ext2_vfs_write_fn,
    .close   = ext2_vfs_close_fn,
    .readdir = ext2_vfs_readdir_fn,
    .dup     = ext2_vfs_dup_fn,
    .stat    = ext2_vfs_stat_fn,
    .poll    = (void *)0,
};
