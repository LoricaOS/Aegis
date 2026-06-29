/* ext2_vfs.h — ext2 VFS adapter: per-fd state + vfs_ops_t for ext2 files.
 *
 * Extracted from vfs.c.  Provides ext2_pool_alloc() and s_ext2_ops so that
 * vfs_open() (in vfs.c) can open ext2 files, and vfs_fchmod/vfs_fchown can
 * identify ext2 fds. */
#ifndef EXT2_VFS_H
#define EXT2_VFS_H

#include "vfs.h"
#include <stdint.h>

/* ── ext2 fd private state ────────────────────────────────────────────── */

/*
 * ext2_fd_priv_t — per-open-file state for ext2 fds.
 *
 * We need a struct rather than a raw inode pointer because:
 *   - ops->write(priv, buf, len) does not receive the current offset.
 *   - We must track write_offset ourselves so sequential writes work.
 *   - sys_read passes f->offset (maintained by sys_read), so reads are
 *     offset-driven from the fd; we just forward to ext2_read().
 *   - sys_write does NOT maintain f->offset, so write position is private.
 *
 * Allocated from s_ext2_pool[] (32 slots); freed on close.
 */
typedef struct {
    uint32_t ino;           /* ext2 inode number */
    uint32_t write_offset;  /* current sequential write position */
    uint32_t in_use;        /* 1 if slot is occupied */
    uint32_t ref_count;     /* number of open fds sharing this slot */
} ext2_fd_priv_t;

/* Allocate a pool slot for the given inode.
 * Returns pointer to slot, or NULL if pool is exhausted. */
ext2_fd_priv_t *ext2_pool_alloc(uint32_t ino);

/* Release a pool slot (decrements ref_count; frees when 0). */
void ext2_pool_free(ext2_fd_priv_t *p);

/* Shared ops table for ext2 fds — used by vfs_open, vfs_fchmod, vfs_fchown
 * to identify ext2 file descriptors. */
extern const vfs_ops_t s_ext2_ops;

/* If (ops,priv) names an ext2 file, return its inode number; else 0.
 * Used by lazy file-backed mmap to record the backing inode in the VMA. */
uint32_t ext2_vfs_ino_of(const vfs_ops_t *ops, void *priv);

#endif /* EXT2_VFS_H */
