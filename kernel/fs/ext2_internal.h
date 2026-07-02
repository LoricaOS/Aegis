/* ext2_internal.h — internal header for ext2 TU communication.
 * Not exported beyond kernel/fs/. Each ext2_*.c includes this. */
#pragma once

#include "ext2.h"
#include "blkdev.h"
#include "printk.h"
#include "spinlock.h"

/* Errno codes (EIO/ENAMETOOLONG/EACCES/EINVAL/ELOOP/…) come from the single
 * source of truth, aegis_errno.h — formerly duplicated here. */
#include "../include/aegis_errno.h"

/* ── Shared state — defined in ext2.c ──────────────────────────────────── */
extern blkdev_t *s_dev;
extern ext2_superblock_t s_sb;
extern uint32_t s_block_size;
extern uint32_t s_num_groups;
extern ext2_bgd_t s_bgd[32];
extern int s_mounted;
extern spinlock_t ext2_lock;

/* Recursive ext2_lock API (see ext2.c).  Every public ext2 entry point and
 * every cache-touching helper acquires via these; nested calls are safe.
 * Use these INSTEAD of spin_lock_irqsave(&ext2_lock) everywhere in the ext2
 * driver, or the recursion bookkeeping desyncs and a nested acquire deadlocks. */
irqflags_t ext2_lock_acquire(void);
void       ext2_lock_release(irqflags_t fl);

/* ── Block cache — defined in ext2_cache.c ─────────────────────────────── */
/* 16-slot write-back LRU.  Measured (perfbench_fs, 2026-06): enlarging this to
 * 2048 slots gave ZERO throughput win on sequential large-file I/O and a tiny
 * regression — the single/double-indirect pointer blocks + bitmaps are touched
 * on every block iteration, so they stay resident even in 16 slots (read
 * dev_reads/data-block measured at 1.06x, i.e. no re-walk).  The real ext2
 * write-path cost was the O(n²) bitmap rescan, fixed with a per-group
 * allocation hint in ext2.c — not the cache size.  Left at 16.
 * (Sequential DATA now bypasses these slots entirely: ext2_read batches
 * contiguous uncached full blocks into one direct device read.) */
#define CACHE_SLOTS 16

/* Cap for ext2_read's multi-block direct-read run (bytes).  64 KiB = 16
 * 4 KiB blocks: well under the NVMe driver's 128 KiB per-command bounce
 * ceiling, big enough to amortize the per-command submit+poll cost. */
#define EXT2_READ_RUN_BYTES 65536u

typedef struct {
    uint32_t block_num;
    uint8_t  dirty;
    /* age 0 = slot unused (sentinel checked by cache_find).  64-bit so the
     * counter can never wrap back to 0 in practice — a wrapped uint32 let
     * the same block load into two slots, and a stale dirty copy could
     * later be written back over newer data. */
    uint64_t age;
    uint8_t  data[4096];    /* max block size */
} cache_slot_t;

extern cache_slot_t s_cache[CACHE_SLOTS];
extern uint64_t s_cache_age;

/* Device-I/O counters (the cache-effectiveness / re-walk metric).  Read by the
 * perf bench; a MISS issues a device read, a dirty eviction/sync a write. */
extern uint64_t s_cache_dev_reads;
extern uint64_t s_cache_dev_writes;

/* Cache functions */
int     cache_find(uint32_t block_num);
int     cache_evict(void);
void    cache_mark_dirty(uint32_t block_num);
uint8_t *cache_get_slot(uint32_t block_num);
/* ext2_perfbench() is declared in the public ext2.h (called from core/main.c). */

/* ── Inode + block helpers — defined in ext2.c ─────────────────────────── */
int      ext2_read_inode(uint32_t ino, ext2_inode_t *out);
int      ext2_write_inode(uint32_t ino, const ext2_inode_t *inode);
uint32_t ext2_block_num(const ext2_inode_t *inode, uint32_t file_block);
uint32_t ext2_alloc_block(uint32_t preferred_group);
uint32_t ext2_alloc_inode(uint32_t preferred_group);

/* ── Directory helpers — defined in ext2_dir.c ─────────────────────────── */
int ext2_lookup_parent(const char *path, uint32_t *parent_ino_out,
                       const char **basename_out);
int ext2_dir_add_entry(uint32_t dir_ino, uint32_t child_ino,
                       const char *name, uint8_t file_type);
int ext2_dir_remove_entry(uint32_t dir_ino, const char *name);
