/* ext2_cache.c — 16-slot LRU block cache, ext2_sync, and the perfbench
 * micro-benchmark.
 *
 * (An enlarged PMM-backed hash+CLOCK cache was prototyped and benchmarked; it
 * gave no throughput win on sequential large-file I/O — the indirect/bitmap
 * blocks stay resident in 16 slots anyway — so it was dropped.  See
 * research/ext2-cache/design.md.) */
#include "ext2_internal.h"
#include "kva.h"
#include "arch.h"   /* arch_get_cycles()/arch_tsc_hz() — perfbench timing */

/* Cache globals */
cache_slot_t s_cache[CACHE_SLOTS];
uint64_t s_cache_age = 0;

/* Device-I/O counters — the cache-effectiveness / re-walk metric.  A cache MISS
 * issues a device read; a dirty eviction / sync issues a device write.  Read by
 * the perf bench (snapshots before/after each pass). */
uint64_t s_cache_dev_reads  = 0;
uint64_t s_cache_dev_writes = 0;

/* cache_find — return slot index of block_num, or -1 if not cached */
int cache_find(uint32_t block_num)
{
    int i;
    for (i = 0; i < CACHE_SLOTS; i++) {
        if (s_cache[i].block_num == block_num && s_cache[i].age != 0)
            return i;
    }
    return -1;
}

/* cache_evict — find the LRU slot (lowest age, prefer clean over dirty).
 * Writes back dirty data before evicting. Returns slot index. */
int cache_evict(void)
{
    int i;
    int best = 0;

    /* Prefer a clean slot with the lowest age */
    for (i = 1; i < CACHE_SLOTS; i++) {
        /* Prefer clean over dirty */
        if (s_cache[i].dirty == 0 && s_cache[best].dirty != 0) {
            best = i;
            continue;
        }
        if (s_cache[i].dirty != 0 && s_cache[best].dirty == 0) {
            continue;
        }
        /* Same cleanliness: pick lower age */
        if (s_cache[i].age < s_cache[best].age) {
            best = i;
        }
    }

    /* Write back if dirty */
    if (s_cache[best].dirty && s_cache[best].block_num != 0) {
        uint64_t lba = (uint64_t)s_cache[best].block_num *
                       (s_block_size / 512);
        s_cache_dev_writes++;
        int wr = s_dev->write(s_dev, lba, s_block_size / 512,
                              s_cache[best].data);
        if (wr != 0) {
            printk("[EXT2] WARN: cache flush failed for block %u\n",
                   s_cache[best].block_num);
            /* Clear dirty anyway to avoid infinite eviction loop */
        }
        s_cache[best].dirty = 0;
    }

    return best;
}


/* cache_mark_dirty — mark the cached slot for block_num dirty */
void cache_mark_dirty(uint32_t block_num)
{
    int idx = cache_find(block_num);
    if (idx >= 0) {
        s_cache[idx].dirty = 1;
    }
}

/* cache_get_slot — return pointer to cached data for block_num,
 * loading from disk if necessary. Returns NULL on I/O error. */
uint8_t *cache_get_slot(uint32_t block_num)
{
    /* Defense-in-depth: block numbers reach here from untrusted on-disk
     * metadata (inode i_block[], indirect blocks, group descriptors).
     * Block 0 is never a valid data/metadata block for the supported block
     * sizes (the superblock occupies the start of the volume), and any block
     * >= s_blocks_count is off the end of the filesystem.  Reject both so a
     * crafted image can't drive a read at an attacker-chosen LBA.  Callers
     * already treat a NULL return as failure. */
    if (block_num == 0 || block_num >= s_sb.s_blocks_count)
        return (uint8_t *)0;

    int idx = cache_find(block_num);

    if (idx < 0) {
        idx = cache_evict();
        s_cache[idx].block_num = block_num;
        s_cache[idx].dirty = 0;
        s_cache_age++;
        s_cache[idx].age = s_cache_age;

        uint64_t lba = (uint64_t)block_num * (s_block_size / 512);
        s_cache_dev_reads++;
        int ret = s_dev->read(s_dev, lba, s_block_size / 512,
                              s_cache[idx].data);
        if (ret < 0) {
            /* Read failed: the slot's data is stale/garbage.  Clear it back
             * to the empty sentinel (age == 0, block_num == 0) so a later
             * request for this block is a cache_find() MISS and re-reads,
             * rather than returning poisoned data.  cache_find() treats a
             * slot as valid only when age != 0, and block 0 is rejected at
             * function entry so it is never a legitimate cached block. */
            s_cache[idx].block_num = 0;
            s_cache[idx].age       = 0;
            s_cache[idx].dirty     = 0;
            return (uint8_t *)0;
        }
    } else {
        s_cache_age++;
        s_cache[idx].age = s_cache_age;
    }

    return s_cache[idx].data;
}

/* ------------------------------------------------------------------ */
/* ext2_sync — flush all dirty cache slots to disk                     */
/* ------------------------------------------------------------------ */

void ext2_sync(void)
{
    int i;
    int flushed = 0;

    /* Lock ordering: sched_lock > ext2_lock.  ext2_sync may be called from
     * sched_exit (which holds sched_lock), so acquiring ext2_lock here is
     * safe — it is the inner lock. */
    irqflags_t fl = ext2_lock_acquire();
    if (!s_mounted || !s_dev) {
        ext2_lock_release(fl);
        return;
    }
    for (i = 0; i < CACHE_SLOTS; i++) {
        if (s_cache[i].dirty && s_cache[i].block_num != 0) {
            uint64_t lba = (uint64_t)s_cache[i].block_num *
                           (s_block_size / 512);
            s_cache_dev_writes++;
            s_dev->write(s_dev, lba, s_block_size / 512, s_cache[i].data);
            s_cache[i].dirty = 0;
            flushed++;
        }
    }
    ext2_lock_release(fl);
    printk("[EXT2] sync: flushed %u dirty blocks\n", (uint32_t)flushed);
}

/* ------------------------------------------------------------------ */
/* ext2_perfbench — cmdline `perfbench_fs` micro-benchmark.            */
/*                                                                     */
/* Writes a large file to the ext2 root then reads it back, reporting  */
/* MiB, elapsed ms and MB/s on serial.  Sized to half the free space  */
/* (capped) so it works on the small ramdisk rootfs and the installed  */
/* NVMe root alike.  Gated by the cmdline token so it never perturbs   */
/* the boot oracle.                                                    */
/* ------------------------------------------------------------------ */

#define PERFBENCH_PATH      "/perfbench.dat"
#define PERFBENCH_CAP_BYTES (32u * 1024u * 1024u)   /* never exceed 32 MiB     */
#define PERFBENCH_CHUNK     (64u * 1024u)           /* per-call I/O size       */

void ext2_perfbench(void)
{
    /* Determine bench size: half of free space, block-rounded, <= cap. */
    uint64_t free_bytes;
    {
        irqflags_t fl = ext2_lock_acquire();
        free_bytes = (uint64_t)s_sb.s_free_blocks_count * s_block_size;
        ext2_lock_release(fl);
    }
    uint64_t want = free_bytes / 2;
    if (want > PERFBENCH_CAP_BYTES)
        want = PERFBENCH_CAP_BYTES;
    want &= ~((uint64_t)PERFBENCH_CHUNK - 1);   /* whole chunks */
    if (want < PERFBENCH_CHUNK) {
        printk("[PERFBENCH] skip: only %u KiB free\n",
               (uint32_t)(free_bytes / 1024));
        return;
    }
    uint32_t total = (uint32_t)want;

    /* Scratch buffer (PMM-backed, not BSS). */
    uint8_t *buf = (uint8_t *)kva_alloc_pages(PERFBENCH_CHUNK / 4096);
    uint32_t i;
    for (i = 0; i < PERFBENCH_CHUNK; i++)
        buf[i] = (uint8_t)(i * 7 + 1);

    /* Fresh file. */
    ext2_unlink(PERFBENCH_PATH, 1);
    if (ext2_create(PERFBENCH_PATH, 0644, 1) != 0) {
        printk("[PERFBENCH] FAIL: create %s\n", PERFBENCH_PATH);
        kva_free_pages(buf, PERFBENCH_CHUNK / 4096);
        return;
    }
    uint32_t ino;
    if (ext2_open(PERFBENCH_PATH, &ino) != 0) {
        printk("[PERFBENCH] FAIL: open %s\n", PERFBENCH_PATH);
        kva_free_pages(buf, PERFBENCH_CHUNK / 4096);
        return;
    }

    uint32_t blocks = total / s_block_size;
    printk("[PERFBENCH] file=%s size=%u MiB (%u blocks) chunk=%u KiB cache=%u slots\n",
           PERFBENCH_PATH, total / (1024u * 1024u), blocks,
           PERFBENCH_CHUNK / 1024u, (uint32_t)CACHE_SLOTS);

    /* Fine-grained timing via TSC.  arch_get_ticks() (100 Hz / 10 ms) is far
     * too coarse: a 14 MiB pass over a ramdisk completes in well under a tick. */
    uint64_t hz = arch_tsc_hz();          /* cycles/sec; 0 if uncalibrated */

    /* ── Write pass ── */
    uint64_t rd0 = s_cache_dev_reads, wr0 = s_cache_dev_writes;
    uint64_t c0 = arch_get_cycles();
    uint32_t off = 0;
    int ok = 1;
    while (off < total) {
        int w = ext2_write(ino, buf, off, PERFBENCH_CHUNK);
        if (w != (int)PERFBENCH_CHUNK) {
            printk("[PERFBENCH] write short at off=%u ret=%x\n", off,
                   (uint32_t)w);
            total = off;            /* read back only what we wrote */
            ok = 0;
            break;
        }
        off += PERFBENCH_CHUNK;
    }
    ext2_sync();
    uint64_t c1 = arch_get_cycles();
    uint64_t w_devr = s_cache_dev_reads - rd0, w_devw = s_cache_dev_writes - wr0;

    /* ── Read pass (cold-ish: cache holds the tail of the write) ── */
    uint64_t rd1 = s_cache_dev_reads, wr1 = s_cache_dev_writes;
    uint64_t c2 = arch_get_cycles();
    off = 0;
    while (off < total) {
        int r = ext2_read(ino, buf, off, PERFBENCH_CHUNK);
        if (r != (int)PERFBENCH_CHUNK) {
            printk("[PERFBENCH] read short at off=%u ret=%x\n", off,
                   (uint32_t)r);
            break;
        }
        off += PERFBENCH_CHUNK;
    }
    uint64_t c3 = arch_get_cycles();
    uint64_t r_devr = s_cache_dev_reads - rd1, r_devw = s_cache_dev_writes - wr1;

    /* ── Content verify (untimed): prove the allocator + cache round-trip the
     * bytes correctly — no corruption on eviction or block remapping.  Every
     * chunk was written from the same pattern buffer, so each read chunk must
     * equal (uint8_t)(j*7+1). */
    int verify_ok = 1;
    off = 0;
    while (off < total) {
        int r = ext2_read(ino, buf, off, PERFBENCH_CHUNK);
        if (r != (int)PERFBENCH_CHUNK) { verify_ok = 0; break; }
        for (i = 0; i < PERFBENCH_CHUNK; i++) {
            if (buf[i] != (uint8_t)(i * 7 + 1)) {
                printk("[PERFBENCH] VERIFY FAIL at off=%u byte=%u got=%x want=%x\n",
                       off, i, (uint32_t)buf[i], (uint32_t)(uint8_t)(i * 7 + 1));
                verify_ok = 0;
                break;
            }
        }
        if (!verify_ok) break;
        off += PERFBENCH_CHUNK;
    }

    /* us = cycles * 1e6 / hz.  MB/s = bytes / us (since bytes/us == MB/s). */
    uint32_t mib    = total / (1024u * 1024u);
    uint64_t wr_cyc = c1 - c0, rd_cyc = c3 - c2;
    uint32_t wr_us  = hz ? (uint32_t)(wr_cyc * 1000000ULL / hz) : 0;
    uint32_t rd_us  = hz ? (uint32_t)(rd_cyc * 1000000ULL / hz) : 0;
    uint32_t wr_mbs = wr_us ? (uint32_t)((uint64_t)total / wr_us) : 0;
    uint32_t rd_mbs = rd_us ? (uint32_t)((uint64_t)total / rd_us) : 0;

    printk("[PERFBENCH] write %u MiB in %u us = %u MB/s  (dev_reads=%u dev_writes=%u)\n",
           mib, wr_us, wr_mbs, (uint32_t)w_devr, (uint32_t)w_devw);
    printk("[PERFBENCH] read  %u MiB in %u us = %u MB/s  (dev_reads=%u dev_writes=%u)\n",
           mib, rd_us, rd_mbs, (uint32_t)r_devr, (uint32_t)r_devw);
    /* The re-walk metric: dev_reads on the read pass divided by data blocks.
     * ~1.0 means no re-walk; >> 1 means indirect/bitmap blocks are thrashing. */
    if (blocks)
        printk("[PERFBENCH] read dev_reads/block x100 = %u (100=ideal, no re-walk)\n",
               (uint32_t)(r_devr * 100 / blocks));
    printk("[PERFBENCH] VERIFY %s\n", verify_ok ? "OK" : "FAIL");
    if (ok && verify_ok)
        printk("[PERFBENCH] OK\n");

    ext2_unlink(PERFBENCH_PATH, 1);
    kva_free_pages(buf, PERFBENCH_CHUNK / 4096);
}
