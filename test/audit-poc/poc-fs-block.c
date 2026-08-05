/* PoC #2 — filesystem/block findings: C2, H4, H5b, H5c, H8.
 * Arithmetic extracted verbatim from the Aegis sources.
 * cc -O0 -fwrapv -o poc2 poc2.c && ./poc2 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>

static int fails = 0;
#define CHECK(cond, msg) do { \
    if (cond) printf("  ok   %s\n", msg); \
    else { printf("  FAIL %s\n", msg); fails++; } } while (0)

/* ── C2: fs/fat.c walk_dir LFN fragment ─────────────────────────────── */
/* Writes into a guarded lfn[]; returns the lowest index written (negative =
 * underflow into the stack locals below the buffer). */
static int c2_lowest_write(uint8_t e0, int fixed)
{
    int lowest = 9999;
    int seq = e0 & 0x1F;
    if (fixed && (seq < 1 || seq > 20)) return lowest;   /* fragment skipped */
    int base = (seq - 1) * 13;
    for (int k = 0; k < 13 && base + k < 259; k++)
        if (base + k < lowest) lowest = base + k;
    return lowest;
}

/* ── H4: fs/ext2.c directory walk termination ───────────────────────── */
/* Returns iterations before termination, capped so the PoC itself ends. */
static unsigned long h4_walk(uint32_t i_size, uint32_t block_size, int fixed)
{
    /* ext2_max_file_size()'s ceiling for a 1024-byte block fs */
    uint64_t ppb = block_size / 4u;
    uint64_t bytes = (12u + ppb + ppb * ppb) * (uint64_t)block_size;
    uint64_t cap = 0xFFFFFFFFull - block_size;
    uint64_t max = bytes < cap ? bytes : cap;

    uint32_t limit = i_size;
    if (fixed && (uint64_t)i_size > max) limit = (uint32_t)max;

    uint32_t walked = 0;
    unsigned long iters = 0;
    while (walked < limit) {
        walked += block_size;          /* sparse block → the "continue" path */
        if (++iters > 20000000UL) return iters;   /* PoC bail: it's infinite */
    }
    return iters;
}

/* ── H5b: fs/fat.c fat_mount geometry ───────────────────────────────── */
/* Returns s_total_clusters, or 0 if the mount is rejected. */
static uint32_t h5b_total_clusters(uint32_t reserved, uint8_t nfats,
                                   uint32_t fat_size, uint32_t total,
                                   uint8_t spc, int fixed)
{
    if (spc == 0 || nfats == 0 || fat_size == 0) return 0;
    if (fixed) {
        uint64_t d64 = (uint64_t)reserved + (uint64_t)nfats * fat_size;
        if (reserved == 0 || d64 >= (uint64_t)total) return 0;  /* EINVAL */
        uint32_t data_lba = (uint32_t)d64;
        return (total - data_lba) / spc;
    }
    uint32_t data_lba = reserved + (uint32_t)nfats * fat_size;  /* can wrap */
    return (total - data_lba) / spc;                            /* can wrap */
}

/* ── H5c: fs/fat.c cluster_lba ──────────────────────────────────────── */
#define FAT_EOC 0x0FFFFFF8u
static uint32_t h5c_lba(uint32_t cl, uint32_t data_lba, uint8_t spc,
                        uint32_t total_clusters, int fixed)
{
    if (fixed) {
        if (!(total_clusters != 0 && cl >= 2 && cl - 2 < total_clusters))
            return 0xFFFFFFFFu;                 /* refused */
    } else {
        if (!(cl >= 2 && cl < FAT_EOC)) return 0xFFFFFFFFu;
    }
    return data_lba + (cl - 2) * spc;           /* overflows uint32 unchecked */
}

/* ── H8: fs/gpt.c partition bounce buffer ───────────────────────────── */
/* Returns the largest byte offset written into s_part_bounce[4096]. */
static uint64_t h8_max_off(uint32_t count, uint32_t native_bs, uint64_t lba,
                           int fixed)
{
    uint64_t byte_start = lba * 512ULL;
    uint64_t remaining  = (uint64_t)count * 512ULL;
    if (!fixed) {
        uint32_t sub_off = (uint32_t)(byte_start % native_bs);
        return sub_off + remaining;             /* one unbounded memcpy */
    }
    uint64_t worst = 0;
    while (remaining) {                          /* shipped: per-sector loop */
        uint32_t sub_off = (uint32_t)(byte_start % native_bs);
        uint32_t chunk   = native_bs - sub_off;
        if ((uint64_t)chunk > remaining) chunk = (uint32_t)remaining;
        if (sub_off + chunk > worst) worst = sub_off + chunk;
        byte_start += chunk; remaining -= chunk;
    }
    return worst;
}

static void run(int fixed)
{
    printf("\n=== %s ===\n", fixed ? "AFTER FIX" : "BEFORE FIX (vulnerable)");

    /* C2: a crafted LFN dirent with e[0] = 0x40 (LAST bit, seq zeroed) */
    int lo = c2_lowest_write(0x40, fixed);
    printf("  C2  LFN seq=0 -> lowest lfn[] index written = %d\n", lo);
    CHECK(lo >= 0, "C2: no write below lfn[0]");
    CHECK(c2_lowest_write(0x41, fixed) == 0,  "C2: seq=1 still writes lfn[0]");
    CHECK(c2_lowest_write(0x02, fixed) == 13, "C2: seq=2 still writes lfn[13]");

    /* H4: crafted directory inode, 1 KiB blocks */
    unsigned long it = h4_walk(0xFFFFFFFFu, 1024, fixed);
    printf("  H4  dir i_size=0xFFFFFFFF -> %lu iterations%s\n", it,
           it > 20000000UL ? " (PoC bail — infinite)" : "");
    CHECK(it <= 20000000UL, "H4: directory walk terminates");
    CHECK(h4_walk(4096, 1024, fixed) == 4, "H4: normal 4-block dir unchanged");

    /* H5b: total < data_lba underflows the cluster count */
    uint32_t tc = h5b_total_clusters(32, 2, 0x10000, 100, 1, fixed);
    printf("  H5b BPB total<data_lba -> s_total_clusters = %u\n", tc);
    CHECK(tc < 0x10000000u, "H5b: cluster count not underflowed");
    CHECK(h5b_total_clusters(32, 2, 1000, 100000, 8, fixed) == 12246,
          "H5b: sane BPB still computes the same geometry");

    /* H5c: dirent first_cluster = 0x0FFFFFF0 with 255 sectors/cluster */
    uint32_t lba = h5c_lba(0x0FFFFFF0u, 2048, 255, 65536, fixed);
    printf("  H5c cluster=0x0FFFFFF0 -> LBA %u (%s)\n", lba,
           lba == 0xFFFFFFFFu ? "refused" : "ISSUED TO DISK");
    CHECK(lba == 0xFFFFFFFFu, "H5c: out-of-range cluster refused");
    CHECK(h5c_lba(3, 2048, 8, 65536, fixed) == 2056,
          "H5c: valid cluster still maps to the same LBA");

    /* H8: sys_blkdev_io's max chunk (128 sectors) on a 4K-native drive */
    uint64_t off = h8_max_off(128, 4096, 8, fixed);
    printf("  H8  count=128 on 4K-native -> writes %llu bytes into 4096\n",
           (unsigned long long)off);
    CHECK(off <= 4096, "H8: bounce buffer not overrun");
    CHECK(h8_max_off(2, 4096, 2, fixed) == 2048,
          "H8: ordinary sub-block read unchanged");
}

int main(void)
{
    run(0);
    run(1);
    printf("\n%d check(s) failed\n", fails);
    return 0;
}
