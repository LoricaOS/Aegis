#include "ramdisk.h"
#include "blkdev.h"
#include "kva.h"
#include "printk.h"
#include <stdint.h>

static uint8_t *s_base;   /* KVA pointer to mapped module */
static uint64_t s_size;   /* byte size */

static blkdev_t s_ramdisk;

static int
ramdisk_read(blkdev_t *dev, uint64_t lba, uint32_t count, void *buf)
{
    (void)dev;
    uint64_t off = lba * 512;
    uint64_t len = (uint64_t)count * 512;
    if (off + len > s_size) return -1;
    __builtin_memcpy(buf, s_base + off, len);
    return 0;
}

static int
ramdisk_write(blkdev_t *dev, uint64_t lba, uint32_t count, const void *buf)
{
    (void)dev;
    uint64_t off = lba * 512;
    uint64_t len = (uint64_t)count * 512;
    if (off + len > s_size) return -1;
    __builtin_memcpy((void *)(s_base + off), buf, len);
    return 0;
}

void
ramdisk_init(uint64_t phys_base, uint64_t size)
{
    if (phys_base == 0 || size == 0)
        return;  /* no module loaded — diskless boot */

    /* Allocate fresh KVA pages and COPY module data into them.
     * We cannot map the module's physical pages in-place because GRUB places
     * the module right after the kernel image, potentially overlapping with
     * physical addresses used by VMM page tables.  Copying avoids the conflict.
     *
     * SAFETY: the identity map [0..1GB) is still active at this point in boot
     * (vmm_teardown_identity runs later), so we can read the module's physical
     * address directly via pointer cast. */
    /* Zero-extend to the ext2's true size. The ISO ships a TRUNCATED rootfs
     * image — trailing free/zero ext2 blocks are dropped at build time to shrink
     * the ISO (the fs is one block group with 4 KiB blocks, so it has no backup
     * superblocks in the tail and the trailing bytes are all zero). We restore
     * the full filesystem here in RAM: read the real block count from the
     * superblock (byte offset 1024; s_blocks_count@+4, s_log_block_size@+24,
     * s_magic@+56), allocate that much, copy the shipped bytes, and zero the
     * rest. Net effect: the live system's free space costs RAM, not ISO bytes,
     * and the installer still reads a full-size image off this blkdev. A bad/
     * absent superblock (e.g. not ext2) falls back to the shipped size. */
    uint64_t true_size = size;
    {
        const uint8_t *sb = (const uint8_t *)(uintptr_t)(phys_base + 1024);
        uint16_t magic = (uint16_t)(sb[56] | (sb[57] << 8));
        if (magic == 0xEF53) {
            uint32_t blocks = (uint32_t)sb[4] | ((uint32_t)sb[5] << 8) |
                              ((uint32_t)sb[6] << 16) | ((uint32_t)sb[7] << 24);
            uint32_t logbs  = (uint32_t)sb[24] | ((uint32_t)sb[25] << 8) |
                              ((uint32_t)sb[26] << 16) | ((uint32_t)sb[27] << 24);
            if (logbs <= 2) {                         /* block size <= 4096 */
                uint64_t fs = (uint64_t)blocks * (1024ULL << logbs);
                if (fs > true_size && fs <= 256ULL * 1024 * 1024)  /* extend only, cap 256 MB */
                    true_size = fs;
            }
        }
    }

    uint32_t num_pages = (uint32_t)((true_size + 4095) / 4096);
    s_base = (uint8_t *)kva_alloc_pages(num_pages);
    s_size = true_size;
    {
        const uint8_t *src = (const uint8_t *)(uintptr_t)phys_base;
        uint64_t i;
        for (i = 0; i < size; i++)            /* shipped (truncated) image */
            s_base[i] = src[i];
        for (; i < true_size; i++)            /* zero-extend (kva_alloc_pages does NOT zero) */
            s_base[i] = 0;
    }
    if (true_size > size)
        printk("[RAMDISK] OK: zero-extended %u MB image to %u MB ext2\n",
               (unsigned)(size / (1024 * 1024)),
               (unsigned)(true_size / (1024 * 1024)));

    /* Build blkdev name manually — no snprintf in kernel */
    s_ramdisk.name[0] = 'r'; s_ramdisk.name[1] = 'a';
    s_ramdisk.name[2] = 'm'; s_ramdisk.name[3] = 'd';
    s_ramdisk.name[4] = 'i'; s_ramdisk.name[5] = 's';
    s_ramdisk.name[6] = 'k'; s_ramdisk.name[7] = '0';
    s_ramdisk.name[8] = '\0';
    s_ramdisk.block_count = true_size / 512;
    s_ramdisk.block_size  = 512;
    s_ramdisk.lba_offset  = 0;
    s_ramdisk.read        = ramdisk_read;
    s_ramdisk.write       = ramdisk_write;
    s_ramdisk.priv        = (void *)0;

    blkdev_register(&s_ramdisk);
    printk("[RAMDISK] OK: %u MB rootfs in RAM\n",
           (unsigned)(true_size / (1024 * 1024)));
}

/* ── Second ramdisk (ramdisk1) for ESP image ───────────────────────── */

static uint8_t *s_base2;
static uint64_t s_size2;
static blkdev_t s_ramdisk2;

static int
ramdisk2_read(blkdev_t *dev, uint64_t lba, uint32_t count, void *buf)
{
    (void)dev;
    uint64_t off = lba * 512;
    uint64_t len = (uint64_t)count * 512;
    if (off + len > s_size2) return -1;
    __builtin_memcpy(buf, s_base2 + off, len);
    return 0;
}

static int
ramdisk2_write(blkdev_t *dev, uint64_t lba, uint32_t count, const void *buf)
{
    (void)dev;
    uint64_t off = lba * 512;
    uint64_t len = (uint64_t)count * 512;
    if (off + len > s_size2) return -1;
    __builtin_memcpy((void *)(s_base2 + off), buf, len);
    return 0;
}

void
ramdisk_init2(uint64_t phys_base, uint64_t size)
{
    if (phys_base == 0 || size == 0)
        return;
    uint32_t num_pages = (uint32_t)((size + 4095) / 4096);
    s_base2 = (uint8_t *)kva_alloc_pages(num_pages);
    s_size2 = size;
    {
        const uint8_t *src = (const uint8_t *)(uintptr_t)phys_base;
        uint64_t i;
        for (i = 0; i < size; i++)
            s_base2[i] = src[i];
    }
    s_ramdisk2.name[0] = 'r'; s_ramdisk2.name[1] = 'a';
    s_ramdisk2.name[2] = 'm'; s_ramdisk2.name[3] = 'd';
    s_ramdisk2.name[4] = 'i'; s_ramdisk2.name[5] = 's';
    s_ramdisk2.name[6] = 'k'; s_ramdisk2.name[7] = '1';
    s_ramdisk2.name[8] = '\0';
    s_ramdisk2.block_count = size / 512;
    s_ramdisk2.block_size  = 512;
    s_ramdisk2.lba_offset  = 0;
    s_ramdisk2.read        = ramdisk2_read;
    s_ramdisk2.write       = ramdisk2_write;
    s_ramdisk2.priv        = (void *)0;
    blkdev_register(&s_ramdisk2);
    printk("[RAMDISK] OK: %u MB ESP mapped from module 2\n",
           (unsigned)(size / (1024 * 1024)));
}
