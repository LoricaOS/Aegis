/* Fuzz the GPT partition-table scanner with a hostile disk.
 *
 * gpt_scan() is the FIRST kernel code to interpret bytes from an attached disk,
 * before any filesystem is mounted. It reads a protective MBR, an LBA-1 header
 * and a partition-entry array whose count and entry size are both taken from
 * that attacker-controlled header, then registers a child blkdev per partition
 * with attacker-chosen start/end LBAs.
 *
 * The image is an exact-size heap allocation so a read past the end of the
 * medium is an ASan report. Each registered partition is then checked: its
 * range must lie inside the disk, or a later filesystem read through that child
 * blkdev is reading something it was never given.
 */
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "blkdev.h"
#include "gpt.h"

uint64_t g_fake_ticks = 0;
volatile int g_in_isr_poll = 0;

static const uint8_t *s_img;
static size_t         s_img_len;

static int img_read(blkdev_t *dev, uint64_t lba, uint32_t count, void *buf)
{
    uint64_t off = (lba + dev->lba_offset) * dev->block_size;
    uint64_t n   = (uint64_t)count * dev->block_size;
    if (off > s_img_len || n > s_img_len - off)
        return -1;
    memcpy(buf, s_img + off, (size_t)n);
    return 0;
}

static int img_write(blkdev_t *dev, uint64_t lba, uint32_t count, const void *b)
{ (void)dev; (void)lba; (void)count; (void)b; return -1; }

static blkdev_t s_disk;

int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n)
{
    uint8_t *img;
    int parts, i;

    if (n < 1024 || n > (1u << 20))
        return 0;

    img = malloc(n);
    if (!img)
        return 0;
    memcpy(img, d, n);
    s_img     = img;
    s_img_len = n;

    /* Drop any children registered by a previous iteration. */
    blkdev_unregister_children("fuzzdisk");

    memset(&s_disk, 0, sizeof(s_disk));
    strcpy(s_disk.name, "fuzzdisk");
    s_disk.block_size  = 512;
    s_disk.block_count = n / 512;
    s_disk.read        = img_read;
    s_disk.write       = img_write;
    blkdev_register(&s_disk);

    parts = gpt_scan("fuzzdisk");

    /* Every partition gpt_scan registered must lie within the disk. A child
     * whose lba_offset or size runs off the end would let a mounted filesystem
     * read outside the medium it was handed. */
    for (i = 0; i < blkdev_count(); i++) {
        blkdev_t *c = blkdev_get_index(i);
        if (!c || c == &s_disk)
            continue;
        if (strncmp(c->name, "fuzzdisk", 8) != 0)
            continue;
        if (c->lba_offset > s_disk.block_count ||
            c->block_count > s_disk.block_count - c->lba_offset) {
            fprintf(stderr, "gpt_scan registered %s outside the disk: "
                            "offset=%llu count=%llu disk=%llu\n",
                    c->name, (unsigned long long)c->lba_offset,
                    (unsigned long long)c->block_count,
                    (unsigned long long)s_disk.block_count);
            abort();
        }
    }
    (void)parts;

    s_img     = NULL;
    s_img_len = 0;
    free(img);
    return 0;
}
