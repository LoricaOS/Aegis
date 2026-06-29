/* blkdev.h — Block device abstraction layer
 *
 * Provides a uniform read/write interface for block storage.
 * NVMe, AHCI, virtio-blk, etc. register themselves here.
 * Filesystems (ext2) hold a blkdev_t pointer.
 */
#ifndef BLKDEV_H
#define BLKDEV_H

#include <stdint.h>

typedef struct blkdev {
    char     name[16];          /* e.g. "nvme0", "nvme0p1" */
    uint64_t block_count;       /* total number of logical blocks */
    uint32_t block_size;        /* bytes per block (512 or 4096) */
    uint64_t lba_offset;        /* partition start LBA (0 for whole disk) */
    int (*read) (struct blkdev *dev, uint64_t lba, uint32_t count, void *buf);
    int (*write)(struct blkdev *dev, uint64_t lba, uint32_t count, const void *buf);
    void    *priv;              /* driver-private data */
} blkdev_t;

#define BLKDEV_MAX 8

/* Register a block device. Returns 0 on success, -1 if table full. */
int       blkdev_register(blkdev_t *dev);

/* Look up a block device by name. Returns NULL if not found. */
blkdev_t *blkdev_get(const char *name);

/* Return the number of registered block devices. */
int blkdev_count(void);

/* Return the i-th registered block device (0-based), or NULL if out of range. */
blkdev_t *blkdev_get_index(int i);

/* Unregister all child devices whose name starts with parent_prefix + "p".
 * Used by gpt_rescan to remove old partition blkdevs before re-scanning. */
void blkdev_unregister_children(const char *parent_prefix);

#endif /* BLKDEV_H */
