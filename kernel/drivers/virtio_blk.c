/* virtio_blk.c — virtio 1.0 block device, on the shared virtio core
 *
 * Registers a blkdev_t ("vblk0") so ext2/GPT use it exactly like NVMe. Most
 * cloud images boot virtio-blk rather than NVMe, so this is the storage path for
 * QEMU/cloud VMs.
 *
 * Each I/O is a 3-part descriptor chain (§5.2.6):
 *   [ req header (16B, device-reads) | data (N×≤4K, scatter-gather) | status (1B, device-writes) ]
 * The data segments are bounce pages from the <4GB DMA pool (scattered, so one
 * descriptor per page — native scatter-gather, no contiguous allocator needed).
 *
 * Completion model: synchronous poll-in-call (spin the used ring until THIS
 * request finishes), like NVMe's poll_cqe. No MSI-X, no background poll. The
 * request queue is serialised by vq->lock, so concurrent callers are safe.
 *
 * References: VIRTIO v1.0 §5.2 Block Device.
 */
#include "virtio.h"
#include "blkdev.h"
#include "arch.h"
#include "printk.h"
#include "spinlock.h"
#include <stdint.h>
#include <stddef.h>

#define VIRTIO_BLK_MODERN  0x1042u
#define VIRTIO_BLK_LEGACY  0x1001u

/* Request types (§5.2.6). */
#define VIRTIO_BLK_T_IN    0u   /* read: device → memory */
#define VIRTIO_BLK_T_OUT   1u   /* write: memory → device */

/* Status byte values. */
#define VIRTIO_BLK_S_OK    0u
#define VIRTIO_BLK_S_IOERR 1u

#define VBLK_SECTOR        512u
#define VBLK_BOUNCE_PAGES  8u                          /* 32 KiB max per chunk */
#define VBLK_MAX_SECTORS   (VBLK_BOUNCE_PAGES * 4096u / VBLK_SECTOR) /* 64 */
#define VBLK_POLL_BUDGET   100000000u

typedef struct __attribute__((packed)) {
    uint32_t type;
    uint32_t reserved;
    uint64_t sector;
} virtio_blk_req_hdr_t;

static virtio_dev_t s_blk_dev;
static virtq_t      s_blk_vq;
static blkdev_t     s_blk;

/* Header + status share one DMA page: header at offset 0, status at offset 16. */
static uintptr_t s_hdr_va;
static uint64_t  s_hdr_pa;

/* Bounce data pages (scattered <4GB pages). */
static uintptr_t s_data_va[VBLK_BOUNCE_PAGES];
static uint64_t  s_data_pa[VBLK_BOUNCE_PAGES];

static void
_memcpy(void *dst, const void *src, uint32_t n)
{
    uint8_t *d = dst;
    const uint8_t *s = src;
    while (n--)
        *d++ = *s++;
}

/* Submit one ≤VBLK_MAX_SECTORS request and wait for completion.
 * is_write: 0 = read (device fills bounce → nothing copied here),
 *           1 = write (caller already staged data into the bounce pages).
 * Returns 0 on success, -1 on error. Caller holds s_blk_vq.lock. */
static int
vblk_xfer_locked(uint64_t sector, uint32_t nsec, int is_write)
{
    uint32_t nbytes  = nsec * VBLK_SECTOR;
    uint32_t npages  = (nbytes + 4095u) / 4096u;
    if (npages == 0 || npages > VBLK_BOUNCE_PAGES)
        return -1;

    /* Build the chain: header (OUT) + data segments + status (IN). */
    virtio_blk_req_hdr_t *hdr = (virtio_blk_req_hdr_t *)s_hdr_va;
    hdr->type     = is_write ? VIRTIO_BLK_T_OUT : VIRTIO_BLK_T_IN;
    hdr->reserved = 0;
    hdr->sector   = sector;

    volatile uint8_t *status = (volatile uint8_t *)(s_hdr_va + 16);
    *status = 0xFFu;   /* device overwrites with 0/1/2 */

    virtq_buf_t segs[2 + VBLK_BOUNCE_PAGES];
    int n = 0;
    segs[n].phys = s_hdr_pa;            segs[n].len = 16;  segs[n].write = 0; n++;

    uint32_t remaining = nbytes;
    uint32_t pg;
    for (pg = 0; pg < npages; pg++) {
        uint32_t seg = remaining < 4096u ? remaining : 4096u;
        segs[n].phys  = s_data_pa[pg];
        segs[n].len   = seg;
        segs[n].write = is_write ? 0 : 1;   /* read → device writes data IN */
        n++;
        remaining -= seg;
    }
    segs[n].phys = s_hdr_pa + 16;       segs[n].len = 1;   segs[n].write = 1; n++;

    uint16_t head;
    if (virtq_publish_chain(&s_blk_vq, segs, n, &head) < 0)
        return -1;
    virtq_notify(&s_blk_vq);

    uint16_t cid = 0;
    uint32_t len = 0;
    int      done = 0;
    uint32_t budget;
    for (budget = 0; budget < VBLK_POLL_BUDGET; budget++) {
        if (virtq_poll_used(&s_blk_vq, &cid, &len)) {
            virtq_free_chain(&s_blk_vq, cid);
            done = 1;
            break;
        }
        arch_pause();
    }
    if (!done) {
        printk("[BLK] WARN: virtio-blk request timed out (sector=%u)\n",
               (uint32_t)sector);
        return -1;
    }
    if (*status != VIRTIO_BLK_S_OK)
        return -1;
    return 0;
}

static int
virtio_blk_read(blkdev_t *dev, uint64_t lba, uint32_t count, void *buf)
{
    (void)dev;
    if (count == 0)
        return 0;
    uint8_t *out = (uint8_t *)buf;

    while (count > 0) {
        uint32_t chunk = count < VBLK_MAX_SECTORS ? count : VBLK_MAX_SECTORS;

        irqflags_t fl = spin_lock_irqsave(&s_blk_vq.lock);
        int rc = vblk_xfer_locked(lba, chunk, 0);
        if (rc == 0) {
            /* Copy device-written bounce pages out to the caller buffer. */
            uint32_t nbytes = chunk * VBLK_SECTOR;
            uint32_t off = 0, pg = 0;
            while (off < nbytes) {
                uint32_t seg = (nbytes - off) < 4096u ? (nbytes - off) : 4096u;
                _memcpy(out + off, (void *)s_data_va[pg], seg);
                off += seg;
                pg++;
            }
        }
        spin_unlock_irqrestore(&s_blk_vq.lock, fl);
        if (rc < 0)
            return -1;

        out   += chunk * VBLK_SECTOR;
        lba   += chunk;
        count -= chunk;
    }
    return 0;
}

static int
virtio_blk_write(blkdev_t *dev, uint64_t lba, uint32_t count, const void *buf)
{
    (void)dev;
    if (count == 0)
        return 0;
    const uint8_t *in = (const uint8_t *)buf;

    while (count > 0) {
        uint32_t chunk = count < VBLK_MAX_SECTORS ? count : VBLK_MAX_SECTORS;

        irqflags_t fl = spin_lock_irqsave(&s_blk_vq.lock);
        /* Stage caller data into the bounce pages, then submit. */
        uint32_t nbytes = chunk * VBLK_SECTOR;
        uint32_t off = 0, pg = 0;
        while (off < nbytes) {
            uint32_t seg = (nbytes - off) < 4096u ? (nbytes - off) : 4096u;
            _memcpy((void *)s_data_va[pg], in + off, seg);
            off += seg;
            pg++;
        }
        int rc = vblk_xfer_locked(lba, chunk, 1);
        spin_unlock_irqrestore(&s_blk_vq.lock, fl);
        if (rc < 0)
            return -1;

        in    += chunk * VBLK_SECTOR;
        lba   += chunk;
        count -= chunk;
    }
    return 0;
}

void
virtio_blk_init(void)
{
    if (virtio_pci_find(VIRTIO_BLK_MODERN, VIRTIO_BLK_LEGACY, &s_blk_dev) < 0)
        return;  /* silent: no virtio-blk present */

    virtio_reset(&s_blk_dev);
    if (virtio_negotiate(&s_blk_dev, 0) < 0)
        return;
    if (virtio_setup_queue(&s_blk_dev, 0, &s_blk_vq) < 0) {
        s_blk_dev.common->device_status = VIRTIO_STATUS_FAILED;
        return;
    }

    /* Capacity in 512-byte sectors: device-config le64 at offset 0 (§5.2.4). */
    uint64_t capacity = 0;
    int i;
    for (i = 0; i < 8; i++)
        capacity |= (uint64_t)s_blk_dev.devcfg[i] << (8 * i);

    /* Allocate header/status page + the bounce data pages. */
    if (virtio_alloc_dma_page(&s_hdr_pa, &s_hdr_va) < 0) {
        s_blk_dev.common->device_status = VIRTIO_STATUS_FAILED;
        return;
    }
    uint32_t pg;
    for (pg = 0; pg < VBLK_BOUNCE_PAGES; pg++) {
        if (virtio_alloc_dma_page(&s_data_pa[pg], &s_data_va[pg]) < 0) {
            s_blk_dev.common->device_status = VIRTIO_STATUS_FAILED;
            return;
        }
    }

    virtio_driver_ok(&s_blk_dev);

    s_blk.name[0]='v'; s_blk.name[1]='b'; s_blk.name[2]='l';
    s_blk.name[3]='k'; s_blk.name[4]='0'; s_blk.name[5]='\0';
    s_blk.block_count = capacity;
    s_blk.block_size  = VBLK_SECTOR;
    s_blk.lba_offset  = 0;
    s_blk.read        = virtio_blk_read;
    s_blk.write       = virtio_blk_write;
    s_blk.priv        = &s_blk_dev;
    blkdev_register(&s_blk);

    printk("[BLK] OK: virtio-blk vblk0 %u sectors\n", (uint32_t)capacity);
}
