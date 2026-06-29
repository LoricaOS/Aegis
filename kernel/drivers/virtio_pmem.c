/* virtio_pmem.c — virtio 1.0 persistent memory, on the shared virtio core
 *
 * The host exposes a persistent-memory region at a guest-physical address; the
 * device config reports its start + size. Unlike block devices there is no data
 * queue — the region is directly byte-addressable. We map it and register a
 * blkdev ("pmem0") whose read/write are plain memcpy into the mapped region.
 * (The single virtqueue is only for FLUSH/persistence, which we set up but do
 * not require for volatile verification.)
 *
 * References: VIRTIO v1.1 §5.16 PMEM Device.
 */
#include "virtio.h"
#include "blkdev.h"
#include "vmm.h"
#include "kva.h"
#include "printk.h"
#include "spinlock.h"
#include "../lib/string.h"
#include <stdint.h>
#include <stddef.h>

#define VIRTIO_PMEM_MODERN  0x105Bu   /* virtio device type 27 */
#define PMEM_SECTOR  512u

static virtio_dev_t s_dev;
static virtq_t      s_reqq;
static uint8_t     *s_region;      /* KVA of the mapped pmem region */
static uint64_t     s_size;
static blkdev_t     s_blk;


/* Map n_pages of WB-cached RAM at guest-physical pa into KVA. */
static uint8_t *
map_ram(uint64_t pa, uint64_t n_pages)
{
    uintptr_t va = (uintptr_t)kva_alloc_pages(n_pages);
    if (!va)
        return NULL;
    for (uint64_t i=0;i<n_pages;i++){ uintptr_t p=va+i*4096;
        vmm_unmap_page(p);
        vmm_map_page(p, pa+i*4096, VMM_FLAG_PRESENT | VMM_FLAG_WRITABLE); }
    return (uint8_t *)va;
}

static int
pmem_read(blkdev_t *dev, uint64_t lba, uint32_t count, void *buf)
{
    (void)dev;
    if ((lba + count) * PMEM_SECTOR > s_size) return -1;
    kmemcpy(buf, s_region + lba * PMEM_SECTOR, (uint64_t)count * PMEM_SECTOR);
    return 0;
}

static int
pmem_write(blkdev_t *dev, uint64_t lba, uint32_t count, const void *buf)
{
    (void)dev;
    if ((lba + count) * PMEM_SECTOR > s_size) return -1;
    kmemcpy(s_region + lba * PMEM_SECTOR, buf, (uint64_t)count * PMEM_SECTOR);
    return 0;
}

void
virtio_pmem_init(void)
{
    if (virtio_pci_find(VIRTIO_PMEM_MODERN, 0, &s_dev) < 0)
        return;

    virtio_reset(&s_dev);
    if (virtio_negotiate(&s_dev, 0) < 0)
        return;
    if (virtio_setup_queue(&s_dev, 0, &s_reqq) < 0) {   /* FLUSH request queue */
        s_dev.common->device_status = VIRTIO_STATUS_FAILED;
        return;
    }
    virtio_driver_ok(&s_dev);

    /* config: start (le64) @ 0, size (le64) @ 8. */
    volatile uint8_t *c = s_dev.devcfg;
    uint64_t start = 0, size = 0;
    for (int i=0;i<8;i++) start |= (uint64_t)c[i] << (8*i);
    for (int i=0;i<8;i++) size  |= (uint64_t)c[8+i] << (8*i);
    if (size == 0)
        return;

    uint64_t pages = (size + 4095u) / 4096u;
    s_region = map_ram(start, pages);
    if (!s_region)
        return;
    s_size = size;

    /* Non-destructive read/modify/write self-test on the last sector. */
    uint64_t last = (size / PMEM_SECTOR) - 1u;
    uint8_t saved[PMEM_SECTOR], pat[PMEM_SECTOR], chk[PMEM_SECTOR];
    pmem_read(&s_blk, last, 1, saved);
    for (int i=0;i<(int)PMEM_SECTOR;i++) pat[i] = (uint8_t)(0xA5 ^ i);
    pmem_write(&s_blk, last, 1, pat);
    pmem_read(&s_blk, last, 1, chk);
    int ok = (kmemcmp(pat, chk, PMEM_SECTOR) == 0);
    pmem_write(&s_blk, last, 1, saved);   /* restore */

    s_blk.name[0]='p'; s_blk.name[1]='m'; s_blk.name[2]='e';
    s_blk.name[3]='m'; s_blk.name[4]='0'; s_blk.name[5]='\0';
    s_blk.block_count = size / PMEM_SECTOR;
    s_blk.block_size  = PMEM_SECTOR;
    s_blk.lba_offset  = 0;
    s_blk.read  = pmem_read;
    s_blk.write = pmem_write;
    s_blk.priv  = NULL;
    blkdev_register(&s_blk);

    printk("[PMEM] OK: virtio-pmem pmem0 %u MiB, write/read verify %s\n",
           (uint32_t)(size >> 20), ok ? "pass" : "FAIL");
}
