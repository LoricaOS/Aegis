/* virtio_balloon.c — virtio 1.0 memory balloon, on the shared virtio core
 *
 * The host sets a target balloon size (config.num_pages); the guest "inflates"
 * by handing pages back (posting their PFNs on the inflate queue) so the host
 * can reclaim them, or "deflates" to take pages back. Enables memory overcommit
 * for cloud/VM hosts.
 *
 * Driven from the 100 Hz PIT poll (no interrupts): each tick moves at most one
 * batch (256 pages) toward the target, so it ramps without stalling the timer.
 * Pages handed out are tracked so deflate returns the same ones.
 *
 * References: VIRTIO v1.0 §5.5 Memory Balloon Device.
 */
#include "virtio.h"
#include "arch.h"
#include "pmm.h"
#include "printk.h"
#include "spinlock.h"
#include <stdint.h>

#define VIRTIO_BALLOON_MODERN  0x1045u
#define VIRTIO_BALLOON_LEGACY  0x1002u

#define BALLOON_PFN_SHIFT      12u
#define BALLOON_BATCH          256u                 /* pages per request */
#define BALLOON_MAX_PAGES      16384u               /* cap: 64 MiB tracked */
#define BALLOON_POLL_BUDGET    2000000u

static virtio_dev_t s_dev;
static virtq_t      s_inflateq, s_deflateq;
static int          s_active;

static uintptr_t s_pfn_va;       /* le32 PFN array buffer (one page) */
static uint64_t  s_pfn_pa;
static uint64_t  s_given[BALLOON_MAX_PAGES];   /* phys we've handed to the host */
static uint32_t  s_actual;       /* pages currently inflated */
static uint32_t  s_capped;       /* logged the cap-hit once */

static inline uint32_t cfg_num_pages(void) { return *(volatile uint32_t *)(s_dev.devcfg + 0); }
static inline void     cfg_set_actual(uint32_t a) { *(volatile uint32_t *)(s_dev.devcfg + 4) = a; }

/* Post the s_pfn buffer (n PFNs) on the given queue and wait for completion. */
static int
balloon_submit(virtq_t *vq, uint32_t n)
{
    virtq_buf_t seg = { s_pfn_pa, n * 4u, 0 };   /* device reads the PFN list */
    uint16_t head;
    if (virtq_publish_chain(vq, &seg, 1, &head) < 0)
        return -1;
    virtq_notify(vq);
    uint16_t cid; uint32_t len;
    for (uint32_t b = 0; b < BALLOON_POLL_BUDGET; b++) {
        if (virtq_poll_used(vq, &cid, &len)) {
            virtq_free_chain(vq, cid);
            return 0;
        }
        arch_pause();
    }
    return -1;
}

void
virtio_balloon_poll(void)
{
    if (!s_active)
        return;

    uint32_t target = cfg_num_pages();
    if (target > BALLOON_MAX_PAGES) {
        if (!s_capped) {
            printk("[BALLOON] WARN: target %u pages exceeds cap %u\n",
                   target, (unsigned)BALLOON_MAX_PAGES);
            s_capped = 1;
        }
        target = BALLOON_MAX_PAGES;
    }

    if (target > s_actual) {
        /* Inflate one batch: allocate pages, hand their PFNs to the host. */
        uint32_t want = target - s_actual;
        if (want > BALLOON_BATCH) want = BALLOON_BATCH;
        volatile uint32_t *pfns = (volatile uint32_t *)s_pfn_va;
        uint32_t got = 0;
        for (uint32_t i = 0; i < want; i++) {
            uint64_t pa = pmm_alloc_page();
            if (pa == 0) break;
            s_given[s_actual + got] = pa;
            pfns[got] = (uint32_t)(pa >> BALLOON_PFN_SHIFT);
            got++;
        }
        if (got > 0 && balloon_submit(&s_inflateq, got) == 0) {
            s_actual += got;
            cfg_set_actual(s_actual);
            printk("[BALLOON] inflated to %u pages\n", s_actual);
        } else {
            /* Submit failed — return any pages we grabbed. */
            for (uint32_t i = 0; i < got; i++)
                pmm_free_page(s_given[s_actual + i]);
        }
    } else if (target < s_actual) {
        /* Deflate one batch: hand PFNs back and reclaim the pages. */
        uint32_t give = s_actual - target;
        if (give > BALLOON_BATCH) give = BALLOON_BATCH;
        volatile uint32_t *pfns = (volatile uint32_t *)s_pfn_va;
        for (uint32_t i = 0; i < give; i++)
            pfns[i] = (uint32_t)(s_given[s_actual - 1u - i] >> BALLOON_PFN_SHIFT);
        if (balloon_submit(&s_deflateq, give) == 0) {
            for (uint32_t i = 0; i < give; i++)
                pmm_free_page(s_given[s_actual - 1u - i]);
            s_actual -= give;
            cfg_set_actual(s_actual);
            printk("[BALLOON] deflated to %u pages\n", s_actual);
        }
    }
}

void
virtio_balloon_init(void)
{
    if (virtio_pci_find(VIRTIO_BALLOON_MODERN, VIRTIO_BALLOON_LEGACY, &s_dev) < 0)
        return;

    virtio_reset(&s_dev);
    if (virtio_negotiate(&s_dev, 0) < 0)   /* no stats/free-page-hint features */
        return;
    if (virtio_setup_queue(&s_dev, 0, &s_inflateq) < 0 ||
        virtio_setup_queue(&s_dev, 1, &s_deflateq) < 0) {
        s_dev.common->device_status = VIRTIO_STATUS_FAILED;
        return;
    }
    virtio_driver_ok(&s_dev);

    if (virtio_alloc_dma_page(&s_pfn_pa, &s_pfn_va) < 0)
        return;
    s_actual = 0;
    s_active = 1;
    printk("[BALLOON] OK: virtio-balloon ready\n");
}
