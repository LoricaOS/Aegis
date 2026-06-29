/* virtio_rng.c — virtio 1.0 entropy device, on the shared virtio core
 *
 * The entropy device (virtio device type 4) has a single request virtqueue. The
 * driver offers a device-writable buffer; the host fills it with random bytes.
 * We pull one bufferful at boot and mix it into the kernel CSPRNG — a real
 * hardware entropy source in a VM, on top of the RDTSC/timer-jitter seed.
 *
 * Synchronous poll-in-call: submit → notify → spin the used ring (bounded) →
 * consume. No interrupt, no background poll.
 *
 * References: VIRTIO v1.0 §5.4 Entropy Device.
 */
#include "virtio.h"
#include "arch.h"
#include "printk.h"
#include "random.h"
#include "spinlock.h"
#include <stdint.h>

#define VIRTIO_RNG_MODERN  0x1044u
#define VIRTIO_RNG_LEGACY  0x1005u

#define VIRTIO_RNG_REQ_LEN     64u       /* bytes requested per refill */
#define VIRTIO_RNG_POLL_BUDGET 2000000u  /* bounded completion spin */

static virtio_dev_t s_rng_dev;
static virtq_t      s_rng_vq;

void
virtio_rng_init(void)
{
    if (virtio_pci_find(VIRTIO_RNG_MODERN, VIRTIO_RNG_LEGACY, &s_rng_dev) < 0)
        return;  /* silent: no entropy device present */

    virtio_reset(&s_rng_dev);
    if (virtio_negotiate(&s_rng_dev, 0) < 0)   /* rng has no driver features */
        return;
    if (virtio_setup_queue(&s_rng_dev, 0, &s_rng_vq) < 0) {
        s_rng_dev.common->device_status = VIRTIO_STATUS_FAILED;
        return;
    }
    virtio_driver_ok(&s_rng_dev);

    uint64_t  pa;
    uintptr_t va;
    if (virtio_alloc_dma_page(&pa, &va) < 0)
        return;

    /* One device-writable (IN) segment. */
    virtq_buf_t seg = { pa, VIRTIO_RNG_REQ_LEN, 1 };
    uint16_t head;

    irqflags_t fl = spin_lock_irqsave(&s_rng_vq.lock);
    if (virtq_publish_chain(&s_rng_vq, &seg, 1, &head) < 0) {
        spin_unlock_irqrestore(&s_rng_vq.lock, fl);
        return;
    }
    virtq_notify(&s_rng_vq);

    uint16_t cid = 0;
    uint32_t got = 0;
    int      done = 0;
    uint32_t budget;
    for (budget = 0; budget < VIRTIO_RNG_POLL_BUDGET; budget++) {
        if (virtq_poll_used(&s_rng_vq, &cid, &got)) {
            virtq_free_chain(&s_rng_vq, cid);
            done = 1;
            break;
        }
        arch_pause();
    }
    spin_unlock_irqrestore(&s_rng_vq.lock, fl);

    if (done && got > 0) {
        if (got > VIRTIO_RNG_REQ_LEN)
            got = VIRTIO_RNG_REQ_LEN;
        random_add_entropy((const void *)va, got);
        printk("[RNG] OK: virtio-rng mixed %u bytes\n", got);
    }
}
