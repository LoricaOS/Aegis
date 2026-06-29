/* virtqueue.c — chain-capable virtqueue submit/poll for the virtio core
 *
 * A small, general descriptor/ring API used by virtio_blk and virtio_rng.
 * virtio_net keeps its own RX/TX ring logic (tuned + test-gated) and only
 * borrows virtq_notify() from here; everything else below is for the
 * submit-a-chain / poll-a-completion drivers.
 *
 * Concurrency: the caller serialises access to a virtq via vq->lock. These
 * functions do not lock themselves — blk takes vq->lock around a whole
 * submit→kick→poll transaction; rng runs single-threaded at boot.
 *
 * Ordering: virtio spec §2.7.13 — the avail ring-slot store and descriptor
 * writes must be globally visible to the device BEFORE the avail->idx publish,
 * and idx before the notify MMIO. These are DMA-shared (WC/uncached) writes, so
 * a compiler barrier is insufficient: arch_wmb() (sfence) is used at each step.
 */
#include "virtio.h"
#include "arch.h"

/* Queue size is always a power of two (virtio spec §2.6), so &(size-1) is a
 * valid modulo for ring indexing. */
#define VQ_MASK(vq) ((uint16_t)((vq)->size - 1u))

int
virtq_alloc_desc(virtq_t *vq)
{
    if (vq->nfree == 0)
        return -1;
    return (int)vq->free[--vq->nfree];
}

/* Publish a single already-allocated descriptor (no chain) to the avail ring. */
void
virtq_publish_single(virtq_t *vq, uint16_t id,
                     uint64_t pa, uint32_t len, int write)
{
    vq->desc[id].addr  = pa;
    vq->desc[id].len   = len;
    vq->desc[id].flags = write ? VIRTQ_DESC_F_WRITE : 0u;
    vq->desc[id].next  = 0;

    uint16_t ai = vq->avail->idx;
    vq->avail->ring[ai & VQ_MASK(vq)] = id;
    arch_wmb();                       /* ring slot + descriptor before idx */
    vq->avail->idx = (uint16_t)(ai + 1u);
}

int
virtq_publish_chain(virtq_t *vq, const virtq_buf_t *segs, int n, uint16_t *head)
{
    if (n <= 0 || (uint16_t)n > vq->nfree)
        return -1;

    /* Pop n descriptors and link them. The device reads OUT (write==0) segments
     * and writes IN (write==1) segments; per the spec all OUT descriptors of a
     * chain precede all IN descriptors, which the callers honour. */
    uint16_t ids[VIRTQ_SIZE];
    int k;
    for (k = 0; k < n; k++)
        ids[k] = vq->free[--vq->nfree];

    for (k = 0; k < n; k++) {
        vq->desc[ids[k]].addr  = segs[k].phys;
        vq->desc[ids[k]].len   = segs[k].len;
        uint16_t fl = segs[k].write ? VIRTQ_DESC_F_WRITE : 0u;
        if (k < n - 1) {
            fl |= VIRTQ_DESC_F_NEXT;
            vq->desc[ids[k]].next = ids[k + 1];
        } else {
            vq->desc[ids[k]].next = 0;
        }
        vq->desc[ids[k]].flags = fl;
    }

    uint16_t ai = vq->avail->idx;
    vq->avail->ring[ai & VQ_MASK(vq)] = ids[0];
    arch_wmb();                       /* chain + ring slot before idx */
    vq->avail->idx = (uint16_t)(ai + 1u);

    *head = ids[0];
    return 0;
}

void
virtq_notify(virtq_t *vq)
{
    arch_wmb();                       /* idx visible before the notify MMIO */
    vq->dev->notify_base[vq->notify_off * vq->dev->notify_off_mult / 4u] =
        vq->index;
}

int
virtq_poll_used(virtq_t *vq, uint16_t *id, uint32_t *len)
{
    if (vq->last_used == vq->used->idx)
        return 0;
    /* Acquire: read used->idx before the element it indexes. x86 does not
     * reorder loads, so a compiler barrier is the correct read-side fence. */
    __asm__ volatile("" ::: "memory");
    uint16_t slot = (uint16_t)(vq->last_used & VQ_MASK(vq));
    *id  = (uint16_t)vq->used->ring[slot].id;
    *len = vq->used->ring[slot].len;
    vq->last_used++;
    return 1;
}

void
virtq_free_chain(virtq_t *vq, uint16_t head)
{
    uint16_t cur = head;
    /* Walk the NEXT chain, returning each descriptor to the free stack. Bound
     * the walk by the queue size: the used ring is device-writable shared
     * memory, so never trust a chain to terminate. */
    uint16_t guard;
    for (guard = 0; guard < vq->size; guard++) {
        uint16_t next     = vq->desc[cur].next;
        uint16_t has_next = (uint16_t)(vq->desc[cur].flags & VIRTQ_DESC_F_NEXT);
        if (cur < vq->size && vq->nfree < vq->size)
            vq->free[vq->nfree++] = cur;
        if (!has_next)
            break;
        cur = next;
    }
}
