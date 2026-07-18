/* nvme.c — NVMe 1.4 controller driver (Phase 20)
 *
 * Init sequence:
 *   1. Find NVMe controller via pcie_find_device(0x01, 0x08, 0x02)
 *   2. Map BAR0 into kernel VA
 *   3. Disable controller (CC.EN=0), wait CSTS.RDY=0
 *   4. Allocate admin SQ+CQ (64 entries each, 1 page each)
 *   5. Set AQA/ASQ/ACQ, set CC.EN=1, wait CSTS.RDY=1
 *   6. Identify Controller (admin cmd 0x06, CNS=1)
 *   7. Identify Namespace (NSID=1, CNS=0)
 *   8. Create I/O CQ (admin cmd 0x05) + I/O SQ (admin cmd 0x01)
 *   9. Register blkdev_t "nvme0"
 *
 * All I/O: submit SQE -> ring doorbell -> poll CQE -> ring CQ head doorbell
 */
#include "nvme.h"
#include "arch.h"
#include "pcie.h"
#include "vmm.h"
#include "kva.h"
#include "pmm.h"
#include "blkdev.h"
#include "printk.h"
#include "spinlock.h"
#include <stdint.h>
#include <stddef.h>

/* -------------------------------------------------------------------------
 * Static state
 * ---------------------------------------------------------------------- */

/* SAFETY: s_bar0 is set once in nvme_init() to a kernel VA for NVMe BAR0
 * MMIO registers. Declared volatile so MMIO reads are not cached by the
 * compiler and register updates are always visible. */
static volatile nvme_regs_t *s_bar0     = NULL;
static uint32_t              s_dstrd    = 0;
static uint16_t              s_cid      = 0;

/* Admin queue */
static nvme_sqe_t           *s_asq      = NULL;
/* SAFETY: s_acq is volatile so CQE phase-tag polls are not optimised away. */
static volatile nvme_cqe_t  *s_acq      = NULL;
static uint32_t              s_asq_tail = 0;
static uint32_t              s_acq_head = 0;
static uint8_t               s_acq_phase = 1;

/* I/O queue (queue ID=1) */
static nvme_sqe_t           *s_iosq      = NULL;
/* SAFETY: s_iocq is volatile so CQE phase-tag polls are not optimised away. */
static volatile nvme_cqe_t  *s_iocq      = NULL;
static uint32_t              s_iosq_tail = 0;
static uint32_t              s_iocq_head = 0;
static uint8_t               s_iocq_phase = 1;

/* Multi-page bounce buffer for read/write I/O (VA-contiguous, physically
 * scattered <4GB pages, described to the controller via a PRP list).
 * Allocated once in nvme_init; reused for all synchronous I/O.  One command
 * now moves up to NVME_BOUNCE_PAGES pages instead of one 4KB round-trip per
 * page (a 128KB read used to be 32 fully-serialized submit+poll cycles).
 * Still synchronous QD1 — no concurrent I/O. */
#define NVME_BOUNCE_PAGES 32u             /* 128 KiB max per command */
static void    *s_iobuf      = NULL;      /* VA of page 0 (contiguous range) */
static uint64_t s_iobuf_phys = 0;         /* phys of page 0 → SQE PRP1 */
static uint64_t s_iobuf_page_phys[NVME_BOUNCE_PAGES];
static uint64_t *s_prplist   = NULL;      /* PRP list page: phys of pages 1..N-1 */
static uint64_t  s_prplist_phys = 0;
static uint32_t  s_max_xfer  = 4096u;     /* min(bounce bytes, MDTS); set in init */
static uint32_t  s_mdts_max  = 0xFFFFFFFFu; /* controller MDTS in bytes (identify) */
static spinlock_t nvme_lock = SPINLOCK_INIT;

/* Bus/DMA offset: the value added to a CPU-physical address to get the PCIe
 * bus address the controller must use to DMA to it. 0 on identity-mapped
 * hosts (x86, QEMU). On the native RPi5 Broadcom RC the inbound DMA window
 * maps PCIe bus 0x10_00000000 -> CPU 0x0, so every DMA target the controller
 * is handed must carry a +0x10_00000000 offset (set via nvme_set_dma_offset
 * before nvme_init). Applied at the two points where a CPU-phys becomes a
 * device-visible bus address (alloc_queue_page + iobuf_alloc); those phys
 * values are ONLY ever used as DMA addresses, never for CPU access. */
static uint64_t  s_dma_offset = 0;
void nvme_set_dma_offset(uint64_t off) { s_dma_offset = off; }

/* Non-coherent DMA: when set, all DMA buffers are allocated non-cacheable so
 * the controller (which does not snoop the CPU cache on this host) and the CPU
 * see each other's writes. 0 on coherent hosts (x86, QEMU). Set for the RPi5
 * Broadcom RC (no `dma-coherent` in its DTB) before nvme_init. */
static int s_dma_nc = 0;
void nvme_set_dma_noncoherent(int nc) { s_dma_nc = nc; }

/* Allocate a <4GB DMA buffer, non-cacheable when the host is non-coherent. */
static void *
nvme_dma_alloc(uint64_t n)
{
    return s_dma_nc ? kva_alloc_pages_low_nc(n) : kva_alloc_pages_low(n);
}

/* iobuf_alloc — (re)allocate the bounce page set and rewrite the PRP list.
 * Falls back to a single page (s_max_xfer = 4096) if the low pool cannot
 * supply the full set.  Returns -1 only if not even one page is available.
 * The PRP list page itself is allocated once and rewritten in place. */
static void *alloc_queue_page(uint64_t *phys_out);
static int
iobuf_alloc(void)
{
    uint32_t pages = NVME_BOUNCE_PAGES;
    uint8_t *va = (uint8_t *)nvme_dma_alloc(pages);
    if (va == NULL) {
        pages = 1u;
        va = (uint8_t *)nvme_dma_alloc(1);
        if (va == NULL)
            return -1;
    }
    if (pages > 1u && s_prplist == NULL) {
        s_prplist = (uint64_t *)alloc_queue_page(&s_prplist_phys);
        if (s_prplist == NULL)
            pages = 1u;               /* no PRP list page → single-page mode */
    }
    for (uint32_t i = 0; i < pages; i++)
        s_iobuf_page_phys[i] = kva_page_phys(va + (uint64_t)i * 4096u) + s_dma_offset;
    for (uint32_t i = 1; i < pages; i++)
        s_prplist[i - 1u] = s_iobuf_page_phys[i];
    s_iobuf      = va;
    s_iobuf_phys = s_iobuf_page_phys[0];
    uint32_t bounce_bytes = pages * 4096u;
    s_max_xfer = (bounce_bytes < s_mdts_max) ? bounce_bytes : s_mdts_max;
    return 0;
}

/* prp2_for — the SQE PRP2 value for a transfer of `bytes` starting at bounce
 * offset 0 (NVMe 1.4 §4.1.1): 0 for one page, the second page's address for
 * exactly two pages, else the PRP list. */
static uint64_t
prp2_for(uint32_t bytes)
{
    if (bytes <= 4096u)  return 0u;
    if (bytes <= 8192u)  return s_iobuf_page_phys[1];
    return s_prplist_phys;
}

/* -------------------------------------------------------------------------
 * Helpers
 * ---------------------------------------------------------------------- */

/* Doorbell register for queue qid, tail (is_head=0) or head (is_head=1).
 * Doorbell stride: bits [55:52] of CAP register gives log2 of stride in
 * 4-byte units (NVMe 1.4 spec section 3.1.8).
 * Doorbell offset = 0x1000 + (2*qid + is_head) * (4 << s_dstrd). */
static volatile uint32_t *
doorbell(uint32_t qid, int is_head)
{
    uint32_t off = 0x1000u +
                   (2u * qid + (uint32_t)is_head) * (4u << s_dstrd);
    /* SAFETY: s_bar0 is a valid kernel VA for NVMe BAR0 MMIO, set in
     * nvme_init(). The offset arithmetic follows NVMe 1.4 spec §3.1.8. */
    return (volatile uint32_t *)((uint8_t *)s_bar0 + off);
}

/* Allocate one 4KB page for NVMe DMA: use kva_alloc_pages_low (which allocates
 * a PMM frame guaranteed below 4GB and maps it into kernel VA), then retrieve
 * the physical address via kva_page_phys.  The page is already mapped and
 * accessible at the returned pointer; *phys_out receives the physical address
 * written into NVMe BAR registers (ASQ/ACQ) or SQE PRP fields.
 *
 * WHY low-pool: every page returned here is a DMA target — the controller
 * reads/writes it after we hand it the physical address (admin/IO queue pages,
 * identify buffers, the I/O bounce buffer).  We do not trust the device's
 * 64-bit addressing blindly, and NVMe is the boot/root disk: a physical
 * address >=4GB reaching the controller would silently corrupt the
 * filesystem.  kva_alloc_pages_low guarantees the backing frame is <4GB so
 * every DMA target stays in the device-safe window — a prerequisite for the
 * PMM handing out RAM above 4GB.
 *
 * Returns NULL on low-pool exhaustion; callers must check (NVMe init treats it
 * as fatal, matching the surrounding allocation-failure handling).
 *
 * NOTE: these pages are never freed (no kva_free_pages call).  At Phase 20
 * scale (admin+IO queue + identify buffer = 5 pages) this is negligible. */
static void *
alloc_queue_page(uint64_t *phys_out)
{
    void *va = nvme_dma_alloc(1);
    if (va == NULL)
        return NULL;
    /* SAFETY: kva_alloc_pages_low returns a kernel VA for a PMM-allocated,
     * mapped page; zeroing via __builtin_memset is safe here. */
    __builtin_memset(va, 0, 4096);
    *phys_out = kva_page_phys(va) + s_dma_offset;
    return va;
}

/* Quarantine the shared I/O bounce buffer after a failed completion.
 *
 * A timed-out (or CID-mismatched) command was never aborted at the
 * controller — it may still complete later and DMA into its data buffer at
 * an unpredictable time.  If we kept using the same bounce page, that late
 * DMA could land mid-way through a subsequent command's memcpy (silently
 * corrupting a read) or between a write's memcpy-in and the controller's
 * fetch (silently corrupting data written to disk).  Replace the page and
 * leak the old one: failures are rare (seconds-scale poll budget) and a
 * 4KB leak per event is bounded and harmless next to silent corruption.
 *
 * The replacement page comes from alloc_queue_page → kva_alloc_pages_low, so
 * it stays in the <4GB DMA-safe pool exactly like the original.
 *
 * Locking: called under nvme_lock (IF=0).  kva_alloc_pages_low takes only the
 * leaf kva/pmm locks, which are never held while nvme_lock is taken. */
static void
iobuf_quarantine(void)
{
    /* Reallocate the whole bounce set (and rewrite the PRP list in place);
     * the old pages are leaked exactly as before — bounded, rare, and
     * harmless next to silent corruption.  On low-pool exhaustion keep the
     * old set (same behavior as the old single-page path). */
    if (iobuf_alloc() == 0)
        printk("[NVME] WARN: bounce buffer quarantined after failed cmd\n");
}

/* Poll for a CQE whose phase tag matches *phase.  On success, advances the
 * head pointer, flips the phase on wrap, rings the CQ head doorbell, and
 * returns 0 if the status code is 0 (success) or -1 on error.
 * Returns -1 on timeout.
 * submitted_cid: the CID embedded in the SQE cdw0[31:16]; verified against
 * the CQE cid field to detect out-of-order or spurious completions. */
static int
poll_cqe(volatile nvme_cqe_t *cq, uint32_t cq_depth,
         uint32_t *cq_head, uint8_t *phase,
         volatile uint32_t *cq_head_db,
         uint32_t qid, uint16_t submitted_cid)
{
    volatile nvme_cqe_t *entry;
    /* Timeout budget: ~200M pause-paced iterations ≈ 1.5-3s of wall clock.
     * Real drives stall for tens of milliseconds on power-state wakes and
     * background GC — far beyond the old 1M tight-loop budget (~1-2ms),
     * which silently failed reads on bare metal (fonts/wallpaper unreadable
     * on installed boots, libauth cold-boot flake) while QEMU's instant
     * completions never exposed it.  The pause keeps per-iteration cost
     * predictable; the happy path still exits on the first poll. */
    uint32_t timeout = 200000000u;

    while (timeout--) {
        entry = &cq[*cq_head];
        /* SAFETY: entry points into a kva-mapped page; volatile ensures each
         * read goes to memory so the hardware-updated phase tag is visible. */
        if (((entry->status) & 1u) == *phase) {
            /* Verify completion belongs to our submission (NVMe 1.4 §4.6). */
            if (entry->cid != submitted_cid) {
                /* Wrong CID — advance head and phase, treat as error.
                 * (Typically a late completion of a previously timed-out
                 * command; consuming it re-syncs the queue.) */
                printk("[NVME] WARN: CQE cid %u != submitted %u (qid %u)\n",
                       (uint32_t)entry->cid, (uint32_t)submitted_cid, qid);
                (*cq_head)++;
                if (*cq_head >= cq_depth) {
                    *cq_head = 0;
                    *phase ^= 1u;
                }
                arch_wmb();
                *cq_head_db = *cq_head;
                return -1;
            }
            uint16_t sc = (uint16_t)((entry->status >> 1) & 0x7FFu);
            (*cq_head)++;
            if (*cq_head >= cq_depth) {
                *cq_head = 0;
                *phase ^= 1u;
            }
            /* sfence: ensure our head-pointer update is visible before
             * the doorbell write that tells the controller we consumed
             * this entry. */
            arch_wmb();
            *cq_head_db = *cq_head;
            if (sc != 0)
                printk("[NVME] WARN: cmd cid %u failed, sc=0x%x (qid %u)\n",
                       (uint32_t)submitted_cid, (uint32_t)sc, qid);
            return (sc == 0) ? 0 : -1;
        }
        /* pause: keeps the poll loop's per-iteration cost predictable
         * (~20-40 cycles) so the iteration budget maps to wall-clock time,
         * and is polite to the other hyperthread. */
        arch_pause();
    }
    printk("[NVME] WARN: I/O timeout waiting for cid %u (qid %u)\n",
           (uint32_t)submitted_cid, qid);
    return -1;   /* timeout */
}

/* -------------------------------------------------------------------------
 * Admin commands
 * ---------------------------------------------------------------------- */

/* Issue an Identify command.
 *   cns=1 : Identify Controller
 *   cns=0 : Identify Namespace (nsid must be 1) */
static int
nvme_identify(uint32_t nsid, uint8_t cns, void *buf, uint64_t buf_phys)
{
    nvme_sqe_t *sqe = &s_asq[s_asq_tail];
    uint16_t    cid = s_cid++;
    (void)buf;
    __builtin_memset(sqe, 0, sizeof(*sqe));
    sqe->cdw0  = NVME_ADMIN_IDENTIFY | ((uint32_t)cid << 16);
    sqe->nsid  = nsid;
    sqe->prp1  = buf_phys;
    sqe->prp2  = 0;
    sqe->cdw10 = cns;

    s_asq_tail++;
    if (s_asq_tail >= NVME_ADMIN_QUEUE_DEPTH)
        s_asq_tail = 0;

    /* sfence: SQE must be fully written before the doorbell write. */
    arch_wmb();
    *doorbell(0, 0) = s_asq_tail;   /* admin SQ tail doorbell */

    return poll_cqe(s_acq, NVME_ADMIN_QUEUE_DEPTH,
                    &s_acq_head, &s_acq_phase,
                    doorbell(0, 1), 0, cid);
}

/* Query the SMART/Health log (admin Get Log Page, LID 0x02, 512 bytes).
 * Uses a persistent DMA buffer allocated on first call. Serialized on the
 * same nvme_lock as I/O so it can't race the admin/IO queues on SMP. */
int
nvme_smart_info(nvme_smart_t *out)
{
    static uint8_t  *s_smart_buf  = NULL;   /* persistent DMA buffer (<4GB) */
    static uint64_t  s_smart_phys = 0;

    if (!s_bar0 || !out)
        return -1;

    irqflags_t fl = spin_lock_irqsave(&nvme_lock);

    if (s_smart_buf == NULL) {
        s_smart_buf = (uint8_t *)alloc_queue_page(&s_smart_phys);
        if (s_smart_buf == NULL) {
            spin_unlock_irqrestore(&nvme_lock, fl);
            return -1;
        }
    }

    nvme_sqe_t *sqe = &s_asq[s_asq_tail];
    uint16_t    cid = s_cid++;
    __builtin_memset(sqe, 0, sizeof(*sqe));
    sqe->cdw0  = NVME_ADMIN_GET_LOG_PAGE | ((uint32_t)cid << 16);
    sqe->nsid  = 0xFFFFFFFFu;                 /* whole-controller log */
    sqe->prp1  = s_smart_phys;
    /* cdw10: LID[7:0]=0x02, NUMDL[31:16]=127 (128 dwords = 512 bytes). */
    sqe->cdw10 = 0x02u | (127u << 16);

    s_asq_tail++;
    if (s_asq_tail >= NVME_ADMIN_QUEUE_DEPTH)
        s_asq_tail = 0;

    arch_wmb();
    *doorbell(0, 0) = s_asq_tail;

    int rc = poll_cqe(s_acq, NVME_ADMIN_QUEUE_DEPTH,
                      &s_acq_head, &s_acq_phase,
                      doorbell(0, 1), 0, cid);
    if (rc != 0) {
        spin_unlock_irqrestore(&nvme_lock, fl);
        return -1;
    }

    /* Parse the 512-byte SMART log (NVMe base spec, Figure for LID 02h). */
    const uint8_t *b = s_smart_buf;
    uint16_t temp_k = 0;
    __builtin_memcpy(&temp_k, b + 1, 2);
    out->critical_warning = b[0];
    out->temp_c           = (int)temp_k - 273;
    out->avail_spare      = b[3];
    out->spare_thresh     = b[4];
    out->pct_used         = b[5];
    __builtin_memcpy(&out->data_read_units,    b + 32,  8);
    __builtin_memcpy(&out->data_written_units, b + 48,  8);
    __builtin_memcpy(&out->power_cycles,       b + 112, 8);
    __builtin_memcpy(&out->power_on_hours,     b + 128, 8);
    __builtin_memcpy(&out->unsafe_shutdowns,   b + 144, 8);
    __builtin_memcpy(&out->media_errors,       b + 160, 8);

    spin_unlock_irqrestore(&nvme_lock, fl);
    return 0;
}

static int
nvme_create_io_cq(uint16_t qid, uint64_t cq_phys, uint16_t depth)
{
    nvme_sqe_t *sqe = &s_asq[s_asq_tail];
    uint16_t    cid = s_cid++;
    __builtin_memset(sqe, 0, sizeof(*sqe));
    sqe->cdw0  = NVME_ADMIN_CREATE_IO_CQ | ((uint32_t)cid << 16);
    sqe->prp1  = cq_phys;
    sqe->cdw10 = ((uint32_t)(depth - 1u) << 16) | qid;
    sqe->cdw11 = 1u;   /* physically contiguous */

    s_asq_tail++;
    if (s_asq_tail >= NVME_ADMIN_QUEUE_DEPTH)
        s_asq_tail = 0;

    arch_wmb();
    *doorbell(0, 0) = s_asq_tail;
    return poll_cqe(s_acq, NVME_ADMIN_QUEUE_DEPTH,
                    &s_acq_head, &s_acq_phase, doorbell(0, 1), 0, cid);
}

static int
nvme_create_io_sq(uint16_t qid, uint64_t sq_phys, uint16_t depth,
                  uint16_t cqid)
{
    nvme_sqe_t *sqe = &s_asq[s_asq_tail];
    uint16_t    cid = s_cid++;
    __builtin_memset(sqe, 0, sizeof(*sqe));
    sqe->cdw0  = NVME_ADMIN_CREATE_IO_SQ | ((uint32_t)cid << 16);
    sqe->prp1  = sq_phys;
    sqe->cdw10 = ((uint32_t)(depth - 1u) << 16) | qid;
    sqe->cdw11 = ((uint32_t)cqid << 16) | 1u;  /* cqid | physically contiguous */

    s_asq_tail++;
    if (s_asq_tail >= NVME_ADMIN_QUEUE_DEPTH)
        s_asq_tail = 0;

    arch_wmb();
    *doorbell(0, 0) = s_asq_tail;
    return poll_cqe(s_acq, NVME_ADMIN_QUEUE_DEPTH,
                    &s_acq_head, &s_acq_phase, doorbell(0, 1), 0, cid);
}

/* -------------------------------------------------------------------------
 * blkdev read/write callbacks — forward declarations
 * ---------------------------------------------------------------------- */
static int nvme_blkdev_read(struct blkdev *dev, uint64_t lba, uint32_t count,
                            void *buf);
static int nvme_blkdev_write(struct blkdev *dev, uint64_t lba, uint32_t count,
                             const void *buf);
static int nvme_read_one(struct blkdev *dev, uint64_t lba, uint32_t count,
                         void *buf);
static int nvme_write_one(struct blkdev *dev, uint64_t lba, uint32_t count,
                          const void *buf);

/* -------------------------------------------------------------------------
 * nvme_init
 * ---------------------------------------------------------------------- */

void
nvme_init(void)
{
    uint32_t i;
    uint32_t timeout;

    /* Step 1: Find NVMe controller via PCIe
     * class=0x01 (storage), subclass=0x08 (NVM), progif=0x02 (NVMe) */
    const pcie_device_t *dev = pcie_find_device(0x01, 0x08, 0x02);
    if (dev == NULL) {
        /* No NVMe controller present — silent return, no boot.txt line */
        return;
    }

    /* Step 2: Map BAR0 into kernel VA.
     * NVMe BAR0 is at minimum 16KB; map 4 pages (16KB) to be safe.
     * kva_alloc_pages allocates PMM frames and maps them — we then overwrite
     * those mappings to point at the actual MMIO physical address range with
     * no-cache flags (PWT+PCD). The PMM frames allocated by kva_alloc_pages
     * are leaked; at one NVMe controller this is an acceptable Phase 20 cost. */
    {
        uint64_t  bar0_phys  = dev->bar[0];
        uint32_t  bar0_pages = 4u;
        uintptr_t bar0_va    = (uintptr_t)kva_alloc_pages(bar0_pages);
        for (i = 0; i < bar0_pages; i++) {
            uintptr_t va = bar0_va + (uintptr_t)i * 4096u;
            /* kva_alloc_pages mapped each page to a PMM frame; unmap first
             * so vmm_map_page does not panic on a double-map.
             * SAFETY: va is a kva-allocated page that is present in the PT
             * (kva_alloc_pages guarantees this); vmm_unmap_page succeeds. */
            vmm_unmap_page(va);
            /* SAFETY: BAR0 is MMIO — map uncached via arch-neutral flags.
             * vmm_map_page installs the MMIO physical address at this VA;
             * the old PMM frame is leaked (see above). */
            vmm_map_page(va, bar0_phys + (uint64_t)i * 4096u,
                         VMM_FLAG_WRITABLE | VMM_FLAG_WC | VMM_FLAG_UCMINUS);
        }
        /* SAFETY: bar0_va is a kernel VA mapped to NVMe BAR0 MMIO registers;
         * volatile cast prevents the compiler caching register reads/writes. */
        s_bar0 = (volatile nvme_regs_t *)bar0_va;
    }

    /* Extract doorbell stride from CAP[55:52] */
    s_dstrd = (uint32_t)((s_bar0->cap >> 32) & 0xFu);

    /* Step 3: Disable controller — write CC.EN=0, wait CSTS.RDY=0 */
    s_bar0->cc = 0u;
    timeout = 500000u;
    while ((s_bar0->csts & NVME_CSTS_RDY) && timeout--)
        ;
    if (s_bar0->csts & NVME_CSTS_RDY) {
        printk("[NVME] FAIL: controller did not disable\n");
        return;
    }

    /* Step 4: Allocate admin SQ and CQ (1 page each = 64 entries) */
    {
        uint64_t asq_phys = 0, acq_phys = 0;  /* -O2 false positive: set by alloc_queue_page on success */
        s_asq = (nvme_sqe_t *)alloc_queue_page(&asq_phys);
        s_acq = (volatile nvme_cqe_t *)alloc_queue_page(&acq_phys);
        /* alloc_queue_page draws from the <4GB DMA-safe pool; NULL means it
         * is exhausted.  These pages are programmed into ASQ/ACQ and DMA'd by
         * the controller, so a high-memory substitute is not acceptable —
         * fail init the same way the rest of nvme_init bails on errors. */
        if (s_asq == NULL || s_acq == NULL) {
            printk("[NVME] FAIL: admin queue low-memory allocation failed\n");
            return;
        }
        s_asq_tail  = 0;
        s_acq_head  = 0;
        s_acq_phase = 1u;   /* initial expected phase tag */
        s_cid       = 0;

        /* Step 5: Program AQA, ASQ, ACQ then enable the controller */
        s_bar0->aqa = ((uint32_t)(NVME_ADMIN_QUEUE_DEPTH - 1u) << 16) |
                      (uint32_t)(NVME_ADMIN_QUEUE_DEPTH - 1u);
        s_bar0->asq = asq_phys;
        s_bar0->acq = acq_phys;
        s_bar0->cc  = NVME_CC_EN | NVME_CC_CSS_NVM | NVME_CC_MPS_4K |
                      NVME_CC_IOSQES | NVME_CC_IOCQES;
    }

    /* Wait for CSTS.RDY=1 */
    timeout = 500000u;
    while (!(s_bar0->csts & NVME_CSTS_RDY) && timeout--)
        ;
    if (!(s_bar0->csts & NVME_CSTS_RDY)) {
        printk("[NVME] FAIL: controller did not become ready\n");
        return;
    }

    /* Step 6: Identify Controller (CNS=1, NSID=0) */
    {
        uint64_t id_phys;
        uint8_t *id_buf = (uint8_t *)alloc_queue_page(&id_phys);
        /* id_buf is DMA'd by the controller (prp1), so it must be <4GB. */
        if (id_buf == NULL) {
            printk("[NVME] FAIL: identify buffer low-memory allocation failed\n");
            return;
        }
        if (nvme_identify(0u, 1u, id_buf, id_phys) != 0) {
            printk("[NVME] FAIL: Identify Controller failed\n");
            return;
        }
        /* Model name at bytes [24,63] — space-padded; not printed for now */

        /* MDTS (byte 77): max data transfer size as 2^MDTS units of the
         * minimum page size (CAP.MPSMIN, bits [51:48]; we run CC.MPS=4K).
         * 0 = no limit.  Clamp our per-command ceiling to it so a large
         * bounce transfer can never exceed what the controller accepts. */
        {
            uint8_t  mdts   = id_buf[77];
            uint32_t mps_min = 4096u << ((s_bar0->cap >> 48) & 0xFu);
            if (mdts != 0u && mdts < 15u)
                s_mdts_max = mps_min << mdts;
        }
    }

    /* Step 7: Identify Namespace NSID=1 (CNS=0) */
    {
        uint64_t  id_phys;
        uint8_t  *id_buf = (uint8_t *)alloc_queue_page(&id_phys);
        uint64_t  nsze;
        uint8_t   flbas;
        uint32_t  lbaf_entry;
        uint32_t  lbads;
        uint32_t  lba_size;

        /* id_buf is DMA'd by the controller (prp1), so it must be <4GB. */
        if (id_buf == NULL) {
            printk("[NVME] FAIL: identify buffer low-memory allocation failed\n");
            return;
        }
        if (nvme_identify(1u, 0u, id_buf, id_phys) != 0) {
            printk("[NVME] FAIL: Identify Namespace failed\n");
            return;
        }

        /* NSZE (offset 0): namespace size in logical blocks */
        __builtin_memcpy(&nsze, id_buf + 0, 8u);
        /* FLBAS (offset 26): lower 4 bits = active LBA format index */
        flbas = id_buf[26] & 0x0Fu;
        /* LBAF[flbas] (offset 128 + flbas*4): bits[23:16] = log2(LBA size) */
        __builtin_memcpy(&lbaf_entry, id_buf + 128u + (uint32_t)flbas * 4u, 4u);
        lbads = (lbaf_entry >> 16) & 0xFFu;
        lba_size = (lbads >= 9u) ? (1u << lbads) : 512u;

        /* Step 8: Create I/O CQ (queue ID=1) then I/O SQ (queue ID=1) */
        {
            uint64_t iosq_phys = 0, iocq_phys = 0;  /* -O2 false positive: set by alloc_queue_page on success */
            s_iosq = (nvme_sqe_t *)alloc_queue_page(&iosq_phys);
            s_iocq = (volatile nvme_cqe_t *)alloc_queue_page(&iocq_phys);
            /* I/O queue pages are programmed into the controller (prp1 of
             * Create I/O SQ/CQ) and DMA'd, so they must be <4GB. */
            if (s_iosq == NULL || s_iocq == NULL) {
                printk("[NVME] FAIL: I/O queue low-memory allocation failed\n");
                return;
            }
            s_iosq_tail  = 0;
            s_iocq_head  = 0;
            s_iocq_phase = 1u;

            if (nvme_create_io_cq(1u, iocq_phys,
                                  (uint16_t)NVME_IO_QUEUE_DEPTH) != 0) {
                printk("[NVME] FAIL: Create I/O CQ failed\n");
                return;
            }
            if (nvme_create_io_sq(1u, iosq_phys,
                                  (uint16_t)NVME_IO_QUEUE_DEPTH, 1u) != 0) {
                printk("[NVME] FAIL: Create I/O SQ failed\n");
                return;
            }
        }

        /* Allocate the multi-page bounce buffer + PRP list for synchronous
         * read/write I/O.  Every page is DMA'd by the controller, so it all
         * comes from the <4GB pool (kva_alloc_pages_low / alloc_queue_page). */
        if (iobuf_alloc() != 0) {
            printk("[NVME] FAIL: bounce buffer low-memory allocation failed\n");
            return;
        }

        /* Step 9: Register blkdev */
        {
            static blkdev_t s_nvme0;
            static const char s_nvme0_name[] = "nvme0";
            __builtin_memcpy(s_nvme0.name, s_nvme0_name,
                             sizeof(s_nvme0_name));
            s_nvme0.block_count = nsze;
            s_nvme0.block_size  = lba_size;
            s_nvme0.lba_offset  = 0;
            s_nvme0.read        = nvme_blkdev_read;
            s_nvme0.write       = nvme_blkdev_write;
            s_nvme0.priv        = NULL;
            blkdev_register(&s_nvme0);
        }

        printk("[NVME] OK: nvme0 %lu sectors x %u bytes\n",
               (unsigned long)nsze, (unsigned)lba_size);
    }
}

/* -------------------------------------------------------------------------
 * blkdev read/write callbacks
 * ---------------------------------------------------------------------- */

/* nvme_io_validate — vet a read/write request before it can build a malformed
 * SQE.  Returns the transfer length in bytes via *bytes_out, or -1 if the
 * request must be rejected.  Shared by the read and write paths so the two
 * cannot drift.
 *
 * Three distinct hazards, all reachable from on-disk metadata or a buggy
 * caller, all of which would otherwise reach the controller as a malformed
 * command against the single shared 4KB bounce buffer:
 *
 *   1. count == 0.  The SQE encodes NLB as a 0-based count (cdw12 = count-1).
 *      A zero count underflows to 0xFFFFFFFF, whose low 16 bits (the NLB
 *      field) are 0xFFFF — a 65536-block transfer — DMA'd into a 4KB page.
 *      Reject up front; a zero-length block I/O is meaningless anyway.
 *
 *   2. bytes overflow.  bytes = count * block_size is uint32 arithmetic.
 *      The old `bytes > 4096` page guard is defeated when the product wraps
 *      (e.g. count = 0x800000, block_size = 512 → 0), letting a huge NLB
 *      through.  Compute the length in 64-bit and bound it to one page; this
 *      also makes the NLB field provably ≤ 8, so the 16-bit field can never
 *      overflow (the original audit concern).
 *
 *   3. lba + count out of device range / 64-bit wrap.  The whole-disk nvme0
 *      device has no upstream range check (only the GPT partition shim does).
 *      A bad LBA from corrupted ext2 metadata would issue an out-of-range
 *      read at an attacker-influenced offset.  Reject lba+count past the
 *      namespace size, computed in 64-bit so the addition itself can't wrap.
 *
 * On success the request fits one page (bytes ≤ 4096), NLB = count-1 ≤ 7,
 * and the LBA range lies wholly within the namespace. */
static int
nvme_io_validate(const struct blkdev *dev, uint64_t lba, uint32_t count,
                 uint32_t *bytes_out)
{
    if (count == 0u)
        return -1;                       /* hazard 1: NLB underflow */

    /* hazard 2: 64-bit length, bounded to the bounce buffer / MDTS.
     * s_max_xfer ≤ 128 KiB, so with 512-byte blocks count ≤ 256 and the
     * 16-bit NLB field (count-1 ≤ 255) still can never overflow. */
    uint64_t bytes64 = (uint64_t)count * (uint64_t)dev->block_size;
    if (bytes64 == 0u || bytes64 > (uint64_t)s_max_xfer)
        return -1;                       /* too large / overflow rejected */

    /* hazard 3: range check in 64-bit (lba + count cannot wrap a uint64
     * for any count that survived the page bound above, but compute defensively
     * and also guard block_count == 0). */
    if (dev->block_count == 0u ||
        lba >= dev->block_count ||
        count > dev->block_count - lba)
        return -1;                       /* out of namespace range */

    *bytes_out = (uint32_t)bytes64;
    return 0;
}

/* nvme_read_one — read up to s_max_xfer bytes (one PRP-list command) from LBA
 * into buf.  Uses the shared multi-page bounce buffer allocated in nvme_init().
 * Callers exceeding s_max_xfer go through nvme_blkdev_read, which splits. */
static int
nvme_read_one(struct blkdev *dev, uint64_t lba, uint32_t count, void *buf)
{
    uint32_t   bytes;
    void      *tmp;
    nvme_sqe_t *sqe;
    int         rc;

    if (nvme_io_validate(dev, lba, count, &bytes) != 0)
        return -1;   /* zero/overflow/out-of-range — see nvme_io_validate */

    irqflags_t fl = spin_lock_irqsave(&nvme_lock);

    /* Bounce buffer: shared single page allocated in nvme_init() */
    tmp = s_iobuf;
    uint64_t buf_phys = s_iobuf_phys;

    {
    uint16_t cid = s_cid++;
    sqe = &s_iosq[s_iosq_tail];
    __builtin_memset(sqe, 0, sizeof(*sqe));
    sqe->cdw0  = NVME_IO_READ | ((uint32_t)cid << 16);
    sqe->nsid  = 1u;
    sqe->prp1  = buf_phys;
    sqe->prp2  = prp2_for(bytes);
    sqe->cdw10 = (uint32_t)(lba & 0xFFFFFFFFu);
    sqe->cdw11 = (uint32_t)(lba >> 32);
    sqe->cdw12 = count - 1u;   /* NLB: 0-based count */

    s_iosq_tail++;
    if (s_iosq_tail >= NVME_IO_QUEUE_DEPTH)
        s_iosq_tail = 0;

    /* sfence: SQE must be fully written to memory before doorbell write. */
    arch_wmb();
    *doorbell(1u, 0) = s_iosq_tail;

    rc = poll_cqe(s_iocq, NVME_IO_QUEUE_DEPTH,
                  &s_iocq_head, &s_iocq_phase,
                  doorbell(1u, 1), 1u, cid);
    }
    if (rc == 0)
        __builtin_memcpy(buf, tmp, bytes);
    else
        iobuf_quarantine();   /* late DMA may still target this page */
    spin_unlock_irqrestore(&nvme_lock, fl);
    return rc;
}

/* nvme_blkdev_read — read `count` native LBAs from LBA into buf, splitting into
 * per-command chunks of at most s_max_xfer bytes.  Callers (sys_disk's
 * whole-disk copy, ext2's contiguous run reads) issue up to 64 KiB at once;
 * on a controller whose MDTS clamps s_max_xfer below that, a single command
 * would be rejected — so the driver, which alone knows the limit, chunks here
 * rather than making every caller track MDTS. */
static int
nvme_blkdev_read(struct blkdev *dev, uint64_t lba, uint32_t count, void *buf)
{
    uint32_t bs = dev->block_size ? dev->block_size : 512u;
    uint32_t max_lbas = s_max_xfer / bs;
    if (max_lbas == 0u) max_lbas = 1u;
    for (uint32_t done = 0; done < count; ) {
        uint32_t n = count - done;
        if (n > max_lbas) n = max_lbas;
        int rc = nvme_read_one(dev, lba + done,
                               n, (uint8_t *)buf + (uint64_t)done * bs);
        if (rc != 0) return rc;
        done += n;
    }
    return 0;
}

/* nvme_flush — issue an NVMe FLUSH (opcode 0x00) so the drive commits its
 * volatile write cache to non-volatile media.  The raw installer copy and
 * ext2 write-back both end at "the controller ACKed the write" — on real
 * drives that means volatile cache, which a reboot-time controller reset
 * is not guaranteed to preserve.  QEMU never loses it (host page cache),
 * so only bare metal sees the difference.  No-op when no NVMe is present. */
void
nvme_flush(void)
{
    nvme_sqe_t *sqe;

    if (s_iosq == NULL)
        return;

    irqflags_t fl = spin_lock_irqsave(&nvme_lock);
    uint16_t cid = s_cid++;
    sqe = &s_iosq[s_iosq_tail];
    __builtin_memset(sqe, 0, sizeof(*sqe));
    sqe->cdw0 = NVME_IO_FLUSH | ((uint32_t)cid << 16);
    sqe->nsid = 1u;

    s_iosq_tail++;
    if (s_iosq_tail >= NVME_IO_QUEUE_DEPTH)
        s_iosq_tail = 0;

    /* sfence: SQE must be fully written to memory before doorbell write. */
    arch_wmb();
    *doorbell(1u, 0) = s_iosq_tail;

    if (poll_cqe(s_iocq, NVME_IO_QUEUE_DEPTH,
                 &s_iocq_head, &s_iocq_phase,
                 doorbell(1u, 1), 1u, cid) != 0)
        printk("[NVME] WARN: flush failed\n");
    spin_unlock_irqrestore(&nvme_lock, fl);
}

/* nvme_write_one — write up to s_max_xfer bytes (one PRP-list command) from buf
 * to LBA.  Uses the shared multi-page bounce buffer allocated in nvme_init().
 * Callers exceeding s_max_xfer go through nvme_blkdev_write, which splits. */
static int
nvme_write_one(struct blkdev *dev, uint64_t lba, uint32_t count,
               const void *buf)
{
    uint32_t   bytes;
    void      *tmp;
    nvme_sqe_t *sqe;

    if (nvme_io_validate(dev, lba, count, &bytes) != 0)
        return -1;   /* zero/overflow/out-of-range — see nvme_io_validate */

    irqflags_t fl = spin_lock_irqsave(&nvme_lock);

    /* Bounce buffer: shared single page allocated in nvme_init() */
    tmp = s_iobuf;
    uint64_t buf_phys = s_iobuf_phys;
    __builtin_memcpy(tmp, buf, bytes);

    {
    uint16_t cid = s_cid++;
    sqe = &s_iosq[s_iosq_tail];
    __builtin_memset(sqe, 0, sizeof(*sqe));
    sqe->cdw0  = NVME_IO_WRITE | ((uint32_t)cid << 16);
    sqe->nsid  = 1u;
    sqe->prp1  = buf_phys;
    sqe->prp2  = prp2_for(bytes);
    sqe->cdw10 = (uint32_t)(lba & 0xFFFFFFFFu);
    sqe->cdw11 = (uint32_t)(lba >> 32);
    sqe->cdw12 = count - 1u;   /* NLB: 0-based count */

    s_iosq_tail++;
    if (s_iosq_tail >= NVME_IO_QUEUE_DEPTH)
        s_iosq_tail = 0;

    /* sfence: SQE must be fully written to memory before doorbell write. */
    arch_wmb();
    *doorbell(1u, 0) = s_iosq_tail;

    int rc = poll_cqe(s_iocq, NVME_IO_QUEUE_DEPTH,
                    &s_iocq_head, &s_iocq_phase,
                    doorbell(1u, 1), 1u, cid);
    if (rc != 0)
        iobuf_quarantine();   /* late DMA may still source this page */
    spin_unlock_irqrestore(&nvme_lock, fl);
    return rc;
    }
}

/* nvme_blkdev_write — write `count` native LBAs from buf to LBA, splitting into
 * per-command chunks of at most s_max_xfer bytes (see nvme_blkdev_read). */
static int
nvme_blkdev_write(struct blkdev *dev, uint64_t lba, uint32_t count,
                  const void *buf)
{
    uint32_t bs = dev->block_size ? dev->block_size : 512u;
    uint32_t max_lbas = s_max_xfer / bs;
    if (max_lbas == 0u) max_lbas = 1u;
    for (uint32_t done = 0; done < count; ) {
        uint32_t n = count - done;
        if (n > max_lbas) n = max_lbas;
        int rc = nvme_write_one(dev, lba + done,
                                n, (const uint8_t *)buf + (uint64_t)done * bs);
        if (rc != 0) return rc;
        done += n;
    }
    return 0;
}
