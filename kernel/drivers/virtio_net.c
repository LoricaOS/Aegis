/* virtio_net.c — virtio 1.0 modern network device, on the shared virtio core
 *
 * The PCI transport (cap walk, BAR map, status handshake, queue allocation, the
 * <4GB DMA allocator) lives in virtio_pci.c / virtqueue.c (virtio.h). This file
 * keeps only the net-specific logic, with its hard-won behaviour intact:
 *   - RX: pre-fill every descriptor with a 1-page buffer; on completion copy the
 *     frame out and RECYCLE the descriptor BEFORE delivering (delivery may TX a
 *     reply synchronously — recycling first stops a single inbound packet being
 *     reprocessed into a reply storm).
 *   - TX: asynchronous submit with lazy completion reaping; bounded spin-reap
 *     backpressure when the ring is momentarily full; a drop is never silent.
 *   - Always ring the RX doorbell each poll (forces a VM-exit so QEMU's SLIRP
 *     backend can inject pending RX frames under TCG).
 *
 * Queue 0 = RX (device writes frames in), Queue 1 = TX (driver writes frames out).
 */
#include "virtio_net.h"
#include "netdev.h"
#include "pcie.h"
#include "kva.h"
#include "vmm.h"
#include "acpi.h"   /* g_bsp_apic_id — MSI-X message destination */
#include "arch.h"
#include "printk.h"
#include "spinlock.h"
#include <stdint.h>
#include <stddef.h>

/* Capacity advertised to the device for each 1-page RX buffer. A used->len
 * exceeding this is a misbehaving backend; the frame is dropped to prevent an
 * OOB read past the page. */
#define VIRTIO_RX_BUF_LEN     1536u
/* Bounded spin-reap budget used ONLY when the TX ring is momentarily full. */
#define VIRTIO_TX_REAP_SPINS  4096u

/* Frame copy/clear helpers. These run on every RX/TX frame, so use the compiler
 * intrinsics: the kernel is built -ffreestanding, which suppresses automatic
 * loop->memcpy conversion, so a hand-written byte loop here would stay scalar
 * (~115x slower than __builtin_memcpy on a ~1.5 KB frame — measured). */
static inline void
_memset(void *dst, int val, uint32_t n)
{
    __builtin_memset(dst, val, n);
}

static inline void
_memcpy(void *dst, const void *src, uint32_t n)
{
    __builtin_memcpy(dst, src, n);
}

/* ── Per-device private state ──────────────────────────────────────────────
 * The descriptor free-stack, ring pointers and last_used cursors all live in
 * the shared virtq_t now. rx_virt/rx_phys and tx_virt/tx_phys map a descriptor
 * SLOT (0..size-1) to its permanently-associated DMA buffer. */
typedef struct {
    virtio_dev_t dev;
    virtq_t      rx;       /* queue 0 */
    virtq_t      tx;       /* queue 1 */
    void        *rx_virt[VIRTQ_SIZE];
    uint64_t     rx_phys[VIRTQ_SIZE];
    uint8_t     *tx_virt[VIRTQ_SIZE];
    uint64_t     tx_phys[VIRTQ_SIZE];
    uint32_t     tx_drops;
    int          msix_ok;          /* 1 if MSI-X RX interrupt is active */
} virtio_net_priv_t;

static virtio_net_priv_t s_priv;
static netdev_t          s_dev;

static int  virtio_net_send(netdev_t *dev, const void *pkt, uint16_t len);
static void virtio_net_poll(netdev_t *dev);

/* ── MSI-X interrupt-driven RX (x86-64) ────────────────────────────────────
 * The 100 Hz PIT poll caps effective RTT at ~10 ms, which throttles a
 * window-limited TCP flow to window/10ms. Wiring the NIC's RX queue to an MSI-X
 * vector lets us service frames — and emit ACKs — the instant they arrive.
 *
 * MSI-X is message-signalled: the device performs a memory write to the LAPIC
 * (0xFEE00000 | apic_id<<12, data = vector) rather than asserting an INTx pin,
 * so no IOAPIC/_PRT routing is needed. We route to the BSP, where the PIT poll
 * also runs (IF=0): the IRQ handler and poll never overlap, so the existing
 * lock-free RX-drain invariant holds. The poll stays registered as a backstop.
 *
 * VIRTIO_NET_RX_VECTOR must match the idt.c dispatch + isr.asm stub (0x40). */
#if defined(__x86_64__)

#define VIRTIO_NET_RX_VECTOR   0x40u
#define VIRTIO_MSI_NO_VECTOR   0xFFFFu   /* §4.1.5.1.2 "no vector configured" */

/* PCI MSI-X capability (cap id 0x11) register layout (PCIe spec §7.7.2):
 *   +0  cap_id (0x11) | cap_next      (low 16 bits of the +0 dword)
 *   +2  Message Control              (high 16 bits of the +0 dword)
 *         bit 15 = MSI-X Enable, bit 14 = Function Mask, bits 10:0 = table size-1
 *   +4  Table Offset (bits 31:3) | Table BIR (bits 2:0)
 *   +8  PBA Offset | PBA BIR */
#define PCI_CAP_ID_MSIX        0x11u
#define MSIX_MSGCTL_ENABLE     (1u << 15)
#define MSIX_MSGCTL_FUNC_MASK  (1u << 14)

/* One MSI-X table entry (16 bytes, in device MMIO). */
typedef struct __attribute__((packed)) {
    volatile uint32_t msg_addr_lo;
    volatile uint32_t msg_addr_hi;
    volatile uint32_t msg_data;
    volatile uint32_t vector_ctrl;   /* bit 0 = mask */
} msix_entry_t;

/* Program the RX queue of p->dev to raise MSI-X vector VIRTIO_NET_RX_VECTOR on
 * the BSP. Must run AFTER the queues are set up but BEFORE DRIVER_OK, while the
 * device is still configurable. Returns 0 if MSI-X is live, -1 to fall back to
 * the 100 Hz poll (NIC then never raises vector 0x40). */
static int
virtio_net_setup_msix(virtio_net_priv_t *p)
{
    const pcie_device_t *d = &p->dev.pci;

    /* Walk the PCI capability list for the MSI-X capability. */
    uint8_t cap = pcie_read8(d->bus, d->dev, d->fn, 0x34) & 0xFCu;
    uint8_t msix_cap = 0;
    while (cap != 0) {
        if ((pcie_read8(d->bus, d->dev, d->fn, cap + 0) & 0xFFu) == PCI_CAP_ID_MSIX) {
            msix_cap = cap;
            break;
        }
        cap = pcie_read8(d->bus, d->dev, d->fn, cap + 1) & 0xFCu;
    }
    if (!msix_cap)
        return -1;   /* device has no MSI-X — poll path stays */

    /* Table Offset/BIR → which BAR holds the table and at what offset.
     * (The table always has >=1 entry; we only need entry 0 for the RX queue.) */
    uint32_t tbl_reg = pcie_read32(d->bus, d->dev, d->fn, msix_cap + 4);
    uint8_t  bir     = (uint8_t)(tbl_reg & 0x7u);
    uint32_t tbl_off = tbl_reg & ~0x7u;
    if (bir > 5 || d->bar[bir] == 0)
        return -1;

    /* Map the page(s) of the BAR covering table entry 0 as uncached MMIO. */
    uint64_t  tbl_pa   = d->bar[bir] + tbl_off;
    uintptr_t page_va  = (uintptr_t)kva_alloc_pages(1);
    if (!page_va)
        return -1;
    vmm_unmap_page(page_va);
    vmm_map_page(page_va, tbl_pa & ~0xFFFULL,
                 VMM_FLAG_WRITABLE | VMM_FLAG_WC | VMM_FLAG_UCMINUS);
    msix_entry_t *tbl = (msix_entry_t *)(page_va + (tbl_pa & 0xFFFULL));

    /* Entry 0 → vector 0x40 on the BSP LAPIC. MSI address/data (Intel SDM
     * Vol.3 §10.11): addr = 0xFEE00000 | dest_apic<<12 (physical, fixed),
     * data = vector (fixed delivery, edge). Leave it unmasked. */
    tbl[0].msg_addr_lo = 0xFEE00000u | ((uint32_t)g_bsp_apic_id << 12);
    tbl[0].msg_addr_hi = 0;
    tbl[0].msg_data    = VIRTIO_NET_RX_VECTOR;
    tbl[0].vector_ctrl = 0;   /* unmasked */
    arch_wmb();

    /* Enable MSI-X and clear the global function mask (RMW the +0 dword's high
     * 16 bits). With MSI-X enabled the device also auto-disables INTx. */
    uint32_t cap0 = pcie_read32(d->bus, d->dev, d->fn, msix_cap + 0);
    cap0 |= ((uint32_t)MSIX_MSGCTL_ENABLE << 16);
    cap0 &= ~((uint32_t)MSIX_MSGCTL_FUNC_MASK << 16);
    pcie_write32(d->bus, d->dev, d->fn, msix_cap + 0, cap0);

    /* Bind the RX queue (0) to table entry 0; leave TX (reaped lazily) and the
     * config-change interrupt with no vector. queue_msix_vector is per-queue,
     * selected by queue_select; the device echoes back NO_VECTOR on failure. */
    volatile virtio_pci_common_cfg_t *c = p->dev.common;
    c->msix_config = VIRTIO_MSI_NO_VECTOR;
    c->queue_select = 1;                       /* TX */
    c->queue_msix_vector = VIRTIO_MSI_NO_VECTOR;
    c->queue_select = 0;                       /* RX */
    c->queue_msix_vector = 0;
    if (c->queue_msix_vector != 0)             /* device rejected the binding */
        return -1;

    return 0;
}

#else  /* !__x86_64__ — no MSI on this arch yet; poll path only. */
static int virtio_net_setup_msix(virtio_net_priv_t *p) { (void)p; return -1; }
#endif

/* ── virtio_net_init ─────────────────────────────────────────────────────── */
void
virtio_net_init(void)
{
    virtio_net_priv_t *p = &s_priv;

    if (virtio_pci_find(VIRTIO_NET_DEVICE_MODERN, VIRTIO_NET_DEVICE_LEGACY,
                        &p->dev) < 0)
        return;  /* silent: make test uses -machine pc, no virtio-net present */

    virtio_reset(&p->dev);
    if (virtio_negotiate(&p->dev, VIRTIO_NET_F_MAC) < 0)
        return;  /* device left FAILED; no netdev registered */

    /* MAC from device-config bytes 0–5. */
    int i;
    for (i = 0; i < 6; i++)
        s_dev.mac[i] = p->dev.devcfg[i];

    /* RX queue (0): allocate a 1-page buffer per descriptor slot and publish
     * them all. RX descriptors are owned permanently (never freed), so we
     * publish by slot id directly and zero the free stack afterwards. */
    if (virtio_setup_queue(&p->dev, 0, &p->rx) < 0) {
        p->dev.common->device_status = VIRTIO_STATUS_FAILED;
        return;
    }
    uint16_t id;
    for (id = 0; id < p->rx.size; id++) {
        uint64_t  pa;
        uintptr_t va;
        if (virtio_alloc_dma_page(&pa, &va) < 0) {
            p->dev.common->device_status = VIRTIO_STATUS_FAILED;
            return;
        }
        p->rx_virt[id] = (void *)va;
        p->rx_phys[id] = pa;
        virtq_publish_single(&p->rx, id, pa, VIRTIO_RX_BUF_LEN, 1);
    }
    p->rx.nfree = 0;   /* all RX descriptors permanently in use */
    virtq_notify(&p->rx);

    /* TX queue (1): one bounce buffer per descriptor slot. The free stack stays
     * full; send() pops a descriptor and uses tx_virt[that-slot]. */
    if (virtio_setup_queue(&p->dev, 1, &p->tx) < 0) {
        p->dev.common->device_status = VIRTIO_STATUS_FAILED;
        return;
    }
    for (id = 0; id < p->tx.size; id++) {
        uint64_t  pa;
        uintptr_t va;
        if (virtio_alloc_dma_page(&pa, &va) < 0) {
            p->dev.common->device_status = VIRTIO_STATUS_FAILED;
            return;
        }
        p->tx_virt[id] = (uint8_t *)va;
        p->tx_phys[id] = pa;
    }
    p->tx_drops = 0;

    /* Bind RX to an MSI-X vector before DRIVER_OK; falls back to the 100 Hz
     * poll if the device has no MSI-X or rejects the binding. */
    p->msix_ok = (virtio_net_setup_msix(p) == 0);

    virtio_driver_ok(&p->dev);

    /* Re-kick RX now that DRIVER_OK is set (QEMU may defer processing the
     * pre-filled descriptors until the device is fully activated). */
    virtq_notify(&p->rx);

    s_dev.name[0]='e'; s_dev.name[1]='t'; s_dev.name[2]='h';
    s_dev.name[3]='0'; s_dev.name[4]='\0';
    s_dev.mtu  = 1500;
    s_dev.send = virtio_net_send;
    s_dev.poll = virtio_net_poll;
    s_dev.priv = p;
    netdev_register(&s_dev);

    printk("[NET] OK: virtio-net eth0 mac=%x:%x:%x:%x:%x:%x rx=%s\n",
           s_dev.mac[0], s_dev.mac[1], s_dev.mac[2],
           s_dev.mac[3], s_dev.mac[4], s_dev.mac[5],
           p->msix_ok ? "msix-irq" : "poll");
}

/* Return completed TX descriptors to the free stack. Caller holds tx.lock. */
static void
virtio_net_tx_reap(virtio_net_priv_t *p)
{
    uint16_t id;
    uint32_t len;
    while (virtq_poll_used(&p->tx, &id, &len))
        virtq_free_chain(&p->tx, id);
}

/* ── virtio_net_send ─────────────────────────────────────────────────────────
 * Transmit one frame asynchronously: reap completions, take a free descriptor,
 * stage [12-byte virtio_net_hdr | frame] in its bounce buffer, publish, notify,
 * and return without waiting. Only when all descriptors are in flight do we
 * briefly spin-reap; if still full, drop ONE frame (rate-limited log) and return
 * -1 so TCP retransmits. Returns 0 if queued, -1 on bad args or ring-full. */
static int
virtio_net_send(netdev_t *dev, const void *pkt, uint16_t len)
{
    if (!dev || !dev->priv || pkt == NULL || len == 0u || len > 1514u)
        return -1;
    virtio_net_priv_t *p = (virtio_net_priv_t *)dev->priv;

    irqflags_t fl = spin_lock_irqsave(&p->tx.lock);

    virtio_net_tx_reap(p);
    int desc = virtq_alloc_desc(&p->tx);
    if (desc < 0) {
        unsigned spins;
        for (spins = 0; spins < VIRTIO_TX_REAP_SPINS && desc < 0; spins++) {
            arch_pause();
            virtio_net_tx_reap(p);
            desc = virtq_alloc_desc(&p->tx);
        }
        if (desc < 0) {
            uint32_t n = ++p->tx_drops;
            spin_unlock_irqrestore(&p->tx.lock, fl);
            if ((n & (n - 1u)) == 0u)   /* log on 1st, 2nd, 4th, 8th, … */
                printk("[NET] WARN: virtio-net TX ring full, frame dropped "
                       "(total=%u)\n", n);
            return -1;
        }
    }

    uint8_t *buf = p->tx_virt[desc];
    _memset(buf, 0, VIRTIO_NET_HDR_SIZE);   /* no offload */
    _memcpy(buf + VIRTIO_NET_HDR_SIZE, pkt, len);
    virtq_publish_single(&p->tx, (uint16_t)desc, p->tx_phys[desc],
                         (uint32_t)(VIRTIO_NET_HDR_SIZE + len), 0);
    virtq_notify(&p->tx);

    spin_unlock_irqrestore(&p->tx.lock, fl);
    return 0;
}

/* ── virtio_net_service ───────────────────────────────────────────────────────
 * Drain the RX used ring and reap TX completions. Shared by the 100 Hz poll and
 * the MSI-X RX interrupt — both run on the BSP with IF=0 and never overlap, so
 * the RX ring needs no lock here (matching the original poll-only design).
 *
 * For each RX frame: copy it out, recycle the descriptor (re-publish the same
 * buffer) BEFORE delivering, then deliver — delivery may TX a reply
 * synchronously, so recycling first stops a single packet being reprocessed into
 * a reply storm. Always ring the RX doorbell at the end (spec §2.7.13). */
static void
virtio_net_service(netdev_t *dev)
{
    virtio_net_priv_t *p = (virtio_net_priv_t *)dev->priv;

    uint16_t id;
    uint32_t rlen;
    while (virtq_poll_used(&p->rx, &id, &rlen)) {
        static uint8_t rx_copy[VIRTIO_RX_BUF_LEN];
        uint16_t dlen = 0;
        if (id < p->rx.size &&
            rlen > VIRTIO_NET_HDR_SIZE && rlen <= VIRTIO_RX_BUF_LEN) {
            dlen = (uint16_t)(rlen - VIRTIO_NET_HDR_SIZE);
            _memcpy(rx_copy,
                    (uint8_t *)p->rx_virt[id] + VIRTIO_NET_HDR_SIZE, dlen);
        }
        /* Recycle the descriptor (re-offer the same buffer) before delivering. */
        if (id < p->rx.size)
            virtq_publish_single(&p->rx, id, p->rx_phys[id],
                                 VIRTIO_RX_BUF_LEN, 1);
        if (dlen)
            netdev_rx_deliver(dev, rx_copy, dlen);
    }

    /* Always notify (VM-exit kick + re-offer of RX buffers, spec §2.7.13). */
    virtq_notify(&p->rx);

    irqflags_t tfl = spin_lock_irqsave(&p->tx.lock);
    virtio_net_tx_reap(p);
    spin_unlock_irqrestore(&p->tx.lock, tfl);
}

/* 100 Hz PIT poll entry. With MSI-X active this is a cheap backstop: the IRQ
 * normally drains the ring first, so the poll finds it empty — but it still runs
 * every tick to recover any coalesced/lost interrupt within 10 ms (and to keep
 * the no-MSI-X fallback path identical). Measured: keeping it costs nothing
 * (~43 MB/s with it, ~45 MB/s without — within noise). */
static void
virtio_net_poll(netdev_t *dev)
{
    virtio_net_service(dev);
}

/* Set while servicing RX from interrupt/PIT context so arp_resolve() (reached
 * via netdev_rx_deliver → tcp → ip_send when a frame triggers a reply) returns
 * -1 instead of blocking — blocking in an ISR would hang. netdev_poll_all sets
 * this for the poll path; the MSI-X path must set it itself. */
extern volatile int g_in_netdev_poll;

/* MSI-X RX interrupt entry (idt.c vector 0x40). Runs IF=0 on the BSP; the
 * shared servicing path is non-blocking. No-op if the NIC never registered. */
void
virtio_net_irq(void)
{
    if (!s_dev.priv)
        return;
    int prev = g_in_netdev_poll;
    g_in_netdev_poll = 1;
    virtio_net_service(&s_dev);
    g_in_netdev_poll = prev;
}
