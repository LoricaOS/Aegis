/* rtl8169.c — Realtek RTL8168/8169 PCIe gigabit Ethernet driver
 *
 * Polling-mode, single-instance driver. Mirrors virtio_net.c's design.
 * Targets the RTL8168 family found in ASUS EQR boxes; tested via VFIO
 * PCI passthrough during development.
 *
 * Memory model:
 *   - PCI config space: pcie_read* / pcie_write32 (ECAM via pcie.h)
 *   - BAR2 MMIO: kva_alloc_pages + vmm_map_page (uncached, WC|UCMINUS)
 *   - DMA buffers: kva_alloc_pages + kva_page_phys
 *
 * Init sequence:
 *   1. Find vendor 0x10EC device 0x8168 in pcie_get_devices().
 *   2. PCI: enable Memory + Bus Master, wake to D0 via PMCSR.
 *   3. Map BAR2 as 1 page of uncached MMIO.
 *   4. Soft reset chip (ChipCmd CmdReset → poll until clear).
 *   5. Read MAC from MAC0/MAC4 registers.
 *   6. Allocate RX/TX descriptor rings (256 × 16B = 4096B = 1 page each).
 *   7. Allocate 256 RX data buffers + 256 TX bounce buffers (1 page each).
 *   8. Pre-fill RX descriptors (DescOwn | RingEnd-on-last).
 *   9. Configure RxConfig/TxConfig/RxMaxSize, write ring base addresses.
 *   10. Enable RX + TX. Disable IRQs (we poll).
 *   11. Register netdev "eth0".
 */
#include "rtl8169.h"
#include "netdev.h"
#include "arch.h"
#include "pcie.h"
#include "kva.h"
#include "vmm.h"
#include "printk.h"
#include <stdint.h>
#include <stddef.h>

/* ── String helpers (no libc in kernel) ───────────────────────────── */

static void
_memset(void *dst, int val, uint32_t n)
{
    uint8_t *p = dst;
    while (n--)
        *p++ = (uint8_t)val;
}

static void
_memcpy(void *dst, const void *src, uint32_t n)
{
    uint8_t *d = dst;
    const uint8_t *s = src;
    while (n--)
        *d++ = *s++;
}

/* ── Register offsets (RTL8168 family) ────────────────────────────── */

enum {
    REG_MAC0       = 0x00,
    REG_MAC4       = 0x04,
    REG_MAR0       = 0x08,    /* multicast filter, 8 bytes */
    REG_TX_LOW     = 0x20,
    REG_TX_HIGH    = 0x24,
    REG_CMD        = 0x37,    /* ChipCmd, 8-bit */
    REG_TXPOLL     = 0x38,    /* 8-bit, write to kick TX */
    REG_INTR_MASK  = 0x3C,    /* 16-bit */
    REG_INTR_STAT  = 0x3E,    /* 16-bit, write to clear */
    REG_TX_CONFIG  = 0x40,
    REG_RX_CONFIG  = 0x44,
    REG_CFG9346    = 0x50,    /* config register lock */
    REG_PHYAR      = 0x60,    /* 32-bit MII access — phy reg + data */
    REG_PHY_STATUS = 0x6C,    /* 8-bit */
    REG_RX_MAXSIZE = 0xDA,    /* 16-bit */
    REG_CPLUS_CMD  = 0xE0,    /* 16-bit */
    REG_RX_LOW     = 0xE4,
    REG_RX_HIGH    = 0xE8,
    REG_MAX_TX_PKT = 0xEC,    /* 8-bit, units of 128 bytes */
    REG_MISC       = 0xF0,    /* 32-bit, 8168e+: RXDV_GATED_EN at bit 19 */
};

#define MISC_RXDV_GATED_EN  (1u << 19)

/* MII PHY register addresses (standard IEEE 802.3 clause 22) */
#define MII_BMCR        0x00    /* Basic Mode Control Register */
#define MII_BMCR_RESET    0x8000
#define MII_BMCR_ANEG_EN  0x1000
#define MII_BMCR_ANEG_RST 0x0200

/* ChipCmd bits */
#define CMD_RESET        0x10
#define CMD_RX_ENABLE    0x08
#define CMD_TX_ENABLE    0x04

/* Cfg9346 values */
#define CFG_LOCK         0x00
#define CFG_UNLOCK       0xC0

/* TxPoll bits — bit 6 = NPQ, kick normal-priority TX queue */
#define TXPOLL_NPQ       0x40

/* Descriptor opts1 bits (little-endian, top bits) */
#define DESC_OWN         (1u << 31)
#define DESC_RING_END    (1u << 30)
#define DESC_FIRST_FRAG  (1u << 29)
#define DESC_LAST_FRAG   (1u << 28)

/* RxConfig bits — 8168c family uses different layout from old 8169 */
#define RX_DMA_BURST_UNLIMITED  (7u << 8)
#define RX_MULTI_EN             (1u << 14)  /* 8168c+ */
#define RX128_INT_EN            (1u << 15)  /* 8168c+ */
#define RX_ACCEPT_PHYS          (1u << 1)   /* AcceptMyPhys */
#define RX_ACCEPT_MULTI         (1u << 2)   /* AcceptMulticast */
#define RX_ACCEPT_BCAST         (1u << 3)   /* AcceptBroadcast */
#define RX_ACCEPT_MASK          (0x3F)      /* low 6 bits = accept mask */

/* TxConfig bits */
#define TX_DMA_BURST_1024       (6u << 8)  /* 6 = 1024 bytes */
#define TX_IFG_STD              (3u << 24) /* standard IFG */

/* CPlusCmd bits we set */
#define CPLUS_RXCHKSUM          (1u << 5)

/* PHYstatus bits */
#define PHY_LINK_STS            (1u << 1)

/* Ring sizes */
#define NUM_RX_DESC     256
#define NUM_TX_DESC     256
#define RX_BUF_SIZE     2048   /* per RX buffer; pages are 4KB so plenty */

/* Power management capability ID */
#define PCI_CAP_ID_PM   0x01

/* PCI command register bits */
#define PCI_CMD_MEM     0x02
#define PCI_CMD_BM      0x04

/* ── Descriptor format (16 bytes, packed, little-endian) ──────────── */

typedef struct __attribute__((packed)) {
    volatile uint32_t opts1;   /* DescOwn|RingEnd|First|Last|len */
    volatile uint32_t opts2;   /* VLAN/checksum offload — we set 0 */
    volatile uint64_t addr;    /* physical buffer address */
} rtl_desc_t;

/* ── Per-device state (single instance) ───────────────────────────── */

typedef struct {
    /* MMIO base (volatile pointer to BAR2) */
    volatile uint8_t *mmio;

    /* Descriptor rings (1 page each, 256 × 16 = 4096) */
    rtl_desc_t *rx_ring;       /* virtual */
    rtl_desc_t *tx_ring;
    uint64_t    rx_ring_pa;
    uint64_t    tx_ring_pa;

    /* Per-slot data buffers (RX) and bounce buffers (TX) */
    uint8_t    *rx_buf_va[NUM_RX_DESC];
    uint64_t    rx_buf_pa[NUM_RX_DESC];
    uint8_t    *tx_buf_va[NUM_TX_DESC];
    uint64_t    tx_buf_pa[NUM_TX_DESC];

    /* Ring head pointers (driver-side) */
    uint16_t    tx_head;       /* next slot to fill */
    uint16_t    rx_head;       /* next slot to drain */

    /* Debug: last-seen PHY status, dump on change */
    uint8_t     last_phy;
    uint32_t    poll_tick;
} rtl_priv_t;

static rtl_priv_t s_priv;
static netdev_t   s_dev;

/* ── MMIO accessors ───────────────────────────────────────────────── */

static inline uint8_t  rd8 (uint16_t off) { return *(volatile uint8_t  *)(s_priv.mmio + off); }
static inline uint16_t rd16(uint16_t off) { return *(volatile uint16_t *)(s_priv.mmio + off); }
static inline uint32_t rd32(uint16_t off) { return *(volatile uint32_t *)(s_priv.mmio + off); }
static inline void wr8 (uint16_t off, uint8_t  v) { *(volatile uint8_t  *)(s_priv.mmio + off) = v; }
static inline void wr16(uint16_t off, uint16_t v) { *(volatile uint16_t *)(s_priv.mmio + off) = v; }
static inline void wr32(uint16_t off, uint32_t v) { *(volatile uint32_t *)(s_priv.mmio + off) = v; }

/* ── Helpers ──────────────────────────────────────────────────────── */

#define MMIO_FLAGS (VMM_FLAG_WRITABLE | VMM_FLAG_WC | VMM_FLAG_UCMINUS)

static uintptr_t
map_bar(uint64_t pa, uint32_t n_pages)
{
    uintptr_t va = (uintptr_t)kva_alloc_pages(n_pages);
    uint32_t i;
    for (i = 0; i < n_pages; i++) {
        uintptr_t page_va = va + (uint64_t)i * 4096;
        vmm_unmap_page(page_va);
        vmm_map_page(page_va, pa + (uint64_t)i * 4096, MMIO_FLAGS);
    }
    return va;
}

static void
alloc_dma_page(uint64_t *phys_out, uintptr_t *virt_out)
{
    uintptr_t va = (uintptr_t)kva_alloc_pages(1);
    uint64_t  pa = kva_page_phys((void *)va);
    _memset((void *)va, 0, 4096);
    *phys_out = pa;
    *virt_out = va;
}

/* Spin for ~us microseconds via tight loop. PIT/LAPIC timer not
 * usable here (we run in early init before scheduler). 1000 inb-style
 * loops ≈ 1us is approximate; we use it only for reset polling so the
 * exact timing doesn't matter — total budget is bounded by retry count. */
static void
busy_wait_us(uint32_t us)
{
    volatile uint32_t i;
    for (i = 0; i < us * 100u; i++)
        __asm__ volatile("pause");
}

/* MII (PHY) register access via PHYAR.
 * Linux convention: write = 0x80000000 | (reg<<16) | val, then poll
 * bit 31 to clear. Read = (reg<<16), then poll bit 31 to set, then
 * read low 16 bits. ~25 iterations × 20us = 500us max wait. */
static void
mdio_write(uint8_t reg, uint16_t value)
{
    wr32(REG_PHYAR, 0x80000000u | ((uint32_t)(reg & 0x1f) << 16) | value);
    int i;
    for (i = 0; i < 100; i++) {
        if ((rd32(REG_PHYAR) & 0x80000000u) == 0)
            break;
        busy_wait_us(20);
    }
    busy_wait_us(20);   /* mandatory post-write delay per spec */
}

static uint16_t
mdio_read(uint8_t reg)
{
    wr32(REG_PHYAR, ((uint32_t)(reg & 0x1f) << 16));
    int i;
    for (i = 0; i < 100; i++) {
        if (rd32(REG_PHYAR) & 0x80000000u)
            break;
        busy_wait_us(20);
    }
    uint16_t v = (uint16_t)(rd32(REG_PHYAR) & 0xFFFFu);
    busy_wait_us(20);
    return v;
}

/* Walk PCI capability list looking for the Power Management capability.
 * Returns the offset of the PMCSR (cap_offset + 4) or 0 if not found. */
static uint8_t
find_pm_pmcsr(const pcie_device_t *d)
{
    /* Check Status register (0x06) bit 4 (capabilities list present) */
    uint16_t status = pcie_read16(d->bus, d->dev, d->fn, 0x06);
    if (!(status & (1 << 4)))
        return 0;

    uint8_t cap = (uint8_t)pcie_read8(d->bus, d->dev, d->fn, 0x34) & 0xFCu;
    int safety = 48;  /* max caps in linked list */
    while (cap != 0 && safety-- > 0) {
        uint8_t id   = pcie_read8(d->bus, d->dev, d->fn, cap + 0);
        uint8_t next = pcie_read8(d->bus, d->dev, d->fn, cap + 1);
        if (id == PCI_CAP_ID_PM)
            return (uint8_t)(cap + 4);  /* PMCSR is at cap+4 */
        cap = next & 0xFCu;
    }
    return 0;
}

/* ── Forward declarations ─────────────────────────────────────────── */

static int  rtl8169_send(netdev_t *dev, const void *pkt, uint16_t len);
static void rtl8169_poll(netdev_t *dev);

/* ── Init ─────────────────────────────────────────────────────────── */

void
rtl8169_init(void)
{
    int i;
    const pcie_device_t *found = NULL;

    /* 1. Scan PCIe devices for vendor 0x10EC, device 0x8168. */
    int count = pcie_device_count();
    for (i = 0; i < count; i++) {
        const pcie_device_t *d = &pcie_get_devices()[i];
        if (d->vendor_id == 0x10EC && d->device_id == 0x8168) {
            found = d;
            break;
        }
    }
    if (!found)
        return; /* silent skip — no RTL8168 present */

    printk("[RTL8169] OK: found at %x:%x.%x\n",
           (unsigned)found->bus, (unsigned)found->dev, (unsigned)found->fn);

    /* 2. PCI command register: enable Memory + Bus Master.
     * Use pcie_read32/pcie_write32 since pcie.h doesn't expose 16-bit write. */
    {
        uint32_t cmd_status = pcie_read32(found->bus, found->dev, found->fn, 0x04);
        cmd_status &= 0xFFFF0000u;  /* preserve status word */
        cmd_status |= (PCI_CMD_MEM | PCI_CMD_BM);
        pcie_write32(found->bus, found->dev, found->fn, 0x04, cmd_status);
    }

    /* 3. Wake to D0 via PMCSR if PM capability is present.
     * PMCSR bits 1:0 = power state. Writing 0 = D0. */
    {
        uint8_t pmcsr_off = find_pm_pmcsr(found);
        if (pmcsr_off) {
            /* PMCSR is 16-bit; pcie_read32 reads dword containing it.
             * Just write 0 to the dword — clearing PME_En and power state. */
            pcie_write32(found->bus, found->dev, found->fn, pmcsr_off, 0);
            busy_wait_us(10000); /* spec: D3hot→D0 transition takes <10ms */
        }
    }

    /* 4. Map BAR2 (4KB MMIO window). */
    if (found->bar[2] == 0) {
        printk("[RTL8169] FAIL: BAR2 unmapped\n");
        return;
    }
    {
        uint64_t pa = found->bar[2] & ~0xFFFULL;
        uintptr_t va = map_bar(pa, 1);
        s_priv.mmio = (volatile uint8_t *)(va + (found->bar[2] & 0xFFFULL));
    }

    /* Sanity probe — if MMIO mapping is wrong or device is dead,
     * MAC0 reads as 0xFFFFFFFF. */
    {
        uint32_t mac_lo = rd32(REG_MAC0);
        if (mac_lo == 0xFFFFFFFFu) {
            printk("[RTL8169] FAIL: MMIO read 0xFFFFFFFF (BAR2 unmapped or D3?)\n");
            return;
        }
    }

    /* 5. Soft reset chip — bit 4 of ChipCmd auto-clears when done. */
    wr8(REG_CMD, CMD_RESET);
    {
        int spin;
        for (spin = 0; spin < 100; spin++) {
            if ((rd8(REG_CMD) & CMD_RESET) == 0)
                break;
            busy_wait_us(100);
        }
        if (spin >= 100) {
            printk("[RTL8169] FAIL: reset bit stuck after 10ms\n");
            return;
        }
    }

    /* 6. Read MAC address from MAC0/MAC4 (latched from eFuse on reset). */
    {
        uint32_t lo = rd32(REG_MAC0);
        uint32_t hi = rd32(REG_MAC4);
        s_dev.mac[0] = (uint8_t)(lo >>  0);
        s_dev.mac[1] = (uint8_t)(lo >>  8);
        s_dev.mac[2] = (uint8_t)(lo >> 16);
        s_dev.mac[3] = (uint8_t)(lo >> 24);
        s_dev.mac[4] = (uint8_t)(hi >>  0);
        s_dev.mac[5] = (uint8_t)(hi >>  8);
    }

    /* 6b. Reset PHY and restart auto-negotiation.
     * The MAC reset (CmdReset) doesn't touch the PHY. If the previous
     * driver (e.g. Linux r8169) put the PHY into ALDPS power-down or
     * left auto-neg disabled, we'd see "link down" forever. Writing
     * BMCR=0x9200 forces a PHY reset, enables auto-neg, and restarts
     * negotiation. The actual link-up happens 3-5 seconds later. */
    mdio_write(MII_BMCR,
               MII_BMCR_RESET | MII_BMCR_ANEG_EN | MII_BMCR_ANEG_RST);
    /* Optional sanity: read it back to confirm MDIO is reachable. */
    {
        uint16_t bmcr = mdio_read(MII_BMCR);
        printk("[RTL8169] phy bmcr after reset = 0x%x\n", (unsigned)bmcr);
    }

    /* 7. Allocate descriptor rings (1 page each = 4096B = 256 × 16B). */
    {
        uint64_t  pa;
        uintptr_t va;
        alloc_dma_page(&pa, &va);
        s_priv.rx_ring    = (rtl_desc_t *)va;
        s_priv.rx_ring_pa = pa;
        alloc_dma_page(&pa, &va);
        s_priv.tx_ring    = (rtl_desc_t *)va;
        s_priv.tx_ring_pa = pa;
    }

    /* 8. Allocate per-slot data buffers and TX bounce buffers. */
    for (i = 0; i < NUM_RX_DESC; i++) {
        uint64_t  pa;
        uintptr_t va;
        alloc_dma_page(&pa, &va);
        s_priv.rx_buf_va[i] = (uint8_t *)va;
        s_priv.rx_buf_pa[i] = pa;
    }
    for (i = 0; i < NUM_TX_DESC; i++) {
        uint64_t  pa;
        uintptr_t va;
        alloc_dma_page(&pa, &va);
        s_priv.tx_buf_va[i] = (uint8_t *)va;
        s_priv.tx_buf_pa[i] = pa;
    }

    /* 9. Pre-fill RX descriptors: device owns each slot, ready to receive. */
    for (i = 0; i < NUM_RX_DESC; i++) {
        uint32_t opts1 = DESC_OWN | RX_BUF_SIZE;
        if (i == NUM_RX_DESC - 1)
            opts1 |= DESC_RING_END;
        s_priv.rx_ring[i].addr  = s_priv.rx_buf_pa[i];
        s_priv.rx_ring[i].opts2 = 0;
        s_priv.rx_ring[i].opts1 = opts1;
    }
    /* TX descriptors start driver-owned (opts1 == 0). Set RingEnd marker
     * on the last slot — required so the chip wraps the ring. */
    for (i = 0; i < NUM_TX_DESC; i++) {
        s_priv.tx_ring[i].addr  = s_priv.tx_buf_pa[i];
        s_priv.tx_ring[i].opts2 = 0;
        s_priv.tx_ring[i].opts1 = (i == NUM_TX_DESC - 1) ? DESC_RING_END : 0;
    }
    s_priv.tx_head = 0;
    s_priv.rx_head = 0;
    arch_wmb();

    /* 10. Configure registers and enable RX/TX.
     *
     * The order matches Linux's rtl_hw_start():
     *   unlock → CPlusCmd → RxMaxSize → ring base addrs → lock
     *   → ChipCmd RxEnb|TxEnb → RxConfig (chip-bits) → TxConfig
     *   → RxConfig (accept mask) → multicast filter
     *
     * Writing RxConfig BEFORE enabling CmdRxEnb leaves it in an
     * intermediate state on 8168 chips that prevents both TX and RX
     * from working properly. */
    wr8(REG_CFG9346, CFG_UNLOCK);

    /* CPlusCmd — preserve existing chip-set bits (RxChkSum/Vlan etc.) */
    wr16(REG_CPLUS_CMD, rd16(REG_CPLUS_CMD));

    /* RxMaxSize: largest frame we'll accept (1500 MTU + headers + FCS) */
    wr16(REG_RX_MAXSIZE, 1538);

    /* Max TX packet size — 8064 / 128 = 63 */
    wr8(REG_MAX_TX_PKT, 63);

    /* Write descriptor ring base addresses (high BEFORE low — Linux comment
     * says some chips latch on the low write, so high must be set first). */
    wr32(REG_TX_HIGH, (uint32_t)(s_priv.tx_ring_pa >> 32));
    wr32(REG_TX_LOW,  (uint32_t)(s_priv.tx_ring_pa & 0xFFFFFFFFu));
    wr32(REG_RX_HIGH, (uint32_t)(s_priv.rx_ring_pa >> 32));
    wr32(REG_RX_LOW,  (uint32_t)(s_priv.rx_ring_pa & 0xFFFFFFFFu));

    wr8(REG_CFG9346, CFG_LOCK);

    /* Clear RXDV_GATED_EN in MISC register (8168e+).
     * Without this, the chip silently drops all RX from the PHY even
     * though the descriptor ring is configured and CmdRxEnb is set. */
    {
        uint32_t misc = rd32(REG_MISC);
        wr32(REG_MISC, misc & ~MISC_RXDV_GATED_EN);
    }

    /* Disable IRQs (we poll), clear any pending status bits. */
    wr16(REG_INTR_MASK, 0);
    wr16(REG_INTR_STAT, 0xFFFF);

    /* Enable RX + TX FIRST, before final RxConfig write (Linux order). */
    wr8(REG_CMD, CMD_RX_ENABLE | CMD_TX_ENABLE);

    /* Now write RxConfig with the chip bits for the 8168 family
     * (RX128_INT_EN | RX_MULTI_EN | RX_DMA_BURST). The accept mask
     * gets ORed in below. */
    wr32(REG_RX_CONFIG,
         RX128_INT_EN | RX_MULTI_EN | RX_DMA_BURST_UNLIMITED |
         RX_ACCEPT_PHYS | RX_ACCEPT_BCAST | RX_ACCEPT_MULTI);

    /* TxConfig: standard IFG, 1024-byte max DMA burst */
    wr32(REG_TX_CONFIG, TX_IFG_STD | TX_DMA_BURST_1024);

    /* Accept all multicast (no hash filter for now) */
    wr32(REG_MAR0 + 0, 0xFFFFFFFFu);
    wr32(REG_MAR0 + 4, 0xFFFFFFFFu);

    arch_wmb();

    /* 11. Register netdev. */
    s_dev.name[0]='e'; s_dev.name[1]='t'; s_dev.name[2]='h';
    s_dev.name[3]='0'; s_dev.name[4]='\0';
    s_dev.mtu  = 1500;
    s_dev.send = rtl8169_send;
    s_dev.poll = rtl8169_poll;
    s_dev.priv = &s_priv;

    if (netdev_register(&s_dev) < 0) {
        printk("[RTL8169] FAIL: netdev_register full\n");
        return;
    }

    printk("[NET] OK: rtl8169 eth0 mac=%x:%x:%x:%x:%x:%x\n",
           s_dev.mac[0], s_dev.mac[1], s_dev.mac[2],
           s_dev.mac[3], s_dev.mac[4], s_dev.mac[5]);

    {
        uint8_t phys = rd8(REG_PHY_STATUS);
        printk("[RTL8169] phy_status=0x%x link=%s\n",
               (unsigned)phys, (phys & PHY_LINK_STS) ? "up" : "down");
    }
}

/* ── Send ─────────────────────────────────────────────────────────── */

static int
rtl8169_send(netdev_t *dev, const void *pkt, uint16_t len)
{
    rtl_priv_t *p = (rtl_priv_t *)dev->priv;
    uint16_t slot = (uint16_t)(p->tx_head & (NUM_TX_DESC - 1));

    if (len > 1518)
        return -1;

    /* If the chip still owns this slot, the ring is full. */
    if (p->tx_ring[slot].opts1 & DESC_OWN)
        return -1;

    /* Copy frame into bounce buffer. */
    _memcpy(p->tx_buf_va[slot], pkt, len);

    /* Build descriptor — DescOwn must be written LAST so the chip
     * doesn't race a half-initialized entry. */
    uint32_t opts1 = DESC_OWN | DESC_FIRST_FRAG | DESC_LAST_FRAG | len;
    if (slot == NUM_TX_DESC - 1)
        opts1 |= DESC_RING_END;
    p->tx_ring[slot].opts2 = 0;
    arch_wmb();
    p->tx_ring[slot].opts1 = opts1;
    arch_wmb();

    /* Kick TX — write NPQ bit to TxPoll. */
    wr8(REG_TXPOLL, TXPOLL_NPQ);

    p->tx_head++;
    return 0;
}

/* ── Poll ─────────────────────────────────────────────────────────── */

static void
rtl8169_poll(netdev_t *dev)
{
    rtl_priv_t *p = (rtl_priv_t *)dev->priv;

    /* Report PHY status changes (e.g. auto-neg completion). */
    {
        uint8_t phys = rd8(REG_PHY_STATUS);
        if (phys != p->last_phy) {
            printk("[RTL8169] phy_status: 0x%x -> 0x%x %s\n",
                   (unsigned)p->last_phy, (unsigned)phys,
                   (phys & PHY_LINK_STS) ? "LINK_UP" : "link_down");
            p->last_phy = phys;
        }
    }

    /* Drain the RX ring until we hit a descriptor still owned by the chip. */
    int budget;
    for (budget = 0; budget < NUM_RX_DESC; budget++) {
        uint16_t slot  = (uint16_t)(p->rx_head & (NUM_RX_DESC - 1));
        uint32_t opts1 = p->rx_ring[slot].opts1;

        if (opts1 & DESC_OWN)
            break;  /* nothing more to deliver this tick */

        uint16_t rlen = (uint16_t)(opts1 & 0x3FFFu);

        /* RTL includes the trailing 4-byte FCS in the length. Strip it.
         *
         * rlen comes from the descriptor written by the chip and can be up to
         * 16383 (14-bit field), but each RX buffer is only RX_BUF_SIZE bytes
         * (the capacity we programmed into the descriptor). A larger value
         * would make netdev_rx_deliver() read past the single-page buffer
         * (OOB read). Drop such frames silently; the descriptor is still
         * recycled below so the ring head/index stay in sync. */
        if (rlen >= 18 && rlen <= RX_BUF_SIZE)  /* 14 hdr + 4 fcs */
            netdev_rx_deliver(dev, p->rx_buf_va[slot],
                              (uint16_t)(rlen - 4));

        /* Hand the descriptor back to the chip. */
        uint32_t new_opts1 = DESC_OWN | RX_BUF_SIZE;
        if (slot == NUM_RX_DESC - 1)
            new_opts1 |= DESC_RING_END;
        p->rx_ring[slot].opts2 = 0;
        arch_wmb();
        p->rx_ring[slot].opts1 = new_opts1;
        arch_wmb();

        p->rx_head++;
    }
}
