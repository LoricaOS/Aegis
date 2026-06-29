/* e1000.c — Intel 8254x / 82540 Gigabit Ethernet driver (QEMU "e1000")
 *
 * Legacy 16-byte descriptor rings, BAR0 MMIO, polled at 100 Hz from the PIT
 * (interrupts masked). Mirrors the virtio-net model: RX descriptors are
 * recycled BEFORE the frame is delivered (delivery may synchronously TX a reply
 * — recycling first prevents a single inbound packet being reprocessed). TX is
 * a ring with bounce buffers; a slot is reused only after the device marks it
 * done (DD), with bounded backpressure.
 *
 * DMA: descriptor rings + buffers live in <4GB cached RAM (x86 PCI DMA is
 * cache-coherent); a store fence orders descriptor writes before the MMIO
 * doorbell. MMIO BAR is mapped uncached.
 *
 * References: Intel 8254x Software Developer's Manual (PCI/PCI-X Family GbE).
 */
#include "e1000.h"
#include "netdev.h"
#include "pcie.h"
#include "arch.h"
#include "kva.h"
#include "vmm.h"
#include "printk.h"
#include "spinlock.h"
#include <stdint.h>
#include <stddef.h>

/* ── PCI identity ─────────────────────────────────────────────────────────── */
#define E1000_VENDOR_INTEL  0x8086u
/* Classic 8254x/82540-family device ids sharing this legacy register layout.
 * (e1000e / 82574 0x10D3 has differences and is intentionally left out.) */
static const uint16_t e1000_ids[] = {
    0x100Eu, /* 82540EM — QEMU default "e1000" */
    0x100Fu, /* 82545EM */
    0x1010u, /* 82546EB */
    0x1015u, /* 82540EP */
    0x1004u, /* 82543GC */
    0x100Cu, /* 82544GC */
    0x10D3u, /* 82574L — QEMU "e1000e"; exposes the same legacy descriptor
              * registers, so the polled legacy path works (we mask its MSI-X). */
};

/* ── Register offsets ─────────────────────────────────────────────────────── */
#define E1000_CTRL    0x0000u
#define E1000_STATUS  0x0008u
#define E1000_EERD    0x0014u
#define E1000_ICR     0x00C0u
#define E1000_IMS     0x00D0u
#define E1000_IMC     0x00D8u
#define E1000_RCTL    0x0100u
#define E1000_TCTL    0x0400u
#define E1000_TIPG    0x0410u
#define E1000_RDBAL   0x2800u
#define E1000_RDBAH   0x2804u
#define E1000_RDLEN   0x2808u
#define E1000_RDH     0x2810u
#define E1000_RDT     0x2818u
#define E1000_TDBAL   0x3800u
#define E1000_TDBAH   0x3804u
#define E1000_TDLEN   0x3808u
#define E1000_TDH     0x3810u
#define E1000_TDT     0x3818u
#define E1000_MTA     0x5200u   /* 128 × u32 multicast table */
#define E1000_RAL0    0x5400u
#define E1000_RAH0    0x5404u

/* CTRL */
#define CTRL_SLU      0x00000040u   /* set link up */
#define CTRL_ASDE     0x00000020u   /* auto-speed detect enable */
#define CTRL_LRST     0x00000008u
#define CTRL_PHY_RST  0x80000000u
#define CTRL_RST      0x04000000u
/* RCTL */
#define RCTL_EN       0x00000002u
#define RCTL_UPE      0x00000008u   /* unicast promiscuous */
#define RCTL_MPE      0x00000010u   /* multicast promiscuous */
#define RCTL_BAM      0x00008000u   /* broadcast accept */
#define RCTL_SECRC    0x04000000u   /* strip Ethernet CRC */
/* (BSIZE 2048 = bits 00, BSEX 0 — the reset default) */
/* TCTL */
#define TCTL_EN       0x00000002u
#define TCTL_PSP      0x00000008u   /* pad short packets */
#define TCTL_CT       0x000000F0u   /* collision threshold 0x0F */
#define TCTL_COLD     0x0003F000u   /* collision distance (full duplex) */
/* descriptor status/cmd */
#define RXD_STAT_DD   0x01u
#define RXD_STAT_EOP  0x02u
#define TXD_CMD_EOP   0x01u
#define TXD_CMD_IFCS  0x02u
#define TXD_CMD_RS    0x08u
#define TXD_STAT_DD   0x01u
/* RAH address-valid */
#define RAH_AV        0x80000000u

#define E1000_RX_DESC   32u
#define E1000_TX_DESC   32u
#define E1000_BUF_SIZE  2048u
#define E1000_TX_SPINS  100000u

typedef struct __attribute__((packed)) {
    uint64_t addr;
    uint16_t length;
    uint16_t checksum;
    uint8_t  status;
    uint8_t  errors;
    uint16_t special;
} e1000_rx_desc_t;

typedef struct __attribute__((packed)) {
    uint64_t addr;
    uint16_t length;
    uint8_t  cso;
    uint8_t  cmd;
    uint8_t  status;
    uint8_t  css;
    uint16_t special;
} e1000_tx_desc_t;

static volatile uint8_t *s_mmio;

static volatile e1000_rx_desc_t *s_rx_ring;
static volatile e1000_tx_desc_t *s_tx_ring;
static uint8_t  *s_rx_buf[E1000_RX_DESC];
static uint8_t  *s_tx_buf[E1000_TX_DESC];
static uint64_t  s_tx_buf_pa[E1000_TX_DESC];
static uint64_t  s_rx_buf_pa[E1000_RX_DESC];

static uint16_t  s_rx_cur;
static uint16_t  s_tx_tail;
static spinlock_t s_tx_lock;
static uint32_t  s_tx_drops;

static netdev_t  s_dev;

static void
_memcpy(void *dst, const void *src, uint32_t n)
{
    uint8_t *d = dst;
    const uint8_t *s = src;
    while (n--)
        *d++ = *s++;
}

static inline uint32_t
e1000_read(uint32_t reg)
{
    return *(volatile uint32_t *)(s_mmio + reg);
}

static inline void
e1000_write(uint32_t reg, uint32_t val)
{
    *(volatile uint32_t *)(s_mmio + reg) = val;
}

/* Allocate one <4GB cached DMA page; return phys, va. -1 on exhaustion. */
static int
alloc_dma_page(uint64_t *pa, uintptr_t *va)
{
    void *p = kva_alloc_pages_low(1);
    if (!p)
        return -1;
    *va = (uintptr_t)p;
    *pa = kva_page_phys(p);
    return 0;
}

static uint16_t
eeprom_read(uint8_t addr)
{
    /* 82540 EERD: START bit0, ADDR bits 15:8, DONE bit4, DATA bits 31:16. */
    e1000_write(E1000_EERD, ((uint32_t)addr << 8) | 1u);
    uint32_t v;
    uint32_t budget = 0;
    do {
        v = e1000_read(E1000_EERD);
    } while (!(v & 0x10u) && ++budget < 1000000u);
    return (uint16_t)(v >> 16);
}

static int  e1000_send(netdev_t *dev, const void *pkt, uint16_t len);
static void e1000_poll(netdev_t *dev);

void
e1000_init(void)
{
    const pcie_device_t *found = NULL;
    int count = pcie_device_count();
    int i;
    for (i = 0; i < count && !found; i++) {
        const pcie_device_t *d = &pcie_get_devices()[i];
        if (d->vendor_id != E1000_VENDOR_INTEL)
            continue;
        unsigned k;
        for (k = 0; k < sizeof(e1000_ids) / sizeof(e1000_ids[0]); k++) {
            if (d->device_id == e1000_ids[k]) {
                found = d;
                break;
            }
        }
    }
    if (!found)
        return;   /* silent: no e1000 present */

    /* Enable PCI memory space + bus mastering — the NIC DMAs. */
    uint32_t cmd = pcie_read32(found->bus, found->dev, found->fn, 0x04);
    pcie_write32(found->bus, found->dev, found->fn, 0x04,
                 cmd | (1u << 1) | (1u << 2));

    s_mmio = kva_map_mmio(found->bar[0] & ~0xFFFULL, 16);
    if (!s_mmio)
        return;

    /* Mask all interrupts (we poll), reset, mask again. */
    e1000_write(E1000_IMC, 0xFFFFFFFFu);
    e1000_write(E1000_CTRL, e1000_read(E1000_CTRL) | CTRL_RST);
    /* RST self-clears once the reset completes (~µs in QEMU); spin-wait for it. */
    uint32_t spin = 0;
    while ((e1000_read(E1000_CTRL) & CTRL_RST) && ++spin < 1000000u)
        arch_pause();
    e1000_write(E1000_IMC, 0xFFFFFFFFu);

    /* Bring the link up; clear soft/PHY reset. */
    e1000_write(E1000_CTRL,
                (e1000_read(E1000_CTRL) | CTRL_SLU | CTRL_ASDE) &
                ~(CTRL_LRST | CTRL_PHY_RST));

    /* Clear the multicast table. */
    for (i = 0; i < 128; i++)
        e1000_write(E1000_MTA + (uint32_t)i * 4u, 0);

    /* MAC: prefer the receive-address registers (QEMU populates them from the
     * EEPROM at reset); fall back to a direct EEPROM read. */
    uint32_t ral = e1000_read(E1000_RAL0);
    uint32_t rah = e1000_read(E1000_RAH0);
    if (ral == 0 && (rah & 0xFFFFu) == 0) {
        uint16_t w0 = eeprom_read(0), w1 = eeprom_read(1), w2 = eeprom_read(2);
        ral = (uint32_t)w0 | ((uint32_t)w1 << 16);
        rah = (uint32_t)w2;
    }
    s_dev.mac[0] = (uint8_t)ral;
    s_dev.mac[1] = (uint8_t)(ral >> 8);
    s_dev.mac[2] = (uint8_t)(ral >> 16);
    s_dev.mac[3] = (uint8_t)(ral >> 24);
    s_dev.mac[4] = (uint8_t)rah;
    s_dev.mac[5] = (uint8_t)(rah >> 8);
    /* Re-arm the unicast filter (AV) in case reset cleared it. */
    e1000_write(E1000_RAL0, ral);
    e1000_write(E1000_RAH0, (rah & 0xFFFFu) | RAH_AV);

    /* ── RX ring ─────────────────────────────────────────────────────────── */
    uint64_t  ring_pa;
    uintptr_t ring_va;
    if (alloc_dma_page(&ring_pa, &ring_va) < 0)
        return;
    s_rx_ring = (volatile e1000_rx_desc_t *)ring_va;

    uint64_t  pg_pa = 0;
    uintptr_t pg_va = 0;
    for (i = 0; i < (int)E1000_RX_DESC; i++) {
        if ((i & 1) == 0) {                 /* two 2048B buffers per page */
            if (alloc_dma_page(&pg_pa, &pg_va) < 0)
                return;
        }
        uint32_t off = (uint32_t)(i & 1) * E1000_BUF_SIZE;
        s_rx_buf[i]    = (uint8_t *)(pg_va + off);
        s_rx_buf_pa[i] = pg_pa + off;
        s_rx_ring[i].addr   = s_rx_buf_pa[i];
        s_rx_ring[i].status = 0;
    }
    e1000_write(E1000_RDBAL, (uint32_t)ring_pa);
    e1000_write(E1000_RDBAH, (uint32_t)(ring_pa >> 32));
    e1000_write(E1000_RDLEN, E1000_RX_DESC * (uint32_t)sizeof(e1000_rx_desc_t));
    e1000_write(E1000_RDH, 0);
    e1000_write(E1000_RDT, E1000_RX_DESC - 1u);
    s_rx_cur = 0;
    /* Promiscuous unicast/multicast: SLIRP and emulated taps are point-to-point
     * and only queue frames meant for us, so accept all (matches virtio-net,
     * which has no hardware MAC filter). The RAL/RAH unicast filter alone proved
     * unreliable in QEMU — unicast ARP replies were silently dropped. */
    e1000_write(E1000_RCTL,
                RCTL_EN | RCTL_UPE | RCTL_MPE | RCTL_BAM | RCTL_SECRC);

    /* ── TX ring ─────────────────────────────────────────────────────────── */
    if (alloc_dma_page(&ring_pa, &ring_va) < 0)
        return;
    s_tx_ring = (volatile e1000_tx_desc_t *)ring_va;
    for (i = 0; i < (int)E1000_TX_DESC; i++) {
        if ((i & 1) == 0) {
            if (alloc_dma_page(&pg_pa, &pg_va) < 0)
                return;
        }
        uint32_t off = (uint32_t)(i & 1) * E1000_BUF_SIZE;
        s_tx_buf[i]    = (uint8_t *)(pg_va + off);
        s_tx_buf_pa[i] = pg_pa + off;
        s_tx_ring[i].addr   = 0;
        s_tx_ring[i].status = TXD_STAT_DD;   /* mark free */
    }
    e1000_write(E1000_TDBAL, (uint32_t)ring_pa);
    e1000_write(E1000_TDBAH, (uint32_t)(ring_pa >> 32));
    e1000_write(E1000_TDLEN, E1000_TX_DESC * (uint32_t)sizeof(e1000_tx_desc_t));
    e1000_write(E1000_TDH, 0);
    e1000_write(E1000_TDT, 0);
    s_tx_tail = 0;
    s_tx_lock = (spinlock_t)SPINLOCK_INIT;
    s_tx_drops = 0;
    e1000_write(E1000_TIPG, 0x0060200Au);
    e1000_write(E1000_TCTL, TCTL_EN | TCTL_PSP | TCTL_CT | TCTL_COLD);

    s_dev.name[0]='e'; s_dev.name[1]='t'; s_dev.name[2]='h';
    s_dev.name[3]='0'; s_dev.name[4]='\0';
    s_dev.mtu  = 1500;
    s_dev.send = e1000_send;
    s_dev.poll = e1000_poll;
    s_dev.priv = NULL;
    netdev_register(&s_dev);

    printk("[NET] OK: e1000 eth0 mac=%x:%x:%x:%x:%x:%x\n",
           s_dev.mac[0], s_dev.mac[1], s_dev.mac[2],
           s_dev.mac[3], s_dev.mac[4], s_dev.mac[5]);
}

static int
e1000_send(netdev_t *dev, const void *pkt, uint16_t len)
{
    (void)dev;
    if (pkt == NULL || len == 0u || len > 1514u)
        return -1;

    irqflags_t fl = spin_lock_irqsave(&s_tx_lock);

    uint16_t idx = s_tx_tail;
    /* Reuse this slot only once the device has finished its previous frame. */
    if (!(s_tx_ring[idx].status & TXD_STAT_DD)) {
        uint32_t spin;
        for (spin = 0; spin < E1000_TX_SPINS &&
                       !(s_tx_ring[idx].status & TXD_STAT_DD); spin++)
            arch_pause();
        if (!(s_tx_ring[idx].status & TXD_STAT_DD)) {
            uint32_t n = ++s_tx_drops;
            spin_unlock_irqrestore(&s_tx_lock, fl);
            if ((n & (n - 1u)) == 0u)
                printk("[NET] WARN: e1000 TX ring full, frame dropped "
                       "(total=%u)\n", n);
            return -1;
        }
    }

    _memcpy(s_tx_buf[idx], pkt, len);
    s_tx_ring[idx].addr    = s_tx_buf_pa[idx];
    s_tx_ring[idx].length  = len;
    s_tx_ring[idx].cso     = 0;
    s_tx_ring[idx].cmd     = TXD_CMD_EOP | TXD_CMD_IFCS | TXD_CMD_RS;
    s_tx_ring[idx].status  = 0;   /* device sets DD when sent */
    s_tx_ring[idx].css     = 0;
    s_tx_ring[idx].special = 0;

    s_tx_tail = (uint16_t)((idx + 1u) % E1000_TX_DESC);
    arch_wmb();                   /* descriptor before the doorbell */
    e1000_write(E1000_TDT, s_tx_tail);

    spin_unlock_irqrestore(&s_tx_lock, fl);
    return 0;
}

static void
e1000_poll(netdev_t *dev)
{
    while (s_rx_ring[s_rx_cur].status & RXD_STAT_DD) {
        static uint8_t rx_copy[E1000_BUF_SIZE];
        uint8_t  st  = s_rx_ring[s_rx_cur].status;
        uint16_t len = s_rx_ring[s_rx_cur].length;
        uint16_t dlen = 0;

        /* Accept any complete frame. The errors byte is NOT gated on: QEMU's
         * e1000 leaves stale/garbage in it for good frames (observed 0x89/0x29
         * on valid DHCP/ARP packets), and dropping on it silently discarded
         * unicast ARP replies. Upper layers (IP/UDP/TCP) validate checksums —
         * matching virtio-net, which has no hardware error field at all. */
        if ((st & RXD_STAT_EOP) && len >= 14u && len <= E1000_BUF_SIZE) {
            dlen = len;
            _memcpy(rx_copy, s_rx_buf[s_rx_cur], dlen);
        }

        /* Recycle the descriptor BEFORE delivering (delivery may TX a reply). */
        s_rx_ring[s_rx_cur].status = 0;
        uint16_t done = s_rx_cur;
        s_rx_cur = (uint16_t)((s_rx_cur + 1u) % E1000_RX_DESC);
        arch_wmb();
        e1000_write(E1000_RDT, done);

        if (dlen)
            netdev_rx_deliver(dev, rx_copy, dlen);
    }
}
