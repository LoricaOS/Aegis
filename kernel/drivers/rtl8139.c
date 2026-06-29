/* rtl8139.c — RealTek RTL8139 Fast Ethernet driver
 *
 * The RTL8139 receives into a single flat circular buffer (RBSTART) rather than
 * a descriptor ring: the chip DMAs packets linearly, each prefixed by a 4-byte
 * header (status + length). This requires a PHYSICALLY CONTIGUOUS receive
 * buffer — pmm_alloc_contig_low() provides it. Transmit uses four descriptors
 * (TSAD/TSD) round-robin, each with its own bounce buffer.
 *
 * MMIO (BAR1), polled at 100 Hz, interrupts masked. RX is recycled into the
 * ring by advancing CAPR. Registers on netdev_t as "eth0".
 *
 * References: RTL8139 Programming Guide; RTL8139D datasheet.
 */
#include "rtl8139.h"
#include "netdev.h"
#include "pcie.h"
#include "arch.h"
#include "kva.h"
#include "vmm.h"
#include "pmm.h"
#include "printk.h"
#include "spinlock.h"
#include <stdint.h>
#include <stddef.h>

#define RTL8139_VENDOR  0x10ECu
#define RTL8139_DEVICE  0x8139u

/* MMIO register offsets. */
#define REG_MAC0    0x00u   /* 6 bytes */
#define REG_TSD0    0x10u   /* TxStatus0..3 at +0x00/04/08/0C */
#define REG_TSAD0   0x20u   /* TxAddr0..3   at +0x00/04/08/0C */
#define REG_RBSTART 0x30u   /* receive buffer physical base */
#define REG_CR      0x37u   /* command */
#define REG_CAPR    0x38u   /* current address of packet read */
#define REG_CBR     0x3Au   /* current buffer address (write ptr) */
#define REG_IMR     0x3Cu
#define REG_ISR     0x3Eu
#define REG_TCR     0x40u
#define REG_RCR     0x44u
#define REG_CONFIG1 0x52u

/* Command register bits. */
#define CR_RST      0x10u
#define CR_RE       0x08u   /* receiver enable */
#define CR_TE       0x04u   /* transmitter enable */
#define CR_BUFE     0x01u   /* receive buffer empty (1 = nothing to read) */

/* Receive Configuration Register. */
#define RCR_AAP     0x01u   /* accept all (promiscuous) */
#define RCR_APM     0x02u   /* accept physical match */
#define RCR_AM      0x04u   /* accept multicast */
#define RCR_AB      0x08u   /* accept broadcast */
#define RCR_WRAP    0x80u   /* wrapped writes (needs pad past the ring end) */

/* Receive status (header word 0). */
#define RX_ROK      0x0001u

/* TxStatus bits. */
#define TSD_OWN     0x2000u /* 1 = DMA done / descriptor free */
#define TSD_TOK     0x8000u /* transmit OK */

/* 8 KiB ring (RBLEN=00) + 16-byte header slack + 1500 WRAP overflow pad. */
#define RX_RING_SIZE   8192u
#define RX_BUF_BYTES   (RX_RING_SIZE + 16u + 1536u)
#define RX_BUF_PAGES   ((RX_BUF_BYTES + 4095u) / 4096u)

#define TX_DESC        4u
#define TX_SPINS       100000u

static volatile uint8_t *s_mmio;
static uint8_t  *s_rx_buf;            /* KVA of the contiguous RX ring */
static uint32_t  s_rx_offset;        /* read cursor within the 8K ring */
static uint8_t  *s_tx_buf[TX_DESC];
static uint64_t  s_tx_buf_pa[TX_DESC];
static uint16_t  s_tx_cur;
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

static inline uint8_t  r8 (uint32_t o) { return *(volatile uint8_t  *)(s_mmio + o); }
static inline uint16_t r16(uint32_t o) { return *(volatile uint16_t *)(s_mmio + o); }
static inline uint32_t r32(uint32_t o) { return *(volatile uint32_t *)(s_mmio + o); }
static inline void w8 (uint32_t o, uint8_t  v) { *(volatile uint8_t  *)(s_mmio + o) = v; }
static inline void w16(uint32_t o, uint16_t v) { *(volatile uint16_t *)(s_mmio + o) = v; }
static inline void w32(uint32_t o, uint32_t v) { *(volatile uint32_t *)(s_mmio + o) = v; }

/* Map n_pages of WB-cached RAM at contiguous phys base pa into KVA. */
static uint8_t *
map_ram(uint64_t pa, uint32_t n_pages)
{
    uintptr_t va = (uintptr_t)kva_alloc_pages(n_pages);
    if (!va)
        return NULL;
    for (uint32_t i = 0; i < n_pages; i++) {
        uintptr_t pv = va + (uint64_t)i * 4096;
        vmm_unmap_page(pv);
        vmm_map_page(pv, pa + (uint64_t)i * 4096,
                     VMM_FLAG_PRESENT | VMM_FLAG_WRITABLE);  /* WB cached */
    }
    return (uint8_t *)va;
}

static int  rtl8139_send(netdev_t *dev, const void *pkt, uint16_t len);
static void rtl8139_poll(netdev_t *dev);

void
rtl8139_init(void)
{
    const pcie_device_t *found = NULL;
    int count = pcie_device_count();
    for (int i = 0; i < count; i++) {
        const pcie_device_t *d = &pcie_get_devices()[i];
        if (d->vendor_id == RTL8139_VENDOR && d->device_id == RTL8139_DEVICE) {
            found = d;
            break;
        }
    }
    if (!found)
        return;   /* silent: no RTL8139 present */

    uint32_t cmd = pcie_read32(found->bus, found->dev, found->fn, 0x04);
    pcie_write32(found->bus, found->dev, found->fn, 0x04,
                 cmd | (1u << 1) | (1u << 2));   /* mem space + bus master */

    /* BAR1 = MMIO register window (BAR0 is I/O, which we avoid). */
    s_mmio = kva_map_mmio(found->bar[1] & ~0xFFFULL, 1);
    if (!s_mmio)
        return;

    /* Power on, then soft reset. */
    w8(REG_CONFIG1, 0x00);
    w8(REG_CR, CR_RST);
    for (uint32_t spin = 0; (r8(REG_CR) & CR_RST) && spin < 1000000u; spin++)
        arch_pause();

    /* MAC from IDR0..5. */
    for (int i = 0; i < 6; i++)
        s_dev.mac[i] = r8(REG_MAC0 + (uint32_t)i);

    /* Contiguous RX ring (8K+16+pad) — flat buffer the chip DMAs into. */
    uint64_t rx_pa = pmm_alloc_contig_low(RX_BUF_PAGES);
    if (rx_pa == 0)
        return;
    s_rx_buf = map_ram(rx_pa, RX_BUF_PAGES);
    if (!s_rx_buf)
        return;
    s_rx_offset = 0;

    /* TX bounce buffers (one page each; scattered is fine — per-descriptor). */
    for (uint32_t i = 0; i < TX_DESC; i++) {
        uint64_t pa = pmm_alloc_page_low();
        if (pa == 0)
            return;
        s_tx_buf_pa[i] = pa;
        s_tx_buf[i] = map_ram(pa, 1);
        if (!s_tx_buf[i])
            return;
    }
    s_tx_cur = 0;
    s_tx_lock = (spinlock_t)SPINLOCK_INIT;
    s_tx_drops = 0;

    /* Mask interrupts (we poll); clear any pending. */
    w16(REG_IMR, 0x0000);
    w16(REG_ISR, 0xFFFF);

    /* Program the RX ring base + reset read cursor. CAPR is biased by 16. */
    w32(REG_RBSTART, (uint32_t)rx_pa);
    w16(REG_CAPR, (uint16_t)(0u - 16u));

    /* RX config: accept all (promiscuous — SLIRP is point-to-point, matches the
     * virtio-net/e1000 model), WRAP on, 8K ring, unlimited DMA burst, no FIFO
     * threshold. */
    w32(REG_RCR, RCR_AAP | RCR_APM | RCR_AM | RCR_AB | RCR_WRAP |
                 (7u << 8) | (7u << 13));
    /* TX config: unlimited DMA burst, standard IFG. */
    w32(REG_TCR, (7u << 8) | (3u << 24));

    /* Enable RX + TX. */
    w8(REG_CR, CR_RE | CR_TE);

    s_dev.name[0]='e'; s_dev.name[1]='t'; s_dev.name[2]='h';
    s_dev.name[3]='0'; s_dev.name[4]='\0';
    s_dev.mtu  = 1500;
    s_dev.send = rtl8139_send;
    s_dev.poll = rtl8139_poll;
    s_dev.priv = NULL;
    netdev_register(&s_dev);

    printk("[NET] OK: rtl8139 eth0 mac=%x:%x:%x:%x:%x:%x\n",
           s_dev.mac[0], s_dev.mac[1], s_dev.mac[2],
           s_dev.mac[3], s_dev.mac[4], s_dev.mac[5]);
}

static int
rtl8139_send(netdev_t *dev, const void *pkt, uint16_t len)
{
    (void)dev;
    if (pkt == NULL || len == 0u || len > 1514u)
        return -1;

    irqflags_t fl = spin_lock_irqsave(&s_tx_lock);

    uint16_t idx = s_tx_cur;
    uint32_t tsd = REG_TSD0 + (uint32_t)idx * 4u;
    /* Reuse this descriptor only once the chip has finished its prior frame
     * (OWN set). On the first four sends OWN may be clear; the bounded spin
     * tolerates that and just proceeds. */
    if (!(r32(tsd) & TSD_OWN)) {
        uint32_t spin;
        for (spin = 0; spin < TX_SPINS && !(r32(tsd) & TSD_OWN); spin++)
            arch_pause();
    }

    _memcpy(s_tx_buf[idx], pkt, len);
    /* RTL8139 pads runts itself only if length >= 60; pad short frames to the
     * 60-byte Ethernet minimum so the wire frame is valid. */
    uint16_t xlen = len < 60u ? 60u : len;
    for (uint16_t z = len; z < xlen; z++)
        s_tx_buf[idx][z] = 0;

    w32(REG_TSAD0 + (uint32_t)idx * 4u, (uint32_t)s_tx_buf_pa[idx]);
    arch_wmb();
    /* Writing the length (with OWN clear) starts the transfer. */
    w32(tsd, (uint32_t)xlen & 0x1FFFu);

    s_tx_cur = (uint16_t)((idx + 1u) % TX_DESC);
    spin_unlock_irqrestore(&s_tx_lock, fl);
    (void)s_tx_drops;
    return 0;
}

static void
rtl8139_poll(netdev_t *dev)
{
    /* Drain the ring while it is not empty (BUFE == 0). */
    while (!(r8(REG_CR) & CR_BUFE)) {
        uint8_t *p = s_rx_buf + s_rx_offset;
        uint16_t status = (uint16_t)(p[0] | (p[1] << 8));
        uint16_t len    = (uint16_t)(p[2] | (p[3] << 8));  /* includes 4B CRC */

        static uint8_t rx_copy[2048];
        uint16_t dlen = 0;
        if ((status & RX_ROK) && len >= 4u + 14u && len <= sizeof(rx_copy) + 4u) {
            dlen = (uint16_t)(len - 4u);   /* strip CRC */
            _memcpy(rx_copy, p + 4, dlen);
        } else if (len == 0u || len > RX_BUF_BYTES) {
            /* Corrupt header — bail to avoid runaway; resync to CBR. */
            s_rx_offset = (uint32_t)r16(REG_CBR) % RX_RING_SIZE;
            break;
        }

        /* Advance the read cursor: 4-byte header + payload, dword-aligned. */
        s_rx_offset = (s_rx_offset + len + 4u + 3u) & ~3u;
        s_rx_offset %= RX_RING_SIZE;
        /* CAPR is the read pointer minus 16 (hardware quirk). */
        w16(REG_CAPR, (uint16_t)(s_rx_offset - 16u));

        if (dlen)
            netdev_rx_deliver(dev, rx_copy, dlen);
    }
}
