/*
 * rp1.c — Raspberry Pi RP1 southbridge access on native Pi 5.
 *
 * The RP1 hosts the USB-A ports, gigabit Ethernet, GPIO, PWM (the fan), etc. It
 * is a PCIe endpoint (1de4:0001) on domain 2 (pcie@1000120000). With
 * `pciex4_reset=0` in config.txt the stock firmware leaves the RP1's PCIe link
 * AND its PLLs up before OS handoff, so from bare metal we do NOT bring up the
 * PCIe RC or the RP1 PLLs — we just map its single BAR1 register window and, per
 * peripheral, enable a clock gate + de-assert a reset.
 *
 * BAR1 window: CPU-phys 0x1f_00000000 (DTB pcie@1000120000 ranges: PCIe 0x0 ->
 * CPU 0x1f_00000000). Every peripheral is a flat offset from there:
 *   SYSINFO 0x000000, RESETS 0x014000, CLOCKS 0x018000, PWM1 0x09c000,
 *   IO_BANK0/1/2 0x0d0000/4000/8000, SYS_RIO0/1/2 0x0e0000/4000/8000,
 *   PADS_BANK0 0x0f0000, ETH 0x100000, PCIE_APBS(MSI-X) 0x108000,
 *   USB dwc3 0x200000/0x300000.
 *
 * Step 0 (this file, for now): map the window and read SYSINFO.CHIP_ID. It must
 * read 0x20001927 (C0 silicon; 0x10001927 = B0). SYSINFO is always-on, so a
 * correct value proves the domain-2 outbound window works with zero clock/reset
 * dependencies — the gate everything else (fan, USB, Ethernet) hangs on.
 */

#include "arch.h"
#include "printk.h"
#include "kva.h"
#include "netdev.h"
#include <stdint.h>

#define RP1_BAR1_PHYS      0x1f00000000UL
#define RP1_WINDOW_PAGES   0x400          /* 4 MiB — the full BAR1 (reaches dwc3 @ 0x200000) */

#define RP1_SYSINFO_BASE   0x000000
#define RP1_CHIP_ID_OFF    0x00
#define RP1_CHIP_ID_C0     0x20001927u
#define RP1_CHIP_ID_B0     0x10001927u

int pcie_rp1_map_window(void);            /* native/pcie_brcmstb.c — domain-2 outbound win */
int vc_get_mac(uint8_t mac[6]);           /* native/vc_mailbox_fb.c — board MAC via mailbox */

static volatile uint8_t *s_rp1;           /* KVA base of the BAR1 window, or NULL */

/* rp1_reg — byte-offset accessor into the mapped RP1 window (32-bit regs). */
static inline volatile uint32_t *
rp1_reg(uint32_t off)
{
    return (volatile uint32_t *)(s_rp1 + off);
}

static inline void     rp1_w(uint32_t off, uint32_t v) { *rp1_reg(off) = v; }
static inline uint32_t rp1_r(uint32_t off)             { return *rp1_reg(off); }

/* RP1 GPIO/PAD/RIO for bank 2 (GPIOs 34-53). Per-pin CTRL @ bank+n*8+4
 * (FUNCSEL in bits[4:0]); pad @ pads+4+n*4 (OUT_DISABLE=bit7); RIO OUT@+0, OE@+4
 * with atomic SET@+0x2000 / CLR@+0x3000 aliases. */
#define RP1_IO_BANK2    0x0d8000
#define RP1_RIO2        0x0e8000
#define RP1_PADS2       0x0f8000
#define RP1_ATOM_SET    0x2000
#define RP1_ATOM_CLR    0x3000
#define RP1_FSEL_GPIO   0x05
#define RP1_PAD_OUT_DIS (1u << 7)
#define FAN_PIN         11          /* GPIO45 (FAN_PWM) = bank2 local pin 11 */

/* rp1_fan_full — spin the Pi 5 fan at full. The FAN_PWM line is inverted
 * (firmware drives it HIGH to STOP the fan), so full speed = pin driven LOW.
 * Drive GPIO45 as a plain GPIO output held low — no PWM peripheral/clock. */
static void
rp1_fan_full(void)
{
    uint32_t ctrl = rp1_r(RP1_IO_BANK2 + FAN_PIN * 8 + 4);
    rp1_w(RP1_IO_BANK2 + FAN_PIN * 8 + 4, (ctrl & ~0x1Fu) | RP1_FSEL_GPIO);
    uint32_t pad = rp1_r(RP1_PADS2 + 4 + FAN_PIN * 4);
    rp1_w(RP1_PADS2 + 4 + FAN_PIN * 4, pad & ~RP1_PAD_OUT_DIS);
    rp1_w(RP1_RIO2 + RP1_ATOM_SET + 0x04, 1u << FAN_PIN);   /* output-enable */
    rp1_w(RP1_RIO2 + RP1_ATOM_CLR + 0x00, 1u << FAN_PIN);   /* drive LOW = full */
    printk("[RP1] fan: GPIO45 low (full speed, inverted line)\n");
}

/* dwc3 host controllers (RP1 offsets 0x200000/0x300000). xHCI regs at the
 * controller base (+0), dwc3 globals at +0xc100 (GSNPSID @ +0xc120 reads the
 * Synopsys core id 0x5533xxxx). Step-0 USB probe: confirm the dwc3 answers
 * through the window before attempting host-mode bring-up. */
#define RP1_USB0        0x200000
#define DWC3_GSNPSID    0xc120

static void
rp1_usb_probe(void)
{
    uint32_t snpsid = rp1_r(RP1_USB0 + DWC3_GSNPSID);
    uint32_t cap    = rp1_r(RP1_USB0 + 0x00);         /* xHCI CAPLENGTH/HCIVERSION */
    printk("[RP1] usb0: dwc3 GSNPSID=0x%x  xhci CAPLENGTH=0x%x HCIVERSION=0x%x\n",
           snpsid, cap & 0xffu, (cap >> 16) & 0xffffu);
}

/* RP1 clocks bank (per-peripheral gates; PLLs already locked by firmware). */
#define RP1_CLOCKS        0x018000
#define CLK_ETH_CTRL      0x064
#define CLK_ETH_TSU_CTRL  0x134
#define CLK_CTRL_ENABLE   (1u << 11)
#define RP1_ETH_BASE      0x100000   /* Cadence GEM (cdns,macb) */
#define GEM_NCR           0x000      /* Network Control */
#define GEM_NCFGR         0x004      /* Network Config */
#define GEM_MID           0x0FC      /* Module ID (IDNUM=0x2 => GEM) */
#define GEM_DCFG1         0x280      /* Design Config Register 1 */
#define GEM_NSR           0x008      /* Network Status; bit2 = MDIO IDLE */
#define GEM_MAN           0x034      /* PHY Maintenance (MDIO) */
#define ETH_PHY_ADDR      1          /* ethernet-phy@1 (DTB) */

/* rp1_delay_ms — busy-wait using the physical counter (self-contained). */
static void
rp1_delay_ms(uint32_t ms)
{
    uint64_t freq, start, now;
    __asm__ volatile("mrs %0, cntfrq_el0" : "=r"(freq));
    __asm__ volatile("mrs %0, cntpct_el0" : "=r"(start));
    uint64_t target = start + (freq * ms) / 1000u;
    do { __asm__ volatile("mrs %0, cntpct_el0" : "=r"(now)); } while (now < target);
}

/* gem_mdio_wait — spin until the MDIO PHY-maintenance op finishes (NSR.IDLE). */
static void
gem_mdio_wait(void)
{
    for (int i = 0; i < 1000000; i++)
        if (rp1_r(RP1_ETH_BASE + GEM_NSR) & (1u << 2))
            break;
}

/* gem_mdio_read/write — Clause-22 MDIO via the GEM MAN register. */
static uint16_t
gem_mdio_read(uint8_t phy, uint8_t reg)
{
    rp1_w(RP1_ETH_BASE + GEM_MAN,
          (1u << 30) | (2u << 28) | ((phy & 0x1Fu) << 23) |
          ((reg & 0x1Fu) << 18) | (2u << 16));       /* SOF=01, OP=10(read) */
    gem_mdio_wait();
    return (uint16_t)(rp1_r(RP1_ETH_BASE + GEM_MAN) & 0xFFFFu);
}

static void
gem_mdio_write(uint8_t phy, uint8_t reg, uint16_t val)
{
    rp1_w(RP1_ETH_BASE + GEM_MAN,
          (1u << 30) | (1u << 28) | ((phy & 0x1Fu) << 23) |
          ((reg & 0x1Fu) << 18) | (2u << 16) | val);  /* SOF=01, OP=01(write) */
    gem_mdio_wait();
}

/* RP1 GEM DMA offset: IDENTITY (0). Read from the firmware's own known-good GEM
 * config after netboot — RBQP=0x3c320640, RBQPH=0 — a plain <4GB CPU-physical
 * address used directly as the bus address. So the RP1 inbound window is 1:1 for
 * the GEM (unlike the NVMe RC's +0x10_00000000). */
#define RP1_DMA_OFFSET    0x0ULL
#define GEM_DMACFG        0x010
#define MACB_RBQP         0x018
#define GEM_RBQPH         0x4D4
#define RX_DESCS          8
#define RX_BUFSZ          4096             /* one buffer per page (kva_page_phys = page base) */

/* rp1_eth_rx_test — bring up a minimal RX path and try to catch one frame off
 * the LAN's broadcast traffic (proves the GEM's non-coherent DMA works). Ring +
 * buffers are Normal-NC (uncached, so no cache maintenance vs the GEM's writes);
 * every address handed to the GEM carries the +0x10_00000000 inbound offset and
 * uses 64-bit addressing (ADDR64) since that puts it past 32 bits. */
/* ── GEM as a netdev: persistent RX/TX rings + registration ────────────── */

#define GEM_TBQP     0x01c
#define GEM_TBQPH    0x4C8
#define GEM_SA1B     0x098
#define GEM_SA1T     0x09C
#define NCR_TSTART   (1u << 9)

#define TX_DESCS     4            /* >1 so the GEM's wrap-prefetch hits a USED desc */

static struct {
    volatile uint32_t *rx_ring;   /* RX_DESCS * 16B (Normal-NC) */
    uint8_t           *rx_bufs;   /* RX_DESCS pages, one buffer each */
    uint32_t           rx_head;
    volatile uint32_t *tx_ring;   /* TX_DESCS * 16B */
    uint8_t           *tx_bufs;   /* TX_DESCS pages */
    uint32_t           tx_prod;
    netdev_t           dev;
} s_gem;

/* gem_poll — deliver received frames to the stack + re-arm descriptors. Called
 * from the PIT tick (100 Hz). Rings are Normal-NC, so no cache maintenance. */
static void
gem_poll(netdev_t *dev)
{
    (void)dev;
    for (int n = 0; n < RX_DESCS; n++) {
        uint32_t i = s_gem.rx_head;
        if (!(s_gem.rx_ring[i*4] & 0x1u))          /* USED not set → no frame */
            break;
        uint16_t len = (uint16_t)(s_gem.rx_ring[i*4 + 1] & 0x1FFFu);
        uint8_t *buf = s_gem.rx_bufs + (uint64_t)i * RX_BUFSZ;
        if (len >= 14 && len <= RX_BUFSZ)
            netdev_rx_deliver(&s_gem.dev, buf, len);
        uint64_t bd = kva_page_phys(buf) + RP1_DMA_OFFSET;
        s_gem.rx_ring[i*4] = (uint32_t)bd | (i == RX_DESCS - 1 ? 0x2u : 0u); /* USED=0 */
        s_gem.rx_head = (i + 1) % RX_DESCS;
    }
}

/* gem_send — transmit one Ethernet frame. Waits (bounded) for the previous TX
 * to complete, then hands the frame to the GEM and rings TSTART. Returns 0. */
static int
gem_send(netdev_t *dev, const void *pkt, uint16_t len)
{
    (void)dev;
    if (len < 14 || len > RX_BUFSZ) return -1;
    uint32_t i = s_gem.tx_prod;
    for (int t = 0; t < 200000; t++)               /* this slot free (USED set)? */
        if (s_gem.tx_ring[i*4 + 1] & (1u << 31)) break;
    uint8_t *buf = s_gem.tx_bufs + (uint64_t)i * RX_BUFSZ;
    __builtin_memcpy(buf, pkt, len);
    uint64_t bd = kva_page_phys(buf) + RP1_DMA_OFFSET;
    s_gem.tx_ring[i*4 + 0] = (uint32_t)bd;
    s_gem.tx_ring[i*4 + 2] = (uint32_t)(bd >> 32);
    s_gem.tx_ring[i*4 + 3] = 0;
    /* len | LAST, USED=0 (hand to GEM); WRAP only on the last ring slot. */
    s_gem.tx_ring[i*4 + 1] = (uint32_t)len | (1u << 15) |
                             (i == TX_DESCS - 1 ? (1u << 30) : 0u);
    __asm__ volatile("dsb sy" ::: "memory");
    rp1_w(RP1_ETH_BASE + GEM_NCR, rp1_r(RP1_ETH_BASE + GEM_NCR) | NCR_TSTART);
    s_gem.tx_prod = (i + 1) % TX_DESCS;
    return 0;
}

/* gem_setup — allocate persistent RX/TX rings, program the GEM, register a
 * netdev. Called once after the PHY link is up. */
static void
gem_setup(void)
{
    s_gem.rx_ring = (volatile uint32_t *)kva_alloc_pages_low_nc(1);
    s_gem.rx_bufs = (uint8_t *)kva_alloc_pages_low_nc(RX_DESCS);
    s_gem.tx_ring = (volatile uint32_t *)kva_alloc_pages_low_nc(1);
    s_gem.tx_bufs = (uint8_t *)kva_alloc_pages_low_nc(TX_DESCS);
    if (!s_gem.rx_ring || !s_gem.rx_bufs || !s_gem.tx_ring || !s_gem.tx_bufs) {
        printk("[RP1] eth: netdev alloc failed\n"); return;
    }
    s_gem.rx_head = 0;
    s_gem.tx_prod = 0;

    for (int i = 0; i < RX_DESCS; i++) {
        uint64_t bd = kva_page_phys(s_gem.rx_bufs + (uint64_t)i * RX_BUFSZ) + RP1_DMA_OFFSET;
        s_gem.rx_ring[i*4 + 0] = (uint32_t)bd | (i == RX_DESCS - 1 ? 0x2u : 0u);
        s_gem.rx_ring[i*4 + 1] = 0;
        s_gem.rx_ring[i*4 + 2] = (uint32_t)(bd >> 32);
        s_gem.rx_ring[i*4 + 3] = 0;
    }
    /* TX ring: all descriptors start USED=1 (SW owns, nothing to send); WRAP on
     * the last so the GEM's ring pointer wraps but idles on USED descriptors. */
    for (int i = 0; i < TX_DESCS; i++) {
        uint64_t tb = kva_page_phys(s_gem.tx_bufs + (uint64_t)i * RX_BUFSZ) + RP1_DMA_OFFSET;
        s_gem.tx_ring[i*4 + 0] = (uint32_t)tb;
        s_gem.tx_ring[i*4 + 1] = (1u << 31) | (i == TX_DESCS - 1 ? (1u << 30) : 0u);
        s_gem.tx_ring[i*4 + 2] = (uint32_t)(tb >> 32);
        s_gem.tx_ring[i*4 + 3] = 0;
    }
    __asm__ volatile("dsb sy" ::: "memory");

    uint64_t rd = kva_page_phys((void *)s_gem.rx_ring) + RP1_DMA_OFFSET;
    uint64_t td = kva_page_phys((void *)s_gem.tx_ring) + RP1_DMA_OFFSET;
    rp1_w(RP1_ETH_BASE + 0x020, 0xF);             /* clear stale RSR */
    rp1_w(RP1_ETH_BASE + GEM_DMACFG, 0x4020071fu);
    rp1_w(RP1_ETH_BASE + MACB_RBQP, (uint32_t)rd);
    rp1_w(RP1_ETH_BASE + GEM_RBQPH, (uint32_t)(rd >> 32));
    rp1_w(RP1_ETH_BASE + GEM_TBQP, (uint32_t)td);
    rp1_w(RP1_ETH_BASE + GEM_TBQPH, (uint32_t)(td >> 32));

    /* MAC via the VideoCore mailbox (firmware clears the GEM address filter). */
    if (vc_get_mac(s_gem.dev.mac) != 0)
        printk("[RP1] eth: mailbox MAC fetch failed\n");
    uint32_t sab = s_gem.dev.mac[0] | ((uint32_t)s_gem.dev.mac[1] << 8) |
                   ((uint32_t)s_gem.dev.mac[2] << 16) | ((uint32_t)s_gem.dev.mac[3] << 24);
    uint32_t sat = s_gem.dev.mac[4] | ((uint32_t)s_gem.dev.mac[5] << 8);
    rp1_w(RP1_ETH_BASE + GEM_SA1B, sab);     /* program our unicast filter */
    rp1_w(RP1_ETH_BASE + GEM_SA1T, sat);     /* (writing SA1T activates it)  */
    rp1_w(RP1_ETH_BASE + GEM_NCR,
          rp1_r(RP1_ETH_BASE + GEM_NCR) | (1u << 2) | (1u << 3) | (1u << 4)); /* RE|TE|MPE */

    s_gem.dev.name[0]='e'; s_gem.dev.name[1]='t'; s_gem.dev.name[2]='h';
    s_gem.dev.name[3]='0'; s_gem.dev.name[4]='\0';
    s_gem.dev.mtu  = 1500;
    s_gem.dev.send = gem_send;
    s_gem.dev.poll = gem_poll;
    netdev_register(&s_gem.dev);
    printk("[RP1] eth0: up, MAC %x:%x:%x:%x:%x:%x — registered as netdev\n",
           s_gem.dev.mac[0], s_gem.dev.mac[1], s_gem.dev.mac[2],
           s_gem.dev.mac[3], s_gem.dev.mac[4], s_gem.dev.mac[5]);
}

/* rp1_eth_probe — step-0 for Ethernet: enable the GEM's clock gates (unlike USB,
 * the Ethernet clocks may be off at handoff) and dump identification registers
 * to confirm the Cadence GEM is reachable + clocked. */
static void
rp1_eth_probe(void)
{
    rp1_w(RP1_CLOCKS + CLK_ETH_CTRL,     rp1_r(RP1_CLOCKS + CLK_ETH_CTRL)     | CLK_CTRL_ENABLE);
    rp1_w(RP1_CLOCKS + CLK_ETH_TSU_CTRL, rp1_r(RP1_CLOCKS + CLK_ETH_TSU_CTRL) | CLK_CTRL_ENABLE);
    printk("[RP1] eth: MID=0x%x NCR=0x%x NCFGR=0x%x DCFG1=0x%x\n",
           rp1_r(RP1_ETH_BASE + GEM_MID),   rp1_r(RP1_ETH_BASE + GEM_NCR),
           rp1_r(RP1_ETH_BASE + GEM_NCFGR), rp1_r(RP1_ETH_BASE + GEM_DCFG1));
    uint16_t id1 = gem_mdio_read(ETH_PHY_ADDR, 2);   /* PHYID1 */
    uint16_t id2 = gem_mdio_read(ETH_PHY_ADDR, 3);   /* PHYID2 */
    /* Firmware tears the network down after netboot ("Stopping network"), so
     * the link is dropped at handoff. Restart auto-negotiation (BMCR: ANEG
     * enable bit12 + restart bit9) and give it time to complete. */
    gem_mdio_write(ETH_PHY_ADDR, 0, 0x1200);
    rp1_delay_ms(4000);
    (void)gem_mdio_read(ETH_PHY_ADDR, 1);            /* BMSR link bit latches low */
    uint16_t bmsr = gem_mdio_read(ETH_PHY_ADDR, 1);
    printk("[RP1] eth: PHY@%u id=0x%x%x BMSR=0x%x link=%u autoneg_done=%u\n",
           ETH_PHY_ADDR, id1, id2, bmsr, (bmsr >> 2) & 1u, (bmsr >> 5) & 1u);
    if (bmsr & (1u << 2))              /* link up → bring up the netdev */
        gem_setup();
}

/* rp1_init — map the BAR1 window and verify the chip is reachable. Leaves
 * s_rp1 set on success so later peripheral bring-up (fan/USB/eth) can reuse it.
 * Returns 1 if the RP1 answered with a known chip id, 0 otherwise. */
int
rp1_init(void)
{
    /* Firmware (pciex4_reset=0) trained the link but left no usable outbound
     * window — program one on pcie2 first, else the read below returns poison. */
    if (!pcie_rp1_map_window()) {
        printk("[RP1] skip: no domain-2 outbound window\n");
        return 0;
    }

    s_rp1 = (volatile uint8_t *)kva_map_mmio(RP1_BAR1_PHYS, RP1_WINDOW_PAGES);
    if (!s_rp1) {
        printk("[RP1] FAIL: could not map BAR1 window at 0x%lx\n", RP1_BAR1_PHYS);
        return 0;
    }

    uint32_t id = *rp1_reg(RP1_SYSINFO_BASE + RP1_CHIP_ID_OFF);
    if (id == RP1_CHIP_ID_C0 || id == RP1_CHIP_ID_B0) {
        printk("[RP1] OK: CHIP_ID 0x%x — reachable over PCIe (firmware-configured)\n",
               id);
        rp1_fan_full();       /* thermal relief now that the RP1 is reachable */
        rp1_usb_probe();      /* step-0: is the dwc3 USB controller reachable? */
        rp1_eth_probe();      /* step-0: is the Cadence GEM reachable + clocked? */
        return 1;
    }

    printk("[RP1] WARN: CHIP_ID 0x%x (want 0x20001927) — outbound window/link not "
           "set up, or pciex4_reset!=0\n", id);
    s_rp1 = 0;      /* don't let peripheral code touch a bad window */
    return 0;
}
