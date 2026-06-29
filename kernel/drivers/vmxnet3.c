/* vmxnet3.c — VMware vmxnet3 paravirtual NIC driver
 *
 * The VMware paravirtual Ethernet device (also emulated by QEMU `-device
 * vmxnet3`). Two MMIO BARs: BAR0 = PT (doorbells + interrupt mask), BAR1 = VD
 * (version/command/MAC/DSA registers). The driver hands the device a
 * Vmxnet3_DriverShared structure (DSAL/DSAH) describing one TX and one RX
 * queue, then issues ACTIVATE_DEV. TX/RX use descriptor rings with a generation
 * bit that flips each time the ring wraps; completion rings report finished
 * descriptors. Polled (interrupts masked), registers on netdev_t as "eth0".
 *
 * Struct layouts match QEMU's hw/net/vmxnet3.h exactly (sizes pinned by
 * _Static_assert); QEMU validates the magic + queue counts + MTU but NOT the
 * driver version or GOS, and ACTIVATE_DEV read-back of 0 means success.
 *
 * References: QEMU hw/net/vmxnet3.{c,h}; Linux drivers/net/vmxnet3.
 */
#include "vmxnet3.h"
#include "netdev.h"
#include "pcie.h"
#include "arch.h"
#include "kva.h"
#include "vmm.h"
#include "printk.h"
#include "spinlock.h"
#include "../lib/string.h"
#include <stdint.h>
#include <stddef.h>

#define VMXNET3_VENDOR  0x15ADu
#define VMXNET3_DEVICE  0x07B0u

/* BAR1 (VD) registers. */
#define VD_VRRS   0x00u
#define VD_UVRS   0x08u
#define VD_DSAL   0x10u
#define VD_DSAH   0x18u
#define VD_CMD    0x20u
#define VD_MACL   0x28u
#define VD_MACH   0x30u
/* BAR0 (PT) registers. */
#define PT_IMR    0x00u
#define PT_TXPROD 0x600u
#define PT_RXPROD 0x800u
#define PT_RXPROD2 0xA00u

#define CMD_ACTIVATE_DEV 0xCAFE0000u
#define CMD_RESET_DEV    0xCAFE0002u

#define VMXNET3_REV1_MAGIC  0xbabefee1u
#define VMXNET3_IC_DISABLE_ALL 0x1u
#define INIT_GEN  1u

#define VMXNET3_RXM_UCAST   0x01u
#define VMXNET3_RXM_BCAST   0x04u
#define VMXNET3_RXM_PROMISC 0x10u

/* Ring sizes (must be multiples of 32). */
#define TX_RING   32u
#define TX_COMP   32u
#define RX0_RING  32u
#define RX1_RING  32u
#define RX_COMP   64u
#define BUF_LEN   2048u

/* ── DriverShared ABI structs (QEMU hw/net/vmxnet3.h) ─────────────────────── */
typedef struct __attribute__((packed)) {
    uint32_t version, gos, vmxnet3RevSpt, uptVerSpt;
} vmxnet3_driver_info_t;

typedef struct __attribute__((packed)) {
    vmxnet3_driver_info_t driverInfo;
    uint64_t uptFeatures, ddPA, queueDescPA;
    uint32_t ddLen, queueDescLen, mtu;
    uint16_t maxNumRxSG;
    uint8_t  numTxQueues, numRxQueues;
    uint32_t reserved[4];
} vmxnet3_misc_conf_t;
_Static_assert(sizeof(vmxnet3_misc_conf_t) == 72, "MiscConf");

typedef struct __attribute__((packed)) {
    uint8_t  autoMask, numIntrs, eventIntrIdx, modLevels[25];
    uint32_t intrCtrl, reserved[2];
} vmxnet3_intr_conf_t;
_Static_assert(sizeof(vmxnet3_intr_conf_t) == 40, "IntrConf");

typedef struct __attribute__((packed)) {
    uint32_t rxMode;
    uint16_t mfTableLen, _pad1;
    uint64_t mfTablePA;
    uint32_t vfTable[128];
} vmxnet3_rx_filter_conf_t;
_Static_assert(sizeof(vmxnet3_rx_filter_conf_t) == 528, "RxFilterConf");

typedef struct __attribute__((packed)) {
    uint32_t confVer, confLen;
    uint64_t confPA;
} vmxnet3_varlen_t;

typedef struct __attribute__((packed)) {
    vmxnet3_misc_conf_t misc;
    vmxnet3_intr_conf_t intrConf;
    vmxnet3_rx_filter_conf_t rxFilterConf;
    vmxnet3_varlen_t rss, pm, plugin;
} vmxnet3_ds_dev_read_t;
_Static_assert(sizeof(vmxnet3_ds_dev_read_t) == 688, "DSDevRead");

typedef struct __attribute__((packed)) {
    uint32_t magic, pad;
    vmxnet3_ds_dev_read_t devRead;
    uint32_t ecr, reserved[5];
} vmxnet3_driver_shared_t;
_Static_assert(sizeof(vmxnet3_driver_shared_t) == 720, "DriverShared");

typedef struct __attribute__((packed)) {
    uint64_t txRingBasePA, dataRingBasePA, compRingBasePA, ddPA, reserved;
    uint32_t txRingSize, dataRingSize, compRingSize, ddLen;
    uint8_t  intrIdx, _pad[7];
} vmxnet3_tx_queue_conf_t;
_Static_assert(sizeof(vmxnet3_tx_queue_conf_t) == 64, "TxQueueConf");

typedef struct __attribute__((packed)) {
    uint64_t rxRingBasePA[2], compRingBasePA, ddPA, reserved;
    uint32_t rxRingSize[2], compRingSize, ddLen;
    uint8_t  intrIdx, _pad[7];
} vmxnet3_rx_queue_conf_t;
_Static_assert(sizeof(vmxnet3_rx_queue_conf_t) == 64, "RxQueueConf");

typedef struct __attribute__((packed)) { uint32_t txNumDeferred, txThreshold; uint64_t reserved; } vmxnet3_tx_queue_ctrl_t;
typedef struct __attribute__((packed)) { uint8_t updateRxProd, _pad[7]; uint64_t reserved; } vmxnet3_rx_queue_ctrl_t;
typedef struct __attribute__((packed)) { uint8_t stopped, _pad[3]; uint32_t error; } vmxnet3_queue_status_t;
typedef struct __attribute__((packed)) { uint64_t s[10]; } vmxnet3_stats_t;

typedef struct __attribute__((packed)) {
    vmxnet3_tx_queue_ctrl_t ctrl;
    vmxnet3_tx_queue_conf_t conf;
    vmxnet3_queue_status_t  status;
    vmxnet3_stats_t         stats;
    uint8_t _pad[88];
} vmxnet3_tx_queue_desc_t;
_Static_assert(sizeof(vmxnet3_tx_queue_desc_t) == 256, "TxQueueDesc");

typedef struct __attribute__((packed)) {
    vmxnet3_rx_queue_ctrl_t ctrl;
    vmxnet3_rx_queue_conf_t conf;
    vmxnet3_queue_status_t  status;
    vmxnet3_stats_t         stats;
    uint8_t _pad[88];
} vmxnet3_rx_queue_desc_t;
_Static_assert(sizeof(vmxnet3_rx_queue_desc_t) == 256, "RxQueueDesc");

/* Ring descriptors (16 bytes each), accessed via explicit words. */
typedef struct __attribute__((packed)) { uint64_t addr; uint32_t word2, word3; } vmxnet3_desc_t;
typedef struct __attribute__((packed)) { uint32_t w0, w1, w2, w3; } vmxnet3_comp_t;

/* ── Driver state ─────────────────────────────────────────────────────────── */
static volatile uint8_t *s_bar0, *s_bar1;
static vmxnet3_desc_t *s_tx_ring, *s_rx0_ring, *s_rx1_ring;
static vmxnet3_comp_t *s_tx_comp, *s_rx_comp;
static uint8_t  *s_tx_buf[TX_RING];   static uint64_t s_tx_buf_pa[TX_RING];
static uint8_t  *s_rx0_buf[RX0_RING]; static uint64_t s_rx0_buf_pa[RX0_RING];
static uint8_t  *s_rx1_buf[RX1_RING]; static uint64_t s_rx1_buf_pa[RX1_RING];
static uint32_t s_tx_prod, s_tx_gen, s_tx_comp_next, s_tx_comp_gen;
static uint32_t s_rx0_fill, s_rx0_repost_gen, s_rx_comp_next, s_rx_comp_gen;
static spinlock_t s_tx_lock;
static netdev_t  s_dev;


static inline uint32_t r0(uint32_t o){ return *(volatile uint32_t *)(s_bar0+o); }
static inline void w0r(uint32_t o, uint32_t v){ *(volatile uint32_t *)(s_bar0+o)=v; }
static inline uint32_t r1(uint32_t o){ return *(volatile uint32_t *)(s_bar1+o); }
static inline void w1r(uint32_t o, uint32_t v){ *(volatile uint32_t *)(s_bar1+o)=v; }

static int alloc_dma(uint64_t *pa, uintptr_t *va)
{
    void *p = kva_alloc_pages_low(1);
    if (!p) return -1;
    *va = (uintptr_t)p; *pa = kva_page_phys(p);
    uint8_t *z=(uint8_t*)*va; for (uint32_t i=0;i<4096;i++) z[i]=0;
    return 0;
}

static int  vmxnet3_send(netdev_t *dev, const void *pkt, uint16_t len);
static void vmxnet3_poll(netdev_t *dev);

void
vmxnet3_init(void)
{
    const pcie_device_t *d = NULL;
    int cnt = pcie_device_count();
    for (int i=0;i<cnt;i++){ const pcie_device_t *x=&pcie_get_devices()[i];
        if (x->vendor_id==VMXNET3_VENDOR && x->device_id==VMXNET3_DEVICE){ d=x; break; } }
    if (!d) return;

    uint32_t cmd = pcie_read32(d->bus,d->dev,d->fn,0x04);
    pcie_write32(d->bus,d->dev,d->fn,0x04, cmd|(1u<<1)|(1u<<2));

    s_bar0 = kva_map_mmio(d->bar[0] & ~0xFFFULL, 4);   /* PT: doorbells up to 0xA00 */
    s_bar1 = kva_map_mmio(d->bar[1] & ~0xFFFULL, 1);   /* VD */
    if (!s_bar0 || !s_bar1) return;

    w1r(VD_CMD, CMD_RESET_DEV);

    /* Version select: read supported revisions, write the chosen one. */
    uint32_t vrrs = r1(VD_VRRS);
    if (!(vrrs & 1u)) return;
    w1r(VD_VRRS, 1);
    uint32_t uvrs = r1(VD_UVRS);
    if (!(uvrs & 1u)) return;
    w1r(VD_UVRS, 1);

    uint32_t macl = r1(VD_MACL), mach = r1(VD_MACH);
    s_dev.mac[0]=(uint8_t)macl; s_dev.mac[1]=(uint8_t)(macl>>8);
    s_dev.mac[2]=(uint8_t)(macl>>16); s_dev.mac[3]=(uint8_t)(macl>>24);
    s_dev.mac[4]=(uint8_t)mach; s_dev.mac[5]=(uint8_t)(mach>>8);

    /* Allocate control structures + rings (each fits one page). */
    uint64_t ds_pa, qd_pa, txr_pa, txc_pa, rx0_pa, rx1_pa, rxc_pa;
    uintptr_t ds_va, qd_va, txr_va, txc_va, rx0_va, rx1_va, rxc_va;
    if (alloc_dma(&ds_pa,&ds_va)<0 || alloc_dma(&qd_pa,&qd_va)<0 ||
        alloc_dma(&txr_pa,&txr_va)<0 || alloc_dma(&txc_pa,&txc_va)<0 ||
        alloc_dma(&rx0_pa,&rx0_va)<0 || alloc_dma(&rx1_pa,&rx1_va)<0 ||
        alloc_dma(&rxc_pa,&rxc_va)<0)
        return;
    s_tx_ring=(vmxnet3_desc_t*)txr_va; s_tx_comp=(vmxnet3_comp_t*)txc_va;
    s_rx0_ring=(vmxnet3_desc_t*)rx0_va; s_rx1_ring=(vmxnet3_desc_t*)rx1_va;
    s_rx_comp=(vmxnet3_comp_t*)rxc_va;

    /* Buffers. */
    for (uint32_t i=0;i<TX_RING;i++){ uintptr_t v; if (alloc_dma(&s_tx_buf_pa[i],&v)<0) return; s_tx_buf[i]=(uint8_t*)v; }
    for (uint32_t i=0;i<RX0_RING;i++){ uintptr_t v; if (alloc_dma(&s_rx0_buf_pa[i],&v)<0) return; s_rx0_buf[i]=(uint8_t*)v; }
    for (uint32_t i=0;i<RX1_RING;i++){ uintptr_t v; if (alloc_dma(&s_rx1_buf_pa[i],&v)<0) return; s_rx1_buf[i]=(uint8_t*)v; }

    /* Queue descriptors: TxQueueDesc @ qd+0, RxQueueDesc @ qd+256. */
    vmxnet3_tx_queue_desc_t *tqd = (vmxnet3_tx_queue_desc_t *)qd_va;
    vmxnet3_rx_queue_desc_t *rqd = (vmxnet3_rx_queue_desc_t *)(qd_va + 256);
    tqd->conf.txRingBasePA = txr_pa;
    tqd->conf.compRingBasePA = txc_pa;
    tqd->conf.txRingSize = TX_RING;
    tqd->conf.compRingSize = TX_COMP;
    tqd->conf.intrIdx = 0;
    rqd->conf.rxRingBasePA[0] = rx0_pa;
    rqd->conf.rxRingBasePA[1] = rx1_pa;
    rqd->conf.compRingBasePA = rxc_pa;
    rqd->conf.rxRingSize[0] = RX0_RING;
    rqd->conf.rxRingSize[1] = RX1_RING;
    rqd->conf.compRingSize = RX_COMP;
    rqd->conf.intrIdx = 0;

    /* DriverShared. */
    vmxnet3_driver_shared_t *ds = (vmxnet3_driver_shared_t *)ds_va;
    ds->magic = VMXNET3_REV1_MAGIC;
    ds->devRead.misc.driverInfo.version = 1;
    ds->devRead.misc.driverInfo.gos = 2u | (1u << 2);   /* BITS_64 | TYPE_LINUX */
    ds->devRead.misc.driverInfo.vmxnet3RevSpt = 1;
    ds->devRead.misc.driverInfo.uptVerSpt = 1;
    ds->devRead.misc.queueDescPA = qd_pa;
    ds->devRead.misc.queueDescLen = 512;
    ds->devRead.misc.mtu = 1500;
    ds->devRead.misc.maxNumRxSG = 1;
    ds->devRead.misc.numTxQueues = 1;
    ds->devRead.misc.numRxQueues = 1;
    ds->devRead.intrConf.numIntrs = 1;
    ds->devRead.intrConf.intrCtrl = VMXNET3_IC_DISABLE_ALL;
    ds->devRead.rxFilterConf.rxMode =
        VMXNET3_RXM_UCAST | VMXNET3_RXM_BCAST | VMXNET3_RXM_PROMISC;
    for (int i=0;i<128;i++) ds->devRead.rxFilterConf.vfTable[i] = 0xFFFFFFFFu;

    /* Hand the shared structure to the device + activate. */
    w1r(VD_DSAL, (uint32_t)ds_pa);
    w1r(VD_DSAH, (uint32_t)(ds_pa >> 32));
    arch_wmb();
    w1r(VD_CMD, CMD_ACTIVATE_DEV);
    uint32_t act = r1(VD_CMD);
    if (act != 0) {
        printk("[NET] WARN: vmxnet3 ACTIVATE_DEV failed (cmd=%x)\n", act);
        return;
    }
    w0r(PT_IMR, 1);   /* mask interrupt 0 (we poll) */

    /* Fill RX ring 0 (HEAD buffers, gen=INIT_GEN) + ring 1 (BODY buffers). */
    for (uint32_t i=0;i<RX0_RING;i++){
        s_rx0_ring[i].addr = s_rx0_buf_pa[i];
        s_rx0_ring[i].word3 = 0;
        arch_wmb();
        s_rx0_ring[i].word2 = (BUF_LEN & 0x3FFFu) | (0u<<14) | (INIT_GEN<<31);
    }
    for (uint32_t i=0;i<RX1_RING;i++){
        s_rx1_ring[i].addr = s_rx1_buf_pa[i];
        s_rx1_ring[i].word3 = 0;
        arch_wmb();
        s_rx1_ring[i].word2 = (BUF_LEN & 0x3FFFu) | (1u<<14) | (INIT_GEN<<31);
    }
    s_rx0_fill = 0; s_rx0_repost_gen = INIT_GEN ^ 1u;
    s_rx_comp_next = 0; s_rx_comp_gen = INIT_GEN;
    s_tx_prod = 0; s_tx_gen = INIT_GEN; s_tx_comp_next = 0; s_tx_comp_gen = INIT_GEN;
    s_tx_lock = (spinlock_t)SPINLOCK_INIT;
    arch_wmb();
    w0r(PT_RXPROD, RX0_RING - 1u);
    w0r(PT_RXPROD2, RX1_RING - 1u);

    s_dev.name[0]='e'; s_dev.name[1]='t'; s_dev.name[2]='h';
    s_dev.name[3]='0'; s_dev.name[4]='\0';
    s_dev.mtu = 1500; s_dev.send = vmxnet3_send; s_dev.poll = vmxnet3_poll;
    s_dev.priv = NULL;
    netdev_register(&s_dev);

    printk("[NET] OK: vmxnet3 eth0 mac=%x:%x:%x:%x:%x:%x\n",
           s_dev.mac[0],s_dev.mac[1],s_dev.mac[2],s_dev.mac[3],s_dev.mac[4],s_dev.mac[5]);
}

static void
vmxnet3_tx_reap(void)
{
    while ((s_tx_comp[s_tx_comp_next].w3 >> 31) == s_tx_comp_gen) {
        s_tx_comp_next++;
        if (s_tx_comp_next == TX_COMP) { s_tx_comp_next = 0; s_tx_comp_gen ^= 1u; }
    }
}

static int
vmxnet3_send(netdev_t *dev, const void *pkt, uint16_t len)
{
    (void)dev;
    if (pkt==NULL || len==0u || len>1514u) return -1;
    irqflags_t fl = spin_lock_irqsave(&s_tx_lock);
    vmxnet3_tx_reap();

    uint32_t idx = s_tx_prod;
    kmemcpy(s_tx_buf[idx], pkt, len);
    s_tx_ring[idx].addr  = s_tx_buf_pa[idx];
    s_tx_ring[idx].word3 = (1u<<12) | (1u<<13);          /* EOP | CQ */
    arch_wmb();
    s_tx_ring[idx].word2 = (len & 0x3FFFu) | (s_tx_gen<<14);  /* gen last */
    arch_wmb();

    s_tx_prod++;
    if (s_tx_prod == TX_RING) { s_tx_prod = 0; s_tx_gen ^= 1u; }
    w0r(PT_TXPROD, s_tx_prod);

    spin_unlock_irqrestore(&s_tx_lock, fl);
    return 0;
}

static void
vmxnet3_poll(netdev_t *dev)
{
    while ((s_rx_comp[s_rx_comp_next].w3 >> 31) == s_rx_comp_gen) {
        uint32_t w0v = s_rx_comp[s_rx_comp_next].w0;
        uint32_t w2v = s_rx_comp[s_rx_comp_next].w2;
        uint32_t rxdIdx = w0v & 0xFFFu;
        uint32_t eop = (w0v >> 14) & 1u;
        uint32_t len = w2v & 0x3FFFu;
        uint32_t err = (w2v >> 14) & 1u;

        static uint8_t rx_copy[BUF_LEN];
        uint16_t dlen = 0;
        if (!err && eop && rxdIdx < RX0_RING && len >= 14u && len <= BUF_LEN) {
            dlen = (uint16_t)len;
            kmemcpy(rx_copy, s_rx0_buf[rxdIdx], dlen);
        }

        /* Re-post the consumed ring-0 descriptor (gen flips per lap). */
        if (rxdIdx < RX0_RING) {
            s_rx0_ring[rxdIdx].addr = s_rx0_buf_pa[rxdIdx];
            s_rx0_ring[rxdIdx].word3 = 0;
            arch_wmb();
            s_rx0_ring[rxdIdx].word2 =
                (BUF_LEN & 0x3FFFu) | (0u<<14) | (s_rx0_repost_gen<<31);
            if (rxdIdx == RX0_RING - 1u) s_rx0_repost_gen ^= 1u;
            s_rx0_fill = (rxdIdx + 1u) % RX0_RING;
        }

        s_rx_comp_next++;
        if (s_rx_comp_next == RX_COMP) { s_rx_comp_next = 0; s_rx_comp_gen ^= 1u; }

        if (dlen)
            netdev_rx_deliver(dev, rx_copy, dlen);
    }
    arch_wmb();
    w0r(PT_RXPROD, s_rx0_fill);

    irqflags_t fl = spin_lock_irqsave(&s_tx_lock);
    vmxnet3_tx_reap();
    spin_unlock_irqrestore(&s_tx_lock, fl);
}
