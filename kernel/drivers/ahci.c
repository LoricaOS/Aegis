/* ahci.c — AHCI 1.x SATA host controller driver
 *
 * Single-port, single-command-slot, synchronous (poll-in-call) — the same
 * model as nvme.c / virtio_blk.c. Uses the first SATA disk found. Data transfer
 * is scatter-gather via the PRDT (one entry per bounce page), so no contiguous
 * data buffer is required; the command list / received-FIS / command table each
 * fit in a single page.
 *
 * References: Serial ATA AHCI 1.3.1 Specification; ATA/ATAPI Command Set (ACS).
 */
#include "ahci.h"
#include "blkdev.h"
#include "pcie.h"
#include "arch.h"
#include "kva.h"
#include "vmm.h"
#include "pmm.h"
#include "printk.h"
#include "spinlock.h"
#include <stdint.h>
#include <stddef.h>

/* ── HBA generic host control registers (ABAR + offset) ───────────────────── */
#define HBA_CAP   0x00u
#define HBA_GHC   0x04u
#define HBA_IS    0x08u
#define HBA_PI    0x0Cu
#define HBA_VS    0x10u
#define GHC_AE    (1u << 31)   /* AHCI enable */

/* ── Port registers (ABAR + 0x100 + port*0x80 + offset) ───────────────────── */
#define PORT_CLB   0x00u
#define PORT_CLBU  0x04u
#define PORT_FB    0x08u
#define PORT_FBU   0x0Cu
#define PORT_IS    0x10u
#define PORT_IE    0x14u
#define PORT_CMD   0x18u
#define PORT_TFD   0x20u
#define PORT_SIG   0x24u
#define PORT_SSTS  0x28u
#define PORT_SCTL  0x2Cu
#define PORT_SERR  0x30u
#define PORT_SACT  0x34u
#define PORT_CI    0x38u

#define CMD_ST     (1u << 0)
#define CMD_FRE    (1u << 4)
#define CMD_FR     (1u << 14)
#define CMD_CR     (1u << 15)
#define TFD_BSY    0x80u
#define TFD_DRQ    0x08u
#define TFD_ERR    0x01u
#define SIG_SATA   0x00000101u

/* ATA commands. */
#define ATA_IDENTIFY        0xECu
#define ATA_READ_DMA_EXT    0x25u
#define ATA_WRITE_DMA_EXT   0x35u

#define AHCI_SECTOR     512u
#define AHCI_BOUNCE_PAGES 8u                          /* 32 KiB / 64 sectors */
#define AHCI_MAX_SECTORS  (AHCI_BOUNCE_PAGES * 4096u / AHCI_SECTOR)
#define AHCI_POLL_BUDGET  100000000u

typedef struct __attribute__((packed)) {
    uint16_t flags;     /* cfl[4:0], a[5], w[6], p[7], r[8], b[9], c[10], pmp[15:12] */
    uint16_t prdtl;     /* PRDT entry count */
    volatile uint32_t prdbc;
    uint32_t ctba;
    uint32_t ctbau;
    uint32_t rsv[4];
} hba_cmd_header_t;      /* 32 bytes */

typedef struct __attribute__((packed)) {
    uint32_t dba;
    uint32_t dbau;
    uint32_t rsv0;
    uint32_t dbc;       /* [21:0] byte count - 1, [31] interrupt-on-completion */
} hba_prdt_entry_t;     /* 16 bytes */

typedef struct __attribute__((packed)) {
    uint8_t cfis[64];
    uint8_t acmd[16];
    uint8_t rsv[48];
    hba_prdt_entry_t prdt[AHCI_BOUNCE_PAGES];
} hba_cmd_tbl_t;

static volatile uint8_t *s_abar;
static uint32_t  s_port_base;          /* 0x100 + port*0x80 */
static hba_cmd_header_t *s_clb;        /* command list (KVA) */
static hba_cmd_tbl_t    *s_ctbl;       /* command table 0 (KVA) */
static uint64_t  s_ctbl_pa;
static uint8_t  *s_bounce[AHCI_BOUNCE_PAGES];
static uint64_t  s_bounce_pa[AHCI_BOUNCE_PAGES];
static spinlock_t s_lock;
static blkdev_t  s_blk;

static void
_memcpy(void *dst, const void *src, uint32_t n)
{
    uint8_t *d = dst;
    const uint8_t *s = src;
    while (n--)
        *d++ = *s++;
}

static void
_memset(void *dst, int v, uint32_t n)
{
    uint8_t *d = dst;
    while (n--)
        *d++ = (uint8_t)v;
}

static inline uint32_t hba_r(uint32_t o) { return *(volatile uint32_t *)(s_abar + o); }
static inline void hba_w(uint32_t o, uint32_t v) { *(volatile uint32_t *)(s_abar + o) = v; }
static inline uint32_t pr(uint32_t o) { return hba_r(s_port_base + o); }
static inline void pw(uint32_t o, uint32_t v) { hba_w(s_port_base + o, v); }

static int
alloc_dma(uint64_t *pa, uintptr_t *va)
{
    void *p = kva_alloc_pages_low(1);
    if (!p)
        return -1;
    *va = (uintptr_t)p;
    *pa = kva_page_phys(p);
    _memset((void *)*va, 0, 4096);
    return 0;
}

/* Issue command slot 0 and wait for completion. Returns 0 on success, -1 on
 * device error or timeout. Caller holds s_lock. */
static int
ahci_run_slot0(void)
{
    /* Wait until the port is neither busy nor expecting data. */
    uint32_t spin = 0;
    while ((pr(PORT_TFD) & (TFD_BSY | TFD_DRQ)) && ++spin < AHCI_POLL_BUDGET)
        arch_pause();
    if (spin >= AHCI_POLL_BUDGET)
        return -1;

    pw(PORT_IS, 0xFFFFFFFFu);     /* clear pending interrupt status */
    arch_wmb();
    pw(PORT_CI, 1u);              /* issue slot 0 */

    spin = 0;
    while ((pr(PORT_CI) & 1u) && ++spin < AHCI_POLL_BUDGET) {
        if (pr(PORT_IS) & (1u << 30)) /* Task File Error Status */
            return -1;
        arch_pause();
    }
    if (spin >= AHCI_POLL_BUDGET)
        return -1;
    if (pr(PORT_TFD) & (TFD_ERR | TFD_BSY))
        return -1;
    return 0;
}

/* Build the slot-0 command header + FIS for an ATA command. nseg PRDT entries
 * must already be set in s_ctbl->prdt. write=1 sets the H2D write bit. */
static void
ahci_build(uint8_t command, uint64_t lba, uint16_t count, int write, int nseg)
{
    s_clb[0].flags = (uint16_t)(5u /* cfl: 5 dwords */ | (write ? (1u << 6) : 0u));
    s_clb[0].prdtl = (uint16_t)nseg;
    s_clb[0].prdbc = 0;
    s_clb[0].ctba  = (uint32_t)s_ctbl_pa;
    s_clb[0].ctbau = (uint32_t)(s_ctbl_pa >> 32);

    uint8_t *f = s_ctbl->cfis;
    _memset(f, 0, 20);
    f[0] = 0x27;                          /* FIS_TYPE_REG_H2D */
    f[1] = 0x80;                          /* C = 1 (command) */
    f[2] = command;
    f[4] = (uint8_t)(lba);
    f[5] = (uint8_t)(lba >> 8);
    f[6] = (uint8_t)(lba >> 16);
    f[7] = (command == ATA_IDENTIFY) ? 0x00u : 0x40u;  /* LBA mode */
    f[8] = (uint8_t)(lba >> 24);
    f[9] = (uint8_t)(lba >> 32);
    f[10] = (uint8_t)(lba >> 40);
    f[12] = (uint8_t)(count);
    f[13] = (uint8_t)(count >> 8);
}

static int
ahci_xfer(uint64_t lba, uint32_t nsec, int write)
{
    uint32_t nbytes = nsec * AHCI_SECTOR;
    uint32_t npages = (nbytes + 4095u) / 4096u;
    if (npages == 0 || npages > AHCI_BOUNCE_PAGES)
        return -1;

    uint32_t remaining = nbytes;
    for (uint32_t i = 0; i < npages; i++) {
        uint32_t seg = remaining < 4096u ? remaining : 4096u;
        s_ctbl->prdt[i].dba  = (uint32_t)s_bounce_pa[i];
        s_ctbl->prdt[i].dbau = (uint32_t)(s_bounce_pa[i] >> 32);
        s_ctbl->prdt[i].rsv0 = 0;
        s_ctbl->prdt[i].dbc  = (seg - 1u) & 0x3FFFFFu;
        remaining -= seg;
    }

    ahci_build(write ? ATA_WRITE_DMA_EXT : ATA_READ_DMA_EXT,
               lba, (uint16_t)nsec, write, (int)npages);
    return ahci_run_slot0();
}

static int
ahci_read(blkdev_t *dev, uint64_t lba, uint32_t count, void *buf)
{
    (void)dev;
    if (count == 0)
        return 0;
    uint8_t *out = (uint8_t *)buf;
    while (count > 0) {
        uint32_t chunk = count < AHCI_MAX_SECTORS ? count : AHCI_MAX_SECTORS;
        irqflags_t fl = spin_lock_irqsave(&s_lock);
        int rc = ahci_xfer(lba, chunk, 0);
        if (rc == 0) {
            uint32_t nbytes = chunk * AHCI_SECTOR, off = 0, pg = 0;
            while (off < nbytes) {
                uint32_t seg = (nbytes - off) < 4096u ? (nbytes - off) : 4096u;
                _memcpy(out + off, s_bounce[pg], seg);
                off += seg; pg++;
            }
        }
        spin_unlock_irqrestore(&s_lock, fl);
        if (rc < 0)
            return -1;
        out += chunk * AHCI_SECTOR; lba += chunk; count -= chunk;
    }
    return 0;
}

static int
ahci_write(blkdev_t *dev, uint64_t lba, uint32_t count, const void *buf)
{
    (void)dev;
    if (count == 0)
        return 0;
    const uint8_t *in = (const uint8_t *)buf;
    while (count > 0) {
        uint32_t chunk = count < AHCI_MAX_SECTORS ? count : AHCI_MAX_SECTORS;
        irqflags_t fl = spin_lock_irqsave(&s_lock);
        uint32_t nbytes = chunk * AHCI_SECTOR, off = 0, pg = 0;
        while (off < nbytes) {
            uint32_t seg = (nbytes - off) < 4096u ? (nbytes - off) : 4096u;
            _memcpy(s_bounce[pg], in + off, seg);
            off += seg; pg++;
        }
        int rc = ahci_xfer(lba, chunk, 1);
        spin_unlock_irqrestore(&s_lock, fl);
        if (rc < 0)
            return -1;
        in += chunk * AHCI_SECTOR; lba += chunk; count -= chunk;
    }
    return 0;
}

void
ahci_init(void)
{
    const pcie_device_t *d = pcie_find_device(0x01, 0x06, 0x01);  /* SATA AHCI */
    if (!d)
        return;

    uint32_t cmd = pcie_read32(d->bus, d->dev, d->fn, 0x04);
    pcie_write32(d->bus, d->dev, d->fn, 0x04, cmd | (1u << 1) | (1u << 2));

    /* ABAR is BAR5. Map 2 pages — port registers extend past one page. */
    s_abar = kva_map_mmio(d->bar[5] & ~0xFFFULL, 2);
    if (!s_abar)
        return;

    hba_w(HBA_GHC, hba_r(HBA_GHC) | GHC_AE);   /* enable AHCI */

    /* Find the first implemented port with a SATA disk present. */
    uint32_t pi = hba_r(HBA_PI);
    int port = -1;
    for (int p = 0; p < 32; p++) {
        if (!(pi & (1u << p)))
            continue;
        uint32_t base = 0x100u + (uint32_t)p * 0x80u;
        uint32_t ssts = hba_r(base + PORT_SSTS);
        if ((ssts & 0x0Fu) != 3u)                 /* DET: device + comm */
            continue;
        if (hba_r(base + PORT_SIG) != SIG_SATA)   /* SATA disk (not ATAPI) */
            continue;
        port = p;
        break;
    }
    if (port < 0)
        return;
    s_port_base = 0x100u + (uint32_t)port * 0x80u;

    /* Stop the port before reprogramming its pointers. */
    pw(PORT_CMD, pr(PORT_CMD) & ~(CMD_ST | CMD_FRE));
    uint32_t spin = 0;
    while ((pr(PORT_CMD) & (CMD_CR | CMD_FR)) && ++spin < 1000000u)
        arch_pause();

    /* Command list (1K, 32 headers), received-FIS (256B), command table 0. */
    uint64_t clb_pa, fis_pa; uintptr_t clb_va, fis_va, ctbl_va;
    if (alloc_dma(&clb_pa, &clb_va) < 0 ||
        alloc_dma(&fis_pa, &fis_va) < 0 ||
        alloc_dma(&s_ctbl_pa, &ctbl_va) < 0)
        return;
    s_clb  = (hba_cmd_header_t *)clb_va;
    s_ctbl = (hba_cmd_tbl_t *)ctbl_va;

    for (uint32_t i = 0; i < AHCI_BOUNCE_PAGES; i++) {
        uintptr_t bva;
        if (alloc_dma(&s_bounce_pa[i], &bva) < 0)
            return;
        s_bounce[i] = (uint8_t *)bva;
    }
    s_lock = (spinlock_t)SPINLOCK_INIT;

    pw(PORT_CLB, (uint32_t)clb_pa);
    pw(PORT_CLBU, (uint32_t)(clb_pa >> 32));
    pw(PORT_FB,  (uint32_t)fis_pa);
    pw(PORT_FBU, (uint32_t)(fis_pa >> 32));
    pw(PORT_SERR, 0xFFFFFFFFu);
    pw(PORT_IS, 0xFFFFFFFFu);

    /* Start: FIS receive enable, then command list. */
    pw(PORT_CMD, pr(PORT_CMD) | CMD_FRE);
    pw(PORT_CMD, pr(PORT_CMD) | CMD_ST);

    /* IDENTIFY DEVICE → capacity + model. */
    s_ctbl->prdt[0].dba  = (uint32_t)s_bounce_pa[0];
    s_ctbl->prdt[0].dbau = (uint32_t)(s_bounce_pa[0] >> 32);
    s_ctbl->prdt[0].rsv0 = 0;
    s_ctbl->prdt[0].dbc  = (512u - 1u);
    ahci_build(ATA_IDENTIFY, 0, 1, 0, 1);
    if (ahci_run_slot0() < 0)
        return;

    const uint16_t *id = (const uint16_t *)s_bounce[0];
    uint64_t sectors = (uint64_t)id[100] | ((uint64_t)id[101] << 16) |
                       ((uint64_t)id[102] << 32) | ((uint64_t)id[103] << 48);
    if (sectors == 0)
        sectors = (uint64_t)id[60] | ((uint64_t)id[61] << 16);  /* LBA28 */

    s_blk.name[0]='s'; s_blk.name[1]='a'; s_blk.name[2]='t';
    s_blk.name[3]='a'; s_blk.name[4]='0'; s_blk.name[5]='\0';
    s_blk.block_count = sectors;
    s_blk.block_size  = AHCI_SECTOR;
    s_blk.lba_offset  = 0;
    s_blk.read  = ahci_read;
    s_blk.write = ahci_write;
    s_blk.priv  = NULL;
    blkdev_register(&s_blk);

    printk("[AHCI] OK: sata0 port %u, %u sectors\n",
           (uint32_t)port, (uint32_t)sectors);
}
