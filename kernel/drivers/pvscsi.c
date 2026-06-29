/* pvscsi.c — VMware Paravirtual SCSI (PVSCSI) host adapter.
 *
 * VMware/vSphere's recommended high-performance SCSI controller, also offered
 * by QEMU (`-device pvscsi`) and VirtualBox. A ring-based paravirtual device
 * (like virtio): the driver places SCSI request descriptors on a request ring
 * in guest memory and rings a doorbell; the device writes completion
 * descriptors on a completion ring. We drive it synchronously (poll the
 * completion producer index) and register the first disk as blkdev "pvscsi0".
 *
 * Register/struct layout transcribed verbatim from QEMU hw/scsi/vmw_pvscsi.h
 * with _Static_assert on every struct size (the vmxnet3 lesson — paravirtual
 * ABIs are unforgiving). MMIO is BAR0; multi-byte DATA fields are the guest's
 * native LE (we run on x86), only the directory-style ring indices live in the
 * shared RingsState page.
 *
 * Reuses the same SCSI CDBs as virtio_scsi.c / ahci.c / xhci MSC.
 */
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

#define PVSCSI_VENDOR 0x15ADu
#define PVSCSI_DEVICE 0x07C0u

/* MMIO register offsets (BAR0). */
#define PVSCSI_REG_COMMAND        0x0000u
#define PVSCSI_REG_COMMAND_DATA   0x0004u
#define PVSCSI_REG_COMMAND_STATUS 0x0008u
#define PVSCSI_REG_INTR_STATUS    0x100Cu
#define PVSCSI_REG_INTR_MASK      0x2010u
#define PVSCSI_REG_KICK_NON_RW_IO 0x3014u
#define PVSCSI_REG_KICK_RW_IO     0x4018u

/* Commands. */
#define PVSCSI_CMD_ADAPTER_RESET 1u
#define PVSCSI_CMD_SETUP_RINGS   3u

/* Interrupt status bits. */
#define PVSCSI_INTR_CMPL_MASK 0x3u

/* Request flags. */
#define PVSCSI_FLAG_CMD_DIR_TOHOST   (1u << 3)
#define PVSCSI_FLAG_CMD_DIR_TODEVICE (1u << 4)

/* host (BTSTAT) success. */
#define PVSCSI_BTSTAT_SUCCESS 0x00u

#include "scsi.h"  /* SCSI CDB opcodes */

#define SECTOR        512u
#define MAX_SECTORS   8u            /* one 4 KiB contiguous bounce page */
#define POLL_BUDGET   100000000u

typedef struct __attribute__((packed)) {
    uint32_t reqRingNumPages;
    uint32_t cmpRingNumPages;
    uint64_t ringsStatePPN;
    uint64_t reqRingPPNs[32];
    uint64_t cmpRingPPNs[32];
} pvscsi_setup_rings_t;
_Static_assert(sizeof(pvscsi_setup_rings_t) == 528, "pvscsi setup_rings size");

typedef struct __attribute__((packed)) {
    uint32_t reqProdIdx;
    uint32_t reqConsIdx;
    uint32_t reqNumEntriesLog2;
    uint32_t cmpProdIdx;
    uint32_t cmpConsIdx;
    uint32_t cmpNumEntriesLog2;
    uint8_t  pad[104];
    uint32_t msgProdIdx;
    uint32_t msgConsIdx;
    uint32_t msgNumEntriesLog2;
} pvscsi_rings_state_t;
_Static_assert(sizeof(pvscsi_rings_state_t) == 140, "pvscsi rings_state size");

typedef struct __attribute__((packed)) {
    uint64_t context;
    uint64_t dataAddr;
    uint64_t dataLen;
    uint64_t senseAddr;
    uint32_t senseLen;
    uint32_t flags;
    uint8_t  cdb[16];
    uint8_t  cdbLen;
    uint8_t  lun[8];
    uint8_t  tag;
    uint8_t  bus;
    uint8_t  target;
    uint8_t  vcpuHint;
    uint8_t  unused[59];
} pvscsi_req_desc_t;
_Static_assert(sizeof(pvscsi_req_desc_t) == 128, "pvscsi req_desc size");

typedef struct __attribute__((packed)) {
    uint64_t context;
    uint64_t dataLen;
    uint32_t senseLen;
    uint16_t hostStatus;
    uint16_t scsiStatus;
    uint32_t pad[2];
} pvscsi_cmp_desc_t;
_Static_assert(sizeof(pvscsi_cmp_desc_t) == 32, "pvscsi cmp_desc size");

#define REQ_ENTRIES 32u            /* 4096 / 128 */
#define CMP_ENTRIES 128u           /* 4096 / 32  */
#define REQ_MASK   (REQ_ENTRIES - 1u)
#define CMP_MASK   (CMP_ENTRIES - 1u)

static volatile uint8_t      *s_mmio;
static pvscsi_rings_state_t  *s_rs;
static pvscsi_req_desc_t     *s_reqRing;
static pvscsi_cmp_desc_t     *s_cmpRing;
static uint8_t               *s_bounce;     /* one contiguous DMA page */
static uint64_t               s_bounce_pa;
static uint64_t               s_ctx;
static spinlock_t             s_lock;
static blkdev_t               s_blk;

static inline uint32_t rd(uint32_t o) { return *(volatile uint32_t *)(s_mmio + o); }
static inline void     wr(uint32_t o, uint32_t v) { *(volatile uint32_t *)(s_mmio + o) = v; }

static void
_memset(void *d, int v, uint32_t n)
{
    uint8_t *p = d;
    while (n--) *p++ = (uint8_t)v;
}
static void
_memcpy(void *d, const void *s, uint32_t n)
{
    uint8_t *dd = d; const uint8_t *ss = s;
    while (n--) *dd++ = *ss++;
}

/* Write a command and its data dwords to the command register pair. */
static void
pvscsi_command(uint32_t cmd, const uint32_t *data, uint32_t ndwords)
{
    wr(PVSCSI_REG_COMMAND, cmd);
    for (uint32_t i = 0; i < ndwords; i++)
        wr(PVSCSI_REG_COMMAND_DATA, data[i]);
}

/* Issue one SCSI command (single contiguous data buffer). data_len 0 = no data;
 * to_host picks the transfer direction. Returns 0 on GOOD status, -1 otherwise.
 * Caller holds s_lock. */
static int
pvscsi_exec(const uint8_t *cdb, uint8_t cdb_len, uint32_t data_len, int to_host)
{
    uint32_t prod = s_rs->reqProdIdx;
    pvscsi_req_desc_t *req = &s_reqRing[prod & REQ_MASK];
    _memset(req, 0, sizeof(*req));
    req->context  = ++s_ctx;
    req->dataAddr = data_len ? s_bounce_pa : 0;
    req->dataLen  = data_len;
    req->flags    = data_len
        ? (to_host ? PVSCSI_FLAG_CMD_DIR_TOHOST : PVSCSI_FLAG_CMD_DIR_TODEVICE)
        : 0u;
    _memcpy(req->cdb, cdb, cdb_len);
    req->cdbLen = cdb_len;
    /* bus 0, target 0, LUN 0 — all already zeroed. */

    arch_wmb();
    s_rs->reqProdIdx = prod + 1u;
    arch_wmb();
    wr(PVSCSI_REG_KICK_RW_IO, 0);

    uint32_t cons = s_rs->cmpConsIdx;
    int done = 0;
    for (uint32_t b = 0; b < POLL_BUDGET; b++) {
        if (s_rs->cmpProdIdx != cons) { done = 1; break; }
        arch_pause();
    }
    if (!done)
        return -1;

    pvscsi_cmp_desc_t *cmp = &s_cmpRing[cons & CMP_MASK];
    int ok = (cmp->hostStatus == PVSCSI_BTSTAT_SUCCESS && cmp->scsiStatus == 0);
    s_rs->cmpConsIdx = cons + 1u;
    wr(PVSCSI_REG_INTR_STATUS, PVSCSI_INTR_CMPL_MASK);  /* ack (RW1C) */
    return ok ? 0 : -1;
}

static int
pvscsi_rw(uint64_t lba, uint32_t nsec, int is_write)
{
    uint8_t cdb[10];
    _memset(cdb, 0, sizeof(cdb));
    cdb[0] = is_write ? SCSI_WRITE10 : SCSI_READ10;
    cdb[2] = (uint8_t)(lba >> 24);
    cdb[3] = (uint8_t)(lba >> 16);
    cdb[4] = (uint8_t)(lba >> 8);
    cdb[5] = (uint8_t)(lba);
    cdb[7] = (uint8_t)(nsec >> 8);
    cdb[8] = (uint8_t)(nsec);
    return pvscsi_exec(cdb, 10, nsec * SECTOR, is_write ? 0 : 1);
}

static int
pvscsi_blk_read(blkdev_t *dev, uint64_t lba, uint32_t count, void *buf)
{
    (void)dev;
    if (count == 0) return 0;
    uint8_t *out = buf;
    while (count > 0) {
        uint32_t chunk = count < MAX_SECTORS ? count : MAX_SECTORS;
        irqflags_t fl = spin_lock_irqsave(&s_lock);
        int rc = pvscsi_rw(lba, chunk, 0);
        if (rc == 0)
            _memcpy(out, s_bounce, chunk * SECTOR);
        spin_unlock_irqrestore(&s_lock, fl);
        if (rc < 0) return -1;
        out += chunk * SECTOR; lba += chunk; count -= chunk;
    }
    return 0;
}

static int
pvscsi_blk_write(blkdev_t *dev, uint64_t lba, uint32_t count, const void *buf)
{
    (void)dev;
    if (count == 0) return 0;
    const uint8_t *in = buf;
    while (count > 0) {
        uint32_t chunk = count < MAX_SECTORS ? count : MAX_SECTORS;
        irqflags_t fl = spin_lock_irqsave(&s_lock);
        _memcpy(s_bounce, in, chunk * SECTOR);
        int rc = pvscsi_rw(lba, chunk, 1);
        spin_unlock_irqrestore(&s_lock, fl);
        if (rc < 0) return -1;
        in += chunk * SECTOR; lba += chunk; count -= chunk;
    }
    return 0;
}

void
pvscsi_init(void)
{
    const pcie_device_t *devs = pcie_get_devices();
    int n = pcie_device_count(), i;
    const pcie_device_t *d = NULL;
    for (i = 0; i < n; i++) {
        if (devs[i].vendor_id == PVSCSI_VENDOR &&
            devs[i].device_id == PVSCSI_DEVICE) { d = &devs[i]; break; }
    }
    if (!d)
        return;                              /* not present → silent skip */

    /* Enable memory space + bus mastering. */
    uint32_t cmd = pcie_read32(d->bus, d->dev, d->fn, 0x04);
    pcie_write32(d->bus, d->dev, d->fn, 0x04, cmd | (1u << 1) | (1u << 2));

    s_mmio = kva_map_mmio(d->bar[0] & ~0xFFFULL, 6);  /* registers up to 0x4018 */
    if (!s_mmio)
        return;

    wr(PVSCSI_REG_COMMAND, PVSCSI_CMD_ADAPTER_RESET);
    wr(PVSCSI_REG_INTR_MASK, 0);             /* we poll, no interrupts */

    /* Allocate the shared rings-state page, the request and completion rings
     * (one page each), and one contiguous bounce page. */
    uintptr_t rs_va, req_va, cmp_va, bn_va;
    uint64_t  rs_pa, req_pa, cmp_pa;
    rs_va  = (uintptr_t)kva_alloc_pages_low(1);
    req_va = (uintptr_t)kva_alloc_pages_low(1);
    cmp_va = (uintptr_t)kva_alloc_pages_low(1);
    bn_va  = (uintptr_t)kva_alloc_pages_low(1);
    if (!rs_va || !req_va || !cmp_va || !bn_va)
        return;
    rs_pa  = kva_page_phys((void *)rs_va);
    req_pa = kva_page_phys((void *)req_va);
    cmp_pa = kva_page_phys((void *)cmp_va);
    s_bounce_pa = kva_page_phys((void *)bn_va);
    s_rs      = (pvscsi_rings_state_t *)rs_va;
    s_reqRing = (pvscsi_req_desc_t *)req_va;
    s_cmpRing = (pvscsi_cmp_desc_t *)cmp_va;
    s_bounce  = (uint8_t *)bn_va;
    _memset(s_rs, 0, 4096);
    _memset(s_reqRing, 0, 4096);
    _memset(s_cmpRing, 0, 4096);

    pvscsi_setup_rings_t setup;
    _memset(&setup, 0, sizeof(setup));
    setup.reqRingNumPages = 1;
    setup.cmpRingNumPages = 1;
    setup.ringsStatePPN   = rs_pa  >> 12;
    setup.reqRingPPNs[0]  = req_pa >> 12;
    setup.cmpRingPPNs[0]  = cmp_pa >> 12;
    pvscsi_command(PVSCSI_CMD_SETUP_RINGS,
                   (const uint32_t *)&setup, sizeof(setup) / 4u);

    s_lock = (spinlock_t)SPINLOCK_INIT;
    s_ctx  = 0;

    /* TEST UNIT READY clears the power-on UNIT ATTENTION; ignore its result. */
    irqflags_t fl = spin_lock_irqsave(&s_lock);
    uint8_t tur = SCSI_TEST_UNIT_READY;
    (void)pvscsi_exec(&tur, 6, 0, 0);

    /* READ CAPACITY(10): 8-byte big-endian {last LBA, block size}. */
    uint8_t cap[10];
    _memset(cap, 0, sizeof(cap));
    cap[0] = SCSI_READ_CAPACITY10;
    int rc = pvscsi_exec(cap, 10, 8, 1);
    uint64_t sectors = 0;
    if (rc == 0) {
        uint8_t *c = s_bounce;
        uint32_t last_lba = ((uint32_t)c[0] << 24) | ((uint32_t)c[1] << 16) |
                            ((uint32_t)c[2] << 8) | c[3];
        sectors = (uint64_t)last_lba + 1u;
    }
    spin_unlock_irqrestore(&s_lock, fl);
    if (rc < 0)
        return;

    s_blk.name[0]='p'; s_blk.name[1]='v'; s_blk.name[2]='s';
    s_blk.name[3]='c'; s_blk.name[4]='s'; s_blk.name[5]='i';
    s_blk.name[6]='0'; s_blk.name[7]='\0';
    s_blk.block_count = sectors;
    s_blk.block_size  = SECTOR;
    s_blk.lba_offset  = 0;
    s_blk.read  = pvscsi_blk_read;
    s_blk.write = pvscsi_blk_write;
    s_blk.priv  = NULL;
    blkdev_register(&s_blk);

    printk("[PVSCSI] OK: pvscsi0 %u sectors\n", (uint32_t)sectors);
}
