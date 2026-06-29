/* virtio_scsi.c — virtio 1.0 SCSI host, on the shared virtio core
 *
 * Registers the first SCSI disk (target 0, LUN 0) as a blkdev ("scsi0"). An
 * alternate storage path to virtio-blk: the guest issues SCSI CDBs over the
 * request virtqueue. Synchronous poll-in-call, PRDT-style scatter-gather over
 * bounce pages — same model as virtio_blk.c / ahci.c.
 *
 * Queues: 0 = controlq (TMFs, unused), 1 = eventq (async events, unused),
 * 2 = first request queue (we use this). All three are set up because the
 * device expects them; only the request queue carries traffic.
 *
 * References: VIRTIO v1.0 §5.6 SCSI Host Device; SCSI Primary/Block Commands.
 */
#include "virtio.h"
#include "blkdev.h"
#include "arch.h"
#include "printk.h"
#include "spinlock.h"
#include <stdint.h>
#include <stddef.h>

#define VIRTIO_SCSI_MODERN  0x1048u
#define VIRTIO_SCSI_LEGACY  0x1004u

#define VIRTIO_SCSI_S_OK    0u      /* response byte */
#define SCSI_STATUS_GOOD    0u      /* status byte */
#define SCSI_REQUESTQ       2u      /* first request queue index */

#define SCSI_SECTOR         512u
#define SCSI_BOUNCE_PAGES   8u
#define SCSI_MAX_SECTORS    (SCSI_BOUNCE_PAGES * 4096u / SCSI_SECTOR)
#define SCSI_POLL_BUDGET    100000000u

#include "scsi.h"  /* SCSI CDB opcodes */

typedef struct __attribute__((packed)) {
    uint8_t  lun[8];
    uint64_t id;
    uint8_t  task_attr;
    uint8_t  prio;
    uint8_t  crn;
    uint8_t  cdb[32];
} virtio_scsi_req_cmd_t;        /* 51 bytes */

typedef struct __attribute__((packed)) {
    uint32_t sense_len;
    uint32_t residual;
    uint16_t status_qualifier;
    uint8_t  status;
    uint8_t  response;
    uint8_t  sense[96];
} virtio_scsi_resp_cmd_t;       /* 108 bytes */

static virtio_dev_t s_dev;
static virtq_t      s_ctrlq, s_eventq, s_reqq;
static uintptr_t s_req_va;     /* req_cmd at +0, resp at +256 */
static uint64_t  s_req_pa;
static uint8_t  *s_bounce[SCSI_BOUNCE_PAGES];
static uint64_t  s_bounce_pa[SCSI_BOUNCE_PAGES];
static spinlock_t s_lock;
static blkdev_t  s_blk;

static void
_memcpy(void *d, const void *s, uint32_t n)
{
    uint8_t *dd = d; const uint8_t *ss = s;
    while (n--) *dd++ = *ss++;
}
static void
_memset(void *d, int v, uint32_t n)
{
    uint8_t *dd = d;
    while (n--) *dd++ = (uint8_t)v;
}

#define REQ ((virtio_scsi_req_cmd_t *)s_req_va)
#define RESP ((virtio_scsi_resp_cmd_t *)(s_req_va + 256))
#define RESP_PA (s_req_pa + 256)

static void
scsi_set_lun(void)
{
    _memset(REQ->lun, 0, 8);
    REQ->lun[0] = 1;       /* addressing method + bus 0 */
    REQ->lun[1] = 0;       /* target 0 */
    REQ->lun[2] = 0x40;    /* LUN 0 (single-level) */
    REQ->lun[3] = 0;
    REQ->id = 0;
    REQ->task_attr = 0;
    REQ->prio = 0;
    REQ->crn = 0;
}

/* Execute one SCSI command. data!=NULL transfers nbytes via the bounce pages
 * (is_write picks direction). Returns 0 on GOOD status, -1 otherwise.
 * Caller holds s_lock. */
static int
scsi_exec(uint32_t nbytes, int is_write)
{
    uint32_t npages = (nbytes + 4095u) / 4096u;
    if (npages > SCSI_BOUNCE_PAGES)
        return -1;

    _memset(RESP, 0, sizeof(virtio_scsi_resp_cmd_t));

    /* Chain: req(OUT) [+ data-out] resp(IN) [+ data-in]. */
    virtq_buf_t segs[2 + SCSI_BOUNCE_PAGES];
    int n = 0;
    segs[n].phys = s_req_pa; segs[n].len = sizeof(virtio_scsi_req_cmd_t);
    segs[n].write = 0; n++;

    uint32_t remaining = nbytes, pg = 0;
    if (is_write) {
        while (remaining) {
            uint32_t seg = remaining < 4096u ? remaining : 4096u;
            segs[n].phys = s_bounce_pa[pg]; segs[n].len = seg; segs[n].write = 0;
            n++; remaining -= seg; pg++;
        }
    }
    segs[n].phys = RESP_PA; segs[n].len = sizeof(virtio_scsi_resp_cmd_t);
    segs[n].write = 1; n++;
    if (!is_write) {
        remaining = nbytes; pg = 0;
        while (remaining) {
            uint32_t seg = remaining < 4096u ? remaining : 4096u;
            segs[n].phys = s_bounce_pa[pg]; segs[n].len = seg; segs[n].write = 1;
            n++; remaining -= seg; pg++;
        }
    }

    uint16_t head;
    if (virtq_publish_chain(&s_reqq, segs, n, &head) < 0)
        return -1;
    virtq_notify(&s_reqq);

    uint16_t cid; uint32_t len; int done = 0;
    for (uint32_t b = 0; b < SCSI_POLL_BUDGET; b++) {
        if (virtq_poll_used(&s_reqq, &cid, &len)) {
            virtq_free_chain(&s_reqq, cid); done = 1; break;
        }
        arch_pause();
    }
    if (!done)
        return -1;
    if (RESP->response != VIRTIO_SCSI_S_OK || RESP->status != SCSI_STATUS_GOOD)
        return -1;
    return 0;
}

static int
scsi_rw(uint64_t lba, uint32_t nsec, int is_write)
{
    scsi_set_lun();
    _memset(REQ->cdb, 0, 32);
    REQ->cdb[0] = is_write ? SCSI_WRITE10 : SCSI_READ10;
    REQ->cdb[2] = (uint8_t)(lba >> 24);
    REQ->cdb[3] = (uint8_t)(lba >> 16);
    REQ->cdb[4] = (uint8_t)(lba >> 8);
    REQ->cdb[5] = (uint8_t)(lba);
    REQ->cdb[7] = (uint8_t)(nsec >> 8);
    REQ->cdb[8] = (uint8_t)(nsec);
    return scsi_exec(nsec * SCSI_SECTOR, is_write);
}

static int
virtio_scsi_read(blkdev_t *dev, uint64_t lba, uint32_t count, void *buf)
{
    (void)dev;
    if (count == 0) return 0;
    uint8_t *out = buf;
    while (count > 0) {
        uint32_t chunk = count < SCSI_MAX_SECTORS ? count : SCSI_MAX_SECTORS;
        irqflags_t fl = spin_lock_irqsave(&s_lock);
        int rc = scsi_rw(lba, chunk, 0);
        if (rc == 0) {
            uint32_t nbytes = chunk * SCSI_SECTOR, off = 0, pg = 0;
            while (off < nbytes) {
                uint32_t seg = (nbytes - off) < 4096u ? (nbytes - off) : 4096u;
                _memcpy(out + off, s_bounce[pg], seg); off += seg; pg++;
            }
        }
        spin_unlock_irqrestore(&s_lock, fl);
        if (rc < 0) return -1;
        out += chunk * SCSI_SECTOR; lba += chunk; count -= chunk;
    }
    return 0;
}

static int
virtio_scsi_write(blkdev_t *dev, uint64_t lba, uint32_t count, const void *buf)
{
    (void)dev;
    if (count == 0) return 0;
    const uint8_t *in = buf;
    while (count > 0) {
        uint32_t chunk = count < SCSI_MAX_SECTORS ? count : SCSI_MAX_SECTORS;
        irqflags_t fl = spin_lock_irqsave(&s_lock);
        uint32_t nbytes = chunk * SCSI_SECTOR, off = 0, pg = 0;
        while (off < nbytes) {
            uint32_t seg = (nbytes - off) < 4096u ? (nbytes - off) : 4096u;
            _memcpy(s_bounce[pg], in + off, seg); off += seg; pg++;
        }
        int rc = scsi_rw(lba, chunk, 1);
        spin_unlock_irqrestore(&s_lock, fl);
        if (rc < 0) return -1;
        in += chunk * SCSI_SECTOR; lba += chunk; count -= chunk;
    }
    return 0;
}

void
virtio_scsi_init(void)
{
    if (virtio_pci_find(VIRTIO_SCSI_MODERN, VIRTIO_SCSI_LEGACY, &s_dev) < 0)
        return;

    virtio_reset(&s_dev);
    if (virtio_negotiate(&s_dev, 0) < 0)
        return;
    /* controlq, eventq, and the first request queue must all be configured. */
    if (virtio_setup_queue(&s_dev, 0, &s_ctrlq) < 0 ||
        virtio_setup_queue(&s_dev, 1, &s_eventq) < 0 ||
        virtio_setup_queue(&s_dev, SCSI_REQUESTQ, &s_reqq) < 0) {
        s_dev.common->device_status = VIRTIO_STATUS_FAILED;
        return;
    }
    virtio_driver_ok(&s_dev);

    if (virtio_alloc_dma_page(&s_req_pa, &s_req_va) < 0)
        return;
    for (uint32_t i = 0; i < SCSI_BOUNCE_PAGES; i++) {
        uintptr_t va;
        if (virtio_alloc_dma_page(&s_bounce_pa[i], &va) < 0)
            return;
        s_bounce[i] = (uint8_t *)va;
    }
    s_lock = (spinlock_t)SPINLOCK_INIT;

    /* TEST UNIT READY clears the power-on UNIT ATTENTION; ignore its result. */
    irqflags_t fl = spin_lock_irqsave(&s_lock);
    scsi_set_lun();
    _memset(REQ->cdb, 0, 32);
    REQ->cdb[0] = SCSI_TEST_UNIT_READY;
    (void)scsi_exec(0, 0);

    /* READ CAPACITY(10): 8-byte reply = last LBA + block size (big-endian). */
    scsi_set_lun();
    _memset(REQ->cdb, 0, 32);
    REQ->cdb[0] = SCSI_READ_CAPACITY10;
    int rc = scsi_exec(8, 0);
    uint64_t sectors = 0;
    if (rc == 0) {
        uint8_t *c = s_bounce[0];
        uint32_t last_lba = ((uint32_t)c[0] << 24) | ((uint32_t)c[1] << 16) |
                            ((uint32_t)c[2] << 8) | c[3];
        sectors = (uint64_t)last_lba + 1u;
    }
    spin_unlock_irqrestore(&s_lock, fl);
    if (rc < 0)
        return;

    s_blk.name[0]='s'; s_blk.name[1]='c'; s_blk.name[2]='s';
    s_blk.name[3]='i'; s_blk.name[4]='0'; s_blk.name[5]='\0';
    s_blk.block_count = sectors;
    s_blk.block_size  = SCSI_SECTOR;
    s_blk.lba_offset  = 0;
    s_blk.read  = virtio_scsi_read;
    s_blk.write = virtio_scsi_write;
    s_blk.priv  = NULL;
    blkdev_register(&s_blk);

    printk("[SCSI] OK: virtio-scsi scsi0 %u sectors\n", (uint32_t)sectors);
}
