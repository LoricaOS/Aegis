/* storvsc.c — Hyper-V synthetic SCSI (StorVSC) over VMBus.
 *
 * The disk on a Generation-2 Hyper-V VM appears here (there is no emulated
 * IDE/AHCI). Handshake: BEGIN_INIT → QUERY_PROTOCOL_VERSION → QUERY_PROPERTIES
 * → END_INIT, then SCSI CDBs via EXECUTE_SRB with the data buffer passed as a
 * VMBus GPA-direct range. Registers the first LUN as blkdev "hvdisk0".
 *
 * Researched against Linux drivers/scsi/storvsc_drv.c. Built blind — logs each
 * handshake step + SRB status so a first Hyper-V boot is diagnosable.
 */
#include "vmbus.h"
#include "blkdev.h"
#include "kva.h"
#include "printk.h"
#include "arch.h"
#include "spinlock.h"
#include "../lib/string.h"
#include <stdint.h>
#include <stddef.h>

/* VSTOR operations. */
#define VSTOR_OP_COMPLETE_IO            1u
#define VSTOR_OP_EXECUTE_SRB            3u
#define VSTOR_OP_BEGIN_INITIALIZATION   7u
#define VSTOR_OP_END_INITIALIZATION     8u
#define VSTOR_OP_QUERY_PROTOCOL_VERSION 9u
#define VSTOR_OP_QUERY_PROPERTIES       10u

#define VSTOR_FLAG_REQUEST_COMPLETION   1u

#define VMSTOR_PROTO_VERSION_WIN8       ((5u << 8) | 1u)   /* 0x0501 */

#define SRB_STATUS_SUCCESS              0x01u
#define SRB_FLAGS_DATA_IN               0x40u
#define SRB_FLAGS_DATA_OUT              0x80u

#define DATA_IN_WRITE   0u
#define DATA_IN_READ    1u
#define DATA_IN_NONE    2u

#include "scsi.h"  /* SCSI CDB opcodes */

#define SECTOR      512u
#define MAX_SECTORS 8u            /* one 4 KiB contiguous bounce page */
#define STOR_DATA_PAGES 4u        /* 16 KiB rings */

typedef struct __attribute__((packed)) {
    uint16_t length;
    uint8_t  srb_status;
    uint8_t  scsi_status;
    uint8_t  port_number;
    uint8_t  path_id;
    uint8_t  target_id;
    uint8_t  lun;
    uint8_t  cdb_length;
    uint8_t  sense_info_length;
    uint8_t  data_in;
    uint8_t  reserved;
    uint32_t data_transfer_length;
    uint8_t  cdb[16];
    uint8_t  cdb_pad[4];          /* cdb union is 20 bytes */
    uint16_t reserve;
    uint8_t  queue_tag;
    uint8_t  queue_action;
    uint32_t srb_flags;
    uint32_t time_out_value;
    uint32_t queue_sort_ey;
} vmscsi_request_t;
_Static_assert(sizeof(vmscsi_request_t) == 52, "vmscsi_request");

typedef struct __attribute__((packed)) {
    uint32_t operation;
    uint32_t flags;
    uint32_t status;
    union {
        vmscsi_request_t vm_srb;
        struct { uint16_t major_minor; uint16_t revision; } version;
        uint8_t buffer[52];
    } u;
} vstor_packet_t;
_Static_assert(sizeof(vstor_packet_t) == 64, "vstor_packet");

static vmbus_channel_t *s_ch;
static uint8_t         *s_bounce;
static uint64_t         s_bounce_pa;
static uint64_t         s_trans = 1;
static spinlock_t       s_lock;
static blkdev_t         s_blk;


/* Send a control vstor_packet (inband) and wait for its completion. */
static int
stor_control(vstor_packet_t *pkt)
{
    pkt->flags = VSTOR_FLAG_REQUEST_COMPLETION;
    if (vmbus_send_inband(s_ch, pkt, sizeof(*pkt), s_trans++, 1) < 0)
        return -1;
    vstor_packet_t resp;
    uint32_t len; uint16_t type; uint64_t tid;
    if (!vmbus_recv_wait(s_ch, &resp, sizeof(resp), &len, &type, &tid))
        return -1;
    *pkt = resp;
    return 0;
}

/* Execute a SCSI CDB. data_len 0 = no data; to_host: 1=read, 0=write.
 * Returns 0 on SRB success. Caller holds s_lock. */
static int
stor_execute(const uint8_t *cdb, uint8_t cdb_len, uint32_t data_len, int to_host)
{
    vstor_packet_t pkt;
    kmemset(&pkt, 0, sizeof(pkt));
    pkt.operation = VSTOR_OP_EXECUTE_SRB;
    pkt.flags     = VSTOR_FLAG_REQUEST_COMPLETION;
    vmscsi_request_t *srb = &pkt.u.vm_srb;
    srb->length            = sizeof(vmscsi_request_t);
    srb->cdb_length        = cdb_len;
    srb->sense_info_length = 20;
    srb->data_transfer_length = data_len;
    kmemcpy(srb->cdb, cdb, cdb_len);
    if (data_len == 0) {
        srb->data_in = DATA_IN_NONE; srb->srb_flags = 0;
    } else if (to_host) {
        srb->data_in = DATA_IN_READ; srb->srb_flags = SRB_FLAGS_DATA_IN;
    } else {
        srb->data_in = DATA_IN_WRITE; srb->srb_flags = SRB_FLAGS_DATA_OUT;
    }

    uint64_t tid = s_trans++;
    int rc;
    if (data_len)
        rc = vmbus_send_gpa(s_ch, &pkt, sizeof(pkt), s_bounce_pa, data_len, tid);
    else
        rc = vmbus_send_inband(s_ch, &pkt, sizeof(pkt), tid, 1);
    if (rc < 0)
        return -1;

    vstor_packet_t resp;
    uint32_t len; uint16_t type; uint64_t rtid;
    if (!vmbus_recv_wait(s_ch, &resp, sizeof(resp), &len, &type, &rtid))
        return -1;
    uint8_t ss = resp.u.vm_srb.srb_status & 0x3Fu;
    if (ss != SRB_STATUS_SUCCESS && resp.u.vm_srb.scsi_status != 0) {
        printk("[STORVSC] SRB cdb=0x%x srb_status=0x%x scsi=0x%x\n",
               (unsigned)cdb[0], (unsigned)resp.u.vm_srb.srb_status,
               (unsigned)resp.u.vm_srb.scsi_status);
        return -1;
    }
    return 0;
}

static int
stor_rw(uint64_t lba, uint32_t nsec, int is_write)
{
    uint8_t cdb[16];
    kmemset(cdb, 0, sizeof(cdb));
    cdb[0] = is_write ? SCSI_WRITE10 : SCSI_READ10;
    cdb[2] = (uint8_t)(lba >> 24); cdb[3] = (uint8_t)(lba >> 16);
    cdb[4] = (uint8_t)(lba >> 8);  cdb[5] = (uint8_t)lba;
    cdb[7] = (uint8_t)(nsec >> 8); cdb[8] = (uint8_t)nsec;
    return stor_execute(cdb, 10, nsec * SECTOR, is_write ? 0 : 1);
}

static int
hv_blk_read(blkdev_t *dev, uint64_t lba, uint32_t count, void *buf)
{
    (void)dev;
    if (count == 0) return 0;
    uint8_t *out = buf;
    while (count > 0) {
        uint32_t chunk = count < MAX_SECTORS ? count : MAX_SECTORS;
        irqflags_t fl = spin_lock_irqsave(&s_lock);
        int rc = stor_rw(lba, chunk, 0);
        if (rc == 0) kmemcpy(out, s_bounce, chunk * SECTOR);
        spin_unlock_irqrestore(&s_lock, fl);
        if (rc < 0) return -1;
        out += chunk * SECTOR; lba += chunk; count -= chunk;
    }
    return 0;
}

static int
hv_blk_write(blkdev_t *dev, uint64_t lba, uint32_t count, const void *buf)
{
    (void)dev;
    if (count == 0) return 0;
    const uint8_t *in = buf;
    while (count > 0) {
        uint32_t chunk = count < MAX_SECTORS ? count : MAX_SECTORS;
        irqflags_t fl = spin_lock_irqsave(&s_lock);
        kmemcpy(s_bounce, in, chunk * SECTOR);
        int rc = stor_rw(lba, chunk, 1);
        spin_unlock_irqrestore(&s_lock, fl);
        if (rc < 0) return -1;
        in += chunk * SECTOR; lba += chunk; count -= chunk;
    }
    return 0;
}

/* StorVSC interface type GUID {ba6163d9-04a1-4d29-b605-72e2ffb1dc7f}. */
static const vmbus_guid_t GUID_STORVSC = {{
    0xd9,0x63,0x61,0xba,0xa1,0x04,0x29,0x4d,0xb6,0x05,0x72,0xe2,0xff,0xb1,0xdc,0x7f }};

void
storvsc_init(void)
{
    if (!vmbus_connected())
        return;
    s_ch = vmbus_find_channel(&GUID_STORVSC);
    if (!s_ch) { printk("[STORVSC] no StorVSC channel offered\n"); return; }
    if (vmbus_open(s_ch, STOR_DATA_PAGES) != 0) {
        printk("[STORVSC] channel open failed\n"); return; }

    /* Handshake. */
    vstor_packet_t pkt;
    kmemset(&pkt, 0, sizeof(pkt));
    pkt.operation = VSTOR_OP_BEGIN_INITIALIZATION;
    if (stor_control(&pkt) != 0 || pkt.status != 0) {
        printk("[STORVSC] BEGIN_INIT failed status=%u\n", (unsigned)pkt.status); return; }

    kmemset(&pkt, 0, sizeof(pkt));
    pkt.operation = VSTOR_OP_QUERY_PROTOCOL_VERSION;
    pkt.u.version.major_minor = VMSTOR_PROTO_VERSION_WIN8;
    pkt.u.version.revision = 0;
    if (stor_control(&pkt) != 0) {
        printk("[STORVSC] QUERY_PROTOCOL_VERSION no response\n"); return; }
    printk("[STORVSC] protocol negotiated (status=%u ver=0x%x)\n",
           (unsigned)pkt.status, (unsigned)pkt.u.version.major_minor);

    kmemset(&pkt, 0, sizeof(pkt));
    pkt.operation = VSTOR_OP_QUERY_PROPERTIES;
    if (stor_control(&pkt) != 0) {
        printk("[STORVSC] QUERY_PROPERTIES no response\n"); return; }

    kmemset(&pkt, 0, sizeof(pkt));
    pkt.operation = VSTOR_OP_END_INITIALIZATION;
    if (stor_control(&pkt) != 0 || pkt.status != 0) {
        printk("[STORVSC] END_INIT failed status=%u\n", (unsigned)pkt.status); return; }
    printk("[STORVSC] handshake complete\n");

    /* Data bounce page (one contiguous low page). */
    s_bounce = (uint8_t *)kva_alloc_pages_low(1);
    if (!s_bounce) { printk("[STORVSC] bounce alloc failed\n"); return; }
    s_bounce_pa = kva_page_phys(s_bounce);
    s_lock = (spinlock_t)SPINLOCK_INIT;

    /* SCSI bring-up: TEST UNIT READY, then READ CAPACITY(10). */
    uint8_t cdb[16];
    irqflags_t fl = spin_lock_irqsave(&s_lock);
    for (int t = 0; t < 4; t++) {
        kmemset(cdb, 0, sizeof(cdb)); cdb[0] = SCSI_TEST_UNIT_READY;
        if (stor_execute(cdb, 6, 0, 0) == 0) break;
    }
    kmemset(cdb, 0, sizeof(cdb)); cdb[0] = SCSI_READ_CAPACITY10;
    int rc = stor_execute(cdb, 10, 8, 1);
    uint64_t sectors = 0; uint32_t bsz = SECTOR;
    if (rc == 0) {
        uint8_t *c = s_bounce;
        uint32_t last = ((uint32_t)c[0]<<24)|((uint32_t)c[1]<<16)|((uint32_t)c[2]<<8)|c[3];
        bsz = ((uint32_t)c[4]<<24)|((uint32_t)c[5]<<16)|((uint32_t)c[6]<<8)|c[7];
        if (bsz == 0 || bsz > 4096) bsz = SECTOR;
        sectors = (uint64_t)last + 1u;
    }
    spin_unlock_irqrestore(&s_lock, fl);
    if (rc != 0) { printk("[STORVSC] READ CAPACITY failed\n"); return; }

    s_blk.name[0]='h'; s_blk.name[1]='v'; s_blk.name[2]='d';
    s_blk.name[3]='i'; s_blk.name[4]='s'; s_blk.name[5]='k';
    s_blk.name[6]='0'; s_blk.name[7]='\0';
    s_blk.block_count = sectors;
    s_blk.block_size  = bsz;
    s_blk.lba_offset  = 0;
    s_blk.read  = hv_blk_read;
    s_blk.write = hv_blk_write;
    s_blk.priv  = NULL;
    blkdev_register(&s_blk);
    printk("[STORVSC] OK: hvdisk0 %u sectors (%u-byte blocks)\n",
           (uint32_t)sectors, (unsigned)bsz);
}
