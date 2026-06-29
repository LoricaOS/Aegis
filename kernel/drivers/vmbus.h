/* vmbus.h — Hyper-V VMBus: channel transport over the SynIC foundation.
 *
 * VMBus is the bus all Hyper-V synthetic devices ride on. This driver connects
 * to the host, negotiates a protocol version, enumerates the channel offers
 * (StorVSC, NetVSC, ...), and provides each device driver with ring-buffer
 * packet send/receive + GPADL buffer sharing.
 *
 * Researched against Linux drivers/hv + iPXE interface/hyperv. Structs are
 * transcribed with _Static_assert on the wire-critical ones.
 */
#ifndef VMBUS_H
#define VMBUS_H

#include <stdint.h>

/* ── Channel message types (CHANNELMSG_*) ─────────────────────────────────── */
#define CHANNELMSG_OFFERCHANNEL        1u
#define CHANNELMSG_REQUESTOFFERS       3u
#define CHANNELMSG_ALLOFFERS_DELIVERED 4u
#define CHANNELMSG_OPENCHANNEL         5u
#define CHANNELMSG_OPENCHANNEL_RESULT  6u
#define CHANNELMSG_GPADL_HEADER        8u
#define CHANNELMSG_GPADL_BODY          9u
#define CHANNELMSG_GPADL_CREATED       10u
#define CHANNELMSG_INITIATE_CONTACT    14u
#define CHANNELMSG_VERSION_RESPONSE    15u

/* VMBus protocol versions: VERSION(major,minor) = (major<<16)|minor. */
#define VMBUS_VERSION_WIN8     0x00020004u
#define VMBUS_VERSION_WIN8_1   0x00030000u
#define VMBUS_VERSION_WIN10    0x00040000u

/* Message connection ids for HvPostMessage (version-dependent). */
#define VMBUS_MSG_CONN_ID_1    1u    /* < WIN10_V5 */
#define VMBUS_MSG_CONN_ID_4    4u    /* >= WIN10_V5 (unused: we target <= WIN10) */

/* VMBus ring packet types. */
#define VMBUS_PKT_DATA_INBAND     6u
#define VMBUS_PKT_DATA_XFER_PAGES 7u
#define VMBUS_PKT_DATA_GPA_DIRECT 9u
#define VMBUS_PKT_COMPLETION      11u

#define VMBUS_PKT_FLAG_COMPLETION 1u   /* request a completion */

/* ── A 16-byte GUID (wire byte order). ────────────────────────────────────── */
typedef struct { uint8_t b[16]; } vmbus_guid_t;

/* ── VMBus ring-buffer control header (one page; data follows at +4096). ───── */
typedef struct __attribute__((packed)) {
    uint32_t write_index;       /* producer byte offset into the data area */
    uint32_t read_index;        /* consumer byte offset                    */
    uint32_t interrupt_mask;
    uint32_t pending_send_sz;
    uint32_t reserved1[12];
    uint32_t feature_bits;
    /* remainder of the page is reserved; data ring starts at +PAGE_SIZE */
} vmbus_ring_t;
_Static_assert(sizeof(vmbus_ring_t) == 68, "vmbus_ring header");

/* ── Ring packet descriptor (16 bytes). offset8/len8 are in 8-byte units. ──── */
typedef struct __attribute__((packed)) {
    uint16_t type;
    uint16_t offset8;           /* offset to inband payload, in qwords */
    uint16_t len8;              /* total length (excl. 8-byte footer), in qwords */
    uint16_t flags;
    uint64_t trans_id;
} vmbus_pkt_hdr_t;
_Static_assert(sizeof(vmbus_pkt_hdr_t) == 16, "vmbus_pkt_hdr");

/* ── An offered + (optionally) opened channel. ────────────────────────────── */
typedef struct vmbus_channel {
    int          in_use;
    int          opened;
    uint32_t     child_relid;
    uint32_t     connection_id;     /* from the offer; used to signal the host */
    vmbus_guid_t if_type;
    vmbus_guid_t if_instance;

    uint8_t     *ring_va;           /* whole ring region (out then in)         */
    uint64_t     ring_pa;
    uint32_t     ring_pages;        /* total pages in the region               */
    uint32_t     data_pages;        /* data pages per direction (power of two) */
    uint32_t     gpadl;             /* ring GPADL handle                       */

    vmbus_ring_t *out_hdr;  uint8_t *out_data;
    vmbus_ring_t *in_hdr;   uint8_t *in_data;
    uint32_t     data_len;          /* data_pages * 4096 (power of two)        */
} vmbus_channel_t;

/* ── API ──────────────────────────────────────────────────────────────────── */

/* Connect to VMBus, negotiate a version, request + enumerate channel offers.
 * Silent no-op when not on Hyper-V. Logs every step + every offer for blind
 * bring-up. Called once from kernel_main (after hyperv_init). */
void vmbus_init(void);

/* True if VMBus connected successfully. */
int  vmbus_connected(void);

/* Find an offered channel by interface-type GUID, or NULL. */
vmbus_channel_t *vmbus_find_channel(const vmbus_guid_t *if_type);

/* Allocate ring buffers, create the ring GPADL, and open the channel. Returns
 * 0 on success. data_pages must be a power of two. */
int  vmbus_open(vmbus_channel_t *ch, uint32_t data_pages);

/* Send an inband control packet (payload copied inline). need_completion sets
 * the completion-requested flag. Returns 0 on success. */
int  vmbus_send_inband(vmbus_channel_t *ch, const void *payload, uint32_t len,
                       uint64_t trans_id, int need_completion);

/* Send a GPA-direct packet: an inband payload plus a data buffer described by
 * its physical pages (buf_pa..buf_pa+buf_len). The host reads/writes the buffer
 * directly. Returns 0 on success. */
int  vmbus_send_gpa(vmbus_channel_t *ch, const void *payload, uint32_t len,
                    uint64_t buf_pa, uint32_t buf_len, uint64_t trans_id);

/* Receive one packet from the inbound ring. Copies up to buflen bytes of the
 * inband payload into buf. Sets *out_len, *out_type, *out_transid. Returns 1 if
 * a packet was read, 0 if the ring was empty. */
int  vmbus_recv(vmbus_channel_t *ch, void *buf, uint32_t buflen,
                uint32_t *out_len, uint16_t *out_type, uint64_t *out_transid);

/* Spin until a packet arrives (or budget exhausted). Returns 1/0 as vmbus_recv. */
int  vmbus_recv_wait(vmbus_channel_t *ch, void *buf, uint32_t buflen,
                     uint32_t *out_len, uint16_t *out_type, uint64_t *out_transid);

/* Receive one packet, copying the FULL packet (16-byte descriptor + body) into
 * buf. Sets *out_total (bytes copied/available), *out_off8 (payload offset in
 * bytes = descriptor offset8*8), *out_type, *out_transid. Returns 1 if read.
 * NetVSC uses this to parse transfer-pages (type 7) descriptors + ranges. */
int  vmbus_recv_raw(vmbus_channel_t *ch, void *buf, uint32_t buflen,
                    uint32_t *out_total, uint32_t *out_off8,
                    uint16_t *out_type, uint64_t *out_transid);

/* Send a completion packet (VM_PKT_COMP) carrying `payload`, tagged trans_id. */
int  vmbus_send_completion(vmbus_channel_t *ch, const void *payload, uint32_t len,
                           uint64_t trans_id);

/* Establish a GPADL for a virtually-contiguous buffer (num_pages ≤ 26 → one
 * message). Sets *out_handle. Returns 0 on success. */
int  vmbus_create_gpadl(vmbus_channel_t *ch, void *va, uint32_t num_pages,
                        uint32_t *out_handle);

/* ── VMBus device drivers ─────────────────────────────────────────────────── */
void storvsc_init(void);   /* synthetic SCSI disk → blkdev "hvdisk0" */
void netvsc_init(void);    /* synthetic NIC → netdev "eth0" */

#endif /* VMBUS_H */
