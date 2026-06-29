/* virtio_9p.c — virtio 1.0 9P transport (host directory sharing)
 *
 * A minimal 9P2000.L client over the shared virtio core: it attaches to the
 * host-exported directory and reads a file, proving host↔guest file sharing.
 * 9P messages travel over one request virtqueue as [T-message (OUT) | R-message
 * (IN)] chains. Sequence: Tversion → Tattach (root fid) → Twalk (bind a fid to
 * a path) → Tlopen → Tread.
 *
 * This is a bring-up/verification client (reads "aegis-9p-test.txt" at boot); a
 * full VFS mount is the follow-up. References: 9P2000.L protocol; VIRTIO §5.7
 * (transport is generic — payload is 9P).
 */
#include "virtio.h"
#include "arch.h"
#include "printk.h"
#include <stdint.h>

#define VIRTIO_9P_MODERN  0x1049u   /* virtio device type 9 */
#define VIRTIO_9P_LEGACY  0x1009u
#define P9_MSIZE   4096u
#define P9_BUDGET  2000000u
#define P9_NOFID   0xFFFFFFFFu
#define P9_NOTAG   0xFFFFu

/* 9P2000.L message types. */
#define Tversion 100u
#define Rversion 101u
#define Tattach  104u
#define Rattach  105u
#define Twalk    110u
#define Rwalk    111u
#define Tlopen   12u
#define Rlopen   13u
#define Tread    116u
#define Rread    117u

static virtio_dev_t s_dev;
static virtq_t      s_reqq;
static uint8_t     *s_tx, *s_rx;
static uint64_t     s_tx_pa, s_rx_pa;
static uint32_t     s_pos;

static uint32_t _slen(const char *s){ uint32_t n=0; while (s[n]) n++; return n; }

static void p_u8(uint8_t v){ s_tx[s_pos++]=v; }
static void p_u16(uint16_t v){ s_tx[s_pos++]=(uint8_t)v; s_tx[s_pos++]=(uint8_t)(v>>8); }
static void p_u32(uint32_t v){ for (int i=0;i<4;i++) s_tx[s_pos++]=(uint8_t)(v>>(8*i)); }
static void p_u64(uint64_t v){ for (int i=0;i<8;i++) s_tx[s_pos++]=(uint8_t)(v>>(8*i)); }
static void p_str(const char *s){ uint16_t n=(uint16_t)_slen(s); p_u16(n); for (uint16_t i=0;i<n;i++) s_tx[s_pos++]=(uint8_t)s[i]; }

static uint32_t g_u32(uint32_t off){ return s_rx[off] | (s_rx[off+1]<<8) | (s_rx[off+2]<<16) | ((uint32_t)s_rx[off+3]<<24); }

static void msg_begin(uint8_t type){ s_pos=0; p_u32(0); p_u8(type); p_u16(0); }

/* Finish the T-message, send it, await the R-message; return its type (or 0). */
static uint8_t
p9_txn(void)
{
    uint32_t sz = s_pos;
    s_tx[0]=(uint8_t)sz; s_tx[1]=(uint8_t)(sz>>8); s_tx[2]=(uint8_t)(sz>>16); s_tx[3]=(uint8_t)(sz>>24);

    virtq_buf_t segs[2] = { { s_tx_pa, sz, 0 }, { s_rx_pa, P9_MSIZE, 1 } };
    uint16_t head;
    if (virtq_publish_chain(&s_reqq, segs, 2, &head) < 0)
        return 0;
    virtq_notify(&s_reqq);
    uint16_t cid; uint32_t l;
    for (uint32_t b=0;b<P9_BUDGET;b++){
        if (virtq_poll_used(&s_reqq, &cid, &l)) { virtq_free_chain(&s_reqq, cid); return s_rx[4]; }
        arch_pause();
    }
    return 0;
}

void
virtio_9p_init(void)
{
    if (virtio_pci_find(VIRTIO_9P_MODERN, VIRTIO_9P_LEGACY, &s_dev) < 0)
        return;
    virtio_reset(&s_dev);
    if (virtio_negotiate(&s_dev, 0) < 0)
        return;
    if (virtio_setup_queue(&s_dev, 0, &s_reqq) < 0) {
        s_dev.common->device_status = VIRTIO_STATUS_FAILED;
        return;
    }
    virtio_driver_ok(&s_dev);

    uintptr_t tv, rv;
    if (virtio_alloc_dma_page(&s_tx_pa, &tv) < 0 ||
        virtio_alloc_dma_page(&s_rx_pa, &rv) < 0)
        return;
    s_tx = (uint8_t *)tv; s_rx = (uint8_t *)rv;

    /* Tversion. */
    msg_begin(Tversion); p_u32(P9_MSIZE); p_str("9P2000.L");
    if (p9_txn() != Rversion) { printk("[9P] FAIL: version\n"); return; }
    /* Tattach: fid 0 = root. */
    msg_begin(Tattach); p_u32(0); p_u32(P9_NOFID); p_str("root"); p_str(""); p_u32(0);
    if (p9_txn() != Rattach) { printk("[9P] FAIL: attach\n"); return; }
    /* Twalk fid0 → fid1 along "aegis-9p-test.txt". */
    msg_begin(Twalk); p_u32(0); p_u32(1); p_u16(1); p_str("aegis-9p-test.txt");
    if (p9_txn() != Rwalk) { printk("[9P] OK: attached host dir (test file absent)\n"); return; }
    /* Tlopen fid1 O_RDONLY. */
    msg_begin(Tlopen); p_u32(1); p_u32(0);
    if (p9_txn() != Rlopen) { printk("[9P] FAIL: open\n"); return; }
    /* Tread fid1 offset 0 count 256. */
    msg_begin(Tread); p_u32(1); p_u64(0); p_u32(256);
    if (p9_txn() != Rread) { printk("[9P] FAIL: read\n"); return; }

    uint32_t cnt = g_u32(7);            /* Rread: count @ +7, data @ +11 */
    char buf[128];
    uint32_t n = cnt < sizeof(buf) - 1u ? cnt : sizeof(buf) - 1u;
    for (uint32_t i=0;i<n;i++){ char c = (char)s_rx[11+i]; buf[i] = (c=='\n') ? ' ' : c; }
    buf[n] = '\0';
    printk("[9P] OK: read aegis-9p-test.txt (%u bytes): %s\n", cnt, buf);
}
