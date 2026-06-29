/* virtio_console.c — virtio 1.0 console (virtio-serial), on the shared core
 *
 * Without VIRTIO_CONSOLE_F_MULTIPORT the device is a single console: queue 0 =
 * receiveq (host → guest), queue 1 = transmitq (guest → host). We arm the RX
 * queue and write a banner out the TX queue, which the host delivers to the
 * port's chardev. A second host↔guest channel beyond the serial port.
 *
 * References: VIRTIO v1.0 §5.3 Console Device.
 */
#include "virtio.h"
#include "arch.h"
#include "printk.h"
#include "spinlock.h"
#include "../lib/string.h"
#include <stdint.h>

#define VIRTIO_CONSOLE_MODERN  0x1043u
#define VIRTIO_CONSOLE_LEGACY  0x1003u
#define VCON_POLL_BUDGET 2000000u

static virtio_dev_t s_dev;
static virtq_t      s_rxq, s_txq;
static uintptr_t    s_tx_va, s_rx_va;
static uint64_t     s_tx_pa, s_rx_pa;
static int          s_active;

static uint32_t _slen(const char *s){ uint32_t n=0; while (s[n]) n++; return n; }

/* Write a buffer out the transmit queue and wait for the device to consume it. */
static int
vcon_write(const void *data, uint32_t len)
{
    if (len > 4096u) len = 4096u;
    kmemcpy((void *)s_tx_va, data, len);
    virtq_buf_t seg = { s_tx_pa, len, 0 };   /* device reads */
    uint16_t head;
    if (virtq_publish_chain(&s_txq, &seg, 1, &head) < 0)
        return -1;
    virtq_notify(&s_txq);
    uint16_t cid; uint32_t l;
    for (uint32_t b=0;b<VCON_POLL_BUDGET;b++){
        if (virtq_poll_used(&s_txq, &cid, &l)) { virtq_free_chain(&s_txq, cid); return 0; }
        arch_pause();
    }
    return -1;
}

void
virtio_console_init(void)
{
    if (virtio_pci_find(VIRTIO_CONSOLE_MODERN, VIRTIO_CONSOLE_LEGACY, &s_dev) < 0)
        return;

    virtio_reset(&s_dev);
    if (virtio_negotiate(&s_dev, 0) < 0)   /* no MULTIPORT: plain console */
        return;
    if (virtio_setup_queue(&s_dev, 0, &s_rxq) < 0 ||
        virtio_setup_queue(&s_dev, 1, &s_txq) < 0) {
        s_dev.common->device_status = VIRTIO_STATUS_FAILED;
        return;
    }
    virtio_driver_ok(&s_dev);

    if (virtio_alloc_dma_page(&s_tx_pa, &s_tx_va) < 0 ||
        virtio_alloc_dma_page(&s_rx_pa, &s_rx_va) < 0)
        return;

    /* Arm one RX buffer so the host can deliver console input. */
    virtq_buf_t rx = { s_rx_pa, 4096, 1 };   /* device writes */
    uint16_t head;
    if (virtq_publish_chain(&s_rxq, &rx, 1, &head) == 0)
        virtq_notify(&s_rxq);

    s_active = 1;
    const char *banner = "Aegis virtio-console online\n";
    int rc = vcon_write(banner, _slen(banner));
    printk("[VCON] OK: virtio-console, banner write %s\n", rc == 0 ? "ok" : "FAIL");
}
