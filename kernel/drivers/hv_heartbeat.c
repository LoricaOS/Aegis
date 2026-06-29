/* hv_heartbeat.c — Hyper-V Heartbeat Integration Component (VMBus).
 *
 * The host periodically sends a HEARTBEAT message carrying a sequence number;
 * the guest must bump it by one and echo it back.  This is what makes Hyper-V
 * Manager / `Get-VMIntegrationService` report the guest as healthy ("OK")
 * instead of "No Contact".  All framing/negotiate/echo lives in hv_ic.c.
 */
#include "hv_ic.h"
#include "printk.h"
#include <stdint.h>
#include <stddef.h>

typedef struct __attribute__((packed)) {
    uint64_t seq_num;
    uint32_t reserved[8];
} heartbeat_msg_data_t;

/* Heartbeat IC interface type {57164f39-9115-4e78-ab55-382f3bd5422d}. */
static const vmbus_guid_t GUID_HEARTBEAT = {{
    0x39,0x4f,0x16,0x57,0x15,0x91,0x78,0x4e,0xab,0x55,0x38,0x2f,0x3b,0xd5,0x42,0x2d }};

static vmbus_channel_t *s_ch;
static int s_ready;

static int
heartbeat_body(uint16_t msgtype, uint8_t *body, uint32_t bodylen)
{
    if (msgtype == ICMSGTYPE_HEARTBEAT && bodylen >= sizeof(uint64_t)) {
        heartbeat_msg_data_t *hb = (heartbeat_msg_data_t *)body;
        hb->seq_num += 1;       /* host expects the sequence echoed +1 */
    }
    return 0;
}

void
hv_heartbeat_poll(void)
{
    if (s_ready)
        hv_ic_poll(s_ch, heartbeat_body);
}

void
hv_heartbeat_init(void)
{
    if (!vmbus_connected())
        return;
    s_ch = vmbus_find_channel(&GUID_HEARTBEAT);
    if (!s_ch) { printk("[HV-HEARTBEAT] no heartbeat channel offered\n"); return; }
    if (vmbus_open(s_ch, 4u) != 0) {
        printk("[HV-HEARTBEAT] channel open failed\n"); return; }
    s_ready = 1;
    printk("[HV-HEARTBEAT] OK: heartbeat IC ready\n");
}
