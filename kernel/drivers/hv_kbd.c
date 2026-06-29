/* hv_kbd.c — Hyper-V synthetic keyboard over VMBus → the shared input ring.
 *
 * Gen 2 VMs have no i8042, so the only keyboard is this VMBus device.  Protocol
 * (Linux drivers/input/serio/hyperv-keyboard.c): after the channel opens, send
 * a PROTOCOL_REQUEST carrying our version; the host replies PROTOCOL_RESPONSE
 * with an "accepted" bit; thereafter the host streams KEYSTROKE events as inband
 * packets.  Each keystroke is a PS/2 Scan Code Set 1 make code + flags (E0/E1
 * prefix, break) — exactly the bytes kbd.c's translator already understands, so
 * we reconstruct the set-1 byte stream and hand it to kbd_feed_scancode().
 *
 * Reuses the VMBus ring/recv plumbing proven by StorVSC/NetVSC.  Gated on
 * vmbus_connected(); QEMU/bare-metal never offer this channel.
 */
#include "vmbus.h"
#include "kbd.h"
#include "printk.h"
#include "arch.h"
#include <stdint.h>
#include <stddef.h>

#define SYNTH_KBD_VERSION            0x00010000u   /* major 1, minor 0 */
#define SYNTH_KBD_PROTOCOL_REQUEST   1u
#define SYNTH_KBD_PROTOCOL_RESPONSE  2u
#define SYNTH_KBD_EVENT              3u
#define PROTOCOL_ACCEPTED            (1u << 0)

#define KBD_IS_UNICODE  (1u << 0)
#define KBD_IS_BREAK    (1u << 1)
#define KBD_IS_E0       (1u << 2)
#define KBD_IS_E1       (1u << 3)
#define XTKBD_EMUL0     0xE0u
#define XTKBD_RELEASE   0x80u

#define HVKBD_DATA_PAGES 4u
#define HVKBD_POLL_BUDGET 200000000u

typedef struct __attribute__((packed)) { uint32_t type; } hk_hdr_t;
typedef struct __attribute__((packed)) { hk_hdr_t hdr; uint32_t version; } hk_request_t;
typedef struct __attribute__((packed)) { hk_hdr_t hdr; uint32_t proto_status; } hk_response_t;
typedef struct __attribute__((packed)) {
    hk_hdr_t hdr;
    uint16_t make_code;
    uint16_t reserved0;
    uint32_t info;
} hk_keystroke_t;
_Static_assert(sizeof(hk_keystroke_t) == 12, "hk_keystroke");

/* Synthetic keyboard interface type {f912ad6d-2b17-48ea-bd65-f927a61c7684}. */
static const vmbus_guid_t GUID_HVKBD = {{
    0x6d,0xad,0x12,0xf9,0x17,0x2b,0xea,0x48,0xbd,0x65,0xf9,0x27,0xa6,0x1c,0x76,0x84 }};

static vmbus_channel_t *s_ch;
static int              s_ready;

void
hv_kbd_poll(void)
{
    if (!s_ready)
        return;
    uint8_t buf[256];
    uint32_t len; uint16_t type; uint64_t tid;
    for (int n = 0; n < 32 && vmbus_recv(s_ch, buf, sizeof(buf), &len, &type, &tid); n++) {
        if (type != VMBUS_PKT_DATA_INBAND || len < sizeof(hk_keystroke_t))
            continue;
        hk_keystroke_t *k = (hk_keystroke_t *)buf;
        if (k->hdr.type != SYNTH_KBD_EVENT)
            continue;
        if (k->info & KBD_IS_UNICODE) {
            /* Host already resolved a Unicode code point (Enhanced Session,
             * Msvm_Keyboard.TypeText, clipboard paste).  make_code is the
             * char, not a scancode — inject ASCII on key-down, ignore key-up. */
            if (!(k->info & KBD_IS_BREAK) && k->make_code && k->make_code < 0x80u)
                kbd_inject((char)k->make_code);
            continue;
        }
        if (k->info & KBD_IS_E1)
            continue;                       /* pause/break — no single scancode */
        if (k->info & KBD_IS_E0)
            kbd_feed_scancode(XTKBD_EMUL0); /* reconstruct the E0 prefix byte */
        uint8_t sc = (uint8_t)(k->make_code & 0xFFu);
        if (k->info & KBD_IS_BREAK)
            sc |= XTKBD_RELEASE;
        kbd_feed_scancode(sc);
    }
}

void
hv_kbd_init(void)
{
    if (!vmbus_connected())
        return;
    s_ch = vmbus_find_channel(&GUID_HVKBD);
    if (!s_ch) { printk("[HVKBD] no keyboard channel offered\n"); return; }
    if (vmbus_open(s_ch, HVKBD_DATA_PAGES) != 0) {
        printk("[HVKBD] channel open failed\n"); return; }

    hk_request_t req;
    req.hdr.type = SYNTH_KBD_PROTOCOL_REQUEST;
    req.version  = SYNTH_KBD_VERSION;
    if (vmbus_send_inband(s_ch, &req, sizeof(req), 1, 1) < 0) {
        printk("[HVKBD] protocol request failed\n"); return; }

    uint8_t buf[256]; uint32_t len; uint16_t type; uint64_t tid;
    int accepted = 0;
    for (uint32_t i = 0; i < HVKBD_POLL_BUDGET && !accepted; i++) {
        if (!vmbus_recv(s_ch, buf, sizeof(buf), &len, &type, &tid)) {
            arch_pause();
            continue;
        }
        if (type != VMBUS_PKT_DATA_INBAND || len < sizeof(hk_response_t))
            continue;
        hk_response_t *r = (hk_response_t *)buf;
        if (r->hdr.type != SYNTH_KBD_PROTOCOL_RESPONSE)
            continue;
        if (!(r->proto_status & PROTOCOL_ACCEPTED)) {
            printk("[HVKBD] protocol rejected (status=0x%x)\n", (unsigned)r->proto_status);
            return;
        }
        accepted = 1;
    }
    if (!accepted) { printk("[HVKBD] no protocol response\n"); return; }

    s_ready = 1;
    printk("[HVKBD] OK: synthetic keyboard ready\n");
}
