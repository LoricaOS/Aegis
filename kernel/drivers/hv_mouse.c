/* hv_mouse.c — Hyper-V synthetic mouse (VMBus) → /dev/mouse ring.
 *
 * Gen 2 has no PS/2 mouse, so the pointer device is this VMBus "synthhid"
 * channel.  Protocol (Linux drivers/hid/hid-hyperv.c): messages are wrapped in
 * a pipe header [ pipe_prt_msg ][ synthhid_msg_hdr ][ payload ].  Handshake:
 *   guest → PROTOCOL_REQUEST(version) ; host → PROTOCOL_RESPONSE(approved)
 *   host  → INITIAL_DEVICE_INFO(HID descriptor) ; guest → DEVICE_INFO_ACK
 *   host  → INPUT_REPORT (ongoing) — a HID mouse report.
 *
 * The Hyper-V mouse reports ABSOLUTE position (0..32767 across the screen); our
 * /dev/mouse path is relative (dx/dy), so we scale the absolute position to
 * framebuffer pixels and inject the delta from the previous position.
 *
 * Reuses the VMBus inband ring proven by StorVSC/NetVSC; gated on
 * vmbus_connected().  NB: synthetic-mouse movement can only be exercised from an
 * interactive VMConnect session, so the input-report bytes are logged (bounded)
 * to confirm the HID report layout on first use.
 */
#include "vmbus.h"
#include "usb_mouse.h"
#include "fb.h"
#include "printk.h"
#include "arch.h"
#include <stdint.h>
#include <stddef.h>

#define SYNTHHID_VERSION             0x00020000u   /* major 2, minor 0 */
#define SYNTH_HID_PROTOCOL_REQUEST   0u
#define SYNTH_HID_PROTOCOL_RESPONSE  1u
#define SYNTH_HID_INITIAL_DEVICE_INFO     2u
#define SYNTH_HID_INITIAL_DEVICE_INFO_ACK 3u
#define SYNTH_HID_INPUT_REPORT       4u
#define PIPE_MESSAGE_DATA            1u

#define HVMOUSE_DATA_PAGES   4u
#define HVMOUSE_POLL_BUDGET  200000000u

typedef struct __attribute__((packed)) { uint32_t type; uint32_t size; } pipe_hdr_t;
typedef struct __attribute__((packed)) { uint32_t type; uint32_t size; } synthhid_hdr_t;

#define PIPE_OFF      0u
#define HID_OFF       (sizeof(pipe_hdr_t))                   /* synthhid_hdr here */
#define HID_BODY_OFF  (HID_OFF + sizeof(synthhid_hdr_t))     /* synthhid payload  */

/* Synthetic mouse interface type {cfa8b69e-5b4a-4cc0-b98b-8ba1a1f3f95a}
 * (wire byte order, captured from a real offer). */
static const vmbus_guid_t GUID_HVMOUSE = {{
    0x9e,0xb6,0xa8,0xcf,0x4a,0x5b,0xc0,0x4c,0xb9,0x8b,0x8b,0xa1,0xa1,0xf3,0xf9,0x5a }};

static vmbus_channel_t *s_ch;
static int       s_ready;
static int       s_have_last;
static int32_t   s_last_px, s_last_py;
static volatile uint32_t s_reports;   /* DIAG */

/* Wrap a synthhid message in a pipe header and send it inband. */
static void
hv_mouse_send(uint32_t hid_type, const void *payload, uint32_t paylen)
{
    uint8_t msg[64];
    if (HID_BODY_OFF + paylen > sizeof(msg))
        return;
    pipe_hdr_t  *p = (pipe_hdr_t *)(msg + PIPE_OFF);
    synthhid_hdr_t *h = (synthhid_hdr_t *)(msg + HID_OFF);
    p->type = PIPE_MESSAGE_DATA;
    p->size = sizeof(synthhid_hdr_t) + paylen;
    h->type = hid_type;
    h->size = paylen;
    for (uint32_t i = 0; i < paylen; i++)
        ((uint8_t *)msg)[HID_BODY_OFF + i] = ((const uint8_t *)payload)[i];
    vmbus_send_inband(s_ch, msg, HID_BODY_OFF + paylen, 1, 0);
}

/* Parse a HID mouse input report (absolute) and inject a relative event.
 * Hyper-V mouse report layout (logged on first use to confirm): byte 0 buttons,
 * [1..2] X abs LE (0..32767), [3..4] Y abs LE, [5] wheel. */
static void
hv_mouse_report(const uint8_t *r, uint32_t len)
{
    if (s_reports < 8u) {
        printk("[HV-MOUSE] report len=%u b=%x %x %x %x %x %x %x\n", (unsigned)len,
               len>0?r[0]:0, len>1?r[1]:0, len>2?r[2]:0, len>3?r[3]:0,
               len>4?r[4]:0, len>5?r[5]:0, len>6?r[6]:0);
    }
    s_reports++;
    if (len < 5)
        return;
    uint8_t  buttons = r[0] & 0x07u;
    uint16_t ax = (uint16_t)(r[1] | (r[2] << 8));
    uint16_t ay = (uint16_t)(r[3] | (r[4] << 8));
    int16_t  wheel = (len > 5) ? (int8_t)r[5] : 0;

    uint64_t phys; uint32_t w = 0, h = 0, pitch;
    fb_get_phys_info(&phys, &w, &h, &pitch);
    if (!w || !h)
        return;
    int32_t px = (int32_t)((uint32_t)ax * w / 32768u);
    int32_t py = (int32_t)((uint32_t)ay * h / 32768u);
    int16_t dx = 0, dy = 0;
    if (s_have_last) {
        dx = (int16_t)(px - s_last_px);
        dy = (int16_t)(py - s_last_py);
    }
    s_last_px = px; s_last_py = py; s_have_last = 1;
    if (wheel)
        mouse_inject_scroll(buttons, dx, dy, wheel);
    else
        mouse_inject(buttons, dx, dy);
}

void
hv_mouse_poll(void)
{
    if (!s_ready)
        return;
    uint8_t buf[256];
    uint32_t len; uint16_t type; uint64_t tid;
    for (int n = 0; n < 16 && vmbus_recv(s_ch, buf, sizeof(buf), &len, &type, &tid); n++) {
        if (type != VMBUS_PKT_DATA_INBAND || len < HID_BODY_OFF)
            continue;
        synthhid_hdr_t *h = (synthhid_hdr_t *)(buf + HID_OFF);
        if (h->type == SYNTH_HID_INPUT_REPORT)
            hv_mouse_report(buf + HID_BODY_OFF, len - HID_BODY_OFF);
        /* INITIAL_DEVICE_INFO can also arrive late; ack it so reports resume. */
        else if (h->type == SYNTH_HID_INITIAL_DEVICE_INFO) {
            uint8_t reserved = 0;
            hv_mouse_send(SYNTH_HID_INITIAL_DEVICE_INFO_ACK, &reserved, 1);
        }
    }
}

void
hv_mouse_init(void)
{
    if (!vmbus_connected())
        return;
    s_ch = vmbus_find_channel(&GUID_HVMOUSE);
    if (!s_ch) { printk("[HV-MOUSE] no mouse channel offered\n"); return; }
    if (vmbus_open(s_ch, HVMOUSE_DATA_PAGES) != 0) {
        printk("[HV-MOUSE] channel open failed\n"); return; }

    uint32_t version = SYNTHHID_VERSION;
    hv_mouse_send(SYNTH_HID_PROTOCOL_REQUEST, &version, sizeof(version));

    uint8_t buf[256]; uint32_t len; uint16_t type; uint64_t tid;
    int approved = 0, got_info = 0;
    for (uint32_t i = 0; i < HVMOUSE_POLL_BUDGET && !got_info; i++) {
        if (!vmbus_recv(s_ch, buf, sizeof(buf), &len, &type, &tid)) {
            arch_pause();
            continue;
        }
        if (type != VMBUS_PKT_DATA_INBAND || len < HID_BODY_OFF)
            continue;
        synthhid_hdr_t *h = (synthhid_hdr_t *)(buf + HID_OFF);
        if (h->type == SYNTH_HID_PROTOCOL_RESPONSE) {
            uint8_t approved_byte = (len > HID_BODY_OFF + sizeof(version))
                                  ? buf[HID_BODY_OFF + sizeof(version)] : 1;
            approved = approved_byte ? 1 : 0;
            if (!approved) { printk("[HV-MOUSE] protocol rejected\n"); return; }
        } else if (h->type == SYNTH_HID_INITIAL_DEVICE_INFO) {
            uint8_t reserved = 0;
            hv_mouse_send(SYNTH_HID_INITIAL_DEVICE_INFO_ACK, &reserved, 1);
            got_info = 1;
        }
    }
    if (!got_info) { printk("[HV-MOUSE] no device info\n"); return; }
    (void)approved;

    s_ready = 1;
    printk("[HV-MOUSE] OK: synthetic mouse ready\n");
}
