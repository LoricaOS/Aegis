/* virtio_input.c — virtio 1.0 input devices (keyboard + mouse), virtio core.
 *
 * QEMU exposes each input device (virtio-keyboard, virtio-mouse/tablet) as a
 * separate virtio-input PCI device. We claim every one we find and route its
 * event stream by type/code, so a single poll loop drives both:
 *   - EV_KEY, code < 128  → keyboard keycode → kbd_usb_inject (like PS/2/USB)
 *   - EV_KEY, BTN_LEFT/RIGHT/MIDDLE (0x110..0x112) → mouse button level
 *   - EV_REL REL_X/REL_Y/REL_WHEEL → accumulate pointer delta / wheel
 *   - EV_SYN → flush the accumulated pointer event into the /dev/mouse ring
 * This is the arm64 desktop's input path (virt has no PS/2; framebuffer is from
 * the bootloader). Also works on x86 QEMU.
 *
 * Queue 0 = eventq (device → guest), queue 1 = statusq (unused). Each event is
 * a virtio_input_event {type, code, value}; the eventq is pre-filled with
 * device-writable 8-byte buffers and recycled. Drained from the 100 Hz poll.
 *
 * References: VIRTIO v1.0 §5.8 Input Device; Linux evdev event codes.
 */
#include "virtio.h"
#include "arch.h"
#include "printk.h"
#include <stdint.h>

#define VIRTIO_INPUT_MODERN  0x1052u
#define VIRTIO_INPUT_CFG_ID_NAME 0x01u

#define EV_SYN  0x00u
#define EV_KEY  0x01u
#define EV_REL  0x02u
#define EV_ABS  0x03u

#define REL_X      0x00u
#define REL_Y      0x01u
#define REL_WHEEL  0x08u
#define BTN_LEFT   0x110u
#define BTN_RIGHT  0x111u
#define BTN_MIDDLE 0x112u

#define VINPUT_SLOTS  256u
#define MAX_VINPUT    4          /* keyboard + mouse + a couple spare */

extern void kbd_usb_inject(uint8_t ascii);
extern void mouse_inject_scroll(uint8_t buttons, int16_t dx, int16_t dy,
                                int16_t scroll);

typedef struct __attribute__((packed)) {
    uint16_t type;
    uint16_t code;
    uint32_t value;
} virtio_input_event_t;

typedef struct {
    virtio_dev_t dev;
    virtq_t      eventq, statusq;
    uint64_t     ev_pa[VINPUT_SLOTS];
    uintptr_t    ev_va[VINPUT_SLOTS];
    int          active;
} vinput_dev_t;

static vinput_dev_t s_in[MAX_VINPUT];
static int          s_nin;
static int          s_logged_first;

/* Accumulated pointer state, flushed to /dev/mouse on EV_SYN. Global because
 * only the mouse device emits EV_REL/BTN; the keyboard's EV_SYN sees no pending
 * motion and is a no-op. Buttons are a level (persist across flushes). */
static uint8_t  s_buttons;
static int32_t  s_dx, s_dy, s_wheel;
static int      s_pointer_dirty;

/* US-layout evdev keycode → unshifted ASCII. */
static const char s_evdev_ascii[128] = {
    [2]='1',[3]='2',[4]='3',[5]='4',[6]='5',[7]='6',[8]='7',[9]='8',[10]='9',[11]='0',
    [12]='-',[13]='=',[14]='\b',[15]='\t',
    [16]='q',[17]='w',[18]='e',[19]='r',[20]='t',[21]='y',[22]='u',[23]='i',[24]='o',[25]='p',
    [26]='[',[27]=']',[28]='\n',
    [30]='a',[31]='s',[32]='d',[33]='f',[34]='g',[35]='h',[36]='j',[37]='k',[38]='l',
    [39]=';',[40]='\'',[41]='`',[43]='\\',
    [44]='z',[45]='x',[46]='c',[47]='v',[48]='b',[49]='n',[50]='m',
    [51]=',',[52]='.',[53]='/',[57]=' ',
};

static void
vinput_handle(const virtio_input_event_t *e)
{
    switch (e->type) {
    case EV_KEY:
        if (e->code < 128u) {                     /* keyboard keycode */
            if (e->value == 1u) {                 /* press only */
                char c = s_evdev_ascii[e->code];
                if (c)
                    kbd_usb_inject((uint8_t)c);
            }
        } else {                                  /* mouse button (level) */
            uint8_t bit = e->code == BTN_LEFT   ? 0x1u :
                          e->code == BTN_RIGHT  ? 0x2u :
                          e->code == BTN_MIDDLE ? 0x4u : 0u;
            if (bit) {
                if (e->value) s_buttons |= bit; else s_buttons &= (uint8_t)~bit;
                s_pointer_dirty = 1;
            }
        }
        break;
    case EV_REL:
        if (e->code == REL_X)          { s_dx    += (int32_t)e->value; s_pointer_dirty = 1; }
        else if (e->code == REL_Y)     { s_dy    += (int32_t)e->value; s_pointer_dirty = 1; }
        else if (e->code == REL_WHEEL) { s_wheel += (int32_t)e->value; s_pointer_dirty = 1; }
        break;
    case EV_SYN:
        if (s_pointer_dirty) {
            mouse_inject_scroll(s_buttons, (int16_t)s_dx, (int16_t)s_dy,
                                (int16_t)s_wheel);
            s_dx = s_dy = s_wheel = 0;
            s_pointer_dirty = 0;
        }
        break;
    default:
        break;                                    /* EV_ABS etc. ignored (rel mouse) */
    }
}

void
virtio_input_poll(void)
{
    int n;
    for (n = 0; n < s_nin; n++) {
        vinput_dev_t *v = &s_in[n];
        if (!v->active)
            continue;
        uint16_t id; uint32_t len;
        while (virtq_poll_used(&v->eventq, &id, &len)) {
            if (id < VINPUT_SLOTS && len >= sizeof(virtio_input_event_t)) {
                const virtio_input_event_t *e =
                    (const virtio_input_event_t *)v->ev_va[id];
                if (!s_logged_first &&
                    (e->type == EV_KEY || e->type == EV_REL)) {
                    printk("[VINPUT] first event dev%d type=%u code=%u val=%u\n",
                           n, e->type, e->code, e->value);
                    s_logged_first = 1;
                }
                vinput_handle(e);
            }
            if (id < VINPUT_SLOTS)
                virtq_publish_single(&v->eventq, id, v->ev_pa[id],
                                     sizeof(virtio_input_event_t), 1);
        }
        virtq_notify(&v->eventq);
    }
}

/* Bring up one virtio-input device (the skip-th match). Returns 0 on success. */
static int
vinput_setup_one(int skip, vinput_dev_t *v)
{
    if (virtio_pci_find_nth(VIRTIO_INPUT_MODERN, 0, skip, &v->dev) < 0)
        return -1;

    virtio_reset(&v->dev);
    if (virtio_negotiate(&v->dev, 0) < 0)
        return -1;
    if (virtio_setup_queue(&v->dev, 0, &v->eventq) < 0 ||
        virtio_setup_queue(&v->dev, 1, &v->statusq) < 0) {
        v->dev.common->device_status = VIRTIO_STATUS_FAILED;
        return -1;
    }

    /* Device name (select/subsel into config space) — for the log line. */
    volatile uint8_t *cfg = v->dev.devcfg;
    cfg[0] = (uint8_t)VIRTIO_INPUT_CFG_ID_NAME;
    cfg[1] = 0;
    uint8_t nlen = cfg[2];
    char name[64];
    uint8_t i;
    for (i = 0; i < nlen && i < sizeof(name) - 1u; i++)
        name[i] = (char)cfg[8 + i];
    name[i] = '\0';

    /* Carve one DMA page into 8-byte event buffers and arm the eventq. */
    uint64_t page_pa; uintptr_t page_va;
    if (virtio_alloc_dma_page(&page_pa, &page_va) < 0)
        return -1;
    uint16_t slots = v->eventq.size < VINPUT_SLOTS
                     ? v->eventq.size : (uint16_t)VINPUT_SLOTS;
    uint16_t s;
    for (s = 0; s < slots; s++) {
        v->ev_va[s] = page_va + (uint64_t)s * 8u;
        v->ev_pa[s] = page_pa + (uint64_t)s * 8u;
        virtq_publish_single(&v->eventq, s, v->ev_pa[s],
                             sizeof(virtio_input_event_t), 1);
    }
    v->eventq.nfree = 0;

    virtio_driver_ok(&v->dev);
    virtq_notify(&v->eventq);
    v->active = 1;

    printk("[VINPUT] OK: virtio-input \"%s\" (dev%d) eventq armed\n", name, skip);
    return 0;
}

void
virtio_input_init(void)
{
    int skip;
    for (skip = 0; skip < MAX_VINPUT; skip++) {
        if (vinput_setup_one(skip, &s_in[s_nin]) == 0)
            s_nin++;
        else
            break;   /* no more virtio-input devices */
    }
    if (s_nin == 0)
        return;
    printk("[VINPUT] %d input device(s) active\n", s_nin);
}
