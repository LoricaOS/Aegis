/* virtio_input.c — virtio 1.0 input device, on the shared virtio core
 *
 * Brings up a virtio-input device (keyboard / tablet) and feeds key presses
 * into the shared keyboard ring, so virtio-keyboard works like the PS/2 and USB
 * HID keyboards. This is what cloud/QEMU consoles use for input.
 *
 * Queue 0 = eventq (device → guest input events), queue 1 = statusq (unused).
 * Each event is a virtio_input_event {type, code, value}. The eventq is pre-
 * filled with device-writable 8-byte buffers and recycled, like virtio-net RX.
 * Drained from the 100 Hz PIT poll.
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

#define VINPUT_SLOTS  256u

extern void kbd_usb_inject(uint8_t ascii);

typedef struct __attribute__((packed)) {
    uint16_t type;
    uint16_t code;
    uint32_t value;
} virtio_input_event_t;

static virtio_dev_t s_dev;
static virtq_t      s_eventq, s_statusq;
static int          s_active;
static uintptr_t    s_ev_page;       /* KVA of the event buffer page */
static uint64_t     s_ev_pa[VINPUT_SLOTS];
static uintptr_t    s_ev_va[VINPUT_SLOTS];
static int          s_logged_first;

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

void
virtio_input_poll(void)
{
    if (!s_active)
        return;

    uint16_t id; uint32_t len;
    while (virtq_poll_used(&s_eventq, &id, &len)) {
        if (id < VINPUT_SLOTS && len >= sizeof(virtio_input_event_t)) {
            const virtio_input_event_t *e =
                (const virtio_input_event_t *)s_ev_va[id];
            if (e->type == EV_KEY && e->value == 1u) {   /* key press */
                if (!s_logged_first) {
                    printk("[VINPUT] first key event code=%u val=%u\n",
                           e->code, e->value);
                    s_logged_first = 1;
                }
                if (e->code < 128u) {
                    char c = s_evdev_ascii[e->code];
                    if (c)
                        kbd_usb_inject((uint8_t)c);
                }
            }
        }
        if (id < VINPUT_SLOTS)
            virtq_publish_single(&s_eventq, id, s_ev_pa[id],
                                 sizeof(virtio_input_event_t), 1);
    }
    virtq_notify(&s_eventq);
}

void
virtio_input_init(void)
{
    if (virtio_pci_find(VIRTIO_INPUT_MODERN, 0, &s_dev) < 0)
        return;

    virtio_reset(&s_dev);
    if (virtio_negotiate(&s_dev, 0) < 0)
        return;
    if (virtio_setup_queue(&s_dev, 0, &s_eventq) < 0 ||
        virtio_setup_queue(&s_dev, 1, &s_statusq) < 0) {
        s_dev.common->device_status = VIRTIO_STATUS_FAILED;
        return;
    }

    /* Read the device name (select/subsel into config space). */
    volatile uint8_t *cfg = s_dev.devcfg;
    cfg[0] = (uint8_t)VIRTIO_INPUT_CFG_ID_NAME;   /* select */
    cfg[1] = 0;                                   /* subsel */
    uint8_t nlen = cfg[2];                        /* size */
    char name[64];
    uint8_t i;
    for (i = 0; i < nlen && i < sizeof(name) - 1u; i++)
        name[i] = (char)cfg[8 + i];
    name[i] = '\0';

    /* Carve one DMA page into 8-byte event buffers and arm the eventq. */
    uint64_t page_pa; uintptr_t page_va;
    if (virtio_alloc_dma_page(&page_pa, &page_va) < 0)
        return;
    s_ev_page = page_va;
    uint16_t slots = s_eventq.size < VINPUT_SLOTS ? s_eventq.size : (uint16_t)VINPUT_SLOTS;
    uint16_t s;
    for (s = 0; s < slots; s++) {
        s_ev_va[s] = page_va + (uint64_t)s * 8u;
        s_ev_pa[s] = page_pa + (uint64_t)s * 8u;
        virtq_publish_single(&s_eventq, s, s_ev_pa[s],
                             sizeof(virtio_input_event_t), 1);
    }
    s_eventq.nfree = 0;   /* all event descriptors permanently armed */

    virtio_driver_ok(&s_dev);
    virtq_notify(&s_eventq);
    s_active = 1;

    printk("[VINPUT] OK: virtio-input \"%s\" eventq armed\n", name);
}
