/*
 * vc_mailbox_fb.c — VideoCore property-mailbox framebuffer for native Pi 5.
 *
 * The BCM2712 has no simple-framebuffer node in its DTB and config.txt sets up
 * no display, so on the native (non-Limine) path nobody hands us a framebuffer
 * and fb_init() stays silent. But the VideoCore firmware that netbooted us is
 * still alive and still services the classic property mailbox (DTB:
 * mailbox@7c013880, compatible "brcm,bcm2835-mbox"). We ask it to allocate a
 * linear framebuffer — the firmware does all the HVS/pixelvalve/HDMI setup
 * itself — and it returns a base + pitch we scan out as-is. No display-pipeline
 * programming on our side.
 *
 * Addresses (this board):
 *   - Mailbox regs: DTB child 0x7c013880 under soc@107c000000 whose
 *     ranges = <0 0x10_00000000 0x80000000> → CPU-phys 0x10_7c013880, inside
 *     the step-2b device block, reachable via arch_dmap (no extra mapping).
 *   - Message-buffer bus address: the firmware node has an empty `dma-ranges`
 *     (identity), so the VideoCore sees DRAM 1:1 — the bus address we write to
 *     the mailbox is just the ARM physical address, provided the buffer is in
 *     the low 4 GB (the mailbox register is 32-bit: [31:4]=addr, [3:0]=chan).
 *     kva_alloc_pages_low_nc gives a <4 GB, non-cacheable page, so no manual
 *     cache maintenance around the (non-coherent) VideoCore access is needed.
 */

#include "arch.h"
#include "printk.h"
#include "kva.h"
#include <stdint.h>

/* Mailbox registers (offsets from the 0x...3880 base; classic bcm2835 layout). */
#define MBOX_BASE_PHYS  0x107c013880UL
#define MBOX_READ       0x00
#define MBOX_STATUS     0x18
#define MBOX_WRITE      0x20
#define MBOX_FULL       0x80000000u
#define MBOX_EMPTY      0x40000000u
#define MBOX_CHAN_PROP  8u              /* ARM→VC property/tags channel */

/* Property tags. */
#define TAG_GET_DISPLAY_WH  0x00040003u
#define TAG_SET_PHYS_WH     0x00048003u
#define TAG_SET_VIRT_WH     0x00048004u
#define TAG_SET_DEPTH       0x00048005u
#define TAG_SET_PIXORDER    0x00048006u
#define TAG_ALLOC_FB        0x00040001u
#define TAG_GET_PITCH       0x00040008u
#define REQ_OK              0x80000000u

/* arch_native_set_fb — publish a framebuffer into arch_mm's s_fb_info so
 * arch_get_fb_info()/fb_init() pick it up (the native counterpart of
 * arch_mm_ingest's Limine framebuffer path). */
void arch_native_set_fb(uint64_t addr, uint32_t w, uint32_t h, uint32_t pitch);

static volatile uint32_t *
mbox_regs(void)
{
    return (volatile uint32_t *)arch_dmap(MBOX_BASE_PHYS);
}

/* mbox_call — hand the VideoCore the 16-byte-aligned physical address of a
 * property message on the given channel and spin until it answers. Returns 1
 * on a matching reply, 0 on a malformed one. Blocking spin-wait: this runs
 * exactly twice at boot, before the scheduler exists. */
/* Bounded spin so a wrong mailbox address/protocol on this first-ever-on-Pi5
 * path degrades to "skip framebuffer" instead of hard-hanging a no-watchdog
 * boot. ~loop budget; the VC answers a property call in microseconds. */
#define MBOX_SPIN_MAX 100000000u

static int
mbox_call(uint32_t msg_phys, uint32_t chan)
{
    volatile uint32_t *m = mbox_regs();
    uint32_t val = (msg_phys & ~0xFu) | (chan & 0xFu);
    uint32_t spin;

    for (spin = 0; spin < MBOX_SPIN_MAX; spin++)
        if (!(m[MBOX_STATUS / 4] & MBOX_FULL))
            break;
    if (spin == MBOX_SPIN_MAX) return 0;
    m[MBOX_WRITE / 4] = val;

    for (spin = 0; spin < MBOX_SPIN_MAX; spin++) {
        if (m[MBOX_STATUS / 4] & MBOX_EMPTY)
            continue;
        uint32_t r = m[MBOX_READ / 4];
        if ((r & 0xFu) == chan)
            return (r & ~0xFu) == (val & ~0xFu);
    }
    return 0;   /* timed out waiting for a reply */
}

/* pi5_mbox_display_wh — ask the firmware for the display size it programmed
 * from the monitor's EDID at boot. Returns 0/0 if no monitor was present. */
static void
pi5_mbox_display_wh(uint32_t *buf, uint32_t buf_phys, uint32_t *w, uint32_t *h)
{
    uint32_t i = 0;
    buf[i++] = 0;                  /* total size (filled below) */
    buf[i++] = 0;                  /* request */
    buf[i++] = TAG_GET_DISPLAY_WH;
    buf[i++] = 8; buf[i++] = 0;    /* value buf size / req */
    uint32_t wi = i++;             /* response: width  */
    uint32_t hi = i++;             /* response: height */
    buf[wi] = 0; buf[hi] = 0;
    buf[i++] = 0;                  /* end tag */
    buf[0] = i * 4;

    *w = *h = 0;
    if (mbox_call(buf_phys, MBOX_CHAN_PROP) && buf[1] == REQ_OK) {
        *w = buf[wi];
        *h = buf[hi];
    }
}

/* pi5_fb_init — allocate a 32-bpp linear framebuffer via the VideoCore and
 * publish it. Sized to the attached monitor (EDID) when one is present, else a
 * 1920x1080 default. Called from kernel_main_arm64 just before fb_init(). */
void
pi5_fb_init(void)
{
    uint32_t *buf = (uint32_t *)kva_alloc_pages_low_nc(1);
    if (!buf) {
        printk("[VCFB] skip: no low-DMA page for mailbox buffer\n");
        return;
    }
    uint64_t bp64 = kva_page_phys(buf);
    if (bp64 == 0 || (bp64 >> 32) != 0) {
        printk("[VCFB] skip: mailbox buffer not in low 4GB (phys=0x%lx)\n", bp64);
        return;
    }
    uint32_t buf_phys = (uint32_t)bp64;

    uint32_t w = 0, h = 0;
    pi5_mbox_display_wh(buf, buf_phys, &w, &h);
    if (w == 0 || h == 0 || w > 16384 || h > 16384) {
        printk("[VCFB] no EDID display size (got %ux%u) — defaulting 1920x1080\n",
               w, h);
        w = 1920; h = 1080;
    } else {
        printk("[VCFB] firmware display size %ux%u (from EDID)\n", w, h);
    }

    /* Build the allocate request: set physical + virtual size, 32bpp, BGR,
     * allocate, get pitch — one message. Responses overwrite the same slots. */
    uint32_t i = 0;
    buf[i++] = 0;                       /* total size (filled below) */
    buf[i++] = 0;                       /* request */

    buf[i++] = TAG_SET_PHYS_WH; buf[i++] = 8; buf[i++] = 0;
    buf[i++] = w; buf[i++] = h;
    buf[i++] = TAG_SET_VIRT_WH; buf[i++] = 8; buf[i++] = 0;
    buf[i++] = w; buf[i++] = h;
    buf[i++] = TAG_SET_DEPTH;   buf[i++] = 4; buf[i++] = 0;
    buf[i++] = 32;
    buf[i++] = TAG_SET_PIXORDER;buf[i++] = 4; buf[i++] = 0;
    buf[i++] = 0;                       /* 0 = BGR (fb.c handles BGR or RGB) */

    buf[i++] = TAG_ALLOC_FB;    buf[i++] = 8; buf[i++] = 0;
    uint32_t basei = i++;               /* in: align 4096 / out: base */
    uint32_t sizei = i++;               /* out: size */
    buf[basei] = 4096; buf[sizei] = 0;

    buf[i++] = TAG_GET_PITCH;   buf[i++] = 4; buf[i++] = 0;
    uint32_t pitchi = i++;              /* out: pitch */
    buf[pitchi] = 0;

    buf[i++] = 0;                       /* end tag */
    buf[0] = i * 4;

    if (!mbox_call(buf_phys, MBOX_CHAN_PROP) || buf[1] != REQ_OK) {
        printk("[VCFB] FAIL: framebuffer-allocate rejected (resp=0x%x)\n", buf[1]);
        return;
    }

    uint32_t fb_bus  = buf[basei];
    uint32_t fb_size = buf[sizei];
    uint32_t pitch   = buf[pitchi];

    /* Bus → ARM physical: the VideoCore returns the base in its bus view; the
     * top two bits are the cache alias (0xC0000000 = uncached). Strip them to
     * get the ARM physical address (identity dma-ranges on this SoC). Logged
     * raw so the mapping can be corrected from serial if a future firmware
     * hands back a genuinely high address instead of an alias. */
    uint64_t fb_phys = (uint64_t)(fb_bus & ~0xC0000000u);

    printk("[VCFB] OK: %ux%u pitch=%u base_bus=0x%x -> phys=0x%lx size=%u KB\n",
           w, h, pitch, fb_bus, fb_phys, fb_size / 1024);

    if (fb_phys == 0 || pitch == 0) {
        printk("[VCFB] FAIL: implausible base/pitch\n");
        return;
    }
    arch_native_set_fb(fb_phys, w, h, pitch);
}
