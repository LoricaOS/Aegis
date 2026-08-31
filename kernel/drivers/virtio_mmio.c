/* virtio_mmio.c — virtio-mmio transport discovery (microVM).
 *
 * MicroVMs expose virtio devices not on a PCI bus but as flat MMIO register
 * blocks at fixed physical addresses (spec §4.2). There is no bus to walk, and
 * the base differs per VMM (Firecracker 0xd0000000, QEMU microvm 0xfeb00000),
 * so we discover devices two ways, in order:
 *
 *   1. The kernel command line, Linux-compatible `virtio_mmio.device=` entries
 *      (`<size>@<base>:<irq>`). The VMM passes one per device — Firecracker does
 *      this automatically — so this is the portable, base-agnostic mechanism.
 *   2. A fixed-window scan of QEMU's x86 microvm or ARM virt transport array as
 *      a fallback for when the cmdline carries no entries.
 *
 * Either way we probe each candidate for the "virt" magic + modern (v2) version
 * and record its device type. Register access + the handshake live in
 * virtio_core.c (dispatched by dev->is_mmio); the drivers poll, so no IRQ wiring
 * is needed — the `:irq` field is parsed and ignored.
 */
#include "virtio.h"
#include "arch.h"        /* arch_get_cmdline */
#include "printk.h"
#include <stddef.h>

/* QEMU microvm transport array (fallback scan). 24 transports today; scan a
 * generous 32. Each slot is 0x200; 32 × 0x200 = 0x4000 = 4 pages. */
#define VMMIO_WINDOW_BASE   0xFEB00000ULL
#define VMMIO_ARM_BASE      0x0A000000ULL
#define VMMIO_SLOT_STRIDE   0x200u
#define VMMIO_SCAN_SLOTS    32u
#define VMMIO_SCAN_PAGES    4u

#define MAX_MMIO_DEVS       16

static struct { volatile uint8_t *base; uint16_t devid; } s_devs[MAX_MMIO_DEVS];
static int s_ndevs;
static int s_probed;

static inline uint32_t rd(volatile uint8_t *b, uint32_t off)
{
    return *(volatile uint32_t *)(b + off);
}

/* Record a candidate transport if it carries a live modern virtio device. */
static void
try_add(uint64_t base_pa)
{
    if (s_ndevs >= MAX_MMIO_DEVS || base_pa == 0)
        return;
    uintptr_t page = virtio_map_mmio(base_pa & ~0xFFFULL, 1);
    if (!page)
        return;
    volatile uint8_t *slot = (volatile uint8_t *)(page + (base_pa & 0xFFFULL));
    if (rd(slot, VMMIO_MAGIC_VALUE) != VIRTIO_MMIO_MAGIC) return;
    if (rd(slot, VMMIO_VERSION) != 2u)                   return;  /* modern only */
    uint32_t id = rd(slot, VMMIO_DEVICE_ID);
    if (id == 0)                                         return;  /* empty slot */
    s_devs[s_ndevs].base  = slot;
    s_devs[s_ndevs].devid = (uint16_t)id;
    s_ndevs++;
}

/* Parse a hex integer (optional 0x), advancing *pp past it. */
static uint64_t
rd_hex(const char **pp)
{
    const char *p = *pp;
    uint64_t v = 0;
    if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X'))
        p += 2;
    for (;; p++) {
        char c = *p;
        uint32_t d;
        if      (c >= '0' && c <= '9') d = (uint32_t)(c - '0');
        else if (c >= 'a' && c <= 'f') d = (uint32_t)(c - 'a' + 10);
        else if (c >= 'A' && c <= 'F') d = (uint32_t)(c - 'A' + 10);
        else break;
        v = v * 16u + d;
    }
    *pp = p;
    return v;
}

static int
matches(const char *s, const char *pfx)
{
    while (*pfx)
        if (*s++ != *pfx++)
            return 0;
    return 1;
}

/* Build s_devs[] once: cmdline `virtio_mmio.device=` entries first, else the
 * QEMU microvm window scan. */
static void
probe(void)
{
    if (s_probed)
        return;
    s_probed = 1;

    const char *cmd = arch_get_cmdline();
    if (cmd) {
        static const char *KEY = "virtio_mmio.device=";
        for (const char *p = cmd; *p; p++) {
            if (!matches(p, KEY))
                continue;
            p += 19;                 /* strlen("virtio_mmio.device=") */
            while (*p && *p != '@' && *p != ' ')  /* skip <size> */
                p++;
            if (*p != '@')
                continue;
            p++;
            try_add(rd_hex(&p));     /* <base> */
            p--;                     /* for-loop's p++ */
        }
    }

#if defined(__x86_64__)
    /* This fixed window belongs to QEMU's x86 microvm machine. Reading an
     * absent MMIO address on ARM raises a synchronous external abort. */
    if (s_ndevs == 0) {              /* fallback: scan QEMU microvm's array */
        uintptr_t win = virtio_map_mmio(VMMIO_WINDOW_BASE, VMMIO_SCAN_PAGES);
        if (win) {
            for (uint32_t i = 0; i < VMMIO_SCAN_SLOTS && s_ndevs < MAX_MMIO_DEVS; i++) {
                volatile uint8_t *slot = (volatile uint8_t *)(win + i * VMMIO_SLOT_STRIDE);
                if (rd(slot, VMMIO_MAGIC_VALUE) != VIRTIO_MMIO_MAGIC) continue;
                if (rd(slot, VMMIO_VERSION) != 2u)                   continue;
                uint32_t id = rd(slot, VMMIO_DEVICE_ID);
                if (id == 0)                                         continue;
                s_devs[s_ndevs].base  = slot;
                s_devs[s_ndevs].devid = (uint16_t)id;
                s_ndevs++;
            }
        }
    }
#elif defined(__aarch64__) && !defined(AEGIS_BOOT_NATIVE)
    /* QEMU virt exposes 32 virtio-mmio transports at 0x0a000000. Native Pi
     * builds must not probe this absent window: an unmapped device read aborts. */
    if (s_ndevs == 0) {
        uintptr_t win = virtio_map_mmio(VMMIO_ARM_BASE, VMMIO_SCAN_PAGES);
        if (win) {
            for (uint32_t i = 0; i < VMMIO_SCAN_SLOTS && s_ndevs < MAX_MMIO_DEVS; i++) {
                volatile uint8_t *slot = (volatile uint8_t *)(win + i * VMMIO_SLOT_STRIDE);
                if (rd(slot, VMMIO_MAGIC_VALUE) != VIRTIO_MMIO_MAGIC) continue;
                if (rd(slot, VMMIO_VERSION) != 2u)                   continue;
                uint32_t id = rd(slot, VMMIO_DEVICE_ID);
                if (id == 0)                                         continue;
                s_devs[s_ndevs].base = slot;
                s_devs[s_ndevs].devid = (uint16_t)id;
                s_ndevs++;
            }
        }
    }
#endif

    if (s_ndevs)
        printk("[VMMIO] %d device(s) discovered\n", s_ndevs);
}

/* Find the (skip+1)-th live virtio-mmio device whose type == device_type.
 * Leaves *out ready for virtio_reset/negotiate/setup_queue (is_mmio=1). */
int
virtio_mmio_find_nth(uint16_t device_type, int skip, virtio_dev_t *out)
{
    if (device_type == 0)
        return -1;
    probe();

    int seen = 0;
    for (int i = 0; i < s_ndevs; i++) {
        if (s_devs[i].devid != device_type)
            continue;
        if (seen++ < skip)
            continue;
        out->is_mmio         = 1;
        out->mmio            = s_devs[i].base;
        out->devcfg          = s_devs[i].base + VMMIO_CONFIG;  /* config @ 0x100 */
        out->common          = NULL;
        out->notify_base     = NULL;
        out->notify_off_mult = 0;
        out->features        = 0;
        return 0;
    }
    return -1;
}
