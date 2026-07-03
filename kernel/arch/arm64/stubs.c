/*
 * stubs.c — arm64 stand-ins for symbols shared code links against whose
 * real providers are x86-only drivers. Each is a fail-closed no-op: absent
 * hardware reads as "no device", never as fake success.
 */

#include "arch.h"
#include "printk.h"
#include "ksym.h"
#include "../../sched/waitq.h"
#include "../../drivers/usb_mouse.h"
#include <stdint.h>

/* ── Backtrace (kernel/core/stackshot.h) ───────────────────────────────────
 * AAPCS64 frame records have the same layout as x86 -fno-omit-frame-pointer
 * frames: [fp+0] = previous fp, [fp+8] = return address (lr). */
void
print_backtrace_from(uint64_t fp, int max)
{
    for (int i = 0; i < max; i++) {
        if (fp < 0xFFFFFFFF80000000ULL || (fp & 7ULL))
            break;
        uint64_t retaddr = ((uint64_t *)fp)[1];
        if (retaddr < 0xFFFFFFFF80000000ULL || retaddr == 0)
            break;
        uint64_t off = 0;
        const char *sym = ksym_lookup(retaddr, &off);
        if (sym)
            printk("    [%u] 0x%lx %s+0x%lx\n", i, retaddr, sym, off);
        else
            printk("    [%u] 0x%lx\n", i, retaddr);
        fp = ((uint64_t *)fp)[0];
    }
}

/* ── pvpanic (kernel/drivers/panic_screen.c) — QEMU x86 ISA device ─────── */
void pvpanic_signal_panic(void) {}

/* /dev/mouse is real on arm64 now: usb_mouse.c provides g_mouse_waiters,
 * mouse_poll and mouse_inject_scroll, fed by virtio-input (virtio_input.c).
 * (The old no-pointer stubs lived here.)
 *
 * virtio_input.c feeds keyboard chars via kbd_usb_inject (the x86 name); on
 * arm64 the keyboard ring is fed by kbd_inject — bridge the two. */
extern void kbd_inject(char c);
void kbd_usb_inject(uint8_t ascii) { kbd_inject((char)ascii); }

/* ── virtio-gpu (kernel/syscall/sys_disk.c fb syscalls) — not ported ───── */
int virtio_gpu_active(void) { return 0; }
void virtio_gpu_flush(void) {}

uint8_t *
virtio_gpu_framebuffer(uint32_t *w, uint32_t *h, uint32_t *pitch)
{
    (void)w; (void)h; (void)pitch;
    return 0;
}
