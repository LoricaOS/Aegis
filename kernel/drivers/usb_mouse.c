/* usb_mouse.c — USB HID boot-protocol mouse driver
 *
 * Parses 3-byte boot protocol mouse reports into mouse_event_t structs
 * and stores them in a ring buffer. /dev/mouse reads from this buffer.
 *
 * Ring buffer: 128 entries (~900 bytes BSS). Static allocation.
 * Blocking read uses sti/hlt/cli pattern (same as kbd_read).
 */
#include "usb_mouse.h"
#include "sched.h"
#include "spinlock.h"
#include "arch.h"
#include "../sched/waitq.h"
#include "../sched/wait_event.h"
#include <stddef.h>

#define MOUSE_BUF_SIZE 128

static mouse_event_t s_buf[MOUSE_BUF_SIZE];
static volatile uint32_t s_head = 0;
static volatile uint32_t s_tail = 0;

static spinlock_t mouse_lock = SPINLOCK_INIT;

/* g_mouse_waiters — the single wake queue for ALL waiters on mouse events:
 * blocking mouse_read_blocking() (registered via wait_event) AND sys_poll /
 * sys_epoll_wait pollers (the /dev/mouse VFS ops in initrd.c extern it for
 * get_waitq).  One mechanism, not two — the old bespoke single-task s_waiter
 * pointer was removed (it could only remember ONE blocked reader, losing a
 * wakeup if two blocked).  Woken from buf_push() in HID dispatch context
 * (PIT ISR → xhci_poll → usb_hid_process_report → buf_push). */
waitq_t g_mouse_waiters = WAITQ_INIT;

/* mouse_has_data — lockless availability hint for wait_event's condition.
 * The authoritative consume happens via mouse_poll() after the wait. */
static int
mouse_has_data(void)
{
    return s_head != s_tail;
}

static void
buf_push(const mouse_event_t *evt)
{
    irqflags_t fl = spin_lock_irqsave(&mouse_lock);
    uint32_t next = (s_head + 1) % MOUSE_BUF_SIZE;
    if (next != s_tail) {
        s_buf[s_head] = *evt;
        s_head = next;
    }
    spin_unlock_irqrestore(&mouse_lock, fl);
    /* Wake everything waiting on mouse events: blocking mouse_read_blocking
     * (registered via wait_event) AND sys_poll / sys_epoll_wait pollers on
     * /dev/mouse — all share this one queue.  waitq_wake_all is documented
     * ISR-safe; called outside mouse_lock to avoid nested locks (and to keep
     * the lock order sched_lock > waitq > mouse_lock). */
    waitq_wake_all(&g_mouse_waiters);
}

void
usb_mouse_process_report(const uint8_t *data, uint32_t len)
{
    if (len < 3) return;

    mouse_event_t evt;
    evt.buttons = data[0];
    evt.dx      = (int16_t)(int8_t)data[1];
    evt.dy      = (int16_t)(int8_t)data[2];
    evt.scroll  = 0;

    buf_push(&evt);
}

int
mouse_poll(mouse_event_t *out)
{
    irqflags_t fl = spin_lock_irqsave(&mouse_lock);
    if (s_head == s_tail) {
        spin_unlock_irqrestore(&mouse_lock, fl);
        return 0;
    }
    *out = s_buf[s_tail];
    s_tail = (s_tail + 1) % MOUSE_BUF_SIZE;
    spin_unlock_irqrestore(&mouse_lock, fl);
    return 1;
}

void
mouse_inject_scroll(uint8_t buttons, int16_t dx, int16_t dy, int16_t scroll)
{
    mouse_event_t evt;
    evt.buttons = buttons;
    evt.dx      = dx;
    evt.dy      = dy;
    evt.scroll  = scroll;
    buf_push(&evt);
}

void
mouse_inject(uint8_t buttons, int16_t dx, int16_t dy)
{
    mouse_inject_scroll(buttons, dx, dy, 0);
}

void
mouse_read_blocking(mouse_event_t *out)
{
    /* Block until a mouse event is available.  Uninterruptible (no signal
     * check — historical mouse_read_blocking semantics: this is the only
     * blocking site and it had no signal_check_pending).
     *
     * wait_event registers on g_mouse_waiters BEFORE the condition check, so
     * an event injected in the gap is not lost (wake_pending closes the
     * race).  mouse_has_data() is the lockless hint; the authoritative
     * consume happens via mouse_poll() after the wait returns.  Loop because
     * wait_event can also return on a shared/spurious wake. */
    arch_enable_irq();
    for (;;) {
        if (mouse_poll(out))
            break;
        wait_event(&g_mouse_waiters, mouse_has_data());
    }
    arch_disable_irq();
}
