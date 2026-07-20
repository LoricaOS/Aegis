#include "kbd.h"
#include "pic.h"
#include "arch.h"
#include "printk.h"
#include "random.h"
#include "signal.h"
#include "tty.h"
#include "sched.h"
#include "spinlock.h"
#include "serial.h"
#include "../../sched/waitq.h"
#include "../../sched/wait_event.h"
#include "../../lib/ringbuf.h"
#include "trace.h"

/* Shared console-input wake queue (defined in kernel/fs/console.c).  ALL
 * waiters on keyboard input register here — blocking kbd_read /
 * kbd_read_interruptible (via wait_event) AND sys_poll / sys_epoll_wait on
 * /dev/tty and /dev/console.  One waiter mechanism, not two: producers
 * (PS/2 kbd_handler, USB kbd_usb_inject, serial kbd_inject — all funnel
 * through buf_push) call waitq_wake_all(&g_console_waiters). */
extern waitq_t g_console_waiters;

#define KBD_DATA   0x60
#define KBD_STATUS 0x64   /* read: status; write: command */
#define KBD_CMD    0x64

/* Input-source counters — exposed via /proc/kbdstat so the bastion greeter
 * can show whether the kernel is receiving input at all on machines with
 * no serial console (the only way to triage "keyboard dead at greeter"
 * reports from bare metal). */
static volatile uint32_t s_cnt_ps2    = 0;
static volatile uint32_t s_cnt_usb    = 0;
static volatile uint32_t s_cnt_serial = 0;

void
kbd_stats_get(uint32_t *ps2, uint32_t *usb, uint32_t *serial)
{
    if (ps2)    *ps2    = s_cnt_ps2;
    if (usb)    *usb    = s_cnt_usb;
    if (serial) *serial = s_cnt_serial;
}

/* 64-byte ring buffer */
#define KBD_BUF_SIZE 64
RINGBUF_ASSERT_POW2(KBD_BUF_SIZE);
static volatile char    s_buf[KBD_BUF_SIZE];
static volatile uint32_t s_head = 0;  /* next write position */
static volatile uint32_t s_tail = 0;  /* next read position  */

static spinlock_t kbd_lock = SPINLOCK_INIT;

/* Shift state */
static volatile int s_shift = 0;

/* Ctrl state */
static volatile int s_ctrl = 0;

/* Alt state */
static volatile int s_alt = 0;

/* US QWERTY scancode set 1 — unshifted (make codes 0x01–0x39).
 * Index 0x01 = Escape. Translates to 0x1B so userspace can act on the
 * Esc key (pre-fix, ESC was 0 here and got silently dropped by the
 * `if (c)` filter below — meaning Escape didn't work anywhere). */
static const char s_sc_lower[] = {
    0,   '\033', '1', '2', '3', '4', '5', '6',  /* 0x00–0x07 */
    '7', '8', '9', '0', '-', '=',  127,  '\t', /* 0x08–0x0F */
    'q', 'w', 'e', 'r', 't', 'y', 'u', 'i',   /* 0x10–0x17 */
    'o', 'p', '[', ']', '\r',  0,  'a', 's',   /* 0x18–0x1F */
    'd', 'f', 'g', 'h', 'j', 'k', 'l', ';',   /* 0x20–0x27 */
    '\'', '`', 0,  '\\','z', 'x', 'c', 'v',   /* 0x28–0x2F */
    'b', 'n', 'm', ',', '.', '/',  0,   '*',   /* 0x30–0x37 */
    0,   ' '                                    /* 0x38–0x39 */
};

/* US QWERTY scancode set 1 — shifted */
static const char s_sc_upper[] = {
    0,   '\033', '!', '@', '#', '$', '%', '^',
    '&', '*', '(', ')', '_', '+', 127,  '\t',
    'Q', 'W', 'E', 'R', 'T', 'Y', 'U', 'I',
    'O', 'P', '{', '}', '\r',  0,  'A', 'S',
    'D', 'F', 'G', 'H', 'J', 'K', 'L', ':',
    '"', '~',  0,  '|', 'Z', 'X', 'C', 'V',
    'B', 'N', 'M', '<', '>', '?',  0,   '*',
    0,   ' '
};

#define SC_TABLE_SIZE ((int)(sizeof(s_sc_lower) / sizeof(s_sc_lower[0])))

static void
buf_push(char c)
{
    /* Receive-time ISIG (^C/^\/^Z) for the console tty — runs BEFORE
     * taking kbd_lock (tty_receive_isig takes sched_lock to signal).
     * Consumed bytes never enter the ring.  In graphical mode the console
     * tty's fg_pgrp is 0, so this is a no-op and Lumen's raw key stream is
     * untouched.  Covers all three input sources (PS/2, USB HID, serial
     * RX) since they all funnel through buf_push. */
    if (tty_receive_isig(tty_console(), c))
        return;

    irqflags_t fl = spin_lock_irqsave(&kbd_lock);
    /* Tracepoint: record every byte that reaches the ring with the head/tail it
     * sees, tagged by CPU — the producer half of the input-race flight record. */
    trace_emit(TRACE_KBD_INJECT, (unsigned char)c, s_head, s_tail);
    /* ringbuf_space() decides full/not-full (mask contract asserted at the
     * SIZE #define); the byte store + index advance stay explicit because
     * s_buf/s_head are volatile and the helper buys little here. */
    if (ringbuf_space(s_head, s_tail, KBD_BUF_SIZE) >= 1) {   /* drop if full */
        s_buf[s_head] = c;
        s_head = (s_head + 1) & (KBD_BUF_SIZE - 1);
    }
    spin_unlock_irqrestore(&kbd_lock, fl);
    /* Wake everything waiting on console input: blocking kbd_read /
     * kbd_read_interruptible (registered via wait_event) AND sys_poll /
     * sys_epoll_wait pollers on /dev/tty and /dev/console — all share this
     * one queue.  waitq_wake_all is documented ISR-safe; done outside
     * kbd_lock to avoid holding nested locks across the wake (and to keep
     * the lock order sched_lock > waitq > kbd_lock). */
    waitq_wake_all(&g_console_waiters);
}

/* ── Explicit 8042 controller init ──────────────────────────────────────
 * Do NOT trust the firmware's controller state.  A USB-stick boot leaves
 * the 8042 fully configured (scancode translation on, port 1 enabled,
 * device scanning on) because firmware used it; a UEFI NVMe boot —
 * especially on laptops — can hand us a controller with translation off
 * (device sends set-2 codes our set-1 tables map to 0 → every key
 * silently dropped), the port clock disabled, or scanning off.  Symptom:
 * keyboard works on the live USB boot, dead on the installed boot, same
 * machine — the i8042 twin of the xHCI PORTSC.PP bug. */

/* Status register bits */
#define I8042_STS_OBF  0x01   /* output buffer full — data readable at 0x60 */
#define I8042_STS_IBF  0x02   /* input buffer full — controller busy */

/* Pause-paced spin budgets.  Laptop embedded controllers service 8042
 * commands in firmware and can take tens of milliseconds per byte — a
 * 1ms budget bails mid-sequence and (in the first version of this code)
 * left the keyboard port disabled.  pause ≈ 20-40 cycles, so:
 *   I8042_SPIN_CMD ≈ 2M  pauses ≈ 15-50ms  (per command/response byte)
 *   I8042_SPIN_BAT ≈ 60M pauses ≈ 0.5-1.5s (keyboard BAT after reset;
 *                                            spec allows 750ms)             */
#define I8042_SPIN_CMD 2000000u
#define I8042_SPIN_BAT 60000000u

/* Diagnostic state for /proc/kbdstat — the bastion greeter renders this,
 * so serial-less machines show their controller state on screen. */
static volatile uint8_t s_i8042_cfg   = 0;
static volatile uint8_t s_i8042_state = KBD_I8042_ABSENT;

void
kbd_i8042_get(uint8_t *cfg, uint8_t *state)
{
    if (cfg)   *cfg   = s_i8042_cfg;
    if (state) *state = s_i8042_state;
}

/* Wait until the controller can accept a command/data byte (IBF clear). */
static int
i8042_wait_ibf_clear(uint32_t spins)
{
    while (spins--) {
        if (!(inb(KBD_STATUS) & I8042_STS_IBF))
            return 0;
        arch_pause();
    }
    return -1;
}

/* Read one response byte from the controller/device, or -1 on timeout. */
static int
i8042_read_data(uint32_t spins)
{
    while (spins--) {
        if (inb(KBD_STATUS) & I8042_STS_OBF)
            return (int)inb(KBD_DATA);
        arch_pause();
    }
    return -1;
}

/* Discard pending output-buffer bytes (stale scancodes, ACKs). */
static void
i8042_drain(void)
{
    uint32_t spins = 64;
    while (spins-- && (inb(KBD_STATUS) & I8042_STS_OBF))
        (void)inb(KBD_DATA);
}

/* Send a controller command (port 0x64). */
static int
i8042_cmd(uint8_t cmd)
{
    if (i8042_wait_ibf_clear(I8042_SPIN_CMD) < 0)
        return -1;
    outb(KBD_CMD, cmd);
    return 0;
}

/* Send a controller command and read its one-byte response. */
static int
i8042_cmd_read(uint8_t cmd)
{
    if (i8042_cmd(cmd) < 0)
        return -1;
    return i8042_read_data(I8042_SPIN_CMD);
}

/* Write a data byte (port 0x60 — config byte parameter or device byte). */
static int
i8042_write_data(uint8_t b)
{
    if (i8042_wait_ibf_clear(I8042_SPIN_CMD) < 0)
        return -1;
    outb(KBD_DATA, b);
    return 0;
}

/* Send a byte to the port-1 device and collect its ACK.  Handles the
 * 0xFE RESEND protocol (up to 3 retries) and skips interleaved scancode
 * bytes from a user typing during boot (bounded).  Returns 0 on 0xFA ACK,
 * -1 on timeout/no-ack. */
static int
i8042_kbd_send(uint8_t b)
{
    int tries = 3;
    while (tries--) {
        if (i8042_write_data(b) < 0)
            return -1;
        int skips = 8;
        int resend = 0;
        while (skips--) {
            int r = i8042_read_data(I8042_SPIN_CMD);
            if (r < 0)
                return -1;      /* no response at all */
            if (r == 0xFA)
                return 0;       /* ACK */
            if (r == 0xFE) {
                resend = 1;     /* RESEND — retry the byte */
                break;
            }
            /* anything else: stale scancode/junk — keep reading */
        }
        if (!resend)
            return -1;          /* junk flood with no ACK */
    }
    return -1;
}

/* Wait for the keyboard's Basic Assurance Test result after 0xFF reset.
 * 0xAA = pass.  Junk bytes are skipped (bounded). */
static int
i8042_kbd_wait_bat(void)
{
    int skips = 8;
    while (skips--) {
        int r = i8042_read_data(I8042_SPIN_BAT);
        if (r < 0)
            return -1;
        if (r == 0xAA)
            return 0;
        if (r == 0xFC || r == 0xFD)
            return -1;          /* BAT failure codes */
    }
    return -1;
}

/* Full controller + device bring-up.  Sequence follows the canonical
 * OSdev/Linux order: drain → disable ports → config read → controller
 * self-test (which may CLOBBER the config on real chips — config is
 * rewritten after) → interface test → config write → port enable →
 * device reset (0xFF → ACK → BAT) with 0xF4 fallback.
 *
 * Hard invariant: every exit path after the port-disable step re-enables
 * port 1.  A timeout mid-sequence must never leave the keyboard deader
 * than we found it. */
static void
i8042_init(void)
{
    int dev_ok = -1;            /* -1 none, 0 reset-ok, 1 f4-only */
    int r;

    i8042_drain();

    /* Disable both ports while reconfiguring.  If even this command
     * cannot be delivered, there is no (responsive) 8042 — leave
     * everything untouched. */
    if (i8042_cmd(0xAD) < 0) {
        printk("[KBD] WARN: no responsive 8042 controller\n");
        s_i8042_state = KBD_I8042_ABSENT;
        return;
    }
    (void)i8042_cmd(0xA7);      /* disable port 2 (aux) */
    i8042_drain();              /* disabling can latch a byte */

    /* Read current config. */
    r = i8042_cmd_read(0x20);
    if (r < 0) {
        printk("[KBD] WARN: 8042 config read failed\n");
        s_i8042_state = KBD_I8042_CFG_FAIL;
        goto reenable;
    }
    uint8_t cfg = (uint8_t)r;

    /* Controller self-test.  Quirk: on real hardware 0xAA can reset the
     * controller to power-on defaults, clobbering the config byte — that
     * is why the config write below happens AFTER the self-test, never
     * before.  A failing/timeout self-test is logged but not fatal
     * (several laptop ECs fail it yet work fine — Linux tolerates this
     * too). */
    r = i8042_cmd_read(0xAA);
    if (r != 0x55)
        printk("[KBD] WARN: 8042 self-test returned 0x%x (continuing)\n",
               (uint32_t)r);

    /* Interface test for port 1 (0x00 = pass).  Diagnostic only. */
    r = i8042_cmd_read(0xAB);
    if (r != 0x00)
        printk("[KBD] WARN: 8042 port-1 interface test 0x%x (continuing)\n",
               (uint32_t)r);

    /* Desired config: IRQ1 on (bit0), scancode translation to set 1 on
     * (bit6), port-1 clock on (bit4=0).  Port 2 stays off — Aegis has no
     * PS/2 aux driver, and stray aux bytes at port 0x60 would interleave
     * into the scancode stream: int off (bit1=0), clock off (bit5=1). */
    cfg |= 0x01;
    cfg |= 0x40;
    cfg &= (uint8_t)~0x10;
    cfg &= (uint8_t)~0x02;
    cfg |= 0x20;

    if (i8042_cmd(0x60) < 0 || i8042_write_data(cfg) < 0) {
        printk("[KBD] WARN: 8042 config write failed\n");
        s_i8042_state = KBD_I8042_CFG_FAIL;
        goto reenable;
    }
    s_i8042_cfg = cfg;

reenable:
    /* ALWAYS re-enable port 1 — even on the failure paths above.  Write
     * the enable command unconditionally if the busy-wait times out:
     * best effort beats a disabled keyboard. */
    if (i8042_wait_ibf_clear(I8042_SPIN_CMD) < 0)
        printk("[KBD] WARN: 8042 busy at port re-enable, forcing\n");
    outb(KBD_CMD, 0xAE);

    if (s_i8042_state == KBD_I8042_CFG_FAIL)
        goto out;

    /* Device reset: known-good state regardless of what firmware left
     * behind (defaults: scancode set 2 + our translation = set 1 on the
     * wire, scanning enabled).  No response is normal on machines whose
     * keyboard is USB-only — not an error. */
    if (i8042_kbd_send(0xFF) == 0 && i8042_kbd_wait_bat() == 0) {
        dev_ok = 0;
    } else if (i8042_kbd_send(0xF4) == 0) {
        /* Reset refused but enable-scanning ACKed — device is alive. */
        dev_ok = 1;
    }

    s_i8042_state = (dev_ok == 0) ? KBD_I8042_DEV_OK
                  : (dev_ok == 1) ? KBD_I8042_DEV_F4
                                  : KBD_I8042_DEV_NONE;

out:
    i8042_drain();
    printk("[KBD] 8042 cfg=0x%x state=%u\n",
           (uint32_t)s_i8042_cfg, (uint32_t)s_i8042_state);
}

void
kbd_init(void)
{
    i8042_init();
    pic_unmask(1);  /* IRQ1 = PS/2 keyboard */
    /* Enable interrupt-driven serial (COM1) input in the same phase: PIC is
     * up and the I/O APIC has not yet taken over.  Serial bytes are injected
     * into this same ring buffer, so the console/tty reads serial keystrokes
     * exactly like PS/2 ones. */
    serial_rx_init();
    printk("[KBD] OK: PS/2 keyboard ready\n");
}

/* kbd_feed_scancode — process one PS/2 Scan Code Set 1 byte: the E0 prefix,
 * break codes, shift/ctrl/alt modifiers, and make-code → ASCII (or ESC
 * sequence) translation pushed into the shared input ring.  Shared by the PS/2
 * ISR (kbd_handler) and the Hyper-V synthetic keyboard (hv_kbd.c), which has no
 * i8042 and instead reconstructs the set-1 byte stream from VMBus keystroke
 * events (0xE0 prefix when IS_E0, make_code|0x80 when IS_BREAK). */
void
kbd_feed_scancode(uint8_t sc)
{
    /* Extended key prefix — set flag, handle next byte */
    static int s_e0_prefix;
    if (sc == 0xE0) {
        s_e0_prefix = 1;
        return;
    }

    /* E0-prefixed keys: arrow keys → ESC [ A/B/C/D sequences */
    if (s_e0_prefix) {
        s_e0_prefix = 0;
        if (sc & 0x80) {
            /* E0 break code — track modifier releases */
            uint8_t make = sc & 0x7F;
            if (make == 0x1D) s_ctrl = 0;  /* right Ctrl release */
            return;
        }
        /* E0 make codes */
        if (sc == 0x1D) { s_ctrl = 1; return; }  /* right Ctrl */
        char arrow = 0;
        switch (sc) {
        case 0x48: arrow = 'A'; break;  /* up */
        case 0x50: arrow = 'B'; break;  /* down */
        case 0x4B: arrow = 'D'; break;  /* left */
        case 0x4D: arrow = 'C'; break;  /* right */
        case 0x47: arrow = 'H'; break;  /* Home */
        case 0x4F: arrow = 'F'; break;  /* End */
        /* PrintScreen makes E0 2A E0 37; the 2A filler falls through
         * unmapped. ESC[p is the compositor's screenshot key (same
         * sequence the USB HID path emits for usage 0x46). */
        case 0x37: arrow = 'p'; break;  /* PrintScreen */
        }
        if (arrow) {
            buf_push('\033');
            buf_push('[');
            buf_push(arrow);
        }
        return;
    }

    /* Break code (key released) — bit 7 set */
    if (sc & 0x80) {
        uint8_t make = sc & 0x7F;
        /* Track shift releases */
        if (make == 0x2A || make == 0x36)
            s_shift = 0;
        if (make == 0x1D) { s_ctrl = 0; }
        if (make == 0x38) { s_alt = 0; }
        return;
    }

    /* Make code */
    if (sc == 0x2A || sc == 0x36) {    /* left or right shift */
        s_shift = 1;
        return;
    }

    /* Ctrl key: left Ctrl = 0x1D make, 0x9D break */
    if (sc == 0x1D) { s_ctrl = 1; return; }

    /* Alt key: left Alt = 0x38 make, 0xB8 break */
    if (sc == 0x38) { s_alt = 1; return; }

    /* Ctrl-D = EOF: push 0x04 (EOT) into ring buffer for line discipline */
    if (s_ctrl && sc == 0x20) {
        buf_push(0x04);
        return;
    }

    if (sc < SC_TABLE_SIZE) {
        char c = s_shift ? s_sc_upper[sc] : s_sc_lower[sc];
        if (c) {
            if (s_ctrl) c &= 0x1F;  /* General Ctrl: mask to control char */
            /* Ctrl+Shift: ESC prefix so compositor can distinguish from plain Ctrl.
             * e.g., Ctrl+Shift+C = ESC + 0x03, plain Ctrl+C = 0x03 */
            if (s_ctrl && s_shift) buf_push(0x1B);
            if (s_alt) buf_push(0x1B);  /* Alt: ESC prefix */
            buf_push(c);
        }
    }
}

void
kbd_handler(void)
{
    uint8_t sc = inb(KBD_DATA);
    s_cnt_ps2++;
    random_add_interrupt_entropy();  /* keyboard timing is excellent entropy */
    /* (The per-scancode [KBD-DBG] diagnostic that lived here was removed
     * after the 1.1.1 i8042 regression was root-caused; /proc/kbdstat
     * carries the delivery counters now.) */
    kbd_feed_scancode(sc);
}

char
kbd_read(void)
{
    char c;
    /*
     * Block until a keystroke is available.  Uninterruptible (a pending
     * signal does not break the wait — historical kbd_read semantics).
     *
     * wait_event registers on g_console_waiters BEFORE the condition check,
     * so a keystroke injected in the gap is not lost (wake_pending closes
     * the race).  kbd_has_data() is the lockless availability hint; the
     * authoritative consume happens via kbd_poll() after the wait returns.
     * Looping because wait_event can also return on a shared/spurious wake.
     *
     * SYSCALL entry clears IF, but sched_block() switches to other tasks
     * (which run with IF=1, the PS/2 IRQ1 fires there and buf_push wakes
     * us) — so no manual sti is needed, unlike the old hand-rolled loop.
     */
    for (;;) {
        if (kbd_poll(&c))
            return c;
        wait_event(&g_console_waiters, kbd_has_data());
    }
}

int
kbd_poll(char *out)
{
    irqflags_t fl = spin_lock_irqsave(&kbd_lock);
    if (ringbuf_empty(s_head, s_tail)) {
        spin_unlock_irqrestore(&kbd_lock, fl);
        return 0;
    }
    *out = s_buf[s_tail];
    /* Tracepoint: the consumer half — byte taken + head/tail seen, by CPU. */
    trace_emit(TRACE_KBD_CONSUME, (unsigned char)*out, s_head, s_tail);
    s_tail = (s_tail + 1) & (KBD_BUF_SIZE - 1);
    spin_unlock_irqrestore(&kbd_lock, fl);
    return 1;
}

int
kbd_has_data(void)
{
    irqflags_t fl = spin_lock_irqsave(&kbd_lock);
    int has = !ringbuf_empty(s_head, s_tail);
    spin_unlock_irqrestore(&kbd_lock, fl);
    return has;
}

/* kbd_usb_inject — inject an ASCII character from USB HID into the keyboard
 * ring buffer.  Called from usb_hid_process_report() in interrupt context
 * (PIT ISR → xhci_poll → usb_hid_process_report → here).
 *
 * Shares the same ring buffer as the PS/2 kbd_handler so that USB and PS/2
 * keystrokes are delivered identically to kbd_read() / kbd_poll() callers.
 * No separate unblock needed: kbd_read() spins on hlt and will wake on the
 * next interrupt after buf_push() has placed the character. */
void
kbd_usb_inject(uint8_t ascii)
{
    s_cnt_usb++;
    if (ascii == 0)
        return;
    buf_push((char)ascii);
}

/* kbd_inject — push a byte received over the serial console (COM1 IRQ4)
 * into the shared input ring.  Called from serial_rx_handler() in interrupt
 * context.  Like kbd_usb_inject, it shares the PS/2 ring so serial input is
 * delivered identically to kbd_read()/kbd_poll() and wakes console pollers;
 * NUL bytes are dropped, every other byte (including control chars and ESC
 * sequences) is passed through verbatim. */
void
kbd_inject(char c)
{
    s_cnt_serial++;
    if (c == 0)
        return;
    buf_push(c);
}

/* Deferred foreground pgrp — set before console tty is initialized.
 * Applied to tty_console()->fg_pgrp once the console tty exists. */
static volatile uint32_t s_deferred_pgrp = 0;

void
kbd_set_tty_pgrp(uint32_t pgid)
{
    tty_t *con = tty_console();
    if (con)
        con->fg_pgrp = pgid;
    else
        s_deferred_pgrp = pgid;
}

uint32_t
kbd_get_tty_pgrp(void)
{
    tty_t *con = tty_console();
    return con ? con->fg_pgrp : s_deferred_pgrp;
}

char
kbd_read_interruptible(int *interrupted)
{
    char c = 0;
    *interrupted = 0;
    for (;;) {
        if (kbd_poll(&c))
            return c;
        /* Block until a character is injected (any source) or a signal is
         * pending.  Interruptible so a Ctrl-C against a process parked in
         * this read delivers.  The authoritative consume re-runs via
         * kbd_poll() at the top of the loop after the wait returns. */
        int rc;
        wait_event_interruptible(&g_console_waiters, kbd_has_data(), rc);
        if (rc == BLOCK_EINTR) {   /* EINTR */
            *interrupted = 1;
            return '\0';
        }
    }
}
