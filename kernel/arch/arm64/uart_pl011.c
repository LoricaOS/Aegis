/*
 * uart_pl011.c — PL011 UART (QEMU virt @ PA 0x09000000, SPI 33).
 *
 * Serves both printk output (serial_write_string) and console input: the
 * RX interrupt feeds a small ring that kbd_read/kbd_poll drain — the
 * arm64 stand-in for the x86 PS/2 keyboard, so the shared tty/console
 * stack works unchanged.
 *
 * The MMIO base is a variable: kernel_main_limine points it at the early
 * TTBR0 identity map first (so boot printk works before vmm_init), then
 * vmm_init's device window moves it to ARCH_DMAP_BASE + PA permanently.
 */

#include "arch.h"
#include "kbd.h"
#include "printk.h"
#include "../../sched/waitq.h"
#include <stdint.h>

#define UART0_PHYS  0x09000000UL

#define UART_DR    0x00
#define UART_FR    0x18
#define UART_IBRD  0x24
#define UART_FBRD  0x28
#define UART_LCRH  0x2C
#define UART_CR    0x30
#define UART_IMSC  0x38
#define UART_MIS   0x40
#define UART_ICR   0x44

#define FR_TXFF   (1u << 5)
#define FR_RXFE   (1u << 4)

static volatile uint32_t *s_uart;   /* NULL until serial_init */
static int s_ready;

extern waitq_t g_console_waiters;   /* kernel/fs/console.c */

static inline uint32_t rd(uint32_t off) { return s_uart[off / 4]; }
static inline void     wr(uint32_t off, uint32_t v) { s_uart[off / 4] = v; }

/* serial_set_base — point the driver at a mapped VA for the PL011. */
void
serial_set_base(volatile void *va)
{
    s_uart = (volatile uint32_t *)va;
}

void
serial_init(void)
{
    if (!s_uart)
        return;
    wr(UART_CR, 0);                       /* disable while configuring */
    wr(UART_ICR, 0x7FF);                  /* clear all interrupts */
    wr(UART_LCRH, (3u << 5) | (1u << 4)); /* 8N1, FIFOs on */
    wr(UART_IMSC, 1u << 4);               /* RX interrupt */
    wr(UART_CR, 1u | (1u << 8) | (1u << 9)); /* UARTEN | TXE | RXE */
    s_ready = 1;
}

void
serial_putc(char c)
{
    if (!s_ready)
        return;
    while (rd(UART_FR) & FR_TXFF)
        ;
    wr(UART_DR, (uint32_t)(uint8_t)c);
}

void
serial_write_string(const char *s)
{
    while (*s) {
        if (*s == '\n')
            serial_putc('\r');
        serial_putc(*s++);
    }
}

/* ── Console input (kbd interface over PL011 RX) ───────────────────────── */

#define RX_RING 256
static char     s_ring[RX_RING];
static uint32_t s_head, s_tail;         /* head = write, tail = read */
static uint32_t s_tty_pgrp;
static uint32_t s_rx_count;             /* /proc/kbdstat serial counter */

/* uart_rx_irq — drain the RX FIFO into the ring; called from arm64_irq
 * (INTID 33). Wakes console readers like the x86 kbd ISR does. */
void
uart_rx_irq(void)
{
    while (!(rd(UART_FR) & FR_RXFE)) {
        char c = (char)rd(UART_DR);
        if (c == '\r')
            c = '\n';
        uint32_t next = (s_head + 1) % RX_RING;
        if (next != s_tail) {           /* drop on overflow */
            s_ring[s_head] = c;
            s_head = next;
        }
        s_rx_count++;
    }
    wr(UART_ICR, 1u << 4);
    waitq_wake_all(&g_console_waiters);
}

void
kbd_init(void)
{
    printk("[KBD] OK: PL011 RX console input\n");
}

int
kbd_poll(char *out)
{
    if (s_tail == s_head)
        return 0;
    *out = s_ring[s_tail];
    s_tail = (s_tail + 1) % RX_RING;
    return 1;
}

int
kbd_has_data(void)
{
    return s_tail != s_head;
}

char
kbd_read(void)
{
    char c;
    while (!kbd_poll(&c))
        arch_wait_for_irq();
    return c;
}

void
kbd_inject(char c)
{
    if (c == '\0')
        return;
    uint32_t next = (s_head + 1) % RX_RING;
    if (next != s_tail) {
        s_ring[s_head] = c;
        s_head = next;
    }
    s_rx_count++;
    waitq_wake_all(&g_console_waiters);
}

/* ── tty foreground pgrp + read-interruptible (kbd.h contract) ─────────── */

#include "../../sched/sched.h"
#include "../../proc/proc.h"

void
kbd_set_tty_pgrp(uint32_t pgid)
{
    s_tty_pgrp = pgid;
}

uint32_t
kbd_get_tty_pgrp(void)
{
    return s_tty_pgrp;
}

char
kbd_read_interruptible(int *interrupted)
{
    char c;
    *interrupted = 0;
    while (!kbd_poll(&c)) {
        aegis_task_t *t = sched_current();
        if (t && t->is_user) {
            aegis_process_t *p = (aegis_process_t *)t;
            if (p->pending_signals & ~p->signal_mask) {
                *interrupted = 1;
                return '\0';
            }
        }
        arch_wait_for_irq();
    }
    return c;
}

void
kbd_stats_get(uint32_t *ps2, uint32_t *usb, uint32_t *serial)
{
    if (ps2)    *ps2 = 0;
    if (usb)    *usb = 0;
    if (serial) *serial = s_rx_count;
}

void
kbd_i8042_get(uint8_t *cfg, uint8_t *state)
{
    if (cfg)   *cfg = 0;
    if (state) *state = KBD_I8042_ABSENT;
}
