#include "serial.h"
#include "kbd.h"
#include "pic.h"
#include "printk.h"
#include "stackshot.h"
#include "trace.h"

/* COM1 base I/O port and register offsets */
#define COM1_BASE   0x3F8
#define COM1_DATA   (COM1_BASE + 0)   /* Data register (DLAB=0) / DLL (DLAB=1) */
#define COM1_IER    (COM1_BASE + 1)   /* Interrupt Enable (DLAB=0) / DLH (DLAB=1) */
#define COM1_FCR    (COM1_BASE + 2)   /* FIFO Control */
#define COM1_LCR    (COM1_BASE + 3)   /* Line Control */
#define COM1_MCR    (COM1_BASE + 4)   /* Modem Control */
#define COM1_LSR    (COM1_BASE + 5)   /* Line Status */

#define LSR_TXEMPTY   (1 << 5)        /* Transmit-hold-register empty */
#define LSR_DATAREADY (1 << 0)        /* Received data available in RBR/FIFO */
#define IER_RX_AVAIL  (1 << 0)        /* Enable "received data available" IRQ */

/* outb — write byte to I/O port.
 * Clobbers: none (volatile prevents reordering). */
static inline void outb(unsigned short port, unsigned char val)
{
    __asm__ volatile ("outb %0, %1" : : "a"(val), "Nd"(port));
}

/* inb — read byte from I/O port. */
static inline unsigned char inb(unsigned short port)
{
    unsigned char val;
    __asm__ volatile ("inb %1, %0" : "=a"(val) : "Nd"(port));
    return val;
}

void serial_init(void)
{
    outb(COM1_IER, 0x00);   /* disable all interrupts */
    outb(COM1_LCR, 0x80);   /* enable DLAB to set baud rate divisor */
    outb(COM1_DATA, 0x01);  /* divisor low byte: 1 → 115200 baud */
    outb(COM1_IER,  0x00);  /* divisor high byte: 0 */
    outb(COM1_LCR, 0x03);   /* 8 data bits, no parity, 1 stop bit; clear DLAB */
    outb(COM1_FCR, 0xC7);   /* enable FIFO, clear TX/RX, 14-byte threshold */
    outb(COM1_MCR, 0x0B);   /* assert DTR, RTS, OUT2 */

    serial_write_string("[SERIAL] OK: COM1 initialized at 115200 baud\n");
}

void serial_write_char(char c)
{
    /* Emit \r before every \n so terminal emulators render correctly. */
    if (c == '\n') {
        while ((inb(COM1_LSR) & LSR_TXEMPTY) == 0) {}
        outb(COM1_DATA, '\r');
    }
    /* Spin until transmit-hold register is empty */
    while ((inb(COM1_LSR) & LSR_TXEMPTY) == 0) {}
    outb(COM1_DATA, (unsigned char)c);
}

void serial_write_string(const char *s)
{
    while (*s != '\0') {
        serial_write_char(*s);
        s++;
    }
}

/* serial_rx_init — enable interrupt-driven COM1 receive.
 *
 * Called from kbd_init() (after pic_init, before ioapic_init) so the IRQ
 * unmask happens in the same phase as the PS/2 keyboard.  The RX FIFO and
 * 14-byte trigger level are already programmed by serial_init (FCR=0xC7),
 * and MCR OUT2 (bit 3) is already asserted there, gating the UART INT line
 * through to the interrupt controller.  Enabling IER bit 0 also arms the
 * UART character-timeout interrupt, so a single keystroke is delivered
 * without waiting for the FIFO trigger level to be reached.
 *
 * Silent (no [SERIAL] line) to keep the boot oracle unchanged. */
void serial_rx_init(void)
{
    outb(COM1_IER, IER_RX_AVAIL);
    /* Legacy-PIC fallback path: unmask IRQ4.  When the I/O APIC is present
     * it disables the PIC and routes IRQ4 itself (ioapic_init route_irq(4)),
     * making this a harmless no-op on that path. */
    pic_unmask(4);
}

/* serial_rx_handler — IRQ4 (vector 0x24) handler.  Drains the entire RX
 * FIFO into the keyboard ring buffer so a burst (a typed/pasted line) is
 * consumed in one interrupt — the hardware FIFO is only 16 bytes deep.
 *
 * Bytes are injected raw: a terminal already sends the same encoding the
 * PS/2 path produces — '\r' for Enter, 0x7F for backspace, 0x03 for Ctrl-C,
 * ESC '[' A/B/C/D for arrows — so the line discipline sees serial and
 * keyboard input identically. */
/* SysRq-over-serial: the prefix byte 0x1F (Ctrl-_, a control code no shell or
 * app emits) followed by a command letter runs an emergency introspection op
 * straight from the RX ISR — so it works even when userspace/the scheduler is
 * wedged.  't' dumps all task stacks (stackshot); 'h' lists commands.  The
 * prefix + command bytes are consumed (never injected into the input ring). */
static void
sysrq_handle(unsigned char cmd)
{
    switch (cmd) {
    case 't':
        dump_all_tasks("sysrq-t");
        break;
    case 'r':
        trace_dump("sysrq-r");
        break;
    case 'h':
        printk("[SYSRQ] commands: t=stackshot r=trace-ring h=help\n");
        break;
    default:
        printk("[SYSRQ] unknown command 0x%x (0x1F then 'h' for help)\n",
               (unsigned)cmd);
        break;
    }
}

void serial_rx_handler(void)
{
    static int sysrq_pending = 0;
    while (inb(COM1_LSR) & LSR_DATAREADY) {
        unsigned char b = inb(COM1_DATA);
        if (sysrq_pending) {
            sysrq_pending = 0;
            sysrq_handle(b);
            continue;
        }
        if (b == 0x1F) {        /* SysRq prefix — consume, await command */
            sysrq_pending = 1;
            continue;
        }
        kbd_inject((char)b);
    }
}
