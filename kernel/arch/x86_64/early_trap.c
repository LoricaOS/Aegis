/* early_trap.c — capture faults that happen before the real IDT exists (x86-64).
 *
 * idt_init() runs late in bring-up (kernel/core/main.c, after PMM, VMM, KVA,
 * the sanitizers and the framebuffer). Until it does there is NO IDT: the IDTR
 * still holds whatever the firmware left, so the first exception or stray IRQ
 * is a triple fault, and QEMU with -no-reboot just exits. The guest dies having
 * printed its last successful line and nothing else.
 *
 * That is exactly how the ubuntu-26.04 regression presented: last serial line
 * `[CMDLINE] OK: boot=text`, no panic, exit in ~0.8s. Nothing in the kernel
 * could say which stage or which instruction died, so the failure was
 * indistinguishable from a hang, a loader problem, or a corrupted image.
 *
 * This installs gates for the 32 architectural exception vectors as soon as the
 * serial port works, and reports on the way down: the named bring-up stage, the
 * vector, the error code, CR2/RIP/CS/RFLAGS, and the stack pointer the fault
 * happened on. The handler deliberately needs nothing that is not set up yet —
 * no PMM, no page tables, no locks, no scheduler, no printk — and it runs on its
 * own static stack (early_trap.asm), because the likeliest reason to arrive
 * here is that the boot stack overflowed into the bootstrap page tables that sit
 * directly below it in .bss.
 *
 * It is replaced wholesale by idt_init() later; nothing here survives that. */
#include "arch.h"
#include "early_trap.h"
#include "idt.h"
#include "serial.h"
#include <stdint.h>

#define EARLY_VECTORS 32

/* The pre-IDT gates. Only the architectural vectors get one; a later vector
 * raises #GP, which vector 13 here catches and reports. */
static aegis_idt_gate_t s_early_idt[EARLY_VECTORS];

/* Stubs in early_trap.asm, one per vector, in vector order. */
extern void *early_trap_stubs[EARLY_VECTORS];

/* Set before each bring-up step in kernel_main so a report can name the stage.
 * Volatile: the report must see the value live at the fault, not a stale
 * register copy the compiler was free to keep. */
static const char *volatile s_stage = "(before first stage)";

void early_trap_stage(const char *stage) { s_stage = stage; }

/* ── Reporting: serial only, no locks, no allocation, no printk ──────────── */

static void put_str(const char *s) { serial_write_string(s); }


static void put_dec(uint64_t v)
{
    char buf[21];
    int  n = 0;

    if (v == 0) { serial_write_char('0'); return; }
    while (v) { buf[n++] = (char)('0' + (v % 10)); v /= 10; }
    while (n) serial_write_char(buf[--n]);
}


/* Hex into a caller buffer, digits built by arithmetic rather than a lookup
 * table: a static const array is one more thing that has to be mapped and
 * readable from a fault handler, and this path is the last chance to say
 * anything at all. */
static void hex_str(uint64_t v, char *out)
{
    for (int i = 0; i < 18; i++)
        out[i] = '0';
    out[0] = '0';
    out[1] = 'x';
    for (int i = 17; i >= 2; i--) {
        unsigned d = (unsigned)(v & 0xF);
        out[i] = (char)(d < 10 ? '0' + d : 'a' + (d - 10));
        v >>= 4;
    }
    out[18] = '\0';
}

/* early_trap_report — called from early_trap_stubs.asm with a normalised frame:
 *   f[0]=vector f[1]=error_code f[2]=rip f[3]=cs f[4]=rflags
 *   f[5]=rsp at the fault (before the stub switched to the trap stack)
 * Never returns: printing is all that is safe, so fail closed and halt.
 *
 * The first line carries the whole verdict (vector and rip) on purpose: if
 * anything later misbehaves, the two fields that name the fault are already
 * on the wire. An earlier version died mid-report and lost exactly those. */
void early_trap_report(const uint64_t *f)
{
    char    hx[19];
    uint64_t cr2 = 0;
    __asm__ volatile ("mov %%cr2, %0" : "=r"(cr2));

    /* Verdict first, on one line. */
    hex_str(f[2], hx);
    put_str("\nEARLY FAULT vec=");
    put_dec(f[0]);
    put_str(" rip=");
    put_str(hx);
    put_str(" stage=");
    put_str(s_stage);
    put_str("\n");

    /* Then the detail, each field printed straight from a fresh buffer. */
    hex_str(f[1], hx); put_str("  err     = "); put_str(hx); put_str("\n");
    hex_str(f[3], hx); put_str("  cs      = "); put_str(hx); put_str("\n");
    hex_str(f[4], hx); put_str("  rflags  = "); put_str(hx); put_str("\n");
    hex_str(cr2,  hx); put_str("  cr2     = "); put_str(hx);
    put_str(f[0] == 14 ? "  (#PF)" : ""); put_str("\n");
    hex_str(f[5], hx); put_str("  faultrsp= "); put_str(hx); put_str("\n");
    put_str("EARLY FAULT: halted\n");

    for (;;) __asm__ volatile ("cli; hlt");
}

void early_trap_init(void)
{
    struct {
        uint16_t limit;
        uint64_t base;
    } __attribute__((packed)) idtr = {
        .limit = sizeof(s_early_idt) - 1,
        .base  = (uint64_t)s_early_idt,
    };

    for (int i = 0; i < EARLY_VECTORS; i++) {
        uint64_t a = (uint64_t)early_trap_stubs[i];
        s_early_idt[i].offset_lo  = (uint16_t)(a & 0xFFFF);
        s_early_idt[i].selector   = ARCH_KERNEL_CS;
        s_early_idt[i].ist        = 0;
        s_early_idt[i].type_attr  = 0x8E;   /* present, DPL=0, interrupt gate */
        s_early_idt[i].offset_mid = (uint16_t)((a >> 16) & 0xFFFF);
        s_early_idt[i].offset_hi  = (uint32_t)(a >> 32);
        s_early_idt[i].zero       = 0;
    }

    __asm__ volatile ("lidt %0" : : "m"(idtr));
}

/* ── Boot-stack high-water mark ─────────────────────────────────────────── */

/* boot.asm paints [boot_stack, boot_stack_top - 256) with 0xAA before the
 * first call, so however deep the stack ever gets leaves the deepest word
 * overwritten. Scanning up from the bottom finds that boundary: the first word
 * that is still 0xAA is the lowest address never used. */
extern uint8_t boot_stack[];
extern uint8_t boot_stack_top[];

#define BOOT_STACK_PAINT_W 0xAAAAAAAAAAAAAAAAULL

uint64_t boot_stack_used(void)
{
    /* Plain integer arithmetic on the symbols: taking the difference of two
     * extern arrays of unknown bound, or indexing one, trips -Warray-bounds. */
    uintptr_t base = (uintptr_t)boot_stack;
    uintptr_t top  = (uintptr_t)boot_stack_top;
    uintptr_t end  = top - 256;
    uintptr_t p    = base;

    while (p < end && *(const uint64_t *)p == BOOT_STACK_PAINT_W)
        p += sizeof(uint64_t);
    if (p >= end)
        return 0;                        /* never went below the top 256 B */
    return (uint64_t)(top - p);
}
