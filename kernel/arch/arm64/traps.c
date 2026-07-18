/*
 * traps.c — EL1 exception dispatch (the arm64 isr_dispatch/idt.c).
 *
 * vectors.S saves the 34-slot frame and calls one of:
 *   arm64_sync_el0  — SVC (syscalls), EL0 aborts/traps
 *   arm64_irq       — IRQ from EL0 or EL1 (GICv3 ack/eoi + timer/UART)
 *   arm64_fault_el1 — sync exception in kernel mode = panic
 *
 * Fault policy mirrors x86 isr_dispatch: EL0 faults become signals
 * (never a kernel panic); not-present data/instruction aborts try demand
 * paging (mm_populate_fault); permission write faults try the COW break
 * (vmm_cow_fault_handle). Kernel faults panic with a backtrace.
 */

#include "arch.h"
#include "idt.h"
#include "printk.h"
#include "fb.h"       /* panic_halt lives here */
#include "vmm.h"
#include "proc.h"
#include "signal.h"
#include "../../sched/sched.h"
#include "../../syscall/syscall.h"
#include "stackshot.h"
#include <stdint.h>

extern char exception_vectors[];

void uart_rx_irq(void);
void timer_irq(void);
uint32_t gic_ack(void);
void gic_eoi(uint32_t intid);
int mm_populate_fault(aegis_process_t *proc, uint64_t va);

/* ESR_EL1 exception classes */
#define EC_UNKNOWN     0x00
#define EC_FP_ACCESS   0x07
#define EC_SVC64       0x15
#define EC_IABT_LOW    0x20    /* instruction abort from a lower EL (EL0) */
#define EC_IABT_CUR    0x21    /* instruction abort from EL1 (kernel)     */
#define EC_DABT_LOW    0x24    /* data abort from a lower EL (EL0)        */
#define EC_DABT_CUR    0x25    /* data abort from EL1 (kernel)            */
#define EC_BRK64       0x3C

/* Kernel exception table: {fault_pc, fixup_pc} pairs emitted by uaccess.S,
 * gathered by the linker between these bounds. */
extern uint64_t __start_ex_table[];
extern uint64_t __stop_ex_table[];

/* ex_table_lookup — map a faulting EL1 PC to its registered fixup (0 if
 * none). Linear scan; the table has only the handful of copy_*_user
 * load/store sites. */
static uint64_t
ex_table_lookup(uint64_t pc)
{
    for (uint64_t *e = __start_ex_table; e < __stop_ex_table; e += 2)
        if (e[0] == pc)
            return e[1];
    return 0;
}

void
idt_init(void)
{
    __asm__ volatile("msr vbar_el1, %0\n\tisb" : : "r"(exception_vectors));
    printk("[IDT] OK: EL1 vector table installed\n");
}

/* uaccess_selftest — prove the exception-table fixup catches a kernel fault
 * on a user address instead of panicking. Copies from 0x50000000, a TTBR0
 * VA past the early device identity map (so the ldrb translation-faults):
 * the EL1 data-abort handler must redirect to the fixup, returning "8 bytes
 * not copied". If the table/handler were broken this would panic the boot.
 * Runs once after vmm_init (device idmap active in TTBR0). */
uint64_t arm64_uaccess_copy(void *dst, const void *src, uint64_t len);

void
uaccess_selftest(void)
{
    uint8_t buf[8];
    uint64_t not_copied = arm64_uaccess_copy(buf, (const void *)0x50000000UL, 8);
    if (not_copied == 8)
        printk("[UACCESS] OK: EL1 fault fixup (%lu/8 uncopied)\n", not_copied);
    else
        printk("[UACCESS] WARN: fixup returned %lu, expected 8\n", not_copied);
}

static inline uint64_t
read_esr(void)
{
    uint64_t v;
    __asm__ volatile("mrs %0, esr_el1" : "=r"(v));
    return v;
}

static inline uint64_t
read_far(void)
{
    uint64_t v;
    __asm__ volatile("mrs %0, far_el1" : "=r"(v));
    return v;
}

/* pend_signal — queue sig against the current process with force-default
 * semantics for synchronous faults (mirrors x86 user_exception). */
static void
pend_signal(aegis_process_t *proc, uint32_t sig)
{
    if (proc->sigactions[sig].sa_handler == SIG_IGN ||
        (proc->signal_mask & (1ULL << sig)))
        proc->sigactions[sig].sa_handler = SIG_DFL;
    proc->signal_mask &= ~(1ULL << sig);
    (void)__atomic_or_fetch(&proc->pending_signals, (1ULL << sig),
                            __ATOMIC_RELAXED);
}

/* el0_fault — non-SVC synchronous exception from user space → signal. */
static void
el0_fault(cpu_state_t *s, uint64_t esr)
{
    uint64_t ec  = (esr >> 26) & 0x3F;
    aegis_process_t *proc = (aegis_process_t *)sched_current();

    if (ec == EC_DABT_LOW || ec == EC_IABT_LOW) {
        uint64_t far  = read_far();
        uint64_t dfsc = esr & 0x3F;
        int is_write  = (ec == EC_DABT_LOW) && (esr & (1UL << 6));

        /* Translation fault (level 0-3) = not-present → demand paging. */
        if (dfsc >= 0x04 && dfsc <= 0x07) {
            if (mm_populate_fault(proc, far) == 0)
                return;
        }
        /* Permission fault on a write → COW break. */
        if (is_write && dfsc >= 0x0C && dfsc <= 0x0F) {
            int cr = vmm_cow_fault_handle(proc->pml4_phys, far);
            if (cr == 0)
                return;
            if (cr == -2) {
                pend_signal(proc, SIGBUS);
                return;
            }
        }
        printk("[SIG] pid %u: %s abort ELR=0x%lx FAR=0x%lx ESR=0x%lx -> SIGSEGV\n",
               proc->pid, (ec == EC_DABT_LOW) ? "data" : "instr",
               s->elr, far, esr);
        pend_signal(proc, SIGSEGV);
        return;
    }

    uint32_t sig;
    switch (ec) {
    case EC_BRK64:     sig = SIGTRAP; break;
    case EC_FP_ACCESS: sig = SIGILL;  break;  /* FP/SIMD off (FPEN=0) v1 */
    default:           sig = SIGILL;  break;
    }
    printk("[SIG] pid %u: exception EC=0x%lx ELR=0x%lx -> signal %u\n",
           proc->pid, (esr >> 26) & 0x3F, s->elr, sig);
    pend_signal(proc, sig);
}

void
arm64_sync_el0(cpu_state_t *s)
{
    uint64_t esr = read_esr();
    uint64_t ec  = (esr >> 26) & 0x3F;

    if (ec == EC_SVC64) {
        /* Linux aarch64 ABI: x8 = syscall number, x0-x5 = args, x0 = ret.
         * syscall_frame_t is the same memory layout as cpu_state_t. */
        syscall_frame_t *f = (syscall_frame_t *)s;
        s->x[0] = syscall_dispatch(f, s->x[8],
                                   s->x[0], s->x[1], s->x[2],
                                   s->x[3], s->x[4], s->x[5]);
    } else {
        el0_fault(s, esr);
    }

    /* Deliver pending signals on the way back to EL0 (the x86 iretq-path
     * signal_deliver equivalent; may rewrite ELR/SP to run a handler, or
     * never return for fatal SIG_DFL). */
    signal_deliver(s);
}

void
arm64_irq(cpu_state_t *s)
{
    for (;;) {
        uint32_t intid = gic_ack();
        if (intid >= 1020 && intid <= 1023)
            break;                      /* spurious / no more pending */
#ifdef AEGIS_BOOT_NATIVE
        if (intid == 30) {              /* physical-timer PPI (real Pi5) */
#else
        if (intid == 27) {              /* virtual-timer PPI (QEMU) */
#endif
            gic_eoi(intid);             /* EOI first: sched_tick may switch */
            timer_irq();
#ifdef AEGIS_BOOT_NATIVE
        } else if (intid == 153) {      /* Pi5 debug PL011 RX (DTB SPI 0x79) */
#else
        } else if (intid == 33) {       /* QEMU virt PL011 RX */
#endif
            gic_eoi(intid);
            uart_rx_irq();
        } else {
            gic_eoi(intid);
        }
    }

    /* Signals for the interrupted user context (x86 isr.asm parity). */
    if ((s->spsr & 0xF) == 0)           /* EL0t */
        signal_deliver(s);
}

void
arm64_fault_el1(cpu_state_t *s)
{
    uint64_t esr = read_esr();
    uint64_t ec  = (esr >> 26) & 0x3F;

    /* Fault-tolerant uaccess: a data/instruction abort taken while the
     * kernel was touching a user buffer (copy_*_user). If the faulting PC
     * is registered in the exception table, redirect execution to its
     * fixup (which returns the un-copied byte count) instead of panicking.
     * vec_el1_sync RESTORE_ALLs and ERETs after we return, so rewriting
     * s->elr resumes at the fixup. */
    if (ec == EC_DABT_CUR || ec == EC_IABT_CUR) {
        uint64_t fixup = ex_table_lookup(s->elr);
        if (fixup) {
            s->elr = fixup;
            return;
        }
    }

    uint64_t far = read_far();
    printk("[PANIC] EL1 sync exception ESR=0x%lx EC=0x%lx FAR=0x%lx ELR=0x%lx\n",
           esr, (esr >> 26) & 0x3F, far, s->elr);
    printk("[PANIC] x0=0x%lx x1=0x%lx x29=0x%lx x30=0x%lx sp_el0=0x%lx\n",
           s->x[0], s->x[1], s->x[29], s->x[30], s->sp_el0);
    printk("[PANIC] backtrace (resolve: make sym ADDR=0x<addr>):\n");
    print_backtrace_from(s->x[29], 16);
    panic_halt("[PANIC] EL1 sync exception");
}
