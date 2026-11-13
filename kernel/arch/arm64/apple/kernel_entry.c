/* Real ARM64 kernel, deliberately stopped before memory/device activation. */
#include "kernel_handoff.h"
#include "probe_console.h"
#include "../arch.h"
#include "../smp.h"
#include "printk.h"
#include "qr_report.h"
#ifdef APPLE_MEMORY_CHECKPOINT
#include "kernel_memory.h"
#endif
#ifdef APPLE_TIMER_CHECKPOINT
#include "kernel_timer.h"
#endif

extern void kernel_main_arm64(void);
extern char apple_kernel_base[], _kernel_end[];

volatile struct {
    uint64_t stage, pc, sp, el, sctlr, daif, vbar, percpu, pan_supported;
} apple_kernel_report;

volatile uint64_t apple_kernel_atomic_report[4];
static uint16_t exclusive_probe;
extern uint32_t printk_checkpoint_lock_state(void);

static int atomic_preflight(void)
{
    uint32_t status = 1, value = 0, attempts;
    uint32_t lock = printk_checkpoint_lock_state();
    uint64_t sctlr;
    __asm__ volatile("mrs %0, sctlr_el1" : "=r"(sctlr));
    probe_puts("BEFORE SHARED INIT - BOUNDED ATOMIC CHECK\n");
    probe_field("EL1 SCTLR", sctlr);
    probe_field("PRINTK LOCK OWNER-NEXT", lock);
    probe_field("EXCLUSIVE INITIAL VALUE", exclusive_probe);
    apple_kernel_atomic_report[0] = 0;
    apple_kernel_atomic_report[1] = UINT64_MAX; /* not attempted */
    apple_kernel_atomic_report[2] = exclusive_probe;
    apple_kernel_atomic_report[3] = lock;
    apple_qr_progress("atomic-before", apple_kernel_atomic_report);
    /* Match spin_lock's relaxed halfword fetch-add, but cap retries. No
     * lock is bypassed and no memory attribute/cache state is changed. */
    for (attempts = 1; attempts <= 128; attempts++) {
        __asm__ volatile("ldxrh %w0, [%2]\nadd %w0, %w0, #1\n"
                         "stxrh %w1, %w0, [%2]"
                         : "=&r"(value), "=&r"(status)
                         : "r"(&exclusive_probe) : "memory");
        if (!status) break;
    }
    __asm__ volatile("clrex\ndmb sy" ::: "memory");
    if (attempts > 128) attempts = 128;
    apple_kernel_atomic_report[0] = attempts;
    apple_kernel_atomic_report[1] = status;
    apple_kernel_atomic_report[2] = exclusive_probe;
    apple_kernel_atomic_report[3] = lock;
    probe_field("EXCLUSIVE ATTEMPTS", attempts);
    probe_field("EXCLUSIVE STORE STATUS", status);
    probe_field("EXCLUSIVE FINAL VALUE", exclusive_probe);
    if (lock || status || exclusive_probe != 1) {
        probe_puts("HALTED - ATOMIC PREFLIGHT FAILED\n");
        probe_puts("NO SHARED LOCKS BYPASSED - PREFLIGHT HALTED\n");
        apple_qr_progress("atomic-failed", apple_kernel_atomic_report);
        __asm__ volatile("dsb sy" ::: "memory");
        apple_kernel_report.stage = 3;
        return 0;
    }
    probe_puts("ATOMIC PREFLIGHT PASSED - ENTERING SHARED INIT\n");
    apple_qr_progress("atomic-passed", apple_kernel_atomic_report);
    return 1;
}

void apple_kernel_entry(const struct apple_kernel_handoff *h)
{
    uint64_t el, sctlr;
    __asm__ volatile("mrs %0, CurrentEL" : "=r"(el));
    __asm__ volatile("mrs %0, sctlr_el1" : "=r"(sctlr));
    if (!h || h->magic != APPLE_KERNEL_HANDOFF_MAGIC ||
        h->kernel_size != (uint64_t)(_kernel_end - apple_kernel_base) ||
        el != 4 || (sctlr & 0x1005) != 5)
        for (;;) __asm__ volatile("wfe");
    probe_console_init(&h->fb);
    probe_puts("AEGIS - REAL ARM64 KERNEL ENTRY\n");
#ifdef APPLE_MEMORY_CHECKPOINT
    probe_puts("APPLE MEMORY PROFILE - OWNED ARENA ONLY\n");
#else
    probe_puts("APPLE CHECKPOINT - NO ALLOCATOR OR DEVICES\n");
#endif
    probe_puts("DATA CACHE ON - INSTRUCTION CACHE OFF\n");
    apple_kernel_report.stage = 1;
    apple_qr_progress("kernel-entry", 0);
    if (!atomic_preflight())
        for (;;) __asm__ volatile("wfe");
#ifdef APPLE_MEMORY_CHECKPOINT
    apple_memory_prepare(h);
#endif
#ifdef APPLE_TIMER_CHECKPOINT
    apple_timer_prepare(h);
#endif
    kernel_main_arm64();
    for (;;) __asm__ volatile("wfe");
}

__attribute__((noreturn))
void apple_kernel_checkpoint(void)
{
    uint64_t mmfr1;
    apple_kernel_report.pc = (uintptr_t)apple_kernel_checkpoint;
    __asm__ volatile("mov %0, sp" : "=r"(apple_kernel_report.sp));
    __asm__ volatile("mrs %0, CurrentEL" : "=r"(apple_kernel_report.el));
    __asm__ volatile("mrs %0, sctlr_el1" : "=r"(apple_kernel_report.sctlr));
    __asm__ volatile("mrs %0, daif" : "=r"(apple_kernel_report.daif));
    __asm__ volatile("mrs %0, vbar_el1" : "=r"(apple_kernel_report.vbar));
    __asm__ volatile("mrs %0, tpidr_el1" : "=r"(apple_kernel_report.percpu));
    __asm__ volatile("mrs %0, id_aa64mmfr1_el1" : "=r"(mmfr1));
    apple_kernel_report.pan_supported = (mmfr1 >> 20) & 15;
    printk("[APPLE] SHARED INIT CHECKPOINT: per-CPU, PAN, vectors, uaccess\n");
    printk("[APPLE] PC=0x%lx SP=0x%lx\n", apple_kernel_report.pc, apple_kernel_report.sp);
#ifdef APPLE_MEMORY_CHECKPOINT
    printk("[APPLE] SHARED INIT DONE - NEXT: OWNED MEMORY CHECKPOINT\n");
#else
    printk("[APPLE] HALTED: no PMM, no IRQ controller, no timer, no device probes\n");
#endif
    apple_qr_progress("shared-complete", apple_kernel_atomic_report);
    __asm__ volatile("dsb sy" ::: "memory");
    apple_kernel_report.stage = 2;
#ifdef APPLE_MEMORY_CHECKPOINT
    apple_memory_run();
#endif
    for (;;) __asm__ volatile("wfe");
}
