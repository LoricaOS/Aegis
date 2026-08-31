/*
 * arch.c — arm64 misc arch glue: percpu/SMP (BSP-only), TTBR0 loading,
 * printk output stubs, diag globals the shared code expects.
 */

#include "arch.h"
#include "smp.h"
#include "printk.h"
#include "sched.h"
#include "proc.h"
#include <stdint.h>

/* ── printk output ─────────────────────────────────────────────────────── */

int vga_available = 0;                 /* no VGA text mode on arm64 */

void
vga_write_string(const char *s)
{
    (void)s;
}

void
arch_init(void)
{
    /* Serial comes up later (kernel_main_limine) once the early device
     * map exists; nothing to do at this point. */
}

/* Per-CPU/SMP data + bring-up now live in kernel/arch/arm64/smp.c. */

int arch_smap_enabled = 0;

void
arm64_pan_init(void)
{
    uint64_t mmfr1;
    __asm__ volatile("mrs %0, id_aa64mmfr1_el1" : "=r"(mmfr1));
    if (((mmfr1 >> 20) & 0xFUL) == 0) {
        if (percpu_self()->cpu_id == 0)
            printk("[PAN] WARN: CPU does not implement privileged access-never\n");
        return;
    }
    uint64_t sctlr;
    __asm__ volatile("mrs %0, sctlr_el1" : "=r"(sctlr));
    sctlr &= ~(1UL << 23);       /* SPAN=0: exceptions from EL0 enter with PAN. */
    __asm__ volatile("msr sctlr_el1, %0\n\tisb\n\t"
                     ".arch_extension pan\n\tmsr pan, #1\n\tisb"
                     : : "r"(sctlr) : "memory");
    arch_smap_enabled = 1;
    if (percpu_self()->cpu_id == 0)
        printk("[PAN] OK: kernel user-page access restricted to uaccess\n");
}

/* ── Address-space + kernel-stack hooks (sched/proc contract) ──────────── */

static uint64_t s_master_pml4;

void
arch_vmm_load_pml4(uint64_t phys)
{
    __asm__ volatile(
        "msr ttbr0_el1, %0\n\t"
        "dsb ish\n\t"
        "tlbi vmalle1\n\t"
        "dsb ish\n\t"
        "isb"
        : : "r"(phys) : "memory");
}

void
arch_set_master_pml4(uint64_t pml4_phys)
{
    s_master_pml4 = pml4_phys;
}

void
arch_set_kernel_stack(uint64_t sp0)
{
    percpu_self()->kernel_stack = sp0;
    /* SP_EL1 self-manages: the return-to-EL0 path fully unwinds the
     * exception frame, so the next EL0 exception lands at the stack top. */
}

/* arm64_load_current_ttbr0 — load the running task's user page table into
 * TTBR0. Called from fork_child_return (proc_enter.S) so a fork child's
 * first return to EL0 runs on its OWN address space, not the parent's
 * (the scheduler only restores TTBR0 when a task resumes from its own
 * ctx_switch, which a first-run child has never reached). */
void
arm64_load_current_ttbr0(void)
{
    aegis_task_t *t = sched_current();
    if (t && t->is_user)
        arch_vmm_load_pml4(((aegis_process_t *)t)->pml4_phys);
}
