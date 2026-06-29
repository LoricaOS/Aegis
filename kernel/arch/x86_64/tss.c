#include "tss.h"
#include "smp.h"
#include "printk.h"
#include "kva.h"   /* per-CPU #DF IST stacks are kva-allocated, not a static array */

/* Verify the TSS is exactly 104 bytes as per x86-64 spec. */
_Static_assert(sizeof(aegis_tss_t) == 104, "TSS must be 104 bytes");

/* Per-CPU TSS — each CPU needs its own because RSP0 differs per-CPU
 * and ltr sets the Busy bit in the TSS descriptor. */
static aegis_tss_t s_tss[MAX_CPUS];

/* Per-CPU 4KB double-fault (#DF) IST stack.  Allocate one kva page PER CPU as
 * it is initialized (arch_tss_init / arch_tss_init_ap) rather than a static
 * [MAX_CPUS][4096] array — at a high MAX_CPUS that array would be megabytes of
 * BSS for CPUs that may not exist; this way absent CPUs cost nothing.  IST1 in
 * the TSS (s_tss[cpu].ist[0], 0-indexed) = IDT-gate IST value 1.  kva pages are
 * 4 KiB-aligned, satisfying the 16-byte #DF-stack alignment requirement. */
static uint64_t df_stack_top(void)
{
    uint8_t *df = (uint8_t *)kva_alloc_pages(1);
    /* Stack grows down: IST entry must point at the TOP (one past the end). */
    return (uint64_t)(uintptr_t)(df + 4096);
}

/*
 * g_master_pml4 — physical address of the master (kernel) PML4.
 * Set by arch_set_master_pml4() after vmm_init() and referenced from
 * isr.asm and syscall_entry.asm to restore the master PML4 at the start
 * of every interrupt/syscall.  This ensures all kernel code (ISR handlers,
 * syscall dispatch, scheduler) runs with the master PML4 where TCBs and
 * kernel stacks are accessible via the identity map.
 */
uint64_t g_master_pml4 = 0;

aegis_tss_t *
arch_tss_get(void)
{
	return &s_tss[0];
}

uint64_t
arch_tss_get_base_ap(uint8_t cpu_id)
{
	return (uint64_t)(uintptr_t)&s_tss[cpu_id];
}

void
arch_tss_init(void)
{
	s_tss[0].iomap_base = 104;   /* offset past end of TSS → I/O bitmap disabled */
	/* IST1 (s_tss[0].ist[0] in 0-indexed C array) — used by the #DF gate. */
	s_tss[0].ist[0] = df_stack_top();
	printk("[TSS] OK: RSP0 initialized\n");
}

void
arch_tss_init_ap(uint8_t cpu_id)
{
	s_tss[cpu_id].iomap_base = 104;
	s_tss[cpu_id].ist[0] = df_stack_top();
}

void
arch_set_kernel_stack(uint64_t rsp0)
{
	/* Write to current CPU's TSS RSP0 */
	percpu_t *p = percpu_self();
	s_tss[p->cpu_id].rsp0 = rsp0;
	/* syscall_entry.asm reads gs:24 (percpu.kernel_stack) for the SYSCALL
	 * stack switch.  Keep it in sync with TSS.RSP0. */
	p->kernel_stack = rsp0;
}

void
arch_set_master_pml4(uint64_t pml4_phys)
{
	g_master_pml4 = pml4_phys;
}
