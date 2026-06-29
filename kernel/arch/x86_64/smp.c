/* smp.c — SMP initialization, AP startup (INIT-SIPI-SIPI), per-CPU data */
#include "smp.h"
#include "arch.h"
#include "sched.h"
#include "acpi.h"
#include "lapic.h"
#include "idt.h"
#include "gdt.h"
#include "tss.h"
#include "printk.h"
#include "kva.h"
#include "vmm.h"
#include "tlb.h"
#include "lockrank.h"

#include <stdint.h>

/* ── Trampoline symbols (defined in ap_trampoline.asm) ──────────────── */
extern uint8_t  ap_trampoline_start[];
extern uint8_t  ap_trampoline_end[];
extern uint32_t ap_pml4;
extern uint64_t ap_entry_addr;
extern uint64_t ap_stacks[];

/* ── Globals ──────────────────────────────────────────────────────────── */
percpu_t g_percpu[MAX_CPUS];
uint32_t g_cpu_count = 1;
volatile uint8_t g_ap_online[MAX_CPUS];

/* Multi-core scheduling.  Default 1 = APs run the scheduler.  The BSP clears
 * this from the kernel cmdline (`nosmp_sched`) before sched_start as a safety
 * escape hatch (APs park in hlt, BSP-only scheduling). */
int g_ap_sched_enabled = 1;

/* DIAG: hardware-watchpoint catcher (cmdline `hwwatch`). */
int g_hwwatch = 0;

/* Arm DR0-3 on THIS CPU as 8-byte WRITE watchpoints over g_percpu[0..3].self.
 * Debug registers are per-CPU, so every CPU must call this (BSP after
 * smp_start_aps; each AP at the end of ap_entry).  All g_percpu[].self are set
 * by smp_start_aps before any arming happens, so the legitimate init writes are
 * never trapped — only a later wild write trips it.  DR7 = 0x99990255:
 *   bits 0,2,4,6 (0x55) = local enable L0-L3
 *   bit 9 (0x200)       = GE (exact data-breakpoint reporting)
 *   each nibble at 16/20/24/28 = 0x9 = LEN(0b10=8 bytes)<<2 | R/W(0b01=write) */
void
hwwatch_arm_local(void)
{
    if (!g_hwwatch)
        return;
    __asm__ volatile("mov %0, %%dr0" :: "r"((uint64_t)(uintptr_t)&g_percpu[0].self));
    __asm__ volatile("mov %0, %%dr1" :: "r"((uint64_t)(uintptr_t)&g_percpu[1].self));
    __asm__ volatile("mov %0, %%dr2" :: "r"((uint64_t)(uintptr_t)&g_percpu[2].self));
    __asm__ volatile("mov %0, %%dr3" :: "r"((uint64_t)(uintptr_t)&g_percpu[3].self));
    __asm__ volatile("mov %0, %%dr7" :: "r"((uint64_t)0x99990255UL) : "memory");
}

/* Physical address where the trampoline is copied */
#define TRAMPOLINE_PHYS 0x8000

/* Number of 4KB pages per AP kernel stack */
#define AP_STACK_PAGES 4

void
smp_percpu_init_bsp(void)
{
    percpu_t *bsp = &g_percpu[0];
    __builtin_memset(bsp, 0, sizeof(*bsp));
    bsp->self     = bsp;
    bsp->cpu_id   = 0;
    bsp->lapic_id = 0;

    arch_set_gs_base((uint64_t)(uintptr_t)bsp);
    arch_write_kernel_gs_base((uint64_t)(uintptr_t)bsp);

    /* The BSP counts as online: tlb_shootdown builds its IPI target mask
     * from g_ap_online[], so without this bit a shootdown initiated on an
     * AP would never IPI the BSP, leaving stale TLB entries there (audit
     * fix; latent while APs only idle).  Safe w.r.t. smp_start_aps — its
     * per-AP loop skips the BSP before touching g_ap_online[]. */
    g_ap_online[0] = 1;

    /* GS.base + the per-CPU current pointer are now valid: safe to start
     * lock-order checking (no-op in release builds). */
    lockrank_arm();
}

/*
 * smp_start_aps — wake Application Processors via the INIT-SIPI-SIPI protocol.
 *
 * Sequence per AP:
 *   1. Copy trampoline to physical 0x8000 (identity-mapped)
 *   2. Fill data area (PML4 phys, ap_entry VA, per-CPU stack top)
 *   3. Send INIT IPI, wait ~20ms
 *   4. Send first SIPI (vector = 0x08 → phys 0x8000)
 *   5. Busy-wait ~200us
 *   6. Send second SIPI
 *   7. Poll g_ap_online[cpu_idx] for up to ~100ms
 */
void
smp_start_aps(void)
{
    uint32_t tramp_size = (uint32_t)(ap_trampoline_end - ap_trampoline_start);

    /* Offsets of data fields within the trampoline blob */
    uint32_t pml4_off   = (uint32_t)((uint8_t *)&ap_pml4      - ap_trampoline_start);
    uint32_t entry_off  = (uint32_t)((uint8_t *)&ap_entry_addr - ap_trampoline_start);
    uint32_t stacks_off = (uint32_t)((uint8_t *)ap_stacks      - ap_trampoline_start);

    /* 1. Copy trampoline to 0x8000 (within the 0-1GB identity map) */
    __builtin_memcpy((void *)(uintptr_t)TRAMPOLINE_PHYS,
                     ap_trampoline_start, tramp_size);

    /* 2. Fill shared data fields */
    *(volatile uint32_t *)(uintptr_t)(TRAMPOLINE_PHYS + pml4_off) =
        (uint32_t)vmm_get_master_pml4();
    *(volatile uint64_t *)(uintptr_t)(TRAMPOLINE_PHYS + entry_off) =
        (uint64_t)(uintptr_t)ap_entry;

    /* Use RDTSC-based busy-wait delays for INIT-SIPI-SIPI timing.
     * Do NOT enable interrupts here — ISR SWAPGS + iretq path crashes
     * before the scheduler is running (no valid task frame on the boot
     * stack). LAPIC timer calibration needs no interrupts either (it
     * polls PIT channel 2 via port 0x61): each AP calibrates in ap_entry
     * below, and the BSP calibrates in kernel_main just before
     * sched_start — after this function returns, so the shared PIT
     * channel 2 is never contended. */

    /* 3. For each AP: allocate stack, fill percpu, send INIT-SIPI-SIPI */
    for (uint32_t i = 0; i < g_smp_cpu_count; i++) {
        uint8_t apic_id = g_smp_cpus[i].apic_id;

        /* Skip BSP */
        if (apic_id == g_bsp_apic_id)
            continue;

        /* Skip disabled CPUs from MADT */
        if (!g_smp_cpus[i].enabled)
            continue;

        /* Allocate per-AP kernel stack (4 pages = 16KB) */
        void *stack_base = kva_alloc_pages(AP_STACK_PAGES);
        if (!stack_base) {
            printk("[SMP] WARN: AP %u stack alloc failed\n", i);
            continue;
        }
        uint64_t stack_top = (uint64_t)(uintptr_t)stack_base +
                             AP_STACK_PAGES * 4096;

        /* Write stack top into trampoline data area (indexed by LAPIC ID) */
        *(volatile uint64_t *)(uintptr_t)(TRAMPOLINE_PHYS + stacks_off +
                                          apic_id * 8) = stack_top;

        /* Init percpu for this AP */
        percpu_t *p = &g_percpu[i];
        __builtin_memset(p, 0, sizeof(*p));
        p->self         = p;
        p->cpu_id       = (uint8_t)i;
        p->lapic_id     = apic_id;
        p->kernel_stack = stack_top;

        /* Clear online flag before sending IPIs */
        g_ap_online[i] = 0;

        /* Send INIT IPI */
        lapic_send_init(apic_id);

        /* Wait ~20ms via RDTSC busy-loop.
         * Assume ≥1 GHz TSC (true for all modern x86). 20ms ≈ 20M cycles. */
        {
            uint64_t start = arch_get_cycles();
            while (arch_get_cycles() - start < 20000000ULL)
                arch_pause();
        }

        /* Send first SIPI — vector 0x08 = physical 0x8000 */
        lapic_send_sipi(apic_id, 0x08);

        /* Busy-wait ~200us */
        {
            volatile uint32_t d = 100000;
            while (d--)
                ;
        }

        /* Send second SIPI */
        lapic_send_sipi(apic_id, 0x08);

        /* Poll for AP online.  The budget is in raw TSC cycles, but the TSC
         * frequency varies wildly: a KVM host passes through ~3-5GHz, so the
         * old 100M-cycle (~25ms at 3.5GHz) budget expired before the AP could
         * finish lapic_init + per-CPU GDT/TSS + lapic_timer_init (the PIT-ch2
         * calibration alone is ~10ms).  When the BSP gave up early it fired the
         * next SIPI while the previous AP was still calibrating ch2, so the APs
         * contended on the shared PIT and none ever signalled online.  Use 2G
         * cycles (~0.4s at 5GHz, ~2s at 1GHz) — generous for a ~30-50ms AP
         * bring-up, and the loop breaks the instant the AP signals, so this
         * only costs wall-time on a genuine no-show. */
        uint64_t poll_start = arch_get_cycles();
        {
            while (!g_ap_online[i] &&
                   (arch_get_cycles() - poll_start) < 2000000000ULL)
                arch_pause();
        }
        uint64_t waited = arch_get_cycles() - poll_start;

        if (g_ap_online[i]) {
            g_cpu_count++;
            /* Checkpoint: how long the AP took to signal online (Mcycles).
             * If this ever creeps toward the 2000 Mcycle budget, the timeout
             * is about to start failing — which is exactly the regression
             * that cost us days when the old 100 Mcycle budget silently
             * expired before the AP finished lapic_timer_init. */
            printk("[SMP] AP %u (LAPIC %u) online after %lu Mcycles\n",
                   i, apic_id, waited / 1000000UL);
        } else {
            printk("[SMP] WARN: AP %u (LAPIC %u) did NOT come online "
                   "(waited %lu Mcycles, online flag=%u)\n",
                   i, apic_id, waited / 1000000UL, (unsigned)g_ap_online[i]);
        }
    }

    printk("[SMP] OK: %u CPUs online\n", g_cpu_count);

    /* Now that more than one CPU may run concurrently, tag every kernel printk
     * line with its originating CPU + uptime so interleaved AP/BSP output is
     * attributable instead of an unreadable character-level garble.  Single-CPU
     * boots (and the -machine pc boot oracle) leave this off → output unchanged. */
    if (g_cpu_count > 1)
        printk_set_decorate(1);
}

/*
 * ap_entry — C entry point for Application Processors.
 *
 * Called from ap_trampoline.asm in 64-bit mode with:
 *   - RSP set to the per-CPU kernel stack top
 *   - CR3 loaded with the master PML4
 *   - Interrupts disabled (CLI in trampoline)
 *
 * Sets up per-CPU GS.base, enables the local APIC, loads the shared IDT,
 * signals the BSP, and enters the idle loop.
 */
void
ap_entry(void)
{
    /* Determine which CPU we are by LAPIC ID */
    uint8_t my_lapic = lapic_id();
    uint32_t my_idx = 0;
    for (uint32_t i = 0; i < g_smp_cpu_count; i++) {
        if (g_smp_cpus[i].apic_id == my_lapic) {
            my_idx = i;
            break;
        }
    }

    /* Set up per-CPU GS.base (both active and KERNEL_GS_BASE for swapgs) */
    percpu_t *me = &g_percpu[my_idx];
    arch_set_gs_base((uint64_t)(uintptr_t)me);
    arch_write_kernel_gs_base((uint64_t)(uintptr_t)me);

    /* Enable LAPIC on this AP (SVR + TPR, reuses BSP's MMIO mapping) */
    lapic_init_ap();

    /* Per-CPU GDT + TSS — without these, the AP has no user segments
     * (0x18/0x20), no TSS (RSP0 for ring-3 interrupts), and no IST
     * stack (double-fault). The trampoline's temporary GDT is insufficient. */
    arch_tss_init_ap(me->cpu_id);
    arch_gdt_init_ap(me->cpu_id, arch_tss_get_base_ap(me->cpu_id));

    /* Configure SYSCALL/SYSRET MSRs — per-CPU, needed for user tasks.
     * Call the shared init function; it prints [SYSCALL] OK which is fine
     * during AP bringup (boot oracle only runs on -machine pc with 1 CPU). */
    arch_syscall_init();

    /* Enable SSE + FXSAVE/FXRSTOR on this AP (per-CPU CR0/CR4 bits:
     * CR0.EM=0, CR0.MP=1, CR4.OSFXSR, CR4.OSXMMEXCPT — same call the BSP
     * makes in kernel_main).  APs only halt today, but if SMP scheduling
     * ever runs tasks here, ctx_switch's fxsave/fxrstor and user SSE code
     * must not fault.  arch_sse_init prints nothing (boot oracle safe). */
    arch_sse_init();

    /* Enable SMAP + SMEP on this AP (per-CPU CR4 bits).
     * Only set if BSP successfully enabled them (same CPU features). */
    if (arch_smap_enabled) {
        uint64_t cr4;
        __asm__ volatile("mov %%cr4, %0" : "=r"(cr4));
        cr4 |= (1UL << 20) | (1UL << 21);  /* SMEP | SMAP */
        __asm__ volatile("mov %0, %%cr4" : : "r"(cr4));
    }

    /* Load the shared IDT (same gate table as BSP — at a fixed kernel VA) */
    arch_load_idt();

    lapic_timer_init();

    /* DIAG: arm this AP's debug-register watchpoints (no-op unless `hwwatch`).
     * me->self was set by the BSP in smp_start_aps before this AP ran, so
     * arming here never traps the legitimate init write. */
    hwwatch_arm_local();

    /* Signal BSP that we are online */
    g_ap_online[my_idx] = 1;

    /* AP scheduling is ON by default; `nosmp_sched` parks APs in sti/hlt as a
     * safety escape hatch.  The AMD-bare-metal #GP on the iretq return to ring 3
     * (SS RPL=0 left unnormalized on some AP path) is fixed — SS RPL is now
     * normalized on every AP return path, so multi-core scheduling is safe on
     * real hardware. */
    if (!g_ap_sched_enabled) {
        for (;;)
            __asm__ volatile("sti; hlt; cli" ::: "memory");
    }

    /* Wait until the BSP has spawned every CPU's idle task and started the
     * scheduler (sched_start sets the ready flag).  Both happen after
     * smp_start_aps returns, so this AP must not touch the run list until
     * then.  Interrupts stay disabled while we spin so the LAPIC timer can't
     * fire sched_tick before we have a current task. */
    while (!sched_is_ready()) {
        /* Service TLB shootdowns while we spin with IF=0: we cannot take the
         * 0xFE IPI here, so without this an initiator (e.g. the BSP freeing
         * KVA during init-task setup → vmm_unmap_page → tlb_shootdown_kernel)
         * would block forever waiting for our ack → boot deadlock. */
        tlb_poll_incoming();
        __asm__ volatile("pause" ::: "memory");
    }

    /* Adopt this CPU's pre-spawned idle task as our current task and switch
     * into it, mirroring sched_start on the BSP.  The idle task's body is the
     * sti/hlt loop; once we are running it, this AP's LAPIC timer drives
     * sched_tick, which pulls runnable work off the shared run list (skipping
     * tasks already executing on another CPU). */
    aegis_task_t *idle = (aegis_task_t *)g_percpu[my_idx].idle_task;
    if (!idle) {
        /* BSP did not pre-spawn our idle (g_cpu_count mismatch) — stay parked
         * rather than scheduling with no current task. */
        for (;;) __asm__ volatile("sti; hlt; cli" ::: "memory");
    }
    idle->on_cpu = (int)my_idx;
    percpu_set_current(idle);
    arch_set_kernel_stack(idle->kernel_stack_top);

    /* dummy is outgoing-only (same pattern as sched_start): ctx_switch saves
     * our throwaway boot-stack pointer into it and abandons it.  Use a STATIC
     * per-CPU dummy rather than a stack local: ctx_switch's fxsave needs the
     * outgoing TCB 16-byte aligned, and the AP trampoline does not guarantee
     * the System V incoming-RSP alignment a stack local's auto-alignment
     * relies on (sched_start gets it for free via a normal call).  A static
     * aegis_task_t is 16-aligned by the struct's fpu_state member; each AP
     * writes only its own slot during this one-shot entry. */
    static aegis_task_t s_ap_entry_dummy[MAX_CPUS];
    ctx_switch(&s_ap_entry_dummy[my_idx], idle);
    __builtin_unreachable();
}
