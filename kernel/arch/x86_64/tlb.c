/* tlb.c -- TLB shootdown via IPI for SMP page table coherence.
 *
 * A single shared shootdown request is protected by s_shootdown_lock.
 * The initiator fills in the target CR3 and VA range, sends a broadcast
 * IPI (vector 0xFE), and spins until all target CPUs acknowledge.
 *
 * Receivers check whether their current CR3 matches the target; if so
 * they execute invlpg for each page in the range.  If CR3 doesn't match,
 * the stale entries will be flushed on the next context switch (CR3 load
 * flushes all non-global TLB entries).
 *
 * Deadlock rules:
 *
 *   1. Lock waiters poll-and-service.  A CPU spinning for
 *      s_shootdown_lock has interrupts off and would never take the
 *      holder's shootdown IPI; if it just spun, two concurrent
 *      initiators would deadlock (each waiting for the other's ack with
 *      IF=0).  So the acquire loop uses spin_trylock and services any
 *      in-flight request inline (tlb_service_incoming) between attempts.
 *
 *   2. NEVER call tlb_shootdown while holding a spinlock that other CPUs
 *      may spin on with interrupts disabled (sched_lock, vmm_window_lock,
 *      ...).  A target CPU stuck in such a spin cannot ack until the
 *      lock's owner releases; if the owner is (transitively) the
 *      shootdown initiator, the system deadlocks.  Both current callers
 *      (vmm_unmap_user_page, vmm_set_user_prot) release vmm_window_lock
 *      before calling here.
 */

#include "tlb.h"
#include "lapic.h"
#include "smp.h"
#include "arch.h"
#include "spinlock.h"
#include <stdint.h>

#define TLB_SHOOTDOWN_VECTOR 0xFE

/* DIAG: broadcast-IPI counters by source (read via sys_reboot). */
volatile uint32_t g_bc_kernel;   /* TLB_TARGET_ALL ranged (kva/kernel maps) */
volatile uint32_t g_bc_user;     /* per-CR3 user-page unmap/mprotect/COW */
volatile uint32_t g_bc_full;     /* tlb_flush_all_cpus (address-space teardown) */

/* g_cpu_cr3[i] = the PML4 phys CPU i currently has loaded (updated by
 * vmm_switch_to via tlb_note_cr3). A per-CR3 (user) shootdown then IPIs only the
 * CPUs actually running that address space — a process unmapping its own page
 * while every other core runs a different CR3 flushes locally with NO IPI. */
volatile uint64_t g_cpu_cr3[MAX_CPUS];

void
tlb_note_cr3(uint64_t pml4_phys)
{
    g_cpu_cr3[percpu_self()->cpu_id] = pml4_phys;
    /* Publish the new CR3 before the caller's `mov %cr3` repopulates the TLB.
     * Pairs with the fence in tlb_shootdown: a shootdown that samples the OLD
     * value here skips this CPU, but this CPU's imminent CR3 load walks the page
     * table fresh (after the unmapper's PTE clear) so it caches nothing stale. */
    __atomic_thread_fence(__ATOMIC_SEQ_CST);
}

/* Shared shootdown request (protected by s_shootdown_lock). */
static spinlock_t        s_shootdown_lock = SPINLOCK_INIT;
static volatile uint64_t s_target_cr3;
static volatile uint64_t s_va_start;
static volatile uint64_t s_va_end;
static volatile uint16_t s_pending;  /* bitmask: CPUs that must respond */
static volatile uint16_t s_ack;      /* bitmask: CPUs that have responded */
static volatile uint8_t  s_full_flush; /* 1 = receivers reload CR3 (flush ALL
                                        * TLB + paging-structure caches) instead
                                        * of invlpg'ing a range — used by
                                        * tlb_flush_all_cpus for address-space
                                        * teardown (vmm_free_user_pml4). */

/* tlb_service_incoming — service the in-flight shootdown request if this
 * CPU is one of its targets.  Called from the IPI handler AND from
 * initiators spinning for s_shootdown_lock with interrupts off (rule 1
 * in the header comment).
 *
 * The pending bit is claimed with an atomic fetch_and, which makes the
 * service exclusive and self-clearing:
 *   - exclusive: the polling path and a (queued) IPI delivery can race to
 *     handle the same request; only the one that wins the claim
 *     invalidates and acks.
 *   - self-clearing: by the time the initiator returns, every target bit
 *     has been consumed, so s_pending is 0 between requests.  A late IPI
 *     for an old request therefore finds no bit and does nothing —
 *     without this, it could spuriously ack the NEXT request before
 *     invalidating its range (stale-TLB correctness bug).
 * The ACQUIRE on the claim pairs with the initiator's RELEASE store of
 * s_pending, making the cr3/range fields visible before they are read. */
static void
tlb_service_incoming(void)
{
    uint8_t  my_id  = percpu_self()->cpu_id;
    uint16_t my_bit = (uint16_t)(1u << my_id);

    if (!(__atomic_load_n(&s_pending, __ATOMIC_ACQUIRE) & my_bit))
        return;

    uint16_t old = __atomic_fetch_and(&s_pending, (uint16_t)~my_bit,
                                      __ATOMIC_ACQ_REL);
    if (!(old & my_bit))
        return;   /* the other path (IPI vs poll) already claimed it */

    /* Check if our CR3 matches the target.  TLB_TARGET_ALL forces the
     * invalidation on every CPU regardless of CR3 — used for kernel-half
     * (KVA) ranges that live in the shared higher-half mapping. */
    uint64_t my_cr3;
    __asm__ volatile("mov %%cr3, %0" : "=r"(my_cr3));

    if (s_target_cr3 == TLB_TARGET_ALL || my_cr3 == s_target_cr3) {
        if (s_full_flush) {
            /* Full flush: reload CR3 so the paging-structure caches are
             * dropped too (a freed page-table page may have been cached as a
             * walk node — invlpg of a range wouldn't evict that). */
            uint64_t cr3;
            __asm__ volatile("mov %%cr3, %0" : "=r"(cr3));
            __asm__ volatile("mov %0, %%cr3" : : "r"(cr3) : "memory");
        } else {
            uint64_t end = s_va_end;
            for (uint64_t va = s_va_start; va < end; va += 4096)
                __asm__ volatile("invlpg (%0)" : : "r"(va) : "memory");
        }
    }
    /* If CR3 doesn't match, stale TLB entries will be flushed on the
     * next context switch when the new CR3 is loaded. */

    __atomic_or_fetch(&s_ack, my_bit, __ATOMIC_RELEASE);
}

void
tlb_shootdown(uint64_t target_cr3, uint64_t va_start, uint64_t va_end)
{
    /* Single-core or pre-LAPIC: local invlpg only. */
    if (!lapic_active() || g_cpu_count <= 1) {
        for (uint64_t va = va_start; va < va_end; va += 4096)
            __asm__ volatile("invlpg (%0)" : : "r"(va) : "memory");
        return;
    }

    /* Acquire the shootdown lock with poll-and-service (rule 1 in the
     * header comment): while another CPU's request is in flight we must
     * keep servicing it or we deadlock — we spin with IF=0 and would
     * never take its IPI. */
    irqflags_t fl = arch_irq_save();
    while (!spin_trylock(&s_shootdown_lock)) {
        tlb_service_incoming();
        arch_pause();
    }

    /* Build target bitmask: all online CPUs except ourselves.
     * We conservatively include every online CPU rather than checking
     * per-CPU CR3, because we cannot safely read another CPU's CR3.
     *
     * Indexed over MAX_CPUS, not g_cpu_count: percpu slots follow MADT
     * order and need not be contiguous when an AP fails bring-up.
     * g_ap_online[0] covers the BSP (set in smp_percpu_init_bsp), so a
     * shootdown initiated on an AP reaches the BSP too. */
    uint8_t my_id = percpu_self()->cpu_id;
    /* For a per-CR3 (user) target, IPI ONLY the CPUs currently running that
     * address space (g_cpu_cr3). A single-threaded process unmapping its own
     * page while other cores run different CR3s then flushes locally with no
     * IPI — this collapses the ~69k user-page broadcasts a build fires. Kernel
     * (TLB_TARGET_ALL) maps live under every CR3, so still target all online.
     * The fence orders the caller's PTE clear before we sample g_cpu_cr3 (pairs
     * with tlb_note_cr3): if a CPU is racing into `target_cr3` we either see it
     * here (and IPI it) or it loads CR3 after the PTE clear (and caches nothing
     * stale) — never both-miss. */
    __atomic_thread_fence(__ATOMIC_SEQ_CST);
    uint16_t target_mask = 0;
    for (uint32_t i = 0; i < MAX_CPUS && i < 16; i++) {
        if (i == my_id)
            continue;
        if (!g_ap_online[i])
            continue;
        if (target_cr3 != TLB_TARGET_ALL && g_cpu_cr3[i] != target_cr3)
            continue;
        target_mask |= (uint16_t)(1u << i);
    }

    /* Local invalidation first. */
    for (uint64_t va = va_start; va < va_end; va += 4096)
        __asm__ volatile("invlpg (%0)" : : "r"(va) : "memory");

    if (target_mask == 0) {
        spin_unlock(&s_shootdown_lock);
        arch_irq_restore(fl);
        return;
    }

    /* Set up shared request.  The RELEASE store to s_pending publishes
     * the cr3/range fields: receivers acquire-load (or acquire-RMW)
     * s_pending before reading them. */
    s_target_cr3 = target_cr3;
    s_va_start   = va_start;
    s_va_end     = va_end;
    s_ack        = 0;
    __atomic_store_n(&s_pending, target_mask, __ATOMIC_RELEASE);

    /* Broadcast IPI to all other CPUs. */
    if (target_cr3 == TLB_TARGET_ALL) g_bc_kernel++; else g_bc_user++;
    lapic_send_ipi_all_excl_self(TLB_SHOOTDOWN_VECTOR);

    /* Spin until all targets acknowledge.  Targets that are themselves
     * trying to initiate a shootdown ack from their trylock loop above;
     * we hold the lock, so no second request can start until we finish. */
    while (__atomic_load_n(&s_ack, __ATOMIC_ACQUIRE) != target_mask)
        arch_pause();

    spin_unlock(&s_shootdown_lock);
    arch_irq_restore(fl);
}

void
tlb_shootdown_kernel(uint64_t va_start, uint64_t va_end)
{
    tlb_shootdown(TLB_TARGET_ALL, va_start, va_end);
}

/* tlb_flush_all_cpus — full TLB + paging-structure-cache flush on EVERY online
 * CPU (each reloads CR3).  Used after tearing down a whole address space
 * (vmm_free_user_pml4): the freed page-table frames return to the PMM and get
 * reused, so any CPU that still has stale TLB or cached paging-structure walk
 * nodes referencing them must be flushed, or a reused frame is accessed through
 * a stale translation (wrong-physical-frame corruption).  A range invlpg is
 * insufficient — only a CR3 reload drops the paging-structure caches.  Call
 * with NO spinlock held that other CPUs spin on with IF=0 (shootdown rule). */
void
tlb_flush_all_cpus(void)
{
    /* Local full flush always. */
    {
        uint64_t cr3;
        __asm__ volatile("mov %%cr3, %0" : "=r"(cr3));
        __asm__ volatile("mov %0, %%cr3" : : "r"(cr3) : "memory");
    }
    if (!lapic_active() || g_cpu_count <= 1)
        return;

    irqflags_t fl = arch_irq_save();
    while (!spin_trylock(&s_shootdown_lock)) {
        tlb_service_incoming();
        arch_pause();
    }

    uint8_t my_id = percpu_self()->cpu_id;
    uint16_t target_mask = 0;
    for (uint32_t i = 0; i < MAX_CPUS; i++) {
        if (i == my_id) continue;
        if (!g_ap_online[i]) continue;
        target_mask |= (uint16_t)(1u << i);
    }
    if (target_mask == 0) {
        spin_unlock(&s_shootdown_lock);
        arch_irq_restore(fl);
        return;
    }

    s_target_cr3 = TLB_TARGET_ALL;
    s_va_start   = 0;
    s_va_end     = 0;
    s_full_flush = 1;
    s_ack        = 0;
    g_bc_full++;
    __atomic_store_n(&s_pending, target_mask, __ATOMIC_RELEASE);
    lapic_send_ipi_all_excl_self(TLB_SHOOTDOWN_VECTOR);
    while (__atomic_load_n(&s_ack, __ATOMIC_ACQUIRE) != target_mask)
        arch_pause();
    s_full_flush = 0;

    spin_unlock(&s_shootdown_lock);
    arch_irq_restore(fl);
}

void
tlb_shootdown_handler(void)
{
    tlb_service_incoming();
    lapic_eoi();
}

void
tlb_poll_incoming(void)
{
    tlb_service_incoming();   /* no EOI: this is a poll, not an IPI delivery */
}

void
tlb_flush_local(void)
{
    uint64_t cr3;
    __asm__ volatile("mov %%cr3, %0" : "=r"(cr3));
    __asm__ volatile("mov %0, %%cr3" : : "r"(cr3) : "memory");
}
