/* tlb.h -- TLB shootdown for SMP page table coherence.
 *
 * When one CPU modifies user-space page tables (munmap, mprotect, execve),
 * other CPUs that may have cached TLB entries for the same address space
 * must invalidate them.  tlb_shootdown() sends an IPI to all other online
 * CPUs and waits for acknowledgement before returning.
 *
 * On single-CPU systems (or before LAPIC init), tlb_shootdown() falls back
 * to local invlpg only.
 */
#ifndef AEGIS_TLB_H
#define AEGIS_TLB_H

#include <stdint.h>

/* Invalidate TLB entries for a VA range in a specific address space.
 * Sends IPI to all other online CPUs, does local invlpg as well.
 * va_start must be page-aligned.  va_end is exclusive. */
void tlb_shootdown(uint64_t target_cr3, uint64_t va_start, uint64_t va_end);

/* Sentinel target_cr3 meaning "invalidate on EVERY online CPU regardless of
 * its current CR3".  Used for kernel-half (KVA) ranges, which live in the
 * shared higher-half mapping present in every address space — so a CR3-match
 * check (as for user ranges) would wrongly skip CPUs running other processes
 * that still cached the kernel VA.  ~0 is never a real (physical) CR3. */
#define TLB_TARGET_ALL  (~0ULL)

/* Invalidate a kernel-half VA range on all online CPUs unconditionally.
 * Thin wrapper over tlb_shootdown with TLB_TARGET_ALL.  Call OUTSIDE
 * vmm_window_lock (shootdown deadlock rule). */
void tlb_shootdown_kernel(uint64_t va_start, uint64_t va_end);

/* Full TLB + paging-structure-cache flush on EVERY online CPU (each reloads
 * CR3).  For whole-address-space teardown (vmm_free_user_pml4) where freed
 * page-table frames return to the PMM and a range invlpg can't evict cached
 * walk nodes.  Call OUTSIDE vmm_window_lock (shootdown deadlock rule). */
void tlb_flush_all_cpus(void);

/* ISR handler for the TLB shootdown IPI vector (0xFE).
 * Called from isr_dispatch; sends LAPIC EOI internally. */
void tlb_shootdown_handler(void);

/* Service any in-flight shootdown request targeting this CPU, WITHOUT an EOI.
 * For CPUs spinning with interrupts disabled (e.g. an AP waiting for the
 * scheduler to come up) that therefore cannot take the 0xFE IPI: call this in
 * the spin loop so an initiator never blocks forever waiting for our ack.
 * Same self-clearing claim as the IPI path, so a later real IPI for the same
 * request finds no pending bit and harmlessly does nothing. */
void tlb_poll_incoming(void);

/* Flush the entire TLB on the local CPU (reload CR3). */
void tlb_flush_local(void);

#endif /* AEGIS_TLB_H */
