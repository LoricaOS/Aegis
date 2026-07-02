/* tlb.h — arm64 TLB maintenance.
 *
 * The tlbi *is variants broadcast to every core in the inner-shareable
 * domain in hardware, so unlike x86 there is no IPI protocol: each
 * "shootdown" is just the right tlbi + DSB. (BSP-only today, but these
 * stay correct when PSCI SMP lands.) */
#ifndef AEGIS_TLB_H
#define AEGIS_TLB_H

#include <stdint.h>

#define TLB_TARGET_ALL  (~0ULL)

static inline void
tlb_flush_local(void)
{
    __asm__ volatile(
        "dsb ishst\n\ttlbi vmalle1\n\tdsb ish\n\tisb" ::: "memory");
}

static inline void
tlb_flush_all_cpus(void)
{
    __asm__ volatile(
        "dsb ishst\n\ttlbi vmalle1is\n\tdsb ish\n\tisb" ::: "memory");
}

static inline void
tlb_shootdown(uint64_t target_root, uint64_t va_start, uint64_t va_end)
{
    (void)target_root;
    __asm__ volatile("dsb ishst" ::: "memory");
    for (uint64_t va = va_start; va < va_end; va += 4096)
        __asm__ volatile("tlbi vaae1is, %0" : : "r"(va >> 12) : "memory");
    __asm__ volatile("dsb ish\n\tisb" ::: "memory");
}

static inline void
tlb_shootdown_kernel(uint64_t va_start, uint64_t va_end)
{
    tlb_shootdown(TLB_TARGET_ALL, va_start, va_end);
}

static inline void tlb_poll_incoming(void) {}

#endif /* AEGIS_TLB_H */
