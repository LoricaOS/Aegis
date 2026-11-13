#ifndef AEGIS_APPLE_KERNEL_MEMORY_H
#define AEGIS_APPLE_KERNEL_MEMORY_H
#include "kernel_handoff.h"
/* Architecture bootstrap policy; flags use the existing abstract VMM ABI.
 * No implicit ranges, rounded RAM blocks, firmware or generic MMIO window. */
struct apple_boot_mapping { uint64_t va, pa, size, flags; };
const struct apple_boot_mapping *apple_memory_mappings(unsigned *count);
void apple_memory_prepare(const struct apple_kernel_handoff *);
void apple_memory_rebase_console(void); /* no output during table switch */
void apple_memory_vmm_ready(uint64_t root); /* publish/clean before switch */
void apple_memory_run(void) __attribute__((noreturn));
struct apple_memory_report {
    uint64_t stage, arena, arena_size, initial_free, baseline_free, final_free;
    uint64_t test_phys, test_va, ttbr1, ttbr0, checks;
    uint64_t mair, tcr, sctlr, daif;
};
extern volatile struct apple_memory_report apple_memory_report;
#endif
