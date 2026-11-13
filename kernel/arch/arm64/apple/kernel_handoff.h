#ifndef AEGIS_APPLE_KERNEL_HANDOFF_H
#define AEGIS_APPLE_KERNEL_HANDOFF_H
#include "../fdt.h"
#define APPLE_KERNEL_HANDOFF_MAGIC 0x41454749534b3031ULL
/* Owned by the RAM-only bridge; no usable-memory authority is conveyed. */
struct apple_kernel_handoff {
    uint64_t magic, kernel_phys, kernel_size, dtb, dtb_size;
    struct fdt_bootfb fb;
#ifdef APPLE_MEMORY_CHECKPOINT
    uint64_t loader_phys, loader_size, arena, arena_size;
#endif
#ifdef APPLE_TIMER_CHECKPOINT
    uint64_t timer_hcr, timer_gate_before, timer_gate_after, timer_cnthctl;
#endif
};
#define APPLE_BOOT_ARENA_SIZE (8ULL * 1024 * 1024)
#endif
