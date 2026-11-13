#ifndef AEGIS_APPLE_PROBE_REPORT_H
#define AEGIS_APPLE_PROBE_REPORT_H
#include <stdint.h>

/* Stable prefix used by the QEMU readback tests and all diagnostic phases. */
struct apple_probe_boot_report {
    uint64_t stage, el, sctlr, mmfr0, dtb;
    uint64_t image, image_size, dtb_size, memory_count;
    uint64_t memory_base[17], memory_size[17];
};
extern volatile struct apple_probe_boot_report apple_probe_report
    __attribute__((visibility("hidden")));
#endif
