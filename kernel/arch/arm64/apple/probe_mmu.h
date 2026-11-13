#ifndef AEGIS_APPLE_PROBE_MMU_H
#define AEGIS_APPLE_PROBE_MMU_H

#include <stdint.h>

#define PROBE_PT_PAGES 48
struct probe_map_request {
    uint64_t image, text_end, ro_end, image_end;
    uint64_t dtb, dtb_size, fb, fb_size;
    uint64_t mmfr0, table_base;
};
struct probe_map_result {
    uint64_t root, tcr, mair, tables, pages;
};

/* Pure bounded table construction. No system-register or device accesses.
 * table_base is the physical address of the pool, inside image RW data.
 * Failure leaves result.root zero; partial tables must never be activated. */
int probe_map_build(const struct probe_map_request *request,
                    struct probe_map_result *result);
const uint64_t *probe_map_pool(void);

#ifdef APPLE_PROBE_TRANSLATION
void apple_probe_translation_begin(const struct probe_map_request *request,
                                   uint64_t incoming_el)
    __attribute__((noreturn));
#endif
#endif
