#ifdef APPLE_PROBE_MEMORY
/* Report-only intake. Candidate addresses are never dereferenced or allocated. */
#include "../boot_memory.h"
#include "probe_mmu.h"
#include "probe_console.h"
#include "probe_report.h"

struct boot_memory_plan apple_probe_memory_report;
struct boot_memory_failure apple_probe_memory_failure;

void apple_probe_memory_begin(const struct probe_map_request *q)
{
    static const unsigned pa_bits[] = {32, 36, 40, 42, 44, 48};
    unsigned pa = q->mmfr0 & 15;
    struct boot_memory_request request = {
        q->image, q->image_end - q->image, q->dtb, q->fb, q->fb_size,
        pa < 6 ? 1ULL << pa_bits[pa] : 0
    };
    apple_probe_report.stage = 9;
    int good = boot_memory_plan((const uint8_t *)(uintptr_t)q->dtb,
                               q->dtb_size, &request, &apple_probe_memory_report,
                               &apple_probe_memory_failure);
    probe_console_reset();
    probe_puts("AEGIS V4 - RESERVATION-AWARE MEMORY REPORT\n");
    if (!good) {
        probe_puts("REFUSED - ");
        probe_puts(boot_memory_error_name(apple_probe_memory_report.error));
        probe_puts("\nNO CANDIDATES - NO ALLOCATOR\n");
        if (apple_probe_memory_failure.source) {
            probe_field("FAILURE SOURCE", apple_probe_memory_failure.source);
            probe_field("FAILURE REASON", apple_probe_memory_failure.reason);
            probe_field("DTB BYTE OFFSET", apple_probe_memory_failure.offset);
            probe_field("TUPLE INDEX", apple_probe_memory_failure.index);
            probe_field("RAW BASE", apple_probe_memory_failure.base);
            probe_field("RAW SIZE", apple_probe_memory_failure.size);
            probe_field("PHYSICAL LIMIT EXCLUSIVE", apple_probe_memory_failure.limit);
        }
    } else {
        probe_field("WHOLE ADVERTISED RAM BYTES", apple_probe_memory_report.bank_bytes);
        probe_field("EXCLUDED BYTES WITHIN RAM", apple_probe_memory_report.excluded_bytes);
        probe_field("CANDIDATE BYTES", apple_probe_memory_report.candidate_bytes);
        probe_field("NORMALIZED RESERVATIONS", apple_probe_memory_report.reserved_count);
        probe_field("CANDIDATE RANGES", apple_probe_memory_report.candidate_count);
        unsigned count = apple_probe_memory_report.candidate_count;
        if (count > 8) count = 8;
        for (unsigned i = 0; i < count; i++) {
            probe_field("BEGIN", apple_probe_memory_report.candidates[i].begin);
            probe_field("END EXCLUSIVE", apple_probe_memory_report.candidates[i].end);
        }
        if (count < apple_probe_memory_report.candidate_count)
            probe_puts("MORE RANGES IN RAM REPORT\n");
        probe_puts("CANDIDATES ONLY - NO ALLOCATOR OR RECLAIM\n");
    }
    probe_puts("HALTED - MMU ON / CACHES OFF / DAIF MASKED\n");
    __asm__ volatile("dsb sy" ::: "memory");
    apple_probe_report.stage = good ? 10 : 11;
}
#endif
