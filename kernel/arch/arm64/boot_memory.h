#ifndef AEGIS_ARM64_BOOT_MEMORY_H
#define AEGIS_ARM64_BOOT_MEMORY_H
#include <stdint.h>

#define BOOT_MEMORY_BANKS 32
#define BOOT_MEMORY_RESERVED 128
#define BOOT_MEMORY_CANDIDATES 192

struct boot_memory_range { uint64_t begin, end; }; /* half-open, 4 KiB aligned */
enum boot_memory_error {
    BOOT_MEMORY_OK, BOOT_MEMORY_HEADER, BOOT_MEMORY_TREE, BOOT_MEMORY_RANGE,
    BOOT_MEMORY_CAPACITY, BOOT_MEMORY_UNSUPPORTED, BOOT_MEMORY_NO_RAM
};
struct boot_memory_request {
    uint64_t image, image_size, dtb, fb, fb_size, physical_limit;
};
enum boot_memory_source {
    BOOT_MEMORY_SOURCE_NONE, BOOT_MEMORY_SOURCE_REQUEST,
    BOOT_MEMORY_SOURCE_MEMRESERVE, BOOT_MEMORY_SOURCE_RAM,
    BOOT_MEMORY_SOURCE_RESERVED, BOOT_MEMORY_SOURCE_INITRD,
    BOOT_MEMORY_SOURCE_IMAGE, BOOT_MEMORY_SOURCE_DTB,
    BOOT_MEMORY_SOURCE_FB, BOOT_MEMORY_SOURCE_CANDIDATE
};
enum boot_memory_reason {
    BOOT_MEMORY_REASON_NONE, BOOT_MEMORY_REASON_ZERO_SIZE,
    BOOT_MEMORY_REASON_BASE_LIMIT, BOOT_MEMORY_REASON_END_LIMIT,
    BOOT_MEMORY_REASON_CAPACITY, BOOT_MEMORY_REASON_REQUEST
};
/* Diagnostic metadata only, never an accepted/normalized range. offset is an
 * original DTB byte offset (zero for request/derived sources); index is the
 * zero-based reg tuple, memreserve entry or derived candidate's bank index.
 * No strings or decoded pointers. */
struct boot_memory_failure {
    uint32_t source, reason, offset, index;
    uint64_t base, size, limit;
};
struct boot_memory_plan {
    uint32_t error, bank_count, reserved_count, candidate_count;
    uint64_t bank_bytes, excluded_bytes, candidate_bytes;
    struct boot_memory_range banks[BOOT_MEMORY_BANKS];
    struct boot_memory_range reserved[BOOT_MEMORY_RESERVED];
    struct boot_memory_range candidates[BOOT_MEMORY_CANDIDATES];
};

/* Strict, bounded FDT memory intake, independent of the legacy peripheral
 * query cache. Reads the original blob including its reservation map.
 * No allocation or physical-memory access through any decoded address.
 * Failure clears the entire plan except error: no partial candidate list.
 * Optional failure output is cleared on entry and describes only rejected
 * range/request/capacity checks; other failures leave it zero.
 * Success is a metadata-derived candidate plan, not allocator activation. */
int boot_memory_plan(const uint8_t *blob, uint32_t available,
                     const struct boot_memory_request *request,
                     struct boot_memory_plan *out, struct boot_memory_failure *failure);
const char *boot_memory_error_name(uint32_t error);
#endif
