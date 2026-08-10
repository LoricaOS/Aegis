/* Crafted-DTB probe for the FDT_PROP length overflow (audit A3-I1).
 *
 * Builds a minimal but structurally valid DTB whose single FDT_PROP declares a
 * length chosen so that, in uint32:
 *     val + len            wraps to a SMALL value -> the bound test passes
 *     (val + len + 3) & ~3 wraps too               -> `off` fails to advance
 *
 * Pre-fix that meant a read far out of range and a walk that never terminated.
 * Post-fix the 64-bit check rejects it and the walker returns.
 *
 * Links against the REAL fdt.c, same as tools/test-fdt.sh:
 *   cc -O2 -DFDT_HOSTTEST -Ikernel/arch/arm64 fdt_evil.c kernel/arch/arm64/fdt.c
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

uint32_t fdt_ingest(const uint8_t *blob, uint32_t max);
int  fdt_compat_exists(const char *compat);

#define FDT_MAGIC       0xd00dfeedu
#define FDT_BEGIN_NODE  1u
#define FDT_PROP        3u
#define FDT_END_NODE    2u
#define FDT_END         9u

static void put32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);  p[3] = (uint8_t)v;
}

int main(void)
{
    static uint8_t blob[4096];
    memset(blob, 0, sizeof blob);

    const uint32_t hdr_sz     = 40;
    const uint32_t struct_off = 64;
    uint8_t *st = blob + struct_off;
    uint32_t o  = 0;

    put32(st + o, FDT_BEGIN_NODE); o += 4;      /* root node, empty name */
    memset(st + o, 0, 4);          o += 4;

    /* The hostile property. val = (struct_off + o + 8) once emitted; pick len
     * so that val + len wraps just past 2^32 to a tiny value. */
    /* `off` inside the walker is token_offset+4, so val = struct_off + o + 4 + 8.
     * Choose len so val + len wraps just past 2^32 to a small value. */
    uint32_t val = struct_off + o + 12;
    uint32_t len = (uint32_t)(0x100000000ull - (uint64_t)val + 8ull);
    put32(st + o, FDT_PROP); o += 4;
    put32(st + o, len);      o += 4;            /* len   */
    put32(st + o, 0);        o += 4;            /* nameoff -> "compatible" */
    put32(st + o, 0);        o += 4;            /* one word of value */

    put32(st + o, FDT_END_NODE); o += 4;
    put32(st + o, FDT_END);      o += 4;

    uint32_t struct_size  = o;
    uint32_t strings_off  = struct_off + struct_size;
    /* strings block: "compatible\0" at offset 0, so nameoff=0 names it and the
     * walker takes the compat_list_has(s_buf + val, len, ...) branch — which
     * scans `len` bytes. With len ~4 GiB that is the out-of-range read. */
    memcpy(blob + struct_off + struct_size, "compatible", 11);
    uint32_t strings_size = 11;
    uint32_t total        = strings_off + strings_size;

    put32(blob + 0,  FDT_MAGIC);
    put32(blob + 4,  total);
    put32(blob + 8,  struct_off);
    put32(blob + 12, strings_off);
    put32(blob + 16, 0);            /* off_mem_rsvmap */
    put32(blob + 20, 17);           /* version */
    put32(blob + 24, 16);           /* last_comp_version */
    put32(blob + 28, 0);
    put32(blob + 32, strings_size);
    put32(blob + 36, struct_size);
    (void)hdr_sz;

    printf("crafted DTB: struct_off=%u struct_size=%u val=%u len=0x%08x\n",
           struct_off, struct_size, val, len);
    printf("  uint32 val+len       = 0x%08x  (wraps -> bound check passes)\n",
           (uint32_t)(val + len));
    printf("  uint32 (val+len+3)&~3= 0x%08x  (off fails to advance)\n",
           (uint32_t)((val + len + 3) & ~3u));

    /* fdt_ingest returns the CAPTURED SIZE; 0 means rejected. */
    if (fdt_ingest(blob, total) == 0) {
        puts("fdt_ingest REJECTED the blob (header validation) — walker not reached");
        return 2;
    }
    puts("fdt_ingest accepted; walking (pre-fix this faults or never returns)...");
    fflush(stdout);

    int r = fdt_compat_exists("nonexistent,device");
    printf("walker returned cleanly: %d\n", r);
    puts("RESULT: PASS — bounded walk, no fault, no hang");
    return 0;
}
