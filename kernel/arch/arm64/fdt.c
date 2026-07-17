/*
 * fdt.c — minimal read-only flattened-device-tree reader.
 *
 * Just enough of the DTB (Devicetree Specification v0.4) format to answer
 * "what physical base did this platform put device X at?" — no libfdt, no
 * mutation, no path lookups. Matches nodes by their "compatible" string
 * and decodes "reg" using the parent scope's #address-cells/#size-cells,
 * which is all the GIC / PCIe drivers need to run on both QEMU virt and
 * Apple Virtualization.framework.
 *
 * The blob is copied into a static buffer at fdt_init() time (while the
 * bootloader HHDM is still mapped) so later queries survive the pmm
 * bootloader-memory reclaim without any MMIO mapping dance.
 */
#include "fdt.h"
#include <stdint.h>
#include <stddef.h>
#ifndef FDT_HOSTTEST
#include "arch.h"
#include "printk.h"
#endif

/* DTB tokens (big-endian in the blob). */
#define FDT_MAGIC       0xd00dfeedu
#define FDT_BEGIN_NODE  0x1u
#define FDT_END_NODE    0x2u
#define FDT_PROP        0x3u
#define FDT_NOP         0x4u
#define FDT_END         0x9u

/* virt DTBs are a few KiB; VZ's is larger but nowhere near this. A blob
 * bigger than the buffer simply isn't captured (fdt stays unavailable). */
#define FDT_BUF_SIZE    (128u * 1024u)
#define FDT_MAX_DEPTH   32

static uint8_t  s_buf[FDT_BUF_SIZE];
static int      s_ok;
static uint32_t s_struct_off, s_struct_end, s_strings_off, s_strings_size;

/* The blob is big-endian; arm64 runs little-endian. */
static inline uint32_t be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8)  | (uint32_t)p[3];
}

/* fdt_ingest — validate a blob's header and copy it into the static
 * buffer. Pure (no arch/printk deps) so it is host-unit-testable. Returns
 * the captured size in bytes, or 0 if the blob is not a usable DTB. */
uint32_t
fdt_ingest(const uint8_t *src, uint32_t avail)
{
    s_ok = 0;
    if (!src || avail < 40 || be32(src) != FDT_MAGIC)
        return 0;

    /* Copy only the struct + strings blocks, not the header's totalsize:
     * QEMU's dumpdtb inflates totalsize to the whole 1 MiB FDT region
     * (real content is a few KiB), and a bootloader-provided blob may be
     * padded too. The meaningful extent is the end of the later block. */
    uint32_t off_struct  = be32(src + 8);
    uint32_t off_strings = be32(src + 12);
    uint32_t sz_strings  = be32(src + 32);
    uint32_t sz_struct   = be32(src + 36);

    uint64_t struct_end  = (uint64_t)off_struct + sz_struct;
    uint64_t strings_end = (uint64_t)off_strings + sz_strings;
    uint64_t need = struct_end > strings_end ? struct_end : strings_end;

    if ((off_struct & 3) || need < 40 || need > avail || need > FDT_BUF_SIZE)
        return 0;

    for (uint32_t i = 0; i < (uint32_t)need; i++)
        s_buf[i] = src[i];

    s_struct_off   = off_struct;
    s_strings_off  = off_strings;
    s_strings_size = sz_strings;
    s_struct_end   = off_struct + sz_struct;
    s_ok = 1;
    return (uint32_t)need;
}

int fdt_available(void) { return s_ok; }

#ifndef FDT_HOSTTEST
void
fdt_init(void)
{
    uint64_t phys = arch_get_dtb_phys();
    if (!phys)
        return;
    /* HHDM VA of the blob (bootloader tables still live). We don't know the
     * blob's length up front; the header's totalsize (checked inside
     * fdt_ingest) bounds the copy — pass FDT_BUF_SIZE as the readable cap. */
    const uint8_t *src = (const uint8_t *)(uintptr_t)(phys + arch_early_pv_off());
    uint32_t n = fdt_ingest(src, FDT_BUF_SIZE);
    if (n)
        printk("[FDT] OK: device tree captured (%u bytes)\n", (unsigned)n);
}
#endif

/* A prop name is an offset into the strings block; compare against a C str. */
static int
str_at_is(uint32_t nameoff, const char *want)
{
    if (nameoff >= s_strings_size)
        return 0;
    const char *s = (const char *)(s_buf + s_strings_off + nameoff);
    uint32_t max = s_strings_size - nameoff;
    for (uint32_t i = 0; ; i++) {
        if (i >= max) return 0;                 /* unterminated */
        if (want[i] == '\0') return s[i] == '\0';
        if (s[i] != want[i]) return 0;
    }
}

/* "compatible" is a list of NUL-terminated strings; does one equal want? */
static int
compat_list_has(const uint8_t *val, uint32_t len, const char *want)
{
    uint32_t i = 0;
    while (i < len) {
        const char *s = (const char *)(val + i);
        uint32_t start = i;
        while (i < len && val[i]) i++;
        if (i >= len) break;                    /* unterminated final entry */
        /* s is [start..i), NUL at i */
        int eq = 1;
        for (uint32_t k = 0; ; k++) {
            char w = want[k];
            char c = (start + k < i) ? s[k] : '\0';
            if (w != c) { eq = 0; break; }
            if (w == '\0') break;
        }
        if (eq) return 1;
        i++;                                    /* past the NUL */
    }
    return 0;
}

/* Walk the structure block. For each node track parent-scope address/size
 * cells so a matched node's reg decodes correctly. If want_reg, fill
 * addr/size from the reg entry at reg_index of the first compatible match;
 * otherwise just report existence. Returns 1 on the wanted outcome. */
static int
walk(const char *compat, int want_reg, int reg_index,
     uint64_t *addr_out, uint64_t *size_out)
{
    if (!s_ok)
        return 0;

    /* cells[d] = #address/#size-cells governing children at depth d, i.e.
     * the cells used to decode the reg of a node opened at depth d+1.
     * Devicetree defaults before any override: 2 address, 1 size. */
    uint32_t ac[FDT_MAX_DEPTH], sc[FDT_MAX_DEPTH];
    int depth = 0;
    ac[0] = 2; sc[0] = 1;

    /* Per current-node state. "compatible" and "reg" can appear in either
     * order within a node, so stash reg and resolve once both are known. */
    int      matched = 0, reg_seen = 0;
    uint32_t reg_val = 0, reg_len = 0;

    uint32_t off = s_struct_off;
    while (off + 4 <= s_struct_end) {
        uint32_t tok = be32(s_buf + off);
        off += 4;

        if (tok == FDT_BEGIN_NODE) {
            /* Node name: NUL-terminated, padded to 4 bytes. */
            uint32_t n = off;
            while (n < s_struct_end && s_buf[n]) n++;
            off = (n + 4) & ~3u;                /* skip NUL + pad */
            if (depth + 1 >= FDT_MAX_DEPTH)
                return 0;                       /* pathological nesting */
            depth++;
            ac[depth] = 2; sc[depth] = 1;       /* defaults until overridden */
            matched = 0; reg_seen = 0;
        } else if (tok == FDT_END_NODE) {
            if (depth == 0) break;
            depth--;
            matched = 0; reg_seen = 0;
        } else if (tok == FDT_PROP) {
            if (off + 8 > s_struct_end) break;
            uint32_t len     = be32(s_buf + off);
            uint32_t nameoff = be32(s_buf + off + 4);
            uint32_t val     = off + 8;
            off = (val + len + 3) & ~3u;
            if (val + len > s_struct_end)
                break;

            if (str_at_is(nameoff, "#address-cells") && len >= 4)
                ac[depth] = be32(s_buf + val);
            else if (str_at_is(nameoff, "#size-cells") && len >= 4)
                sc[depth] = be32(s_buf + val);
            else if (str_at_is(nameoff, "compatible")) {
                if (compat_list_has(s_buf + val, len, compat)) {
                    if (!want_reg)
                        return 1;               /* existence query done */
                    matched = 1;
                }
            } else if (str_at_is(nameoff, "reg")) {
                reg_seen = 1; reg_val = val; reg_len = len;
            }

            /* Resolve as soon as this node has both a matching compatible
             * and a reg, regardless of which came first. */
            if (want_reg && matched && reg_seen) {
                uint32_t pac = ac[depth - 1], psc = sc[depth - 1];
                if (pac == 0 || pac > 2 || psc > 2)
                    return 0;                   /* unsupported cell width */
                uint32_t stride = (pac + psc) * 4;
                uint32_t base = (uint32_t)reg_index * stride;
                if (base + stride > reg_len)
                    return 0;                   /* index out of range */
                uint64_t a = 0, s = 0;
                for (uint32_t c = 0; c < pac; c++)
                    a = (a << 32) | be32(s_buf + reg_val + base + c * 4);
                for (uint32_t c = 0; c < psc; c++)
                    s = (s << 32) | be32(s_buf + reg_val + base + (pac + c) * 4);
                if (addr_out) *addr_out = a;
                if (size_out) *size_out = s;
                return 1;
            }
        } else if (tok == FDT_NOP) {
            /* nothing */
        } else if (tok == FDT_END) {
            break;
        } else {
            return 0;                           /* corrupt stream */
        }
    }
    return 0;
}

int
fdt_reg_by_compat(const char *compat, int index,
                  uint64_t *addr_out, uint64_t *size_out)
{
    return walk(compat, 1, index, addr_out, size_out);
}

int
fdt_compat_exists(const char *compat)
{
    return walk(compat, 0, 0, NULL, NULL);
}

/* Same node-walking shape as walk() above, but counts NODE matches instead
 * of returning on the first one -- needed for BCM2712's three identically-
 * compatible PCIe root complexes (pcie0/pcie1/pcie2), which walk() cannot
 * tell apart. */
int
fdt_reg_by_compat_nth(const char *compat, int node_index,
                      uint64_t *addr_out, uint64_t *size_out)
{
    if (!s_ok || node_index < 0)
        return 0;

    uint32_t ac[FDT_MAX_DEPTH], sc[FDT_MAX_DEPTH];
    int depth = 0;
    ac[0] = 2; sc[0] = 1;

    int      matched = 0, reg_seen = 0;
    uint32_t reg_val = 0, reg_len = 0;
    int      seen_nodes = 0;

    uint32_t off = s_struct_off;
    while (off + 4 <= s_struct_end) {
        uint32_t tok = be32(s_buf + off);
        off += 4;

        if (tok == FDT_BEGIN_NODE) {
            uint32_t n = off;
            while (n < s_struct_end && s_buf[n]) n++;
            off = (n + 4) & ~3u;
            if (depth + 1 >= FDT_MAX_DEPTH)
                return 0;
            depth++;
            ac[depth] = 2; sc[depth] = 1;
            matched = 0; reg_seen = 0;
        } else if (tok == FDT_END_NODE) {
            if (depth == 0) break;
            depth--;
            matched = 0; reg_seen = 0;
        } else if (tok == FDT_PROP) {
            if (off + 8 > s_struct_end) break;
            uint32_t len     = be32(s_buf + off);
            uint32_t nameoff = be32(s_buf + off + 4);
            uint32_t val     = off + 8;
            off = (val + len + 3) & ~3u;
            if (val + len > s_struct_end)
                break;

            if (str_at_is(nameoff, "#address-cells") && len >= 4)
                ac[depth] = be32(s_buf + val);
            else if (str_at_is(nameoff, "#size-cells") && len >= 4)
                sc[depth] = be32(s_buf + val);
            else if (str_at_is(nameoff, "compatible")) {
                if (compat_list_has(s_buf + val, len, compat))
                    matched = 1;
            } else if (str_at_is(nameoff, "reg")) {
                reg_seen = 1; reg_val = val; reg_len = len;
            }

            if (matched && reg_seen) {
                if (seen_nodes != node_index) {
                    seen_nodes++;
                    matched = 0; reg_seen = 0;   /* keep walking past this node */
                    continue;
                }
                uint32_t pac = ac[depth - 1], psc = sc[depth - 1];
                if (pac == 0 || pac > 2 || psc > 2)
                    return 0;
                uint32_t stride = (pac + psc) * 4;
                if (stride > reg_len)
                    return 0;
                uint64_t a = 0, s = 0;
                for (uint32_t c = 0; c < pac; c++)
                    a = (a << 32) | be32(s_buf + reg_val + c * 4);
                for (uint32_t c = 0; c < psc; c++)
                    s = (s << 32) | be32(s_buf + reg_val + (pac + c) * 4);
                if (addr_out) *addr_out = a;
                if (size_out) *size_out = s;
                return 1;
            }
        } else if (tok == FDT_NOP) {
            /* nothing */
        } else if (tok == FDT_END) {
            break;
        } else {
            return 0;
        }
    }
    return 0;
}

/* "memory" nodes are identified by device_type, not compatible -- a
 * separate walk from the compat-matching one above. Also different from
 * walk()'s single-match/single-reg-index contract: collects every reg
 * pair from every matching node (a node's own reg property emits all its
 * pairs at FDT_END_NODE, once #address-cells/#size-cells for that node
 * are known). */
int
fdt_memory_regions(uint64_t *addr_out, uint64_t *size_out, int max)
{
    if (!s_ok)
        return 0;

    uint32_t ac[FDT_MAX_DEPTH], sc[FDT_MAX_DEPTH];
    int depth = 0;
    ac[0] = 2; sc[0] = 1;

    int      is_memory = 0, reg_seen = 0;
    uint32_t reg_val = 0, reg_len = 0;
    int      n = 0;

    uint32_t off = s_struct_off;
    while (off + 4 <= s_struct_end) {
        uint32_t tok = be32(s_buf + off);
        off += 4;

        if (tok == FDT_BEGIN_NODE) {
            uint32_t p = off;
            while (p < s_struct_end && s_buf[p]) p++;
            off = (p + 4) & ~3u;
            if (depth + 1 >= FDT_MAX_DEPTH)
                return n;
            depth++;
            ac[depth] = 2; sc[depth] = 1;
            is_memory = 0; reg_seen = 0;
        } else if (tok == FDT_END_NODE) {
            if (depth == 0) break;
            if (is_memory && reg_seen && n < max) {
                uint32_t pac = ac[depth - 1], psc = sc[depth - 1];
                if (pac >= 1 && pac <= 2 && psc <= 2) {
                    uint32_t stride = (pac + psc) * 4;
                    uint32_t count = stride ? reg_len / stride : 0;
                    for (uint32_t k = 0; k < count && n < max; k++) {
                        uint32_t base = k * stride;
                        uint64_t a = 0, s = 0;
                        for (uint32_t c = 0; c < pac; c++)
                            a = (a << 32) | be32(s_buf + reg_val + base + c * 4);
                        for (uint32_t c = 0; c < psc; c++)
                            s = (s << 32) | be32(s_buf + reg_val + base + (pac + c) * 4);
                        addr_out[n] = a;
                        size_out[n] = s;
                        n++;
                    }
                }
            }
            depth--;
            is_memory = 0; reg_seen = 0;
        } else if (tok == FDT_PROP) {
            if (off + 8 > s_struct_end) break;
            uint32_t len     = be32(s_buf + off);
            uint32_t nameoff = be32(s_buf + off + 4);
            uint32_t val     = off + 8;
            off = (val + len + 3) & ~3u;
            if (val + len > s_struct_end)
                break;

            if (str_at_is(nameoff, "#address-cells") && len >= 4)
                ac[depth] = be32(s_buf + val);
            else if (str_at_is(nameoff, "#size-cells") && len >= 4)
                sc[depth] = be32(s_buf + val);
            else if (str_at_is(nameoff, "device_type")) {
                static const char want[] = "memory";
                int eq = (len >= sizeof(want));
                for (uint32_t k = 0; eq && k < sizeof(want) - 1; k++)
                    if (s_buf[val + k] != want[k]) eq = 0;
                if (eq) is_memory = 1;
            } else if (str_at_is(nameoff, "reg")) {
                reg_seen = 1; reg_val = val; reg_len = len;
            }
        } else if (tok == FDT_NOP) {
            /* nothing */
        } else if (tok == FDT_END) {
            break;
        } else {
            return n;                           /* corrupt stream */
        }
    }
    return n;
}
