/*
 * Strict boot-memory trust boundary. The older FDT peripheral queries can
 * return early/partial results; those must not decide which pages are free.
 * This intake validates a complete stream, reserves conservatively, then
 * subtracts normalized exclusions. It never allocates or reclaims a page.
 */
#include "boot_memory.h"
#include <stddef.h>

#define PAGE 4096ULL
#define DEPTH 32
#define ROOT 0
#define OTHER 1
#define RESERVED_ROOT 2
#define RESERVED_CHILD 3
#define CHOSEN 4
#define REG 1u
#define AC 2u
#define SC 4u
#define STATUS 8u
#define TYPE 16u
#define RANGES 32u
#define INIT_START 64u
#define INIT_END 128u

struct frame {
    uint32_t kind, ac, sc, seen, reg, reg_size;
    uint32_t enabled, children, is_memory, memory_name, restricted;
    uint32_t init_offset, disabled;
    uint64_t init_start, init_end;
};

static void clear(void *p, size_t size)
{
    volatile uint8_t *bytes = p;
    while (size--) *bytes++ = 0;
}

static uint32_t be32(const uint8_t *p)
{
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 |
           (uint32_t)p[2] << 8 | p[3];
}

static uint64_t be64(const uint8_t *p)
{
    return (uint64_t)be32(p) << 32 | be32(p + 4);
}

static int equal(const uint8_t *p, uint32_t n, const char *s)
{
    uint32_t i = 0;
    while (s[i]) {
        if (i >= n || p[i] != (uint8_t)s[i]) return 0;
        i++;
    }
    return i + 1 == n && p[i] == 0;
}

static int prefix(const uint8_t *p, uint32_t n, const char *s)
{
    for (uint32_t i = 0; s[i]; i++)
        if (i >= n || p[i] != (uint8_t)s[i]) return 0;
    return 1;
}

static int string(const uint8_t *p, uint32_t n)
{
    if (!n || p[n - 1]) return 0;
    for (uint32_t i = 0; i + 1 < n; i++)
        if (!p[i]) return 0;
    return 1;
}

static int overlap(uint64_t a, uint64_t end, uint64_t b, uint64_t bend)
{
    return a < bend && b < end;
}

static void rejected(struct boot_memory_failure *f, uint32_t source, uint32_t reason,
                     uint32_t offset, uint32_t index,
                     uint64_t base, uint64_t size, uint64_t limit)
{
    if (!f) return;
    f->source = source; f->reason = reason;
    f->offset = offset; f->index = index;
    f->base = base; f->size = size; f->limit = limit;
}

static int append(struct boot_memory_range *v, uint32_t *count, uint32_t cap,
                  uint64_t base, uint64_t size, uint64_t limit, int reserve,
                  struct boot_memory_failure *failure, uint32_t source,
                  uint32_t offset, uint32_t index)
{
    uint32_t reason = !size ? BOOT_MEMORY_REASON_ZERO_SIZE :
                      base >= limit ? BOOT_MEMORY_REASON_BASE_LIMIT :
                      size > limit - base ? BOOT_MEMORY_REASON_END_LIMIT : 0;
    if (reason) {
        rejected(failure, source, reason, offset, index, base, size, limit);
        return BOOT_MEMORY_RANGE;
    }
    uint64_t original_base = base, original_size = size;
    uint64_t end = base + size;
    if (reserve) {
        base &= ~(PAGE - 1);
        end = (end + PAGE - 1) & ~(PAGE - 1);
    } else {
        base = (base + PAGE - 1) & ~(PAGE - 1);
        end &= ~(PAGE - 1);
    }
    if (base >= end) return BOOT_MEMORY_OK; /* no whole RAM page */
    if (*count == cap) {
        rejected(failure, source, BOOT_MEMORY_REASON_CAPACITY, offset, index,
                 original_base, original_size, limit);
        return BOOT_MEMORY_CAPACITY;
    }
    v[*count].begin = base;
    v[*count].end = end;
    (*count)++;
    return BOOT_MEMORY_OK;
}

static void normalize(struct boot_memory_range *v, uint32_t *count)
{
    for (uint32_t i = 1; i < *count; i++) {
        struct boot_memory_range value = v[i];
        uint32_t j = i;
        while (j && v[j - 1].begin > value.begin) {
            v[j] = v[j - 1];
            j--;
        }
        v[j] = value;
    }
    uint32_t n = 0;
    for (uint32_t i = 0; i < *count; i++) {
        if (n && v[i].begin <= v[n - 1].end) {
            if (v[i].end > v[n - 1].end) v[n - 1].end = v[i].end;
        } else {
            v[n++] = v[i];
        }
    }
    *count = n;
}

static int decode_reg(const uint8_t *blob, const struct frame *f,
                      const struct frame *parent, uint64_t limit,
                      struct boot_memory_range *v, uint32_t *count,
                      uint32_t cap, int reserve, struct boot_memory_failure *failure,
                      uint32_t source)
{
    if (parent->ac < 1 || parent->ac > 2 || parent->sc < 1 || parent->sc > 2)
        return BOOT_MEMORY_UNSUPPORTED;
    uint32_t stride = (parent->ac + parent->sc) * 4;
    if (!(f->seen & REG) || !f->reg_size || f->reg_size % stride)
        return BOOT_MEMORY_TREE;
    for (uint32_t off = 0; off < f->reg_size; off += stride) {
        const uint8_t *p = blob + f->reg + off;
        uint64_t base = parent->ac == 2 ? be64(p) : be32(p);
        p += parent->ac * 4;
        uint64_t size = parent->sc == 2 ? be64(p) : be32(p);
        /* A structurally valid, explicitly disabled static placeholder has
         * no pages to exclude. Do not generalize to active/unknown statuses,
         * nonempty reservations, or out-of-range addresses. */
        if (reserve && f->disabled && !size && base < limit)
            continue;
        int error = append(v, count, cap, base, size, limit, reserve,
                           failure, source, f->reg + off, off / stride);
        if (error) return error;
    }
    return BOOT_MEMORY_OK;
}

static int finish_node(const uint8_t *blob, const struct frame *f,
                       const struct frame *parent, const struct frame *root,
                       unsigned depth, uint64_t limit, struct boot_memory_plan *out,
                       struct boot_memory_failure *failure)
{
    if (f->kind == RESERVED_ROOT) {
        if ((f->seen & REG) ||
            (f->seen & (AC | SC | RANGES)) != (AC | SC | RANGES) ||
            f->ac != root->ac || f->sc != root->sc ||
            f->ac < 1 || f->ac > 2 || f->sc < 1 || f->sc > 2)
            return BOOT_MEMORY_UNSUPPORTED;
    } else if (f->kind == RESERVED_CHILD) {
        /* Even disabled/reusable/no-map static reservations remain excluded.
         * An active dynamic reservation cannot be resolved without an allocator. */
        if (!(f->seen & REG))
            return f->enabled ? BOOT_MEMORY_UNSUPPORTED : BOOT_MEMORY_OK;
        return decode_reg(blob, f, parent, limit, out->reserved,
                          &out->reserved_count, BOOT_MEMORY_RESERVED, 1,
                          failure, BOOT_MEMORY_SOURCE_RESERVED);
    } else if (f->kind == CHOSEN) {
        unsigned init = f->seen & (INIT_START | INIT_END);
        if (init) {
            if (init != (INIT_START | INIT_END) || f->init_end <= f->init_start)
                return BOOT_MEMORY_TREE;
            return append(out->reserved, &out->reserved_count, BOOT_MEMORY_RESERVED,
                          f->init_start, f->init_end - f->init_start, limit, 1,
                          failure, BOOT_MEMORY_SOURCE_INITRD, f->init_offset, 0);
        }
    }
    if (depth == 2 && (f->is_memory || f->memory_name)) {
        if (f->kind != OTHER || !f->is_memory)
            return BOOT_MEMORY_TREE;
        if (!f->enabled) return BOOT_MEMORY_OK;
        if (f->restricted) return BOOT_MEMORY_UNSUPPORTED;
        return decode_reg(blob, f, parent, limit, out->banks,
                          &out->bank_count, BOOT_MEMORY_BANKS, 0,
                          failure, BOOT_MEMORY_SOURCE_RAM);
    }
    return BOOT_MEMORY_OK;
}

static int property(const uint8_t *name, uint32_t name_size, const uint8_t *val,
                    uint32_t size, uint32_t offset, struct frame *f)
{
    unsigned bit = 0;
    if (equal(name, name_size, "reg")) bit = REG;
    else if (equal(name, name_size, "#address-cells")) bit = AC;
    else if (equal(name, name_size, "#size-cells")) bit = SC;
    else if (equal(name, name_size, "status")) bit = STATUS;
    else if (equal(name, name_size, "device_type")) bit = TYPE;
    else if (f->kind == RESERVED_ROOT && equal(name, name_size, "ranges")) bit = RANGES;
    else if (f->kind == CHOSEN && equal(name, name_size, "linux,initrd-start")) bit = INIT_START;
    else if (f->kind == CHOSEN && equal(name, name_size, "linux,initrd-end")) bit = INIT_END;
    else if (f->kind == CHOSEN &&
             (equal(name, name_size, "linux,usable-memory-range") ||
              equal(name, name_size, "linux,elfcorehdr")))
        return BOOT_MEMORY_UNSUPPORTED; /* never silently ignore exclusions */
    else if (equal(name, name_size, "linux,usable-memory") ||
             equal(name, name_size, "hotpluggable"))
        f->restricted = 1;
    if (bit && (f->seen & bit)) return BOOT_MEMORY_TREE;
    f->seen |= bit;
    if (bit == REG) {
        f->reg = offset; f->reg_size = size;
    } else if (bit == AC || bit == SC) {
        if (size != 4) return BOOT_MEMORY_TREE;
        if (bit == AC) f->ac = be32(val);
        else f->sc = be32(val);
    } else if (bit == STATUS || bit == TYPE) {
        if (!string(val, size)) return BOOT_MEMORY_TREE;
        if (bit == STATUS) {
            f->enabled = f->enabled && (equal(val, size, "okay") || equal(val, size, "ok"));
            f->disabled |= equal(val, size, "disabled");
        } else
            f->is_memory = equal(val, size, "memory");
    } else if (bit == RANGES) {
        if (size) return BOOT_MEMORY_UNSUPPORTED;
    } else if (bit == INIT_START || bit == INIT_END) {
        if (size != 4 && size != 8) return BOOT_MEMORY_TREE;
        uint64_t value = size == 4 ? be32(val) : be64(val);
        if (bit == INIT_START) { f->init_start = value; f->init_offset = offset; }
        else f->init_end = value;
    }
    return BOOT_MEMORY_OK;
}

int boot_memory_plan(const uint8_t *b, uint32_t avail,
                     const struct boot_memory_request *q, struct boot_memory_plan *out,
                     struct boot_memory_failure *failure)
{
    if (failure) clear(failure, sizeof(*failure));
    if (!out) return 0;
    clear(out, sizeof(*out));
    int error = BOOT_MEMORY_HEADER;
    if (!b || !q || avail < 40 || be32(b) != 0xd00dfeed)
        goto fail;
    uint64_t limit = q->physical_limit;
    if (limit < PAGE || limit > (1ULL << 48) || (limit & (limit - 1)) ||
        !q->image || !q->image_size || !q->dtb || (!q->fb_size && q->fb)) {
        uint32_t source = BOOT_MEMORY_SOURCE_REQUEST;
        uint64_t base = 0, size = 0;
        if (limit >= PAGE && limit <= (1ULL << 48) && !(limit & (limit - 1))) {
            if (!q->image || !q->image_size) {
                source = BOOT_MEMORY_SOURCE_IMAGE; base = q->image; size = q->image_size;
            } else if (!q->dtb) {
                source = BOOT_MEMORY_SOURCE_DTB; base = q->dtb; size = avail;
            } else {
                source = BOOT_MEMORY_SOURCE_FB; base = q->fb; size = q->fb_size;
            }
        }
        rejected(failure, source, BOOT_MEMORY_REASON_REQUEST, 0, 0, base, size, limit);
        error = BOOT_MEMORY_RANGE; goto fail;
    }
    uint32_t total = be32(b + 4), st = be32(b + 8), strings = be32(b + 12);
    uint32_t reserve = be32(b + 16), sn = be32(b + 32), tn = be32(b + 36);
    uint64_t se = (uint64_t)st + tn, ne = (uint64_t)strings + sn;
    if (total < 40 || total > avail || total > 2 * 1024 * 1024 ||
        be32(b + 20) != 17 || be32(b + 24) > 17 ||
        st < 40 || (st & 3) || tn < 12 || (tn & 3) || se > total ||
        strings < 40 || ne > total || overlap(st, se, strings, ne) ||
        reserve < 40 || (reserve & 7))
        goto fail;
    uint64_t off = reserve;
    uint32_t reserve_index = 0;
    for (;;) {
        error = BOOT_MEMORY_HEADER;
        if (off + 16 > total || overlap(off, off + 16, st, se) ||
            overlap(off, off + 16, strings, ne))
            goto fail;
        uint64_t base = be64(b + off), size = be64(b + off + 8);
        off += 16;
        if (!base && !size) break;
        error = append(out->reserved, &out->reserved_count, BOOT_MEMORY_RESERVED,
                       base, size, limit, 1, failure, BOOT_MEMORY_SOURCE_MEMRESERVE,
                       (uint32_t)(off - 16), reserve_index++);
        if (error) goto fail;
    }
    struct frame stack[DEPTH];
    clear(stack, sizeof(stack));
    unsigned depth = 0, root_seen = 0, root_closed = 0, ended = 0;
    unsigned reserved_seen = 0, chosen_seen = 0;
    off = st;
    error = BOOT_MEMORY_TREE;
    while (off + 4 <= se) {
        uint32_t token = be32(b + off);
        off += 4;
        if (token == 4) continue;       /* NOP is legal around nodes/end */
        if (ended) goto fail;
        if (token == 1) {
            if (root_closed || depth == DEPTH) goto fail;
            uint64_t start = off;
            while (off < se && b[off]) {
                if (b[off] == '/') goto fail;
                off++;
            }
            if (off == se) goto fail;
            uint32_t length = (uint32_t)(off - start + 1);
            off = (off + 4) & ~3ULL;
            if (off > se || (depth && length == 1)) goto fail;
            struct frame *f = &stack[depth];
            clear(f, sizeof(*f));
            f->ac = 2; f->sc = 1; f->kind = OTHER;
            f->enabled = depth ? stack[depth - 1].enabled : 1;
            f->disabled = depth ? stack[depth - 1].disabled : 0;
            if (!depth) {
                if (root_seen || length != 1) goto fail;
                root_seen = 1; f->kind = ROOT;
            } else {
                stack[depth - 1].children = 1;
                if (stack[depth - 1].kind == RESERVED_CHILD) {
                    error = BOOT_MEMORY_UNSUPPORTED; goto fail;
                }
                if (stack[depth - 1].kind == RESERVED_ROOT)
                    f->kind = RESERVED_CHILD;
                if (depth == 1) {
                    f->memory_name = equal(b + start, length, "memory") ||
                                     prefix(b + start, length, "memory@");
                    if (equal(b + start, length, "reserved-memory")) {
                        if (reserved_seen++) goto fail;
                        f->kind = RESERVED_ROOT;
                    } else if (prefix(b + start, length, "reserved-memory@")) {
                        error = BOOT_MEMORY_UNSUPPORTED; goto fail;
                    } else if (equal(b + start, length, "chosen") ||
                               equal(b + start, length, "chosen@0")) {
                        if (chosen_seen++) goto fail;
                        f->kind = CHOSEN;
                    }
                }
            }
            depth++;
        } else if (token == 2) {
            if (!depth) goto fail;
            struct frame *f = &stack[depth - 1];
            error = finish_node(b, f, depth > 1 ? &stack[depth - 2] : f,
                                &stack[0], depth, limit, out, failure);
            if (error) goto fail;
            depth--;
            if (!depth) root_closed = 1;
            error = BOOT_MEMORY_TREE;
        } else if (token == 3) {
            if (!depth || stack[depth - 1].children || off + 8 > se) goto fail;
            uint32_t size = be32(b + off), name = be32(b + off + 4);
            off += 8;
            uint64_t next = (off + size + 3) & ~3ULL;
            if (next > se || name >= sn) goto fail;
            uint32_t end = name;
            while (end < sn && b[strings + end]) end++;
            if (end == sn || end == name) goto fail;
            error = property(b + strings + name, end - name + 1,
                             b + off, size, (uint32_t)off, &stack[depth - 1]);
            if (error) goto fail;
            off = next;
            error = BOOT_MEMORY_TREE;
        } else if (token == 9) {
            if (!root_seen || !root_closed || depth) goto fail;
            ended = 1;
        } else goto fail;
    }
    if (!ended || off != se) goto fail;
    error = append(out->reserved, &out->reserved_count, BOOT_MEMORY_RESERVED,
                   q->image, q->image_size, limit, 1,
                   failure, BOOT_MEMORY_SOURCE_IMAGE, 0, 0);
    if (error) goto fail;
    error = append(out->reserved, &out->reserved_count, BOOT_MEMORY_RESERVED,
                   q->dtb, total, limit, 1, failure, BOOT_MEMORY_SOURCE_DTB, 0, 0);
    if (error) goto fail;
    if (q->fb_size) {
        error = append(out->reserved, &out->reserved_count, BOOT_MEMORY_RESERVED,
                       q->fb, q->fb_size, limit, 1, failure, BOOT_MEMORY_SOURCE_FB, 0, 0);
        if (error) goto fail;
    }
    normalize(out->banks, &out->bank_count);
    normalize(out->reserved, &out->reserved_count);
    if (!out->bank_count) { error = BOOT_MEMORY_NO_RAM; goto fail; }
    for (uint32_t i = 0; i < out->bank_count; i++) {
        uint64_t cursor = out->banks[i].begin, end = out->banks[i].end;
        out->bank_bytes += end - cursor;
        for (uint32_t j = 0; j < out->reserved_count && cursor < end; j++) {
            struct boot_memory_range r = out->reserved[j];
            if (r.end <= cursor) continue;
            if (r.begin >= end) break;
            if (r.begin > cursor) {
                error = append(out->candidates, &out->candidate_count,
                               BOOT_MEMORY_CANDIDATES, cursor, r.begin - cursor, limit, 0,
                               failure, BOOT_MEMORY_SOURCE_CANDIDATE, 0, i);
                if (error) goto fail;
            }
            if (r.end > cursor) cursor = r.end;
        }
        if (cursor < end) {
            error = append(out->candidates, &out->candidate_count,
                           BOOT_MEMORY_CANDIDATES, cursor, end - cursor, limit, 0,
                           failure, BOOT_MEMORY_SOURCE_CANDIDATE, 0, i);
            if (error) goto fail;
        }
    }
    for (uint32_t i = 0; i < out->candidate_count; i++)
        out->candidate_bytes += out->candidates[i].end - out->candidates[i].begin;
    out->excluded_bytes = out->bank_bytes - out->candidate_bytes;
    return 1;
fail:
    clear(out, sizeof(*out));
    out->error = error;
    return 0;
}

const char *boot_memory_error_name(uint32_t e)
{
    switch (e) {
    case BOOT_MEMORY_OK: return "OK";
    case BOOT_MEMORY_HEADER: return "INVALID FDT HEADER OR RESERVATION MAP";
    case BOOT_MEMORY_TREE: return "INVALID MEMORY TREE";
    case BOOT_MEMORY_RANGE: return "INVALID PHYSICAL RANGE";
    case BOOT_MEMORY_CAPACITY: return "MEMORY PLAN CAPACITY EXCEEDED";
    case BOOT_MEMORY_UNSUPPORTED: return "UNRESOLVED OR UNSUPPORTED MEMORY BINDING";
    case BOOT_MEMORY_NO_RAM: return "NO WHOLE RAM PAGES";
    default: return "UNKNOWN MEMORY ERROR";
    }
}
