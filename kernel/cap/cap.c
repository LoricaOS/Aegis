/*
 * cap.c — the capability core: cap_init / cap_grant / cap_check.
 *
 * This is a straight C reimplementation of the former Rust crate
 * (kernel/cap/src/lib.rs). The behavior is byte-for-byte identical — the
 * security model is unchanged: unforgeable per-process capability slots,
 * fail-closed (-ENOCAP) on any miss, NULL guard, and a clamp to
 * CAP_TABLE_SIZE so a bad `n` can never index past the PCB's caps[] array.
 *
 * Why C now: the Rust crate was the kernel's ONLY dependency on cargo/rustc
 * (and thus LLVM). Removing it lets the kernel build with a plain C toolchain,
 * which is a prerequisite for LoricaOS self-hosting (building Aegis on Aegis
 * without porting the entire Rust toolchain). See the self-hosting roadmap.
 *
 * DO NOT weaken any check here — this is the trust boundary the whole kernel
 * rests on. Every C caller tests the result as `< 0` / `!= 0` / `>= 0`, never
 * equality to a specific value, so -ENOCAP (aliased to -EPERM) is only a
 * "nonzero on failure" signal.
 */

#include "cap.h"

/* serial_write_string — polling serial write; declared here to avoid pulling in
 * an arch header. serial_init() runs in arch_init() before cap_init(). */
void serial_write_string(const char *s);

/* cap_init — announce the subsystem is live. Matches the old Rust output
 * exactly (serial only; no printk/VGA — revisit if a printk path is wanted). */
void
cap_init(void)
{
    serial_write_string("[CAP] OK: capability subsystem initialized\n");
}

/*
 * cap_grant — write (kind, rights) into the first empty slot of table[0..n).
 * Returns the slot index on success, or -ENOCAP if the table is full / invalid.
 */
int
cap_grant(cap_slot_t *table, uint32_t n, uint32_t kind, uint32_t rights)
{
    if (table == 0 || n == 0)
        return -ENOCAP;

    /* Clamp so a wrong `n` never walks past the PCB's fixed caps[] array. */
    if (n > CAP_TABLE_SIZE)
        n = CAP_TABLE_SIZE;

    for (uint32_t i = 0; i < n; i++) {
        if (table[i].kind == CAP_KIND_NULL) {
            table[i].kind   = kind;
            table[i].rights = rights;
            return (int)i;
        }
    }
    return -ENOCAP;
}

/*
 * cap_check — 0 if table[0..n) has a slot matching `kind` with at least the
 * requested `rights`; -ENOCAP otherwise. The cap-gate read path.
 */
int
cap_check(const cap_slot_t *table, uint32_t n, uint32_t kind, uint32_t rights)
{
    if (table == 0 || n == 0)
        return -ENOCAP;

    if (n > CAP_TABLE_SIZE)
        n = CAP_TABLE_SIZE;

    for (uint32_t i = 0; i < n; i++) {
        if (table[i].kind == kind && (table[i].rights & rights) == rights)
            return 0;
    }
    return -ENOCAP;
}

void
cap_ceiling_from_table(uint32_t ceiling[CAP_KIND_MAX + 1u],
                       const cap_slot_t *caps)
{
    uint32_t i;
    for (i = 0; i <= CAP_KIND_MAX; i++)
        ceiling[i] = 0;
    for (i = 0; i < CAP_TABLE_SIZE; i++) {
        uint32_t kind = caps[i].kind;
        if (kind != CAP_KIND_NULL && kind <= CAP_KIND_MAX)
            ceiling[kind] |= caps[i].rights;
    }
}

void
cap_apply_ceiling(cap_slot_t *caps,
                  const uint32_t ceiling[CAP_KIND_MAX + 1u])
{
    uint32_t i;
    for (i = 0; i < CAP_TABLE_SIZE; i++) {
        uint32_t kind = caps[i].kind;
        if (kind == CAP_KIND_NULL)
            continue;
        if (kind > CAP_KIND_MAX) {
            caps[i].kind = CAP_KIND_NULL;
            caps[i].rights = 0;
            continue;
        }
        caps[i].rights &= ceiling[kind];
        if (caps[i].rights == 0)
            caps[i].kind = CAP_KIND_NULL;
    }
}
