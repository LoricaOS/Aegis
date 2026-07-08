/* thermal.c — CPU die temperature.
 *
 * AMD (Zen/Zen2/Zen3, families 17h/19h — the Ryzen 4750U is Zen2/Renoir):
 * temperature is read the k10temp way, through the Data Fabric's SMN indirect
 * window in PCI config space of device 00:18.3 — write the SMN address to F3
 * register 0x60, read the value back from 0x64. No MSR, no ACPI/AML. The
 * reported-temperature register (SMN 0x59800) encodes Tctl in bits [31:21] at
 * 0.125 °C/LSB, with a -49 °C range offset applied when bit 19 is set.
 *
 * Returns -1 when unavailable: an Intel/other CPU, or no Data Fabric — in a VM
 * the 00:18.3 device is absent, so this is boot-safe there and only yields real
 * readings on hardware. Intel DTS (MSR 0x19C) would be a separate path.
 */
#include <stdint.h>
#include "thermal.h"
#include "pcie.h"
#include "kva.h"

#define DF_F3_BUS   0
#define DF_F3_DEV   0x18
#define DF_F3_FN    3
#define SMN_INDEX   0x60
#define SMN_DATA    0x64
#define ZEN_REPORTED_TEMP_CTRL   0x00059800u
#define ZEN_TEMP_RANGE_SEL       (1u << 19)

static inline void
cpuid_leaf(uint32_t leaf, uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d)
{
    __asm__ volatile("cpuid"
                     : "=a"(*a), "=b"(*b), "=c"(*c), "=d"(*d)
                     : "a"(leaf), "c"(0));
}

int
cpu_temp_read(int *tjmax_out)
{
    uint32_t a, b, c, d;

    /* Vendor must be "AuthenticAMD" (EBX/EDX/ECX of leaf 0). */
    cpuid_leaf(0, &a, &b, &c, &d);
    if (!(b == 0x68747541u && d == 0x69746E65u && c == 0x444D4163u))
        return -1;

    /* Family 17h/19h carry the SMN reported-temperature register. */
    cpuid_leaf(1, &a, &b, &c, &d);
    uint32_t base_fam = (a >> 8) & 0xf;
    uint32_t fam = base_fam + (base_fam == 0xf ? ((a >> 20) & 0xff) : 0);
    if (fam != 0x17 && fam != 0x19)
        return -1;

    /* The Data Fabric function 3 must be a real AMD device (absent in a VM). */
    if ((pcie_read32(DF_F3_BUS, DF_F3_DEV, DF_F3_FN, 0x00) & 0xffff) != 0x1022u)
        return -1;

    /* SMN indirect read of the reported-temperature control register.
     * ponytail: single reader (the once/sec hwmon poll); add a lock if another
     * SMN consumer ever appears — the 0x60/0x64 index/data pair is stateful. */
    pcie_write32(DF_F3_BUS, DF_F3_DEV, DF_F3_FN, SMN_INDEX, ZEN_REPORTED_TEMP_CTRL);
    uint32_t rv = pcie_read32(DF_F3_BUS, DF_F3_DEV, DF_F3_FN, SMN_DATA);
    if (rv == 0xffffffffu)
        return -1;

    int milli = (int)((rv >> 21) * 125);        /* 0.125 °C per LSB */
    if (rv & ZEN_TEMP_RANGE_SEL)
        milli -= 49000;
    if (tjmax_out)
        *tjmax_out = 100;               /* AMD throttles ~95-100 °C; nominal ceiling */
    return milli / 1000;
}

/* Battery — ThinkPad (Ryzen 4750U) exposes battery data in a memory-mapped EC
 * region (from its DSDT: OperationRegion ECOE, SystemMemory, 0xFE00DE00). 16-bit
 * LE fields: SBAC(rate)@0x1A, SBRC(remaining)@0x1E, SBFC(full-charge)@0x22.
 * percent = SBRC*100/SBFC; charging from SBAC's sign (>=0x8000 = discharging).
 *
 * Gated by AMD + a plausibility check, so on any other machine or a VM (where
 * that physical address isn't battery data) it reads back as "no battery".
 * ponytail: the address is this ThinkPad's; a machine-general path would need an
 * AML interpreter to evaluate each system's own _BST — out of scope for now. */
#define ECOE_PHYS   0xFE00DE00u
#define ECOE_PAGE   (ECOE_PHYS & ~0xFFFu)
#define ECOE_OFF    (ECOE_PHYS & 0xFFFu)

static volatile uint8_t *s_ecoe;        /* cached mapping of the ECOE region */

static uint16_t rd16(volatile uint8_t *p, int off) { return (uint16_t)(p[off] | (p[off + 1] << 8)); }

int
battery_read(int *percent, int *charging, int *ac)
{
    uint32_t a, b, c, d;
    cpuid_leaf(0, &a, &b, &c, &d);
    if (!(b == 0x68747541u && d == 0x69746E65u && c == 0x444D4163u))
        return 0;                       /* not AuthenticAMD */

    if (!s_ecoe) {
        void *va = kva_map_mmio(ECOE_PAGE, 1);
        if (!va) return 0;
        s_ecoe = (volatile uint8_t *)va + ECOE_OFF;
    }

    uint16_t sbac = rd16(s_ecoe, 0x1A);
    uint16_t sbrc = rd16(s_ecoe, 0x1E);
    uint16_t sbfc = rd16(s_ecoe, 0x22);

    /* Reject implausible reads (0 / 0xFFFF / remaining>full) — i.e. this isn't
     * the ThinkPad's battery memory. */
    if (sbfc < 100 || sbfc >= 0xFFF0 || sbrc == 0xFFFF || sbrc > sbfc + sbfc / 20)
        return 0;

    int pct = (int)((uint32_t)sbrc * 100 / sbfc);
    if (pct > 100) pct = 100;
    if (pct < 0) pct = 0;
    *percent = pct;
    *charging = (sbac != 0 && sbac < 0x8000);
    *ac = *charging || pct >= 99;
    return 1;
}
