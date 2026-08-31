/* thermal.c — CPU die temperature.
 *
 * AMD (Zen/Zen2/Zen3, families 17h/19h — the Ryzen 4750U is Zen2/Renoir):
 * temperature is read the k10temp way, through the Data Fabric's SMN indirect
 * window in PCI config space of device 00:18.3 — write the SMN address to F3
 * register 0x60, read the value back from 0x64. No MSR, no ACPI/AML. The
 * reported-temperature register (SMN 0x59800) encodes Tctl in bits [31:21] at
 * 0.125 °C/LSB, with a -49 °C range offset applied when bit 19 is set.
 *
 * Intel uses the architectural Digital Thermal Sensor: IA32_THERM_STATUS gives
 * degrees below the TCC activation target from IA32_TEMPERATURE_TARGET.
 * Returns -1 when the running CPU exposes neither supported sensor.
 */
#include <stdint.h>
#include "thermal.h"
#include "acpi.h"
#include "pcie.h"
#include "kva.h"

#define SMN_INDEX   0x60
#define SMN_DATA    0x64
#define ZEN_REPORTED_TEMP_CTRL   0x00059800u
#define ZEN_TEMP_RANGE_SEL       (1u << 19)
#define IA32_THERM_STATUS        0x19Cu
#define IA32_TEMPERATURE_TARGET  0x1A2u

static inline void
cpuid_leaf(uint32_t leaf, uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d)
{
    __asm__ volatile("cpuid"
                     : "=a"(*a), "=b"(*b), "=c"(*c), "=d"(*d)
                     : "a"(leaf), "c"(0));
}

static inline uint64_t
rdmsr(uint32_t msr)
{
    uint32_t lo, hi;
    __asm__ volatile("rdmsr" : "=a"(lo), "=d"(hi) : "c"(msr));
    return ((uint64_t)hi << 32) | lo;
}

int
cpu_temp_read(int *tjmax_out)
{
    uint32_t a, b, c, d;

    /* Intel DTS is architectural when CPUID.06H:EAX[0] is set. Restrict the
     * MSR reads to that advertised path so an unsupported CPU cannot #GP. */
    cpuid_leaf(0, &a, &b, &c, &d);
    if (b == 0x756E6547u && d == 0x49656E69u && c == 0x6C65746Eu && a >= 6) {
        cpuid_leaf(6, &a, &b, &c, &d);
        if (a & 1u) {
            uint64_t status = rdmsr(IA32_THERM_STATUS);
            uint64_t target = rdmsr(IA32_TEMPERATURE_TARGET);
            if (status & (1UL << 31)) {
                int tjmax = (int)((target >> 16) & 0xFFu);
                int temp = tjmax - (int)((status >> 16) & 0x7Fu);
                if (tjmax >= 70 && tjmax <= 125 && temp > 0 && temp <= tjmax) {
                    if (tjmax_out) *tjmax_out = tjmax;
                    return temp;
                }
            }
        }
        return -1;
    }

    if (!(b == 0x68747541u && d == 0x69746E65u && c == 0x444D4163u))
        return -1;

    /* Family 17h/19h carry the SMN reported-temperature register. */
    cpuid_leaf(1, &a, &b, &c, &d);
    uint32_t base_fam = (a >> 8) & 0xf;
    uint32_t fam = base_fam + (base_fam == 0xf ? ((a >> 20) & 0xff) : 0);
    if (fam != 0x17 && fam != 0x19)
        return -1;

    /* SMN temperature is read through the AMD ROOT COMPLEX (00:00.0), not the
     * Data Fabric — k10temp writes the SMN address to the root's index register
     * (0x60) and reads the value back from its data register (0x64). (Reading it
     * on the DF at 18.3 returned 0 → the widget showed "0C".)
     * ponytail: single reader (the once/sec hwmon poll); add a lock if another
     * SMN consumer ever appears — the 0x60/0x64 index/data pair is stateful. */
    if ((pcie_read32(0, 0, 0, 0x00) & 0xffff) != 0x1022u)
        return -1;                      /* root complex absent / not AMD (e.g. a VM) */

    pcie_write32(0, 0, 0, SMN_INDEX, ZEN_REPORTED_TEMP_CTRL);
    uint32_t rv = pcie_read32(0, 0, 0, SMN_DATA);
    if (rv == 0xffffffffu || rv == 0)
        return -1;

    int milli = (int)((rv >> 21) * 125);        /* 0.125 °C per LSB */
    if (rv & ZEN_TEMP_RANGE_SEL)
        milli -= 49000;
    int t = milli / 1000;
    if (t <= 0 || t > 125)              /* implausible → report unavailable, not 0 */
        return -1;
    if (tjmax_out)
        *tjmax_out = 100;               /* AMD throttles ~95-100 °C; nominal ceiling */
    return t;
}

/* Battery — some ThinkPads expose battery data in a SystemMemory operation
 * region. acpi.c discovers the region and fields from the DSDT rather than
 * fixing them to one machine. 16-bit LE fields provide rate, remaining charge,
 * and full charge.
 * percent = SBRC*100/SBFC; charging from SBAC's sign (>=0x8000 = discharging).
 *
 * Other firmware exposes _BST through executable AML; those machines remain
 * unavailable instead of guessing at registers. */
static volatile uint8_t *s_battery;
static acpi_battery_mmio_t s_battery_desc;

static uint16_t rd16(volatile uint8_t *p, int off) { return (uint16_t)(p[off] | (p[off + 1] << 8)); }

int
battery_read(int *percent, int *charging, int *ac)
{
    if (!s_battery) {
        if (!acpi_get_battery_mmio(&s_battery_desc)) return 0;
        uint64_t page = s_battery_desc.phys & ~0xFFFUL;
        uint64_t off = s_battery_desc.phys & 0xFFFUL;
        uint32_t last = s_battery_desc.rate_off;
        if (s_battery_desc.remaining_off > last) last = s_battery_desc.remaining_off;
        if (s_battery_desc.full_off > last) last = s_battery_desc.full_off;
        uint32_t pages = (uint32_t)((off + last + 2 + 0xFFF) >> 12);
        void *va = kva_map_mmio(page, pages);
        if (!va) return 0;
        s_battery = (volatile uint8_t *)va + off;
    }

    uint16_t sbac = rd16(s_battery, (int)s_battery_desc.rate_off);
    uint16_t sbrc = rd16(s_battery, (int)s_battery_desc.remaining_off);
    uint16_t sbfc = rd16(s_battery, (int)s_battery_desc.full_off);

    /* Reject implausible reads (0 / 0xFFFF / remaining>full) — i.e. this isn't
     * battery data. */
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
