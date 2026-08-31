/* acpi.c — ACPI table parser (MCFG + MADT + FADT + bounded AML data)
 *
 * Phase 19: MCFG for PCIe ECAM, MADT for interrupt routing.
 * Phase 35: FADT for power button shutdown (SCI interrupt + PM1a registers).
 * No control-method interpreter: static DSDT objects used by power and battery
 * telemetry are decoded only when their values are constant and unambiguous.
 */
#include "acpi.h"
#include "fs_ops.h"
#include "arch.h"
#include "signal.h"
#include "printk.h"
#include "vmm.h"
#include "kva.h"
#include "pic.h"
#include "ext2.h"
#include <stdint.h>
#include <stddef.h>

uint64_t g_mcfg_base      = 0;
uint8_t  g_mcfg_start_bus = 0;
uint8_t  g_mcfg_end_bus   = 0;
int      g_madt_found     = 0;

/* SMP CPU info parsed from MADT */
smp_cpu_t  g_smp_cpus[SMP_MAX_CPUS];
uint32_t   g_smp_cpu_count  = 0;
uint8_t    g_bsp_apic_id    = 0;

/* I/O APIC info from MADT */
uint64_t   g_ioapic_addr     = 0;
uint32_t   g_ioapic_gsi_base = 0;

/* Interrupt Source Overrides from MADT */
madt_iso_t g_madt_iso[MADT_MAX_ISO];
uint32_t   g_madt_iso_count = 0;

/* ── ACPI power management (from FADT + DSDT) ──────────────────────── */
static uint16_t s_sci_int     = 0;     /* SCI interrupt (IRQ number) */
static uint32_t s_pm1a_evt    = 0;     /* PM1a Event Block I/O port */
static uint32_t s_pm1a_cnt    = 0;     /* PM1a Control Block I/O port */
static uint32_t s_pm1b_cnt    = 0;     /* PM1b Control Block (0 = absent) */
static uint8_t  s_pm1_evt_len = 0;     /* PM1 Event Block length (usually 4) */
static uint16_t s_slp_typa    = 0;     /* SLP_TYPa value for S5 (from DSDT) */
static uint16_t s_slp_typb    = 0;     /* SLP_TYPb value for S5 */
static int      s_acpi_pm_ok  = 0;     /* 1 if power management is ready */
static uint32_t s_smi_cmd     = 0;     /* SMI Command port (FADT offset 48) */
static uint8_t  s_acpi_enable = 0;     /* ACPI Enable value (FADT offset 52) */
static acpi_battery_mmio_t s_battery_mmio;
static int s_battery_mmio_ok;

/* -----------------------------------------------------------------------
 * Single-page KVA window for temporary ACPI table access.
 *
 * We allocate one 4KB KVA page once and remap it for each physical page
 * we need to read.  This avoids allocating a new KVA page for every table
 * access while keeping the code simple (no multi-page spanning).
 *
 * The window is only valid during acpi_init(); after that it is abandoned
 * (KVA is a bump allocator — no free path).
 * ----------------------------------------------------------------------- */
static void    *s_win_va  = NULL;   /* KVA of the window page */
static uint64_t s_win_phys = (uint64_t)-1; /* currently mapped phys page */

/* Map phys page (aligned) into the window; invalidate TLB.
 *
 * kva_alloc_pages maps the window VA to a PMM frame initially.  Before we
 * can install our own physical page we must clear that existing PTE, because
 * vmm_map_page panics on double-map.  This applies both to the initial PMM
 * frame (first call) and any subsequent remap (later calls).
 * SAFETY: s_win_va is always mapped after kva_alloc_pages (first call) or
 * after a previous vmm_map_page call (subsequent); vmm_unmap_page succeeds. */
static void
win_map(uint64_t phys_page)
{
    if (s_win_phys == phys_page)
        return;     /* already mapped — nothing to do */
    /* Clear the existing PTE (initial PMM frame or previous physical page). */
    vmm_unmap_page((uint64_t)(uintptr_t)s_win_va);
    /* SAFETY: PTE is now absent; vmm_map_page installs phys_page safely.
     * Flags 0x03 = Present|Write (kernel-only, cached). */
    vmm_map_page((uint64_t)(uintptr_t)s_win_va, phys_page, 0x03);
    s_win_phys = phys_page;
}

/* Read a byte from any physical address using the window. */
static uint8_t
phys_read8(uint64_t phys)
{
    uint64_t page   = phys & ~(uint64_t)0xFFF;
    uint64_t offset = phys &  (uint64_t)0xFFF;
    win_map(page);
    /* SAFETY: s_win_va is mapped to page via win_map(); offset is within
     * the page (< 4096); the cast to uint8_t* and dereference is safe. */
    return ((const uint8_t *)s_win_va)[offset];
}

/* Read a 4-byte little-endian uint32 from any physical address. */
static uint32_t
phys_read32(uint64_t phys)
{
    uint32_t v = 0;
    uint32_t i;
    for (i = 0; i < 4; i++)
        v |= ((uint32_t)phys_read8(phys + i)) << (i * 8);
    return v;
}

/* Read an 8-byte little-endian uint64 from any physical address. */
static uint64_t
phys_read64(uint64_t phys)
{
    uint64_t v = 0;
    uint32_t i;
    for (i = 0; i < 8; i++)
        v |= ((uint64_t)phys_read8(phys + i)) << (i * 8);
    return v;
}

/* Read `len` bytes from physical address phys into dst. */
static void
phys_read_bytes(uint64_t phys, void *dst, uint32_t len)
{
    uint8_t *d = (uint8_t *)dst;
    uint32_t i;
    for (i = 0; i < len; i++)
        d[i] = phys_read8(phys + i);
}

static int acpi_checksum_phys(uint64_t phys, uint32_t len)
{
    uint8_t sum = 0;
    uint32_t i;
    for (i = 0; i < len; i++)
        sum += phys_read8(phys + i);
    return sum == 0;
}

/* Decode the small, non-executable AML subset needed to locate the battery
 * fields already exposed by Lenovo DSDTs: constant SystemMemory
 * OperationRegion declarations and Field bit offsets. Unsupported TermArgs
 * are rejected; this is intentionally not a permissive AML interpreter. */
typedef struct {
    char name[4];
    uint64_t base;
    uint32_t length;
} aml_region_t;

static int
aml_nameseg(uint64_t *pos, uint64_t end, char out[4])
{
    uint64_t p = *pos;
    while (p < end && (phys_read8(p) == 0x5c || phys_read8(p) == 0x5e)) p++;
    if (p >= end) return 0;
    uint8_t lead = phys_read8(p);
    uint32_t count = 1;
    if (lead == 0x2e) { count = 2; p++; }
    else if (lead == 0x2f) {
        if (++p >= end) return 0;
        count = phys_read8(p++);
        if (count == 0) return 0;
    }
    if (p + (uint64_t)count * 4 > end) return 0;
    p += (uint64_t)(count - 1) * 4;
    for (uint32_t i = 0; i < 4; i++) out[i] = (char)phys_read8(p + i);
    *pos = p + 4;
    return 1;
}

static int
aml_integer(uint64_t *pos, uint64_t end, uint64_t *value)
{
    uint64_t p = *pos;
    if (p >= end) return 0;
    uint8_t op = phys_read8(p++);
    if (op == 0x00 || op == 0x01 || op == 0xff) {
        *value = op == 0xff ? ~(uint64_t)0 : op;
        *pos = p;
        return 1;
    }
    uint32_t n = op == 0x0a ? 1 : op == 0x0b ? 2 :
                 op == 0x0c ? 4 : op == 0x0e ? 8 : 0;
    if (!n || p + n > end) return 0;
    uint64_t v = 0;
    for (uint32_t i = 0; i < n; i++) v |= (uint64_t)phys_read8(p + i) << (i * 8);
    *value = v;
    *pos = p + n;
    return 1;
}

static int
aml_pkglen(uint64_t *pos, uint64_t end, uint32_t *length)
{
    uint64_t p = *pos;
    if (p >= end) return 0;
    uint8_t lead = phys_read8(p++);
    uint32_t follow = lead >> 6;
    uint32_t v = follow ? (lead & 0x0f) : (lead & 0x3f);
    if (p + follow > end) return 0;
    for (uint32_t i = 0; i < follow; i++)
        v |= (uint32_t)phys_read8(p++) << (4 + i * 8);
    if (!v) return 0;
    *pos = p;
    *length = v;
    return 1;
}

static int
aml_name_eq(const char a[4], const char b[4])
{
    return a[0] == b[0] && a[1] == b[1] && a[2] == b[2] && a[3] == b[3];
}

static void
scan_dsdt_battery(uint64_t dsdt_phys, uint32_t dsdt_len)
{
    aml_region_t regions[16];
    uint32_t nregions = 0;
    uint64_t begin = dsdt_phys + 36, end = dsdt_phys + dsdt_len;

    for (uint64_t p = begin; p + 8 < end; p++) {
        if (phys_read8(p) != 0x5b || phys_read8(p + 1) != 0x80) continue;
        uint64_t q = p + 2, base, length;
        char name[4];
        if (!aml_nameseg(&q, end, name) || q >= end || phys_read8(q++) != 0 ||
            !aml_integer(&q, end, &base) || !aml_integer(&q, end, &length) ||
            !length || length > 0x100000 || nregions == 16)
            continue;
        for (uint32_t i = 0; i < 4; i++) regions[nregions].name[i] = name[i];
        regions[nregions].base = base;
        regions[nregions].length = (uint32_t)length;
        nregions++;
    }

    uint32_t rate = UINT32_MAX, remaining = UINT32_MAX, full = UINT32_MAX;
    int region_index = -1;
    for (uint64_t p = begin; p + 8 < end; p++) {
        if (phys_read8(p) != 0x5b || phys_read8(p + 1) != 0x81) continue;
        uint64_t pkg = p + 2, q = pkg;
        uint32_t pkg_len;
        if (!aml_pkglen(&q, end, &pkg_len)) continue;
        uint64_t pkg_end = pkg + pkg_len;
        if (pkg_end > end || pkg_end <= q) continue;
        char region_name[4];
        if (!aml_nameseg(&q, pkg_end, region_name) || q >= pkg_end) continue;
        q++;                            /* FieldFlags */
        int ri = -1;
        for (uint32_t i = 0; i < nregions; i++)
            if (aml_name_eq(region_name, regions[i].name)) { ri = (int)i; break; }
        if (ri < 0) continue;

        uint64_t bit = 0;
        while (q < pkg_end) {
            uint8_t op = phys_read8(q);
            if (op == 0x00) {           /* ReservedField */
                uint32_t bits; q++;
                if (!aml_pkglen(&q, pkg_end, &bits)) break;
                bit += bits;
            } else if (op == 0x01) {    /* AccessField */
                if (q + 3 > pkg_end) break;
                q += 3;
            } else if (op == 0x03) {    /* ExtendedAccessField */
                if (q + 4 > pkg_end) break;
                q += 4;
            } else {
                char field[4]; uint32_t bits;
                if (!aml_nameseg(&q, pkg_end, field) ||
                    !aml_pkglen(&q, pkg_end, &bits)) break;
                if ((bit & 7) == 0 && bits >= 16) {
                    uint32_t off = (uint32_t)(bit >> 3);
                    if (aml_name_eq(field, "SBAC")) rate = off;
                    if (aml_name_eq(field, "SBRC")) remaining = off;
                    if (aml_name_eq(field, "SBFC")) full = off;
                    if (rate != UINT32_MAX && remaining != UINT32_MAX &&
                        full != UINT32_MAX) region_index = ri;
                }
                bit += bits;
            }
        }
        if (region_index >= 0) break;
    }

    if (region_index >= 0) {
        aml_region_t *r = &regions[region_index];
        uint32_t max = rate > remaining ? rate : remaining;
        if (full > max) max = full;
        if (max + 2 <= r->length) {
            s_battery_mmio.phys = r->base;
            s_battery_mmio.length = r->length;
            s_battery_mmio.rate_off = rate;
            s_battery_mmio.remaining_off = remaining;
            s_battery_mmio.full_off = full;
            s_battery_mmio_ok = 1;
        }
    }
}

int
acpi_get_battery_mmio(acpi_battery_mmio_t *out)
{
    if (!out || !s_battery_mmio_ok) return 0;
    *out = s_battery_mmio;
    return 1;
}

/* ── FADT + DSDT parsing for power management ──────────────────────── */

static void
scan_dsdt_s5(uint64_t dsdt_phys)
{
    uint32_t dsdt_len = phys_read32(dsdt_phys + 4);
    if (dsdt_len < 40 || dsdt_len > 0x100000)
        return;  /* sanity */

    /* Scan DSDT bytecode (skip 36-byte SDT header) for "_S5_" */
    uint64_t p   = dsdt_phys + 36;
    uint64_t end = dsdt_phys + dsdt_len;

    while (p < end - 4) {
        uint8_t b0 = phys_read8(p);
        if (b0 == '_') {
            uint8_t b1 = phys_read8(p+1);
            uint8_t b2 = phys_read8(p+2);
            uint8_t b3 = phys_read8(p+3);
            if (b1 == 'S' && b2 == '5' && b3 == '_') {
                /* Validate: preceding byte should be NameOp (0x08) */
                uint8_t prev = (p > dsdt_phys + 36) ? phys_read8(p-1) : 0;
                uint8_t prev2 = (p > dsdt_phys + 37) ? phys_read8(p-2) : 0;
                if (prev == 0x08 || (prev2 == 0x08 && prev == 0x5C)) {
                    p += 4;  /* skip "_S5_" */
                    if (phys_read8(p) == 0x12) {  /* PackageOp */
                        p++;
                        uint8_t pkg_lead = phys_read8(p);
                        p += (uint64_t)(pkg_lead >> 6) + 1;  /* skip PkgLength */
                        p++;  /* skip NumElements */
                        /* Read SLP_TYPa */
                        uint8_t op = phys_read8(p);
                        if (op == 0x0A) { p++; s_slp_typa = phys_read8(p); }
                        else if (op <= 0x01) { s_slp_typa = op; }
                        p++;
                        /* Read SLP_TYPb */
                        op = phys_read8(p);
                        if (op == 0x0A) { p++; s_slp_typb = phys_read8(p); }
                        else if (op <= 0x01) { s_slp_typb = op; }
                    }
                    return;
                }
            }
        }
        p++;
    }
}

static void
parse_fadt(uint64_t hdr_phys)
{
    uint32_t length = phys_read32(hdr_phys + 4);
    if (length < 116)
        return;  /* too short for fields we need */

    /* FADT fields (32-bit I/O port addresses) */
    s_sci_int     = (uint16_t)phys_read32(hdr_phys + 46);
    s_smi_cmd     = phys_read32(hdr_phys + 48);
    s_acpi_enable = phys_read8(hdr_phys + 52);
    s_pm1a_evt    = phys_read32(hdr_phys + 56);
    s_pm1b_cnt    = phys_read32(hdr_phys + 68);  /* 0 if absent */
    s_pm1a_cnt    = phys_read32(hdr_phys + 64);
    s_pm1_evt_len = phys_read8(hdr_phys + 88);

    /* Modern FADTs (notably Hyper-V Gen 2) leave the legacy 32-bit PM1 block
     * fields zero and populate only the 64-bit extended (GAS) fields.  Fall
     * back to those — the address sits 4 bytes into each 12-byte GAS struct.
     * Without this, ACPI power-off writes to I/O port 0 and the VM never dies. */
    if (s_pm1a_cnt == 0 && length >= 184)
        s_pm1a_cnt = (uint32_t)phys_read64(hdr_phys + 172 + 4);  /* X_PM1a_CNT_BLK */
    if (s_pm1a_evt == 0 && length >= 160)
        s_pm1a_evt = (uint32_t)phys_read64(hdr_phys + 148 + 4);  /* X_PM1a_EVT_BLK */
    if (s_pm1b_cnt == 0 && length >= 196)
        s_pm1b_cnt = (uint32_t)phys_read64(hdr_phys + 184 + 4);  /* X_PM1b_CNT_BLK */
    /* ACPI mode transition is deferred to acpi_power_button_init() —
     * must happen AFTER IOAPIC + SCI handler are installed. */

    /* DSDT pointer */
    uint64_t dsdt_phys = 0;
    uint8_t fadt_rev = phys_read8(hdr_phys + 8);
    if (fadt_rev >= 2 && length >= 148) {
        /* Try 64-bit X_DSDT at offset 140 */
        dsdt_phys = phys_read64(hdr_phys + 140);
    }
    if (dsdt_phys == 0) {
        /* Fall back to 32-bit DSDT at offset 40 */
        dsdt_phys = (uint64_t)phys_read32(hdr_phys + 40);
    }

    if (dsdt_phys != 0)
        scan_dsdt_s5(dsdt_phys);
    if (dsdt_phys != 0) {
        uint32_t dsdt_len = phys_read32(dsdt_phys + 4);
        if (dsdt_len >= 40 && dsdt_len <= 0x100000 &&
            acpi_checksum_phys(dsdt_phys, dsdt_len))
            scan_dsdt_battery(dsdt_phys, dsdt_len);
    }

    if (s_pm1a_evt != 0 && s_pm1a_cnt != 0) {
        s_acpi_pm_ok = 1;
    }
}

static void parse_mcfg(uint64_t hdr_phys)
{
    uint32_t length = phys_read32(hdr_phys + 4);
    /* MCFG header is acpi_sdt_header_t (36 bytes) + 8-byte reserved = 44
     * bytes before the first allocation entry. */
    uint64_t p   = hdr_phys + sizeof(acpi_mcfg_t);
    uint64_t end = hdr_phys + length;

    while (p + sizeof(acpi_mcfg_alloc_t) <= end) {
        uint64_t base    = phys_read64(p + 0);
        uint16_t segment = (uint16_t)phys_read32(p + 8);   /* only 16 bits */
        uint8_t  sbus    = phys_read8(p + 10);
        uint8_t  ebus    = phys_read8(p + 11);

        if (segment == 0 && g_mcfg_base == 0) {
            g_mcfg_base      = base;
            g_mcfg_start_bus = sbus;
            g_mcfg_end_bus   = ebus;
        }
        p += sizeof(acpi_mcfg_alloc_t);
    }
}

/* ── MADT parsing ─────────────────────────────────────────────────── */

static void
parse_madt(uint64_t hdr_phys)
{
    uint32_t length = phys_read32(hdr_phys + 4);
    if (length < 44)
        return;  /* too short for MADT header */

    /* Variable-length entries start at offset 44 */
    uint64_t p   = hdr_phys + 44;
    uint64_t end = hdr_phys + length;

    while (p + 2 <= end) {
        uint8_t type = phys_read8(p);
        uint8_t elen = phys_read8(p + 1);
        if (elen < 2 || p + elen > end)
            break;

        if (type == 0 && elen >= 8) {
            /* Processor Local APIC */
            uint8_t apic_id = phys_read8(p + 3);
            uint32_t flags  = phys_read32(p + 4);
            if (g_smp_cpu_count < SMP_MAX_CPUS) {
                g_smp_cpus[g_smp_cpu_count].apic_id = apic_id;
                g_smp_cpus[g_smp_cpu_count].enabled  = (flags & 1) ? 1 : 0;
                g_smp_cpu_count++;
            }
        } else if (type == 1 && elen >= 12) {
            /* I/O APIC — take the first one */
            if (g_ioapic_addr == 0) {
                g_ioapic_addr     = (uint64_t)phys_read32(p + 4);
                g_ioapic_gsi_base = phys_read32(p + 8);
            }
        } else if (type == 2 && elen >= 10) {
            /* Interrupt Source Override */
            if (g_madt_iso_count < MADT_MAX_ISO) {
                g_madt_iso[g_madt_iso_count].bus        = phys_read8(p + 2);
                g_madt_iso[g_madt_iso_count].source_irq = phys_read8(p + 3);
                g_madt_iso[g_madt_iso_count].gsi        = phys_read32(p + 4);
                g_madt_iso[g_madt_iso_count].flags      = (uint16_t)phys_read32(p + 8);
                g_madt_iso_count++;
            }
        }

        p += elen;
    }
}

/* AMD IOMMU (AMD-Vi) — if the firmware left it enabled and TRANSLATING, every
 * device DMA faults because Aegis has no IOMMU driver / device tables, so the
 * AX200 firmware asserts HW_ERR and xHCI RX never completes. We have no use for
 * DMA remapping, so disable translation (clear IommuEn) → all DMA is untranslated
 * (identity), which is what every driver assumes. Inert on Intel / VMs (no IVRS).
 *
 * The IOMMU MMIO base is in each IVHD block of the IVRS table (offset +8); the
 * MMIO Control Register is at base+0x18 and bit 0 is IommuEn. IVRS layout: a
 * 48-byte header, then a chain of IVHD blocks {type[7:0], flags[15:8], len[31:16]}. */
#define AMD_IOMMU_CTRL_OFF   0x18u
#define AMD_IOMMU_CTRL_EN    0x1u          /* IommuEn (bit 0 of the control reg) */

static void amd_iommu_disable(uint64_t ivrs_phys, uint32_t ivrs_len)
{
    uint64_t off = 48;                     /* skip the IVRS header */
    int disabled = 0, seen = 0;

    while (off + 24 <= (uint64_t)ivrs_len) {
        uint32_t hdr  = phys_read32(ivrs_phys + off);
        uint8_t  type = (uint8_t)(hdr & 0xFFu);
        uint16_t len  = (uint16_t)(hdr >> 16);
        if (len < 24)
            break;                         /* malformed — stop walking */
        /* IVHD types that carry an IOMMU MMIO base at +8. */
        if (type == 0x10u || type == 0x11u || type == 0x40u) {
            uint64_t base = (uint64_t)phys_read32(ivrs_phys + off + 8) |
                            ((uint64_t)phys_read32(ivrs_phys + off + 12) << 32);
            if (base >= 0x1000u && (base & 0xFFFu) == 0u) {
                seen++;
                volatile uint8_t *mmio =
                    (volatile uint8_t *)kva_map_mmio(base, 1);
                if (mmio) {
                    volatile uint32_t *ctrl =
                        (volatile uint32_t *)(mmio + AMD_IOMMU_CTRL_OFF);
                    uint32_t v = *ctrl;
                    if (v & AMD_IOMMU_CTRL_EN) {
                        *ctrl = v & ~AMD_IOMMU_CTRL_EN;   /* clear IommuEn */
                        disabled++;
                    }
                }
            }
        }
        off += len;
    }
    if (seen)
        printk("[IOMMU] AMD-Vi: %d/%d unit(s) disabled (DMA now untranslated)\n",
               disabled, seen);
}

static void scan_table(uint64_t phys)
{
    char sig[4];
    uint32_t length;

    if (phys == 0)
        return;

    /* Read signature (4 bytes) */
    phys_read_bytes(phys, sig, 4);

    /* Read length field at offset 4 */
    length = phys_read32(phys + 4);
    if (length < 36 || length > 65536)
        return;   /* sanity check */

    if (!acpi_checksum_phys(phys, length))
        return;

    if (__builtin_memcmp(sig, "MCFG", 4) == 0)
        parse_mcfg(phys);
    else if (__builtin_memcmp(sig, "APIC", 4) == 0) {
        g_madt_found = 1;
        parse_madt(phys);
    }
    else if (__builtin_memcmp(sig, "FACP", 4) == 0)
        parse_fadt(phys);
    else if (__builtin_memcmp(sig, "IVRS", 4) == 0)
        amd_iommu_disable(phys, length);
}

void acpi_init(void)
{
    uint64_t rsdp_phys = arch_get_rsdp_phys();

    if (rsdp_phys == 0) {
        printk("[ACPI] OK: MADT parsed, 0 CPUs, no MCFG (legacy machine)\n");
        return;
    }

    /* Map the RSDP page as the reusable physical-read window. Subsequent table
     * reads remap this VA, so no disposable PMM backing page is needed. */
    s_win_va = kva_map_phys_pages(rsdp_phys & ~0xFFFULL, 1);
    if (!s_win_va) {
        printk("[ACPI] FAIL: out of memory for table window\n");
        return;
    }
    s_win_phys = rsdp_phys & ~0xFFFULL;

    {
        char rsdp_sig[8];
        uint8_t  rsdp_rev;
        uint32_t xsdt_lo, xsdt_hi;
        uint64_t xsdt_phys;
        uint32_t rsdt_phys32;

        phys_read_bytes(rsdp_phys, rsdp_sig, 8);
        if (__builtin_memcmp(rsdp_sig, "RSD PTR ", 8) != 0) {
            printk("[ACPI] FAIL: invalid RSDP signature\n");
            return;
        }

        rsdp_rev = phys_read8(rsdp_phys + 15);   /* revision field */

        if (rsdp_rev >= 2) {
            /* ACPI 2.0+: XSDT address at offset 24 (8 bytes) */
            xsdt_lo  = phys_read32(rsdp_phys + 24);
            xsdt_hi  = phys_read32(rsdp_phys + 28);
            xsdt_phys = ((uint64_t)xsdt_hi << 32) | xsdt_lo;

            if (xsdt_phys != 0) {
                uint32_t xsdt_len = phys_read32(xsdt_phys + 4);
                uint32_t count    = 0;
                uint64_t ep;

                if (xsdt_len >= 36)
                    count = (xsdt_len - 36) / 8;

                ep = xsdt_phys + 36;   /* entries start after SDT header */
                {
                    uint32_t i;
                    for (i = 0; i < count; i++) {
                        uint64_t entry = phys_read64(ep);
                        scan_table(entry);
                        ep += 8;
                    }
                }
            }
        } else {
            /* ACPI 1.0: RSDT address at offset 16 (4 bytes) */
            rsdt_phys32 = phys_read32(rsdp_phys + 16);

            if (rsdt_phys32 != 0) {
                uint64_t rsdt_phys = (uint64_t)rsdt_phys32;
                uint32_t rsdt_len  = phys_read32(rsdt_phys + 4);
                uint32_t count     = 0;
                uint64_t ep;

                if (rsdt_len >= 36)
                    count = (rsdt_len - 36) / 4;

                ep = rsdt_phys + 36;
                {
                    uint32_t i;
                    for (i = 0; i < count; i++) {
                        uint64_t entry = (uint64_t)phys_read32(ep);
                        scan_table(entry);
                        ep += 4;
                    }
                }
            }
        }
    }

    /* Detect BSP APIC ID via CPUID leaf 1 (EBX[31:24]) */
    {
        uint32_t eax, ebx, ecx, edx;
        __asm__ volatile("cpuid"
                         : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
                         : "a"(1));
        g_bsp_apic_id = (uint8_t)(ebx >> 24);
    }

    if (g_mcfg_base != 0)
        printk("[ACPI] OK: MCFG+MADT parsed, %u CPUs\n",
               (unsigned)g_smp_cpu_count);
    else
        printk("[ACPI] OK: MADT parsed, %u CPUs, no MCFG (legacy machine)\n",
               (unsigned)g_smp_cpu_count);

    /* Enable power button SCI if FADT was found */
    if (s_acpi_pm_ok)
        acpi_power_button_init();
}

/* ── ACPI power button ─────────────────────────────────────────────── */
/* Port I/O via outb/inb/outw/inw from arch.h (no local wrappers). */

void
acpi_power_button_init(void)
{
    if (!s_acpi_pm_ok || s_pm1a_evt == 0)
        return;

    /* Transition from legacy to ACPI mode if SCI_EN is not already set.
     * On UEFI systems SCI_EN is always 1 (firmware boots in ACPI mode),
     * so this is a no-op on UEFI. Only runs on legacy BIOS boot. */
    if (s_smi_cmd != 0 && s_acpi_enable != 0 && s_pm1a_cnt != 0) {
        uint16_t pm1_cnt = inw((uint16_t)s_pm1a_cnt);
        if (!(pm1_cnt & 1)) {  /* SCI_EN not set → legacy mode */
            printk("[ACPI] transitioning to ACPI mode (SMI_CMD=0x%x, val=0x%x)\n",
                   (unsigned)s_smi_cmd, (unsigned)s_acpi_enable);
            outb((uint16_t)s_smi_cmd, s_acpi_enable);
            for (int i = 0; i < 3000; i++) {
                pm1_cnt = inw((uint16_t)s_pm1a_cnt);
                if (pm1_cnt & 1) break;
                (void)inb(0x80);
            }
            if (pm1_cnt & 1)
                printk("[ACPI] ACPI mode enabled (SCI_EN set)\n");
            else
                printk("[ACPI] WARN: ACPI mode transition failed\n");
        }
    }

    uint16_t evt_base = (uint16_t)s_pm1a_evt;
    uint16_t en_off   = (uint16_t)(s_pm1_evt_len / 2);  /* PM1_EN offset */

    /* Disable ALL PM1 event enables first to prevent spurious SCI */
    outw(evt_base + en_off, 0x0000);

    /* Clear ALL pending PM1 status bits (write-1-to-clear) */
    outw(evt_base, 0xFFFF);

    /* Small delay for hardware to settle */
    for (int i = 0; i < 100; i++)
        (void)inb(0x80);

    /* Clear again — some chipsets latch status between clear and enable */
    outw(evt_base, 0xFFFF);

    /* Now enable ONLY the power button event */
    outw(evt_base + en_off, 0x0100);  /* PWRBTN_EN = bit 8 */

    /* Clear one more time after enable — catches any edge-triggered latch */
    outw(evt_base, 0x0100);

    /* Unmask the SCI IRQ in the PIC (IOAPIC already routes it if present) */
    if (s_sci_int < 16)
        pic_unmask((uint8_t)s_sci_int);

    printk("[ACPI] OK: power button enabled (SCI IRQ %u, PM1a=0x%x)\n",
           (unsigned)s_sci_int, (unsigned)s_pm1a_evt);
}

/* Initiate ACPI S5 power off from any context (userspace syscall or SCI). */
void
acpi_do_poweroff(void)
{
    if (!s_acpi_pm_ok)
        return;

    printk("[ACPI] initiating S5 power off\n");
    g_rootfs->sync();
    printk("[AEGIS] System halted.\n");

    uint16_t cnt = (uint16_t)s_pm1a_cnt;
    uint16_t val = (s_slp_typa << 10) | (1 << 13);
    outw(cnt, val);
    if (s_pm1b_cnt != 0) {
        uint16_t val_b = (s_slp_typb << 10) | (1 << 13);
        outw((uint16_t)s_pm1b_cnt, val_b);
    }
    for (;;)
        __asm__ volatile ("cli; hlt");
}

void
acpi_sci_handler(void)
{
    if (!s_acpi_pm_ok)
        return;

    uint16_t evt_base = (uint16_t)s_pm1a_evt;
    uint16_t en_off   = (uint16_t)(s_pm1_evt_len / 2);
    uint16_t sts = inw(evt_base);
    uint16_t en  = inw(evt_base + en_off);
    printk("[SCIDBG] sci sts=%x en=%x\n", (unsigned)sts, (unsigned)en);

    if ((sts & 0x0100) && (en & 0x0100)) {
        /* Power button pressed — signal init for graceful shutdown */
        outw(evt_base, 0x0100);  /* clear PWRBTN_STS */
        printk("[ACPI] power button pressed — sending SIGTERM to init\n");
        signal_send_pid(1, 15);  /* SIGTERM to PID 1 (vigil) */
    }
    /* Not a power button event — spurious or other ACPI event, ignore */
}

uint16_t
acpi_get_sci_irq(void)
{
    return s_sci_int;
}
