/* acpi.h — ACPI table parser for PCIe MCFG and MADT
 *
 * Minimal static parser: no AML, no power management.
 * Finds MCFG (PCIe config space base) and MADT (interrupt routing).
 */
#ifndef ACPI_H
#define ACPI_H

#include <stdint.h>
#include "../../limits.h"

/* ACPI System Description Table header (common to all SDTs) */
typedef struct __attribute__((packed)) {
    char     signature[4];
    uint32_t length;
    uint8_t  revision;
    uint8_t  checksum;
    char     oem_id[6];
    char     oem_table_id[8];
    uint32_t oem_revision;
    uint32_t creator_id;
    uint32_t creator_revision;
} acpi_sdt_header_t;

/* RSDP (Root System Description Pointer) — v1 layout, extended for v2 */
typedef struct __attribute__((packed)) {
    char     signature[8];    /* "RSD PTR " */
    uint8_t  checksum;
    char     oem_id[6];
    uint8_t  revision;        /* 0 = ACPI 1.0, 2 = ACPI 2.0+ */
    uint32_t rsdt_address;    /* physical address of RSDT (32-bit) */
    /* ACPI 2.0+ fields follow if revision >= 2: */
    uint32_t length;
    uint64_t xsdt_address;    /* physical address of XSDT (64-bit) */
    uint8_t  extended_checksum;
    uint8_t  reserved[3];
} acpi_rsdp_t;

/* MCFG table: PCIe MMIO config space allocation */
typedef struct __attribute__((packed)) {
    acpi_sdt_header_t header;
    uint64_t          reserved;
    /* Followed by one or more acpi_mcfg_alloc_t entries */
} acpi_mcfg_t;

typedef struct __attribute__((packed)) {
    uint64_t base_address;    /* MMIO base of PCIe config space */
    uint16_t segment;         /* PCI segment group (0 for most systems) */
    uint8_t  start_bus;
    uint8_t  end_bus;
    uint32_t reserved;
} acpi_mcfg_alloc_t;

/* MADT table: interrupt controller descriptions */
typedef struct __attribute__((packed)) {
    acpi_sdt_header_t header;
    uint32_t          local_apic_address;
    uint32_t          flags;
    /* Followed by variable-length MADT entries */
} acpi_madt_t;

/* Parsed ACPI state — available after acpi_init() */
extern uint64_t g_mcfg_base;     /* PCIe MMIO config space base, 0 if absent */
extern uint8_t  g_mcfg_start_bus;
extern uint8_t  g_mcfg_end_bus;
extern int      g_madt_found;    /* 1 if MADT was located */

/* SMP CPU info parsed from MADT.
 * Legacy alias — value single-sourced in limits.h (AEGIS_MAX_CPUS). */
#define SMP_MAX_CPUS AEGIS_MAX_CPUS

typedef struct {
    uint8_t apic_id;
    uint8_t enabled;
} smp_cpu_t;

extern smp_cpu_t  g_smp_cpus[SMP_MAX_CPUS];
extern uint32_t   g_smp_cpu_count;
extern uint8_t    g_bsp_apic_id;

/* I/O APIC info from MADT */
extern uint64_t   g_ioapic_addr;
extern uint32_t   g_ioapic_gsi_base;

/* Interrupt Source Overrides from MADT */
#define MADT_MAX_ISO 16
typedef struct {
    uint8_t  bus;
    uint8_t  source_irq;
    uint32_t gsi;
    uint16_t flags;
} madt_iso_t;

extern madt_iso_t g_madt_iso[MADT_MAX_ISO];
extern uint32_t   g_madt_iso_count;

/* Initialize ACPI: parse RSDP -> RSDT/XSDT -> find MCFG + MADT + FADT.
 * Enables power button SCI if FADT is found.
 * Prints [ACPI] OK or FAIL to serial. */
void acpi_init(void);

/* acpi_power_button_init — enable SCI for power button events.
 * Called automatically from acpi_init if FADT is present. */
void acpi_power_button_init(void);

/* acpi_sci_handler — handle SCI interrupt (called from isr_dispatch).
 * Checks for power button press; if so, syncs ext2 and powers off. */
void acpi_sci_handler(void);

/* acpi_get_sci_irq — return SCI IRQ number (from FADT), 0 if unknown. */
uint16_t acpi_get_sci_irq(void);

/* acpi_do_poweroff — sync ext2 and enter ACPI S5 (power off). */
void acpi_do_poweroff(void);

#endif /* ACPI_H */
