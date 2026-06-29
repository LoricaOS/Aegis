/*
 * ioapic.c — I/O APIC driver for x86-64 SMP interrupt routing
 *
 * Maps the I/O APIC MMIO page into kernel VA and programs the 24-entry
 * redirection table. Disables the legacy 8259A PIC when the I/O APIC is
 * available. If no I/O APIC address was found in the MADT, init is a no-op
 * and the system continues using the PIC.
 */

#include "ioapic.h"
#include "lapic.h"
#include "acpi.h"
#include "arch.h"
#include "vmm.h"
#include "kva.h"
#include "printk.h"

#include <stdint.h>

/* I/O APIC indirect register access: write index to IOREGSEL (offset 0x00),
 * then read/write data via IOWIN (offset 0x10). */
#define IOREGSEL    0x00
#define IOWIN       0x10

/* I/O APIC registers */
#define IOAPIC_ID       0x00
#define IOAPIC_VER      0x01
#define IOAPIC_REDTBL   0x10

/* Redirection entry bits (low 32 bits) */
#define REDIR_MASK_BIT      (1u << 16)
#define REDIR_LEVEL_TRIG    (1u << 15)
#define REDIR_ACTIVE_LOW    (1u << 13)

/* 8259A PIC ports (for disabling) */
#define PIC1_CMD    0x20
#define PIC1_DATA   0x21
#define PIC2_CMD    0xA0
#define PIC2_DATA   0xA1
#define ICW1_INIT   0x11
#define ICW4_8086   0x01

static volatile uint32_t *s_ioapic_base; /* kernel VA of I/O APIC MMIO page */
static int                s_active;      /* 1 after successful init */
static uint32_t           s_max_redir;   /* max redirection entry index */

/* --------------------------------------------------------------------------
 * MMIO helpers — indirect register access via IOREGSEL/IOWIN
 * -------------------------------------------------------------------------- */

static inline uint32_t
ioapic_read(uint32_t reg)
{
    s_ioapic_base[IOREGSEL / 4] = reg;
    return s_ioapic_base[IOWIN / 4];
}

static inline void
ioapic_write(uint32_t reg, uint32_t val)
{
    s_ioapic_base[IOREGSEL / 4] = reg;
    s_ioapic_base[IOWIN / 4] = val;
}

/* --------------------------------------------------------------------------
 * PIC disable — remap to vectors 0xF0-0xFF and mask all lines
 * -------------------------------------------------------------------------- */

static void
io_wait(void)
{
    outb(0x80, 0);
}

static void
pic_disable(void)
{
    /* Reinitialize the 8259A PICs with vectors in the 0xF0-0xFF range
     * (well above the IDT vectors we use), then mask everything. */
    outb(PIC1_CMD,  ICW1_INIT); io_wait();
    outb(PIC2_CMD,  ICW1_INIT); io_wait();
    outb(PIC1_DATA, 0xF0);     io_wait();  /* master: IRQ0-7 → 0xF0-0xF7 */
    outb(PIC2_DATA, 0xF8);     io_wait();  /* slave:  IRQ8-15 → 0xF8-0xFF */
    outb(PIC1_DATA, 0x04);     io_wait();  /* master: slave on IRQ2 */
    outb(PIC2_DATA, 0x02);     io_wait();  /* slave: cascade identity = 2 */
    outb(PIC1_DATA, ICW4_8086); io_wait();
    outb(PIC2_DATA, ICW4_8086); io_wait();
    outb(PIC1_DATA, 0xFF);                 /* mask all master */
    outb(PIC2_DATA, 0xFF);                 /* mask all slave */
}

/* --------------------------------------------------------------------------
 * ISO lookup — find MADT Interrupt Source Override for a given ISA IRQ
 * -------------------------------------------------------------------------- */

static const madt_iso_t *
find_iso(uint8_t source_irq)
{
    for (uint32_t i = 0; i < g_madt_iso_count; i++) {
        if (g_madt_iso[i].source_irq == source_irq)
            return &g_madt_iso[i];
    }
    return (void *)0;
}

/* --------------------------------------------------------------------------
 * Internal: write a full 64-bit redirection entry
 * -------------------------------------------------------------------------- */

static void
ioapic_write_redir(uint8_t pin, uint32_t low, uint32_t high)
{
    ioapic_write(IOAPIC_REDTBL + pin * 2, low);
    ioapic_write(IOAPIC_REDTBL + pin * 2 + 1, high);
}

/* --------------------------------------------------------------------------
 * Internal: route one IRQ with ISO flag handling
 * -------------------------------------------------------------------------- */

static void
route_irq(uint8_t source_irq, uint8_t vector, uint8_t dest_apic_id)
{
    const madt_iso_t *iso = find_iso(source_irq);
    uint8_t  pin   = iso ? (uint8_t)iso->gsi : source_irq;
    uint16_t flags = iso ? iso->flags : 0;

    uint32_t low  = (uint32_t)vector;  /* delivery=fixed, destmode=physical */
    uint32_t high = (uint32_t)dest_apic_id << 24;

    /* ISO flags: bit 1 = active-low polarity, bit 3 = level-triggered */
    if (flags & 0x02)
        low |= REDIR_ACTIVE_LOW;
    if (flags & 0x08)
        low |= REDIR_LEVEL_TRIG;

    ioapic_write_redir(pin, low, high);
}

/* --------------------------------------------------------------------------
 * Public API
 * -------------------------------------------------------------------------- */

/*
 * ioapic_init — map I/O APIC, disable PIC, program default IRQ routes.
 *
 * If g_ioapic_addr is 0 (no MADT or no I/O APIC entry), skip entirely
 * and let the system continue using the legacy 8259A PIC.
 */
void
ioapic_init(void)
{
    if (g_ioapic_addr == 0)
        return;

    /* Map the I/O APIC MMIO page into kernel VA — same pattern as LAPIC. */
    void *va = kva_alloc_pages(1);
    if (!va) {
        printk("[IOAPIC] FAIL: kva_alloc_pages returned NULL\n");
        return;
    }
    vmm_unmap_page((uintptr_t)va);
    vmm_map_page((uintptr_t)va, g_ioapic_addr,
                 VMM_FLAG_WRITABLE | VMM_FLAG_WC | VMM_FLAG_UCMINUS);

    s_ioapic_base = (volatile uint32_t *)va;

    /* Read version register to get max redirection entry count */
    uint32_t ver = ioapic_read(IOAPIC_VER);
    s_max_redir = (ver >> 16) & 0xFF;

    /* Mask all redirection entries first */
    for (uint32_t pin = 0; pin <= s_max_redir; pin++) {
        ioapic_write_redir((uint8_t)pin,
                           REDIR_MASK_BIT | (0x20 + pin), /* masked, dummy vector */
                           0);
    }

    /* Disable the legacy 8259A PIC */
    pic_disable();

    /* Route standard IRQs to BSP:
     *   PIT     (ISA IRQ 0)  → vector 0x20 (may be remapped to pin 2 by ISO)
     *   KBD     (ISA IRQ 1)  → vector 0x21
     *   PS/2    (ISA IRQ 12) → vector 0x2C
     *   SCI     (from FADT)  → vector for the SCI IRQ
     */
    route_irq(0,  0x20, g_bsp_apic_id);    /* PIT timer */
    route_irq(1,  0x21, g_bsp_apic_id);    /* PS/2 keyboard */
    route_irq(4,  0x24, g_bsp_apic_id);    /* COM1 serial RX */
    route_irq(12, 0x2C, g_bsp_apic_id);    /* PS/2 mouse */

    /* Route ACPI SCI interrupt if known */
    uint16_t sci_irq = acpi_get_sci_irq();
    if (sci_irq > 0 && sci_irq < 16) {
        route_irq((uint8_t)sci_irq, 0x20 + (uint8_t)sci_irq, g_bsp_apic_id);
    }

    s_active = 1;

    printk("[IOAPIC] OK: %u pins, PIC disabled\n", s_max_redir + 1);
}

/*
 * ioapic_route_irq — program a redirection entry for the given pin.
 *
 * pin:          I/O APIC input pin (0-23)
 * vector:       IDT vector to deliver (0x20+)
 * dest_apic_id: LAPIC ID of the target CPU
 * flags:        MADT ISO flags (bit 1 = active-low, bit 3 = level-triggered)
 */
void
ioapic_route_irq(uint8_t pin, uint8_t vector, uint8_t dest_apic_id, uint16_t flags)
{
    if (!s_active || pin > s_max_redir)
        return;

    uint32_t low  = (uint32_t)vector;
    uint32_t high = (uint32_t)dest_apic_id << 24;

    if (flags & 0x02)
        low |= REDIR_ACTIVE_LOW;
    if (flags & 0x08)
        low |= REDIR_LEVEL_TRIG;

    ioapic_write_redir(pin, low, high);
}

/*
 * ioapic_mask — mask a redirection entry (set bit 16 of the low dword).
 */
void
ioapic_mask(uint8_t pin)
{
    if (!s_active || pin > s_max_redir)
        return;

    uint32_t low = ioapic_read(IOAPIC_REDTBL + pin * 2);
    low |= REDIR_MASK_BIT;
    ioapic_write(IOAPIC_REDTBL + pin * 2, low);
}

/*
 * ioapic_unmask — unmask a redirection entry (clear bit 16 of the low dword).
 */
void
ioapic_unmask(uint8_t pin)
{
    if (!s_active || pin > s_max_redir)
        return;

    uint32_t low = ioapic_read(IOAPIC_REDTBL + pin * 2);
    low &= ~REDIR_MASK_BIT;
    ioapic_write(IOAPIC_REDTBL + pin * 2, low);
}

/*
 * ioapic_active — return 1 if I/O APIC has been initialized, 0 otherwise.
 */
int
ioapic_active(void)
{
    return s_active;
}
