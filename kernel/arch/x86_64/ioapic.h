/* ioapic.h — I/O APIC driver for SMP interrupt routing */
#ifndef AEGIS_IOAPIC_H
#define AEGIS_IOAPIC_H

#include <stdint.h>

void ioapic_init(void);
void ioapic_route_irq(uint8_t pin, uint8_t vector, uint8_t dest_apic_id, uint16_t flags);
void ioapic_mask(uint8_t pin);
void ioapic_unmask(uint8_t pin);
int  ioapic_active(void);

#endif
