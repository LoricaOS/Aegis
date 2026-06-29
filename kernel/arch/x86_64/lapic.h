/* lapic.h — Local APIC driver for x86-64 SMP */
#ifndef AEGIS_LAPIC_H
#define AEGIS_LAPIC_H

#include <stdint.h>

void     lapic_init(void);
void     lapic_init_ap(void);
uint8_t  lapic_id(void);
void     lapic_eoi(void);
void     lapic_send_ipi(uint8_t dest_apic_id, uint8_t vector);
void     lapic_send_ipi_all_excl_self(uint8_t vector);
void     lapic_send_init(uint8_t dest_apic_id);
void     lapic_send_sipi(uint8_t dest_apic_id, uint8_t vector);
int      lapic_active(void);
void     lapic_timer_init(void);
void     lapic_timer_handler(void);

#endif
