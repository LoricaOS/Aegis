#ifndef AEGIS_PIC_H
#define AEGIS_PIC_H

#include <stdint.h>

/* Initialize the 8259A dual PIC.
 * Remaps IRQ0-7 to vectors 0x20-0x27, IRQ8-15 to 0x28-0x2F.
 * Masks all IRQs after remapping (drivers unmask their own IRQ). */
void pic_init(void);

/* Send End-Of-Interrupt to the PIC.
 * For IRQ >= 8, sends EOI to both slave and master. */
void pic_send_eoi(uint8_t irq);

/* Read the PIC In-Service Register to check if the IRQ is real.
 * Per 8259A spec, a spurious IRQ7/IRQ15 must NOT receive EOI.
 * Returns 1 if the IRQ is real (in-service), 0 if spurious. */
int pic_irq_is_real(uint8_t irq);

/* Unmask (enable) a single IRQ line (0-15). */
void pic_unmask(uint8_t irq);

/* Mask (disable) a single IRQ line (0-15). */
void pic_mask(uint8_t irq);

#endif /* AEGIS_PIC_H */
