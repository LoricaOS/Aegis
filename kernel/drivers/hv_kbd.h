/* hv_kbd.h — Hyper-V synthetic keyboard (VMBus).
 *
 * Generation 2 Hyper-V VMs have no i8042/PS-2 controller, so keyboard input for
 * the console + GUI greeter arrives over a VMBus channel instead.  The host
 * sends PS/2 Scan Code Set 1 make/break codes, which we funnel into the same
 * kbd.c translation path as the PS/2 ISR (kbd_feed_scancode).
 */
#ifndef HV_KBD_H
#define HV_KBD_H

/* Find + open the synthetic keyboard channel and negotiate the protocol.
 * No-op (silent) when not on Hyper-V or no keyboard channel is offered. */
void hv_kbd_init(void);

/* Drain pending keystroke events from the channel and inject them into the
 * shared input ring.  Called every tick from timer_bsp_tick (no-op until ready);
 * Gen 2 has no IRQ for this, so like everything else on Hyper-V it is polled. */
void hv_kbd_poll(void);

#endif /* HV_KBD_H */
