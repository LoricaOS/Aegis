/* hv_mouse.h — Hyper-V synthetic mouse (VMBus) → /dev/mouse.
 * Gen 2 has no PS/2 mouse; absolute HID reports are scaled to relative deltas.
 * No-op when not on Hyper-V. */
#ifndef HV_MOUSE_H
#define HV_MOUSE_H

void hv_mouse_init(void);   /* find + open the synthetic mouse channel */
void hv_mouse_poll(void);   /* drain HID input reports (polled) */

#endif /* HV_MOUSE_H */
