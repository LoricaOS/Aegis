/* usb_stub.c — compiled only when CONFIG_USB is off (see Makefile).
 *
 * The per-tick poll loop (poll_sources.c), the PS/2 keyboard path (kbd.c), and
 * /proc (procfs.c) reference the xHCI host surface. With no USB stack these are
 * inert: no host, nothing to poll, empty diagnostics. */
#include <stdint.h>
#include "xhci.h"
#include "usb_mouse.h"   /* the shared mouse interface lives in usb_mouse.c */
#include "waitq.h"

void xhci_init(void) {}
void xhci_poll(void) {}
void xhci_usbnet_diag(xhci_usbnet_diag_t *out) { if (out) *out = (xhci_usbnet_diag_t){0}; }
void xhci_host_diag(xhci_host_diag_t *out)     { if (out) *out = (xhci_host_diag_t){0}; }

/* g_mouse_waiters + the mouse event interface are defined in usb_mouse.c but are
 * shared by every mouse source (PS/2, virtio, hv). With USB off and no mouse in
 * a headless build, the queue exists but never has data. */
waitq_t g_mouse_waiters = WAITQ_INIT;
int  mouse_poll(mouse_event_t *out) { (void)out; return 0; }
int  mouse_has_data(void) { return 0; }
void mouse_inject_scroll(uint8_t buttons, int16_t dx, int16_t dy, int16_t scroll)
     { (void)buttons; (void)dx; (void)dy; (void)scroll; }
