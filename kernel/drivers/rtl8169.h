/* rtl8169.h — Realtek RTL8168/8169 PCIe gigabit Ethernet driver
 *
 * Polling-mode driver for the RTL8168/8169 family. Reads MAC from
 * eFuse, sets up 256-entry RX/TX descriptor rings, and registers an
 * eth0 netdev_t. Drained at 100Hz from netdev_poll_all() (PIT ISR).
 */
#ifndef RTL8169_H
#define RTL8169_H

void rtl8169_init(void);

#endif /* RTL8169_H */
