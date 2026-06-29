/* rtl8139.h — RealTek RTL8139 Fast Ethernet (QEMU/VirtualBox legacy NIC)
 *
 * The classic RTL8139: a single flat circular receive buffer (not a descriptor
 * ring) + four transmit descriptors. MMIO (BAR1), polled. Registers on netdev_t.
 * Covers the common legacy emulated NIC in QEMU (`-device rtl8139`) and older
 * VirtualBox defaults.
 */
#ifndef RTL8139_H
#define RTL8139_H

/* Scan PCI for an RTL8139 (10EC:8139), bring it up, register it as "eth0".
 * Silent if none found. Called from kernel_main after the other NIC probes. */
void rtl8139_init(void);

#endif /* RTL8139_H */
