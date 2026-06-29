/* e1000.h — Intel 8254x / 82540 Gigabit Ethernet (QEMU default "e1000")
 *
 * Legacy descriptor, MMIO, polled (no MSI). Registers on netdev_t as the virtio
 * and RTL drivers do. The single most common emulated NIC across QEMU (default),
 * VirtualBox and VMware, so this covers the majority of non-virtio VM configs.
 */
#ifndef E1000_H
#define E1000_H

/* Scan PCI for a supported Intel 8254x NIC, bring it up, register it as "eth0".
 * Silent (no printk) if none found. Called from kernel_main after the virtio /
 * RTL NIC probes. */
void e1000_init(void);

#endif /* E1000_H */
