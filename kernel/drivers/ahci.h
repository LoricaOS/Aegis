/* ahci.h — AHCI (SATA) host controller driver
 *
 * Brings up the first SATA disk on an AHCI controller and registers it as a
 * blkdev ("sata0"), so ext2/GPT use it like NVMe/virtio-blk. AHCI is the
 * default disk controller in VirtualBox, VMware and many QEMU configs
 * (`-device ich9-ahci`), so this closes the main storage gap for VMs.
 */
#ifndef AHCI_H
#define AHCI_H

/* Probe for an AHCI controller (PCI class 01:06:01), bring up the first SATA
 * disk, register it as "sata0". Silent if none found. Called from kernel_main
 * alongside nvme_init / virtio_blk_init. */
void ahci_init(void);

#endif /* AHCI_H */
