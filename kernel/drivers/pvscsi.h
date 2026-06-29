/* pvscsi.h — VMware Paravirtual SCSI host adapter (kernel/drivers/pvscsi.c). */
#ifndef PVSCSI_H
#define PVSCSI_H

/* Probe for a PVSCSI controller (PCI 15ad:07c0), bring up the rings, and
 * register the first disk as blkdev "pvscsi0". Silent if not present. */
void pvscsi_init(void);

#endif /* PVSCSI_H */
