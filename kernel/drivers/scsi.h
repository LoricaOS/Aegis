/* scsi.h — SCSI CDB operation codes shared by the SCSI-speaking block drivers
 * (virtio_scsi, pvscsi, storvsc). These are fixed wire-protocol values; keeping
 * one copy stops the per-driver lists from drifting (storvsc once carried an
 * INQUIRY define the others lacked).
 *
 * ponytail: opcodes only. The READ(10)/WRITE(10) CDB-build block is near-
 * identical across drivers but writes into each driver's own buffer/zeroing
 * convention — not unified until there's bare-metal SCSI coverage to verify it.
 */
#ifndef KERNEL_DRIVERS_SCSI_H
#define KERNEL_DRIVERS_SCSI_H

#define SCSI_TEST_UNIT_READY 0x00u
#define SCSI_INQUIRY         0x12u
#define SCSI_READ_CAPACITY10 0x25u
#define SCSI_READ10          0x28u
#define SCSI_WRITE10         0x2Au

#endif /* KERNEL_DRIVERS_SCSI_H */
