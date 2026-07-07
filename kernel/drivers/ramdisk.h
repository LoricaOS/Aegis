#ifndef AEGIS_RAMDISK_H
#define AEGIS_RAMDISK_H

#include <stdint.h>

/* ramdisk_init — create a RAM-backed blkdev from a physical memory region.
 * Maps phys_base..phys_base+size into KVA, registers as blkdev "ramdisk0".
 * Called from kernel_main after kva_init. If phys_base is 0 (no module),
 * silently returns without registering anything. */
void ramdisk_init(uint64_t phys_base, uint64_t size);

/* ramdisk_init2 — same as ramdisk_init but registers as "ramdisk1".
 * Used for the second GRUB module (ESP image for installer). */
void ramdisk_init2(uint64_t phys_base, uint64_t size);

/* Hand back ramdisk0's raw KVA bytes (a boot module a driver wants to read
 * directly, e.g. firmware). Returns 0 and fills out+size, or -1 if absent. */
int ramdisk_get_blob(const uint8_t **out, uint64_t *size);

/* ramdisk_init_fw — copy the third module (iwlwifi firmware) into KVA as a raw
 * blob (not a blkdev). ramdisk_get_fw_blob hands it back (0 ok, -1 absent). */
void ramdisk_init_fw(uint64_t phys_base, uint64_t size);
int  ramdisk_get_fw_blob(const uint8_t **out, uint64_t *size);

#endif /* AEGIS_RAMDISK_H */
