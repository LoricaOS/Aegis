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

#endif /* AEGIS_RAMDISK_H */
