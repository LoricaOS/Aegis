#ifndef GPT_H
#define GPT_H

#include <stdint.h>

/* gpt_scan — scan the GPT on blkdev `devname` and register each valid
 * partition as a child blkdev named "<devname>p<N>" (e.g. "nvme0p1").
 *
 * Returns 0 silently when no blkdev named devname exists (consistent
 * with nvme_init, pcie_init, xhci_init behavior on absent hardware).
 *
 * Prints [GPT] OK: <n> partition(s) found on <devname>
 *     or [GPT] WARN: <reason> on failure after the device is found.
 *
 * Returns the number of partitions registered (0 on failure). */
int gpt_scan(const char *devname);

/* gpt_rescan — unregister old partitions on devname, then scan again.
 * Returns number of new partitions found, or 0 on failure. */
int gpt_rescan(const char *devname);

#endif /* GPT_H */
