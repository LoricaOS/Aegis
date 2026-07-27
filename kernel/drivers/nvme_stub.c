/* nvme_stub.c — compiled only when CONFIG_NVME is off (see Makefile).
 *
 * sys_identity / sys_file flush the disk write cache before a reset, and procfs
 * reads NVMe SMART health for /proc/smart. With no NVMe driver these are inert:
 * nothing to flush, no SMART data. */
#include "nvme.h"

void nvme_flush(void) {}
int  nvme_smart_info(nvme_smart_t *out) { (void)out; return -1; }
