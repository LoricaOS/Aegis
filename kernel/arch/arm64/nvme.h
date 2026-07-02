#ifndef ARM64_NVME_H
#define ARM64_NVME_H
/* No NVMe driver on arm64 yet; shared callers guard nvme_* with
 * __x86_64__. This header only satisfies unconditional #includes. */
#endif
