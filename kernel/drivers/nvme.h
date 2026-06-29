/* nvme.h — NVMe controller driver
 *
 * Implements NVMe 1.4 admin + I/O command sets.
 * Synchronous doorbell+poll I/O — no interrupts.
 * Single namespace (NSID=1). Queue depth 64 entries.
 */
#ifndef NVME_H
#define NVME_H

#include <stdint.h>

/* NVMe controller registers (BAR0 MMIO) */
typedef struct __attribute__((packed)) {
    uint64_t cap;       /* 0x00: Controller Capabilities */
    uint32_t vs;        /* 0x08: Version */
    uint32_t intms;     /* 0x0C: Interrupt Mask Set */
    uint32_t intmc;     /* 0x10: Interrupt Mask Clear */
    uint32_t cc;        /* 0x14: Controller Configuration */
    uint32_t reserved0; /* 0x18 */
    uint32_t csts;      /* 0x1C: Controller Status */
    uint32_t nssr;      /* 0x20: NVM Subsystem Reset */
    uint32_t aqa;       /* 0x24: Admin Queue Attributes */
    uint64_t asq;       /* 0x28: Admin SQ Base Address (physical) */
    uint64_t acq;       /* 0x30: Admin CQ Base Address (physical) */
} nvme_regs_t;

/* Submission Queue Entry — 64 bytes */
typedef struct __attribute__((packed)) {
    uint32_t cdw0;      /* opcode[7:0], fuse[9:8], psdt[15:14], cid[31:16] */
    uint32_t nsid;
    uint64_t reserved;
    uint64_t mptr;      /* Metadata Pointer */
    uint64_t prp1;      /* Physical Region Page 1 */
    uint64_t prp2;      /* Physical Region Page 2 */
    uint32_t cdw10;
    uint32_t cdw11;
    uint32_t cdw12;
    uint32_t cdw13;
    uint32_t cdw14;
    uint32_t cdw15;
} nvme_sqe_t;

/* Completion Queue Entry — 16 bytes */
typedef struct __attribute__((packed)) {
    uint32_t dw0;       /* command-specific */
    uint32_t dw1;       /* reserved */
    uint16_t sq_head;   /* SQ Head Pointer */
    uint16_t sq_id;     /* SQ Identifier */
    uint16_t cid;       /* Command Identifier */
    uint16_t status;    /* bit 0 = phase tag; bits[15:1] = status code */
} nvme_cqe_t;

/* Admin command opcodes */
#define NVME_ADMIN_DELETE_IO_SQ      0x00
#define NVME_ADMIN_CREATE_IO_SQ      0x01
#define NVME_ADMIN_DELETE_IO_CQ      0x04
#define NVME_ADMIN_CREATE_IO_CQ      0x05
#define NVME_ADMIN_IDENTIFY          0x06
#define NVME_ADMIN_GET_LOG_PAGE      0x02

/* I/O command opcodes */
#define NVME_IO_FLUSH                0x00
#define NVME_IO_WRITE                0x01
#define NVME_IO_READ                 0x02

/* Controller Configuration bits */
#define NVME_CC_EN                   (1U << 0)
#define NVME_CC_CSS_NVM              (0U << 4)   /* NVM command set */
#define NVME_CC_MPS_4K               (0U << 7)   /* 2^(12+0) = 4096 */
#define NVME_CC_IOSQES               (6U << 16)  /* 2^6 = 64 bytes per SQE */
#define NVME_CC_IOCQES               (4U << 20)  /* 2^4 = 16 bytes per CQE */

/* Controller Status bits */
#define NVME_CSTS_RDY                (1U << 0)
#define NVME_CSTS_CFS                (1U << 1)   /* Controller Fatal Status */

/* Queue depths — must fit in 1 pmm_alloc_page() each */
#define NVME_ADMIN_QUEUE_DEPTH       64   /* 64×64B = 4096B = 1 page */
#define NVME_IO_QUEUE_DEPTH          64   /* 64×64B = 4096B = 1 page */

/* Initialize NVMe: find controller via PCIe, set up queues, register blkdev.
 * Safe to call when no NVMe device present — prints skip message. */
void nvme_init(void);

/* Commit the drive's volatile write cache to media (NVMe FLUSH).
 * No-op when no NVMe controller is present. Called from sys_sync. */
void nvme_flush(void);

/* SMART / Health information from the controller's Get Log Page (LID 0x02). */
typedef struct {
    uint8_t  critical_warning;   /* nonzero = a health bit is set */
    int      temp_c;             /* composite temperature, Celsius */
    uint8_t  avail_spare;        /* available spare, percent */
    uint8_t  spare_thresh;       /* spare threshold, percent */
    uint8_t  pct_used;           /* endurance used, percent */
    uint64_t power_on_hours;
    uint64_t power_cycles;
    uint64_t unsafe_shutdowns;
    uint64_t media_errors;
    uint64_t data_read_units;    /* 1000 × 512-byte units */
    uint64_t data_written_units;
} nvme_smart_t;

/* Query the SMART/health log. Returns 0 and fills *out, or -1 if no NVMe
 * controller is present or the command fails. */
int nvme_smart_info(nvme_smart_t *out);

#endif /* NVME_H */
