/* kernel/mm/vma.h — per-process Virtual Memory Area tracking */
#ifndef AEGIS_VMA_H
#define AEGIS_VMA_H

#include <stdint.h>

/* VMA type constants */
#define VMA_NONE         0
#define VMA_ELF_TEXT     1   /* PT_LOAD with PROT_EXEC */
#define VMA_ELF_DATA     2   /* PT_LOAD without PROT_EXEC */
#define VMA_HEAP         3   /* [brk_base..brk] */
#define VMA_STACK        4   /* user stack */
#define VMA_MMAP         5   /* anonymous mmap */
#define VMA_THREAD_STACK 6   /* thread stack via pthread_create */
#define VMA_GUARD        7   /* guard page (PROT_NONE) */
#define VMA_SHARED       8   /* MAP_SHARED mapping — phys pages owned by memfd */
#define VMA_FILE         9   /* demand-paged MAP_PRIVATE file mapping (ext2) */

typedef struct {
    uint64_t base;
    uint64_t len;
    uint64_t file_off;   /* VMA_FILE: byte offset into the backing file */
    uint64_t file_size;  /* VMA_FILE: backing file size (EOF zero-fill bound) */
    uint32_t prot;       /* PROT_READ | PROT_WRITE | PROT_EXEC */
    uint32_t file_ino;   /* VMA_FILE: ext2 inode number (0 = not file-backed) */
    uint8_t  type;       /* VMA_* constant */
    uint8_t  _pad[3];
    uint32_t file_gen;   /* VMA_FILE: inode generation at mmap (secfix M2) */
} vma_entry_t;  /* 48 bytes */

/* Forward-declare to avoid circular include with proc.h */
struct aegis_process;

/* vma_set_file_backing — attach ext2 file backing to the VMA_FILE entry whose
 * base == base (set right after vma_insert reserves it). Lazy file mmap: the
 * page-fault handler reads file pages on demand via the stored ino+offset. */
void vma_set_file_backing(struct aegis_process *proc, uint64_t base,
                          uint32_t ino, uint64_t file_off, uint64_t file_size,
                          uint32_t file_gen);

/* vma_init — allocate a kva page for the VMA table.
 * Sets proc->vma_table, vma_count=0, vma_capacity=170, and initialises the
 * page-embedded share count to 1 (see vma.c vma_rc()). */
void vma_init(struct aegis_process *proc);

/* vma_find — VMA entry containing va, or NULL. Used by demand-paging fault. */
vma_entry_t *vma_find(struct aegis_process *proc, uint64_t va);

/* vma_range_covered — 1 if [addr, addr+len) is fully spanned by VMAs (no hole).
 * Cheap (O(VMAs spanned) binary searches) — the uaccess fast path uses it to
 * validate a user buffer without a per-page windowed PTE walk. */
int vma_range_covered(struct aegis_process *proc, uint64_t addr, uint64_t len);

/* vma_insert — add a VMA entry sorted by base address.
 * Merges with adjacent entries if same prot+type.
 * Returns 0 on success (inserted or merged), -1 on failure: NULL table,
 * len==0, or the tracking table is full. On -1 the region is NOT tracked, so
 * the caller MUST roll back any page tables it set up for [base, base+len)
 * (otherwise /proc/maps is wrong and munmap/teardown cannot free it). */
int vma_insert(struct aegis_process *proc,
               uint64_t base, uint64_t len, uint32_t prot, uint8_t type);

/* vma_remove — remove [base, base+len) from VMA table.
 * Splits the single enclosing entry in two if the range falls entirely inside
 * it. Returns 0 on success, -1 if that split needs a free table slot and the
 * table is full. On -1 the table is left UNMODIFIED (all-or-nothing): callers
 * that pair this with irreversible page teardown must call it FIRST and abort
 * (e.g. munmap → -ENOMEM) on -1 before unmapping anything. A NULL table or
 * len==0 is a successful no-op (returns 0). */
int vma_remove(struct aegis_process *proc, uint64_t base, uint64_t len);

/* vma_update_prot — change permissions for [base, base+len).
 * Splits entries at boundaries (up to two new entries per straddled VMA) when
 * the range partially overlaps them. Returns 0 on success, -1 if the required
 * splits cannot fit in the table. On -1 the table is left UNMODIFIED
 * (all-or-nothing): mprotect must call this BEFORE changing page protections,
 * or be prepared to fail with -ENOMEM without having desynced the two. A NULL
 * table or len==0 is a successful no-op (returns 0). */
int vma_update_prot(struct aegis_process *proc,
                    uint64_t base, uint64_t len, uint32_t new_prot);

/* vma_clear — set count to 0 (called by execve). */
void vma_clear(struct aegis_process *proc);

/* vma_clone — deep copy VMA table from src to dst (for fork).
 * Allocates a new kva page for dst, copies entries. */
void vma_clone(struct aegis_process *dst, struct aegis_process *src);

/* vma_share — share VMA table from parent to child (for CLONE_VM threads).
 * Increments refcount, copies pointer. */
void vma_share(struct aegis_process *child, struct aegis_process *parent);

/* vma_count_get — number of live VMA entries (reads the shared table header).
 * Use this instead of a per-process field: CLONE_VM threads share one count. */
uint32_t vma_count_get(struct aegis_process *proc);

/* vma_free — decrement refcount; free kva page if refcount reaches 0. */
void vma_free(struct aegis_process *proc);

#endif /* AEGIS_VMA_H */
