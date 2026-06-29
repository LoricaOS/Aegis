#ifndef AEGIS_ELF_H
#define AEGIS_ELF_H

#include <stdint.h>
#include <stddef.h>

/* elf_load_result_t — returned by elf_load on success.
 *   entry:       ELF entry point virtual address
 *   brk:         first byte after last loaded segment (page-aligned)
 *   phdr_va:     virtual address of the program header table in loaded image
 *                (= first PT_LOAD's p_vaddr + e_phoff)
 *   phdr_count:  number of program headers (e_phnum) -- for AT_PHNUM auxv entry
 */
#define ET_DYN       3
#define PT_INTERP    3
#define INTERP_BASE  0x40000000ULL

typedef struct {
    uint64_t entry;
    uint64_t brk;
    uint64_t phdr_va;
    uint32_t phdr_count;
    uint64_t base;
    char     interp[256];
} elf_load_result_t;

/* elf_load -- parse ELF64; map all PT_LOAD segments into pml4_phys.
 * Returns 0 on success; fills *out. Returns -1 on parse error.
 * base is added to all virtual addresses (0 for ET_EXEC, INTERP_BASE for interp).
 * phdr_va = first PT_LOAD p_vaddr + base + e_phoff (VA of program header table).
 * phdr_count = e_phnum.
 *
 * `proc` is the process the segments belong to — its vma_table receives one
 * VMA per PT_LOAD.  This MUST be the target process (the one owning pml4_phys),
 * NOT sched_current(): for sys_spawn the caller (spawner) and the target
 * (child) differ, and recording into the caller leaks the child's VMAs into
 * the spawner's table (an unbounded per-spawn /proc/maps + VmSize leak that
 * eventually exhausts the spawner's vma_table).  May be NULL, or have a NULL
 * vma_table (e.g. early init before vma_init), in which case VMA recording is
 * skipped. */
struct aegis_process;
int elf_load(struct aegis_process *proc, uint64_t pml4_phys, const uint8_t *data,
             size_t len, uint64_t base, elf_load_result_t *out);

#endif /* AEGIS_ELF_H */
