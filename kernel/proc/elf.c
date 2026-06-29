#include "elf.h"
#include "arch.h"     /* USER_ADDR_MAX */
#include "vmm.h"
#include "kva.h"
#include "printk.h"
#include "vma.h"
#include "proc.h"
#include "sched.h"
#include <stdint.h>
#include <stddef.h>

/* ELF64 header */
typedef struct {
    uint8_t  e_ident[16];
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uint64_t e_entry;
    uint64_t e_phoff;
    uint64_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
} __attribute__((packed)) Elf64_Ehdr;

/* ELF64 program header */
typedef struct {
    uint32_t p_type;
    uint32_t p_flags;
    uint64_t p_offset;
    uint64_t p_vaddr;
    uint64_t p_paddr;
    uint64_t p_filesz;
    uint64_t p_memsz;
    uint64_t p_align;
} __attribute__((packed)) Elf64_Phdr;

#define PT_LOAD    1
#define PF_X       1      /* program header execute flag */
#define PF_W       2      /* program header write flag */
#define ELFCLASS64 2
#define ET_EXEC    2
#define ET_DYN_LOCAL 3
#define EM_X86_64   0x3E
#define EM_AARCH64  0xB7

#ifdef __aarch64__
#define EM_CURRENT EM_AARCH64
#else
#define EM_CURRENT EM_X86_64
#endif

int
elf_load(struct aegis_process *proc, uint64_t pml4_phys, const uint8_t *data,
         size_t len, uint64_t base, elf_load_result_t *out)
{
    const Elf64_Ehdr *eh = (const Elf64_Ehdr *)data;

    /* BUG #4: len is the exact on-disk file size — every read from
     * data[...] must be proven in-bounds with overflow-safe arithmetic
     * (a > LIMIT - b, never a + b > LIMIT which can wrap). */
    if (len < sizeof(Elf64_Ehdr)) {
        printk("[ELF] FAIL: file smaller than ELF header\n");
        return -1;
    }

    /* Verify ELF magic */
    if (eh->e_ident[0] != 0x7F || eh->e_ident[1] != 'E' ||
        eh->e_ident[2] != 'L'  || eh->e_ident[3] != 'F') {
        printk("[ELF] FAIL: bad magic\n");
        return -1;
    }
    if (eh->e_ident[4] != ELFCLASS64 ||
        (eh->e_type != ET_EXEC && eh->e_type != ET_DYN_LOCAL) ||
        eh->e_machine != EM_CURRENT) {
        printk("[ELF] FAIL: not an ELF64 executable for this arch\n");
        return -1;
    }

    /* BUG #4 part 1: program header table must lie within the file.
     * Cap e_phnum (also fixes a downstream procfs issue).  All
     * comparisons are overflow-safe: e_phoff > len, and the table-size
     * check is written as N > len - e_phoff (e_phoff <= len already). */
    if (eh->e_phnum > 64) {
        printk("[ELF] FAIL: too many program headers\n");
        return -1;
    }
    if (eh->e_phoff > (uint64_t)len) {
        printk("[ELF] FAIL: phoff past end of file\n");
        return -1;
    }
    if ((uint64_t)eh->e_phnum * sizeof(Elf64_Phdr) >
        (uint64_t)len - eh->e_phoff) {
        printk("[ELF] FAIL: program header table past end of file\n");
        return -1;
    }

    out->base = base;
    out->interp[0] = '\0';

    const Elf64_Phdr *phdrs = (const Elf64_Phdr *)(data + eh->e_phoff);

    /* Scan for PT_INTERP before loading segments */
    {
        uint16_t pi;
        for (pi = 0; pi < eh->e_phnum; pi++) {
            const Elf64_Phdr *ph = &phdrs[pi];
            if (ph->p_type != PT_INTERP)
                continue;
            /* BUG #4 part 2: bound the interp string read against the file.
             * Overflow-safe: p_offset > len, then p_filesz > len - p_offset. */
            if (ph->p_offset > (uint64_t)len ||
                ph->p_filesz > (uint64_t)len - ph->p_offset) {
                printk("[ELF] FAIL: PT_INTERP past end of file\n");
                return -1;
            }
            /* BUG #4 part 4: interp[] is 256 bytes; reject if the path could
             * not fit (need room for the NUL terminator). */
            if (ph->p_filesz >= sizeof(out->interp)) {
                printk("[ELF] FAIL: PT_INTERP path too long\n");
                return -1;
            }
            uint64_t plen = ph->p_filesz;
            if (plen == 0 || plen > 255)
                plen = 255;
            const char *src = (const char *)(data + ph->p_offset);
            uint64_t ci;
            for (ci = 0; ci < plen && src[ci] != '\0'; ci++)
                out->interp[ci] = src[ci];
            out->interp[ci] = '\0';
            break;
        }
    }

    uint64_t seg_end = 0;
    /* first_pt_load_vaddr: p_vaddr of the first PT_LOAD segment.
     * Used to compute phdr_va = first_pt_load_vaddr + e_phoff, which is
     * the virtual address at which the program header table appears in the
     * loaded image (needed for the AT_PHDR auxv entry). */
    uint64_t first_pt_load_vaddr = 0;
    int found_pt_load = 0;
    uint16_t i;
    for (i = 0; i < eh->e_phnum; i++) {
        const Elf64_Phdr *ph = &phdrs[i];
        if (ph->p_type != PT_LOAD)
            continue;

        /* BUG #2b: a well-formed binary never maps a segment both writable
         * and executable.  Reject W^X violations in the on-disk image. */
        if ((ph->p_flags & PF_W) && (ph->p_flags & PF_X)) {
            printk("[ELF] FAIL: PT_LOAD is both writable and executable\n");
            return -1;
        }

        /* BUG #4 part 2: the segment's file-backed bytes must lie within
         * the file.  Overflow-safe: p_offset > len, then
         * p_filesz > len - p_offset. */
        if (ph->p_offset > (uint64_t)len ||
            ph->p_filesz > (uint64_t)len - ph->p_offset) {
            printk("[ELF] FAIL: PT_LOAD past end of file\n");
            return -1;
        }

        if (!found_pt_load) {
            first_pt_load_vaddr = ph->p_vaddr;
            found_pt_load = 1;
        }

        uint64_t this_end = ph->p_vaddr + base + ph->p_memsz;
        if (this_end > seg_end)
            seg_end = this_end;

        /*
         * Page-align the virtual base downward.
         * ELF segments are not required to start on a page boundary.
         * The mapping must start at the page containing p_vaddr, and
         * the data must be placed at the correct sub-page offset within
         * that first page so the virtual layout is correct.
         *
         * va_base    = page-aligned start of mapping
         * va_offset  = byte offset of p_vaddr within the first page
         * page_count = pages covering [va_base, p_vaddr + p_memsz)
         */
        uint64_t va_base   = (ph->p_vaddr + base) & ~4095UL;
        uint64_t va_offset = (ph->p_vaddr + base) & 4095UL;

        /* S1: Guard against integer overflow in page_count calculation.
         * A crafted ELF with p_memsz near UINT64_MAX wraps the addition
         * to a small value, causing a tiny allocation but huge copy/zero. */
        if (ph->p_memsz > 0x100000000ULL)   /* 4 GB per-segment cap */
            return -1;
        if (ph->p_filesz > ph->p_memsz)
            return -1;

        /* BUG #4 part 3: the loaded segment must lie entirely within the
         * user half of the address space.  va_lo = p_vaddr + base may itself
         * overflow (crafted p_vaddr near UINT64_MAX); check that first, then
         * va_lo + p_memsz.  p_memsz is already <= 4 GB (guard above), so the
         * additions cannot wrap once va_lo is known not to.  Reject anything
         * that reaches or exceeds the user ceiling (also rejects the
         * non-canonical hole, since USER_ADDR_MAX is below it). */
        uint64_t va_lo = ph->p_vaddr + base;
        if (va_lo < ph->p_vaddr)                       /* base addition wrapped */
            return -1;
        if (va_lo >= USER_ADDR_MAX ||
            va_lo + ph->p_memsz > USER_ADDR_MAX) {
            printk("[ELF] FAIL: PT_LOAD outside user address space\n");
            return -1;
        }

        /* Allocate kva pages for this segment — no contiguity assumption on
         * physical frames; kva maps each PMM page to a consecutive kernel VA. */
        uint64_t page_count = (va_offset + ph->p_memsz + 4095UL) / 4096UL;
        uint64_t j;

        /* Reject a PT_LOAD whose target pages are ALREADY mapped in this PML4.
         * vmm_map_user_page panic_halt()s on a present PTE ("double-map"), so a
         * crafted ELF could panic the kernel (unprivileged-execve DoS) two ways:
         * two PT_LOADs sharing a page within one image, OR a segment that lands
         * on a page already mapped by an earlier elf_load into the same address
         * space (the main executable's segments are mapped before the PT_INTERP
         * interpreter is loaded at INTERP_BASE — a main segment at INTERP_BASE,
         * or an interp segment overlapping the main, double-maps). Checking the
         * live PML4 with vmm_phys_of_user_raw covers all of these uniformly,
         * including PROT_NONE pages. Reject cleanly (every caller turns -1 into a
         * graceful exec failure / teardown) instead of panicking. */
        for (j = 0; j < page_count; j++) {
            if (vmm_phys_of_user_raw(pml4_phys, va_base + j * 4096UL) != 0) {
                printk("[ELF] FAIL: PT_LOAD overlaps an already-mapped page\n");
                return -1;
            }
        }

        uint8_t *dst = kva_alloc_pages(page_count);
        /* BUG #4 part 5: kva_alloc_pages returns NULL on exhaustion.
         * The copy/zero loops below dereference dst unconditionally. */
        if (!dst) {
            printk("[ELF] FAIL: kva_alloc_pages exhausted\n");
            return -1;
        }

        /* Zero the first (possibly partial) page so bytes before p_vaddr
         * within it are clean.  Then copy file bytes at the sub-page offset. */
        uint64_t k;
        for (k = 0; k < va_offset; k++)
            dst[k] = 0;

        /* Copy file bytes through kernel VA */
        const uint8_t *src = data + ph->p_offset;
        for (k = 0; k < ph->p_filesz; k++)
            dst[va_offset + k] = src[k];

        /* Zero BSS (bytes past p_filesz up to p_memsz) */
        for (k = ph->p_filesz; k < ph->p_memsz; k++)
            dst[va_offset + k] = 0;

        /* Map each page into the user address space.
         * kva_page_phys recovers the physical address of each page
         * (individual walk — O(page_count × 4) invlpg, acceptable at this scale).
         * Mapping starts at the page-aligned va_base, not raw p_vaddr. */
        /* BUG #2b: W^X — set NX on every non-executable segment so data and
         * BSS pages cannot be executed.  Executable segments (PF_X) leave NX
         * clear.  The W+X combination was already rejected above. */
        uint64_t map_flags = VMM_FLAG_USER;
        if (ph->p_flags & PF_W)
            map_flags |= VMM_FLAG_WRITABLE;
        if (!(ph->p_flags & PF_X))
            map_flags |= VMM_FLAG_NX;

        for (j = 0; j < page_count; j++) {
            vmm_map_user_page(pml4_phys,
                              va_base + j * 4096UL,
                              kva_page_phys(dst + j * 4096UL),
                              map_flags);
        }

        /* The segment's frames now belong to the user PML4 (implicit refcount
         * 1). Drop the kernel-side kva mapping WITHOUT freeing the frames and
         * reclaim its VA. Previously `dst` was leaked forever: kva_free_pages
         * would pmm_free_page the frames the user now owns (double-free at exit),
         * so the old code deliberately never freed dst — leaking the kva VA and
         * the page-table entries backing it, once per PT_LOAD segment per exec
         * (an unbounded KVA + PT-memory leak over uptime). kva_unmap_keep_frames
         * clears the kva PTEs only and returns the VA to the freelist; the frames
         * stay allocated for their new user owner and are freed exactly once at
         * process teardown via the user-half page-table walk. */
        kva_unmap_keep_frames(dst, page_count);

        /* Record VMA for this PT_LOAD segment into the TARGET process `proc`
         * (the owner of pml4_phys) — never sched_current(), which for
         * sys_spawn is the spawner, not the child (that mismatch leaked the
         * child's segments into the spawner's vma_table).  A NULL proc or
         * NULL vma_table (e.g. early init before vma_init) skips recording. */
        {
            if (proc && proc->vma_table) {
                aegis_process_t *p = proc;
                uint32_t seg_prot = 0x01;  /* PROT_READ always */
                if (ph->p_flags & PF_W)
                    seg_prot |= 0x02;      /* PROT_WRITE */
                if (ph->p_flags & 1)       /* PF_X */
                    seg_prot |= 0x04;      /* PROT_EXEC */
                uint8_t seg_type = (ph->p_flags & 1) ? VMA_ELF_TEXT
                                                      : VMA_ELF_DATA;
                /* Fail the load if the VMA table is full. The segment's pages
                 * are already mapped into the user PML4 at this point; an
                 * untracked region would corrupt /proc/maps and defeat
                 * teardown. Returning -1 is elf_load's failure convention —
                 * every caller responds by tearing down the whole user
                 * address space (sys_execve → sched_exit; sys_spawn →
                 * vmm_free_user_pml4; proc_spawn → panic_halt), which frees
                 * this segment's frames via the user-half page-table walk.
                 * The kva `dst` mapping was already dropped above by
                 * kva_unmap_keep_frames (frames kept, owned by the user PML4),
                 * so there is nothing to free here and no double-free risk. */
                if (vma_insert(p, va_base, page_count * 4096UL,
                               seg_prot, seg_type) != 0) {
                    printk("[ELF] FAIL: VMA table full\n");
                    return -1;
                }
            }
        }
    }

    if (!found_pt_load) {
        printk("[ELF] FAIL: no PT_LOAD segment\n");
        return -1;
    }

    out->entry       = eh->e_entry + base;
    out->brk         = (seg_end + 4095UL) & ~4095UL;
    out->phdr_va     = first_pt_load_vaddr + base + eh->e_phoff;
    out->phdr_count  = eh->e_phnum;
    return 0;
}
