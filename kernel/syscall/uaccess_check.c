/* uaccess_check.c — mapped-range validation behind user_ptr_valid.
 *
 * Separate translation unit so syscall_util.h (included nearly everywhere)
 * does not need proc.h/sched.h/vmm.h.  See vmm_user_range_mapped for why
 * the walk is race-free against munmap on the current single-core,
 * IF=0-during-syscalls design. */

#include <stdint.h>
#include "sched.h"
#include "proc.h"
#include "vmm.h"

int
uaccess_range_mapped(uint64_t addr, uint64_t len)
{
    aegis_task_t *t = sched_current();
    /* Kernel tasks have no user PML4 to walk; user_ptr_valid calls from
     * boot-time / kernel-task context keep the historical range-only
     * semantics. */
    if (!t || !t->is_user)
        return 1;
    aegis_process_t *p = (aegis_process_t *)t;
    if (vmm_user_range_mapped(p->pml4_phys, addr, len))
        return 1;
    /* Demand paging: the range may include not-yet-faulted lazy anon pages.
     * Populate page-by-page and stop at the FIRST page that is not a populatable
     * lazy page (mm_populate_fault returns non-zero). The old code populated the
     * ENTIRE range unconditionally before a single re-check, so a caller could
     * pass a multi-GiB len whose first hole is one page in and still force the
     * kernel to walk+allocate every page (forced eager population → memory spike
     * + long IF=0 stall). Early-exit makes the cost proportional to the
     * contiguous populatable prefix, and a genuine hole yields EFAULT at once.
     * (mm_populate_fault returns 0 for an already-present page, so a fully valid
     * large lazy buffer still populates correctly.) */
    uint64_t end = addr + len;
    for (uint64_t va = addr & ~0xFFFULL; va < end; va += 4096UL)
        if (mm_populate_fault(p, va) != 0)
            return 0;  /* not a populatable page → EFAULT, don't touch the rest */
    return 1;
}
