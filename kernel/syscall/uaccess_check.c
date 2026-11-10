/* Permission-aware uaccess snapshots. No locks survive a return to the caller;
 * validation cannot replace checking a fault-contained copy's residual. */
#include <stdint.h>
#include "sched.h"
#include "proc.h"
#include "vmm.h"
#include "vma.h"

int
uaccess_range_accessible(uint64_t addr, uint64_t len, uint32_t prot)
{
    if (len == 0) return 1;
    aegis_task_t *t = sched_current();
    if (!t || !t->is_user) return 1;
    aegis_process_t *p = (aegis_process_t *)t;
    uint64_t end = addr + len; /* caller has checked canonical range/overflow */
    uint64_t va = addr & ~0xFFFULL;
    while (va < end) {
        vma_entry_t v;
        if (vma_find_copy(p, va, &v)) {
            /* An explicit denial must NEVER fall back to stale/live PTEs.
             * VMA permissions also describe lazy pages and writable COW. */
            if ((prot ? (v.prot & prot) != prot : !(v.prot & 7u)) ||
                v.base + v.len <= va) return 0;
            va = v.base + v.len;
        } else {
            /* Some kernel-published mappings have no VMA. The raw accessor
             * returns abstract flags on both architectures, including COW. */
            uint64_t pte = vmm_pte_of_user_raw(p->pml4_phys, va);
            if ((pte & (VMM_FLAG_PRESENT | VMM_FLAG_USER)) !=
                       (VMM_FLAG_PRESENT | VMM_FLAG_USER)) return 0;
            if ((prot & 2u) && !(pte & (VMM_FLAG_WRITABLE | VMM_FLAG_COW))) return 0;
            va += 4096;
        }
    }
    return 1;
}

int
uaccess_range_mapped(uint64_t addr, uint64_t len)
{
    return uaccess_range_accessible(addr, len, 0);
}
