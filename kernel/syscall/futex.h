/* kernel/syscall/futex.h — futex wait/wake for thread synchronization */
#ifndef FUTEX_H
#define FUTEX_H

#include <stdint.h>

#define FUTEX_WAIT         0
#define FUTEX_WAKE         1
#define FUTEX_REQUEUE      3
#define FUTEX_CMP_REQUEUE  4
#define FUTEX_PRIVATE_FLAG 128

uint64_t sys_futex(uint64_t addr, uint64_t op, uint64_t val,
                   uint64_t timeout, uint64_t addr2, uint64_t val3);

/* Wake waiters on addr — called from thread exit for clear_child_tid */
/* mm = the address-space key (waker's process pml4_phys); only waiters in the
 * same address space at `addr` are woken (see the mm field in futex.c). */
int futex_wake_addr(uint64_t addr, uint32_t count, uint64_t mm);

#endif
