#ifndef AEGIS_STACKSHOT_H
#define AEGIS_STACKSHOT_H

#include <stdint.h>

/* print_backtrace_from — walk the frame-pointer chain starting at rbp and print
 * up to `max` return addresses, symbolized via ksym_lookup when a symbol table
 * is present (else bare hex, resolvable with `make sym ADDR=`).  Each frame:
 * "    [i] 0x<ret> <sym>+0x<off>". */
void print_backtrace_from(uint64_t rbp, int max);

/* dump_all_tasks — "stackshot": print every task with state / on_cpu / last
 * syscall / wait target, plus a kernel backtrace (live frame for the current
 * task; saved-context frame for blocked tasks; skipped for tasks live on
 * another CPU, whose saved SP is stale).  The single artifact that reveals a
 * whole-system deadlock or lost-wakeup at a glance.
 *
 * `blocking` picks how sched_lock is taken, and the choice is a correctness
 * one, not a preference:
 *
 *   0 — trylock, proceed anyway if busy.  ONLY for the SysRq / hung-task /
 *       panic paths, where sched_lock may be held forever by a wedged CPU and
 *       an inconsistent dump beats no dump.  The walk is then LOCKLESS: a
 *       concurrent waitpid reaper can free a PCB out from under `t = t->next`,
 *       so this can fault or print a freed task's memory.  Acceptable only
 *       because the machine is already dying.
 *   1 — blocking spin_lock_irqsave.  Required for any caller reachable from a
 *       healthy system (procfs), where that same lockless walk is a
 *       use-after-free and a kernel-address leak rather than a last resort. */
void dump_all_tasks(const char *reason, int blocking);

#endif /* AEGIS_STACKSHOT_H */
