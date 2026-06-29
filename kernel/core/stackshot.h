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
 * another CPU, whose saved SP is stale).  Best-effort: takes sched_lock via
 * trylock so it is safe from an ISR (SysRq / hung-task watchdog) without
 * deadlocking.  The single artifact that reveals a whole-system deadlock or
 * lost-wakeup at a glance. */
void dump_all_tasks(const char *reason);

#endif /* AEGIS_STACKSHOT_H */
