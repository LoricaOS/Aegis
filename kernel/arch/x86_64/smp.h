/* smp.h — SMP per-CPU data structures */
#ifndef AEGIS_SMP_H
#define AEGIS_SMP_H

#include <stdint.h>
#include "../../limits.h"

/* Forward declaration to avoid circular include with sched.h */
struct aegis_task_t;

/* Legacy alias — value single-sourced in limits.h (AEGIS_MAX_CPUS). */
#define MAX_CPUS AEGIS_MAX_CPUS

/* Per-CPU data structure. GS.base points here in kernel mode.
 * FIELD OFFSETS (assembly uses gs:OFFSET directly):
 *   self            = gs:0
 *   cpu_id          = gs:8
 *   lapic_id        = gs:9
 *   current_task    = gs:16
 *   kernel_stack    = gs:24
 *   user_rsp_scratch= gs:32
 *   ticks           = gs:40
 */
typedef struct percpu {
    struct percpu         *self;              /* offset 0 */
    uint8_t                cpu_id;            /* offset 8 */
    uint8_t                lapic_id;          /* offset 9 */
    uint8_t                _pad[6];           /* offset 10-15 */
    struct aegis_task_t   *current_task;      /* offset 16 */
    uint64_t               kernel_stack;      /* offset 24 */
    uint64_t               user_rsp_scratch;  /* offset 32 */
    uint64_t               ticks;             /* offset 40 */
    /* Deferred dying task cleanup — per-CPU to avoid SMP race on globals. */
    void                  *prev_dying_tcb;    /* offset 48 */
    void                  *prev_dying_stack;  /* offset 56 */
    uint64_t               prev_dying_stack_pages; /* offset 64 */
    /* Per-CPU idle task — each CPU runs its OWN idle task when no real work is
     * runnable, so two idle CPUs never adopt the same task.  Set by the BSP
     * before smp_start_aps (one per detected CPU).  Past the asm-visible
     * offsets above, so assembly is unaffected. */
    struct aegis_task_t   *idle_task;         /* offset 72 */
} percpu_t;

/* Assembly-visible offset constants */
#define PERCPU_SELF            0
#define PERCPU_CPU_ID          8
#define PERCPU_CURRENT_TASK    16
#define PERCPU_KERNEL_STACK    24
#define PERCPU_USER_RSP        32
#define PERCPU_TICKS           40

extern percpu_t g_percpu[MAX_CPUS];
extern uint32_t g_cpu_count;
extern volatile uint8_t g_ap_online[MAX_CPUS];

/* Opt-in multi-core scheduling toggle (kernel cmdline `smp_sched`).
 * 0 = APs halt (default, safe); 1 = APs run the scheduler. */
extern int g_ap_sched_enabled;

/* DIAG: hardware-watchpoint catcher (kernel cmdline `hwwatch`).  When set, every
 * CPU arms DR0-3 to trap any write to g_percpu[].self (observed corrupted to 0
 * under SMP); the #DB handler in idt.c prints the writing instruction's RIP +
 * backtrace.  Self-hosted (no JTAG/gdb), so it works on bare metal too. */
extern int g_hwwatch;
void hwwatch_arm_local(void);

void smp_percpu_init_bsp(void);
void smp_start_aps(void);
void ap_entry(void);

/* Return pointer to the current CPU's percpu_t via gs:0 (self pointer). */
static inline percpu_t *
percpu_self(void)
{
    percpu_t *p;
    __asm__ volatile("movq %%gs:0, %0" : "=r"(p));
    return p;
}

static inline struct aegis_task_t *
percpu_current(void)
{
    struct aegis_task_t *t;
    __asm__ volatile("movq %%gs:16, %0" : "=r"(t));
    return t;
}

static inline void
percpu_set_current(struct aegis_task_t *t)
{
    __asm__ volatile("movq %0, %%gs:16" : : "r"(t));
}

#endif /* AEGIS_SMP_H */
