/* smp.h — ARM64 per-CPU data. BSP-only for now (no PSCI CPU_ON yet);
 * the structure and API mirror x86 so shared code is oblivious. */
#ifndef AEGIS_SMP_H
#define AEGIS_SMP_H

#include <stdint.h>
#include "../../limits.h"

struct aegis_task_t;

#define MAX_CPUS AEGIS_MAX_CPUS

/* Per-CPU data. TPIDR_EL1 points here in kernel mode (the GS.base
 * equivalent). Same field layout as x86 for familiarity; no assembly
 * consumes these offsets on arm64 yet. */
typedef struct percpu {
    struct percpu         *self;
    uint8_t                cpu_id;
    uint8_t                lapic_id;           /* MPIDR affinity 0 here */
    uint8_t                _pad[6];
    struct aegis_task_t   *current_task;
    uint64_t               kernel_stack;
    uint64_t               user_rsp_scratch;
    uint64_t               ticks;
    void                  *prev_dying_tcb;
    void                  *prev_dying_stack;
    uint64_t               prev_dying_stack_pages;
    struct aegis_task_t   *idle_task;
} percpu_t;

extern percpu_t g_percpu[MAX_CPUS];
extern uint32_t g_cpu_count;
extern volatile uint8_t g_ap_online[MAX_CPUS];
extern int g_ap_sched_enabled;

/* DIAG parity with x86 (no DR registers here; always off). */
extern int g_hwwatch;
void hwwatch_arm_local(void);

void smp_percpu_init_bsp(void);
void smp_start_aps(void);      /* ponytail: BSP-only v1; PSCI CPU_ON later */

static inline percpu_t *
percpu_self(void)
{
    percpu_t *p;
    __asm__ volatile("mrs %0, tpidr_el1" : "=r"(p));
    return p;
}

static inline struct aegis_task_t *
percpu_current(void)
{
    return percpu_self()->current_task;
}

static inline void
percpu_set_current(struct aegis_task_t *t)
{
    percpu_self()->current_task = t;
}

#endif /* AEGIS_SMP_H */
