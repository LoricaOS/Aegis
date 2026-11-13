#ifndef AEGIS_APPLE_QR_REPORT_H
#define AEGIS_APPLE_QR_REPORT_H
#include <stdint.h>
/* Lock-free, fixed-buffer, local text report. No URL, uploads or allocator.
 * atomic[] is attempts/status/value/lock; NULL means not yet attempted. */
void apple_qr_progress(const char *phase, const volatile uint64_t *atomic);
#ifdef APPLE_MEMORY_CHECKPOINT
extern volatile uint64_t apple_qr_memory[4] __attribute__((visibility("hidden")));
/* arena, bytes, free, root; hidden keeps the low loader GOT-free */
#endif
#ifdef APPLE_TIMER_CHECKPOINT
extern volatile uint64_t apple_qr_timer[8] __attribute__((visibility("hidden")));
/* frequency, delivered, returned, failure, HCR, gate before/after, CNTHCTL */
extern volatile uint64_t apple_timer_el2_state[4] __attribute__((visibility("hidden")));
#endif
#ifdef APPLE_SCHED_CHECKPOINT
extern volatile uint64_t apple_qr_sched[8] __attribute__((visibility("hidden")));
/* A/B completed rounds, required rounds, reason, CPACR, DAIF, tasks, free */
#endif
#ifdef APPLE_PREEMPT_CHECKPOINT
extern volatile uint64_t apple_qr_preempt[6] __attribute__((visibility("hidden")));
/* ticks, interrupted A/B, resumed A/B, frequency */
#endif
#ifdef APPLE_USER_CHECKPOINT
extern volatile uint64_t apple_qr_user[12] __attribute__((visibility("hidden")));
#endif
#endif
