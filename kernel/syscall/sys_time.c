/* sys_time.c — Time-related syscalls: nanosleep, clock_gettime, clock_settime */
#include "sys_impl.h"
#include "sched.h"
#include "proc.h"
#include "arch.h"

/*
 * sys_nanosleep — syscall 35
 * arg1 = user pointer to struct timespec { int64_t tv_sec; int64_t tv_nsec; }
 * arg2 = user pointer to remainder (NULL allowed; not populated)
 *
 * Sets sleep_deadline in the task struct and calls sched_block().
 * sched_tick auto-wakes the task when the deadline passes.
 * This properly removes the task from scheduling, unlike the old
 * sti;hlt;cli busy-wait which kept the task RUNNING and stole 50%
 * of CPU from other tasks.
 */
uint64_t
sys_nanosleep(uint64_t arg1, uint64_t arg2)
{
    (void)arg2;
    struct { int64_t tv_sec; int64_t tv_nsec; } ts;
    COPY_FROM_USER(&ts, arg1);

    if (ts.tv_sec < 0 || ts.tv_nsec < 0 || ts.tv_nsec >= 1000000000)
        return SYS_ERR(EINVAL);

    uint64_t ticks = (uint64_t)ts.tv_sec * 100ULL
                   + (uint64_t)ts.tv_nsec / 10000000ULL;
    if (ticks == 0 && ts.tv_nsec > 0) ticks = 1;

    aegis_task_t *cur = sched_current();
    cur->sleep_deadline = arch_get_ticks() + ticks;
    /* Loop until the deadline. sched_block() may return early (the lost-wakeup
     * guard returns without blocking if a wake raced the block window), so a
     * single block is not enough — re-check the deadline or nanosleep would
     * under-sleep. A pending signal breaks out so it is still interruptible
     * (the signal is delivered on the syscall-return path, preserving the
     * existing Ctrl-C-during-sleep behavior); otherwise we re-block. */
    while (arch_get_ticks() < cur->sleep_deadline) {
        if (signal_check_pending())
            break;
        sched_block();
    }
    cur->sleep_deadline = 0;
    return 0;
}

/*
 * sys_clock_gettime — syscall 228
 *
 * arg1 = clk_id  (CLOCK_REALTIME=0, CLOCK_MONOTONIC=1)
 * arg2 = user pointer to struct timespec { int64_t tv_sec; int64_t tv_nsec; }
 *
 * CLOCK_REALTIME returns wall-clock time (epoch_offset + ticks/100).
 * CLOCK_MONOTONIC returns raw PIT ticks (no epoch offset).
 * Returns 0 on success, negative errno on failure.
 */
uint64_t
sys_clock_gettime(uint64_t clk_id, uint64_t timespec_uptr)
{
    /* Accept the _COARSE variants as aliases of their base clocks: 5 =
     * CLOCK_REALTIME_COARSE → CLOCK_REALTIME, 6 = CLOCK_MONOTONIC_COARSE →
     * CLOCK_MONOTONIC. They are just lower-resolution forms, and Aegis's clock
     * is already coarse (100 Hz). musl/glibc event loops use the COARSE clocks
     * (e.g. Ladybird's Core::EventLoop via AK MonotonicTime::now_coarse); EINVAL
     * here froze every timer because the monotonic clock never advanced. */
    int is_realtime  = (clk_id == 0 || clk_id == 5);
    int is_monotonic = (clk_id == 1 || clk_id == 6);
    if (!is_realtime && !is_monotonic) return SYS_ERR(EINVAL);
    if (!user_ptr_valid(timespec_uptr, 16)) return SYS_ERR(EFAULT);

    int64_t tv_sec, tv_nsec;
    if (is_realtime) {
        /* CLOCK_REALTIME — wall clock set by NTP */
        uint64_t sec, nsec;
        arch_clock_gettime(&sec, &nsec);
        tv_sec  = (int64_t)sec;
        tv_nsec = (int64_t)nsec;
    } else {
        /* CLOCK_MONOTONIC — ns resolution (TSC/CNTVCT-derived), no epoch
         * offset. Was 10 ms tick-quantized, which made musl mkstemp derive
         * IDENTICAL temp names in same-tick processes (parallel-build killer). */
        uint64_t ns = arch_clock_mono_ns();
        tv_sec  = (int64_t)(ns / 1000000000ULL);
        tv_nsec = (int64_t)(ns % 1000000000ULL);
    }
    copy_to_user((void *)(uintptr_t)timespec_uptr,       &tv_sec,  8);
    copy_to_user((void *)(uintptr_t)(timespec_uptr + 8), &tv_nsec, 8);
    return 0;
}

/*
 * sys_clock_settime — syscall 227
 *
 * arg1 = clk_id (CLOCK_REALTIME=0 only)
 * arg2 = user pointer to struct timespec { int64_t tv_sec; int64_t tv_nsec; }
 *
 * Sets the wall clock epoch offset so that subsequent clock_gettime(CLOCK_REALTIME)
 * returns real Unix time. Called by the chronos NTP daemon.
 * Returns 0 on success, negative errno on failure.
 */
uint64_t
sys_clock_settime(uint64_t clk_id, uint64_t timespec_uptr)
{
    aegis_process_t *proc = current_proc();
    if (cap_check(proc->caps, CAP_TABLE_SIZE,
                  CAP_KIND_NET_ADMIN, CAP_RIGHTS_WRITE) != 0)
        return SYS_ERR(EPERM);
    if (clk_id != 0) return SYS_ERR(EINVAL); /* EINVAL: only CLOCK_REALTIME */
    if (!user_ptr_valid(timespec_uptr, 16)) return SYS_ERR(EFAULT);

    uint64_t sec;
    copy_from_user(&sec, (const void *)(uintptr_t)timespec_uptr, 8);
    arch_clock_settime(sec);
    return 0;
}
