/* sys_poll.c — general I/O multiplexing syscalls: poll/ppoll, select/pselect6,
 * and epoll. Extracted verbatim from sys_socket.c because these are NOT
 * socket-specific — they operate over any fd through the generic VFS poll
 * interface, so a kernel built without CONFIG_NET still needs them. The socket
 * API proper (sys_socket.c) is gated on CONFIG_NET; this file never is. */
#include "sys_impl.h"
#include "syscall_util.h"
#include "sched.h"
#include "waitq.h"
#include "wait_event.h"
#include "fd_waitq.h"
#include "proc.h"
#include "vfs.h"
#include "epoll.h"
#include "arch.h"
#include "signal.h"
#include "fd_resolve.h"
#include "../include/aegis_errno.h"
#include <stdint.h>
#include <stddef.h>

/* ── sys_ppoll ─────────────────────────────────────────────────────────── */
/* aarch64 (and other generic-ABI arches) have NO poll(2) syscall — musl's
 * poll() wrapper issues ppoll(fds, nfds, timespec*, sigmask, sigsetsize).
 * Without this every poll() returned ENOSYS on arm64, so e.g. Lumen's event
 * loop never saw its listen socket become readable and never accepted GUI
 * clients (the dock/apps hung in connect()). Convert the timespec to a
 * millisecond timeout and delegate to sys_poll; the signal mask is ignored
 * (poll() callers pass none, and v1 has no poll-with-sigmask semantics). */
uint64_t
sys_ppoll(uint64_t fds_ptr, uint64_t nfds, uint64_t ts_ptr,
          uint64_t sigmask, uint64_t sigsetsize)
{
    (void)sigmask; (void)sigsetsize;
    uint64_t timeout_ms;
    if (ts_ptr == 0) {
        timeout_ms = (uint64_t)-1;    /* NULL timespec → block indefinitely */
    } else {
        struct { int64_t tv_sec; int64_t tv_nsec; } ts;
        /* Validate before copying — sys_select and pselect6 both do. Without
         * it the copy's success or failure is a mapped/unmapped probe, and the
         * fault-fixup path a timing oracle. */
        if (!user_ptr_valid(ts_ptr, sizeof(ts)))
            return SYS_ERR(EFAULT);
        if (copy_from_user(&ts, (const void *)(uintptr_t)ts_ptr, sizeof(ts)) != 0)
            return SYS_ERR(EFAULT);
        /* Validate before converting (audit L2). tv_nsec was unchecked, and
         * `tv_sec * 1000` is SIGNED overflow — undefined behaviour near
         * INT64_MAX/1000, and in practice it wrapped negative, hit the `ms < 0`
         * clamp, and silently turned a long wait into a zero-timeout poll.
         * Compare in unsigned and saturate instead. (sys_nanosleep already
         * range-checks its timespec; this brings ppoll in line.) */
        if (ts.tv_sec < 0 || ts.tv_nsec < 0 || ts.tv_nsec >= 1000000000LL)
            return SYS_ERR(EINVAL);
        if ((uint64_t)ts.tv_sec > (uint64_t)-2 / 1000ULL)
            timeout_ms = (uint64_t)-2;      /* saturate; -1 means "forever" */
        else
            timeout_ms = (uint64_t)ts.tv_sec * 1000ULL +
                         (uint64_t)ts.tv_nsec / 1000000ULL;
    }
    return sys_poll(fds_ptr, nfds, timeout_ms);
}

/* ── sys_poll ──────────────────────────────────────────────────────────── */

/* struct pollfd layout (Linux ABI) */
typedef struct {
    int      fd;
    uint16_t events;
    uint16_t revents;
} k_pollfd_t;

#define POLLIN   0x0001
#define POLLOUT  0x0004
#define POLLERR  0x0008
#define POLLHUP  0x0010
#define POLLNVAL 0x0020

uint64_t
sys_poll(uint64_t fds_ptr, uint64_t nfds, uint64_t timeout_ms)
{
    if (nfds > 64) return SYS_ERR(EINVAL);
    if (!user_ptr_valid(fds_ptr, nfds * sizeof(k_pollfd_t))) return SYS_ERR(EFAULT);

    aegis_process_t *proc = current_proc();

    uint64_t now0 = arch_get_ticks();
    uint64_t deadline = (timeout_ms == (uint64_t)-1) ? 0
                       : (timeout_ms == 0)           ? now0
                                                     : now0 + (timeout_ms / 10);

    waitq_entry_t fd_entries[64];
    waitq_t      *fd_queues[64];
    fd_pin_t      fd_pins[64];      /* object refs held across the block */
    /* The timer entry is ALWAYS initialized and ALWAYS added to g_timer_waitq
     * before sched_block (see below), even on the infinite-timeout path. The
     * 100 Hz PIT wakes g_timer_waitq every tick, so the poller re-checks
     * readiness regularly instead of waiting solely on a socket waitq event —
     * which could otherwise miss a deliverable-data window and hang. Only the
     * deadline-EXPIRY return is gated on a finite deadline. */
    waitq_entry_t timer_entry;
    timer_entry.task     = sched_current();
    timer_entry.next     = (void *)0;
    timer_entry.prev     = (void *)0;
    timer_entry.on_queue = 0;

    /* Cache fd values once at entry — userspace mutating the pollfd
     * array mid-syscall would otherwise let us poll one fd and register
     * on a different one (TOCTOU). */
    int fds_cached[64];
    for (uint64_t i = 0; i < nfds; i++) {
        k_pollfd_t pfd;
        copy_from_user(&pfd,
            (const void *)(uintptr_t)(fds_ptr + i * sizeof(k_pollfd_t)),
            sizeof(k_pollfd_t));
        fds_cached[i] = pfd.fd;
    }

    for (;;) {
        /* Re-validate the user pollfd array each iteration: it was checked once
         * at entry, but this loop blocks (sched_block below) and then re-runs
         * copy_from_user / copy_to_user on it. A sibling thread (CLONE_VM) can
         * munmap it during the block; copy_*_user are raw memcpy with no fault
         * fixup, so a post-block access of the unmapped page #PFs in ring 0 and
         * panics the kernel. Re-checking here closes that TOCTOU (same fix as
         * epoll_wait). One page-walk per wake. */
        if (!user_ptr_valid(fds_ptr, nfds * sizeof(k_pollfd_t)))
            return SYS_ERR(EFAULT);
        int ready = 0;
        uint64_t i;
        for (i = 0; i < nfds; i++) {
            k_pollfd_t pfd;
            copy_from_user(&pfd,
                (const void *)(uintptr_t)(fds_ptr + i * sizeof(k_pollfd_t)),
                sizeof(k_pollfd_t));
            pfd.revents = 0;
            if (pfd.fd >= 0 && (uint32_t)pfd.fd < PROC_MAX_FDS &&
                proc->fd_table->fds[pfd.fd].ops) {
                /* AF_INET + AF_UNIX sockets, pipes, ttys, memfd, etc. all carry
                 * a vfs_ops_t. AF_INET readiness now lives in sock_vfs_poll
                 * (socket.c) — the single source of truth shared with epoll,
                 * replacing the formerly-divergent inline block here (which
                 * wrongly conflated CLOSE_WAIT with POLLHUP). */
                const vfs_ops_t *ops = proc->fd_table->fds[pfd.fd].ops;
                if (ops->poll) {
                    uint16_t r = ops->poll(proc->fd_table->fds[pfd.fd].priv);
                    pfd.revents = r & (pfd.events | POLLERR | POLLHUP);
                } else {
                    /* No .poll — permissive default */
                    pfd.revents = pfd.events & (POLLIN | POLLOUT);
                }
            } else {
                pfd.revents = POLLNVAL;
            }
            if (pfd.revents) ready++;
            copy_to_user(
                (void *)(uintptr_t)(fds_ptr + i * sizeof(k_pollfd_t)),
                &pfd, sizeof(k_pollfd_t));
        }
        if (ready > 0 || timeout_ms == 0) return (uint64_t)ready;
        if (deadline && arch_get_ticks() >= deadline) return 0;

        /* Register on every fd's waitq + g_timer_waitq (always, see below).
         * Then sched_block. fd values come from fds_cached
         * (snapshotted at entry) so a concurrent userspace mutation
         * cannot make us register on a different fd than we polled.
         * On wake, unregister from every queue (waitq_remove is
         * idempotent — only removes if still queued; the wake path
         * leaves entries for the woken task to detach itself). */
        /* Pin each object for as long as our stack-allocated entry is linked
         * into its queue — see fd_waitq.h. Without this a sibling thread
         * (CLONE_FILES) closing the fd frees the object under us and the
         * waitq_remove below writes into whatever now owns that memory. */
        for (i = 0; i < nfds; i++) {
            fd_waitq_pin(fds_cached[i], &fd_pins[i]);
            fd_queues[i]           = fd_pins[i].q;
            fd_entries[i].task     = sched_current();
            fd_entries[i].next     = (void *)0;
            fd_entries[i].prev     = (void *)0;
            fd_entries[i].on_queue = 0;
            if (fd_queues[i])
                waitq_add(fd_queues[i], &fd_entries[i]);
        }
        /* ALWAYS register on the timer waitq — even for an infinite timeout —
         * so the 100 Hz PIT re-wakes us to re-check readiness. */
        waitq_add(&g_timer_waitq, &timer_entry);

        sched_block();

        for (i = 0; i < nfds; i++) {
            if (fd_queues[i])
                waitq_remove(fd_queues[i], &fd_entries[i]);
            fd_waitq_unpin(&fd_pins[i]);   /* drop the ref AFTER unlinking */
        }
        waitq_remove(&g_timer_waitq, &timer_entry);

        /* Interruptible: after cleanup (so no waitq entry is leaked), abort on a
         * pending signal. This is the DNS/Ctrl-C hang fix — placed AFTER the
         * waitq_remove bracket so every queue we registered on is detached
         * before we return EINTR. */
        if (signal_check_pending())
            return SYS_ERR(EINTR);
    }
}

/* ── select / pselect6 ──────────────────────────────────────────────────── */
/* Implemented over the same fd → ops->poll + waitq machinery as sys_poll (the
 * jobserver in `make -j` waits on its token pipe via pselect). fd_set is a
 * 1024-bit bitmap; we gather the SET fds into a bounded pollfd array (≤64, the
 * same cap sys_poll uses) and run one block/wake loop. Security: every user
 * pointer is bounds-checked (fail closed with EFAULT), nfds is clamped to
 * [0, FD_SETSIZE], and >64 armed fds is rejected rather than overrunning the
 * on-stack arrays. */

#define K_FD_SETSIZE 1024
#define K_FD_WORDS   (K_FD_SETSIZE / 64)
typedef struct { uint64_t w[K_FD_WORDS]; } k_fd_set;

static int  fdset_isset(const k_fd_set *s, int fd) { return (int)((s->w[fd >> 6] >> (fd & 63)) & 1); }
static void fdset_set(k_fd_set *s, int fd)          { s->w[fd >> 6] |= (1ULL << (fd & 63)); }
static void fdset_zero(k_fd_set *s)                 { for (int i = 0; i < K_FD_WORDS; i++) s->w[i] = 0; }

/* Block/wake loop over a KERNEL-resident pollfd array (no user memory touched
 * in the loop, so no per-iteration re-validation as in sys_poll). Returns the
 * ready count (>=0) or -EINTR. */
static int64_t
do_poll_k(k_pollfd_t *pf, uint64_t nfds, uint64_t timeout_ms)
{
    aegis_process_t *proc = current_proc();
    uint64_t now0 = arch_get_ticks();
    uint64_t deadline = (timeout_ms == (uint64_t)-1) ? 0
                       : (timeout_ms == 0)           ? now0
                                                     : now0 + (timeout_ms / 10);
    waitq_entry_t fd_entries[64];
    waitq_t      *fd_queues[64];
    fd_pin_t      fd_pins[64];      /* object refs held across the block */
    waitq_entry_t timer_entry;
    timer_entry.task = sched_current(); timer_entry.next = (void *)0;
    timer_entry.prev = (void *)0;       timer_entry.on_queue = 0;

    for (;;) {
        int ready = 0;
        uint64_t i;
        for (i = 0; i < nfds; i++) {
            pf[i].revents = 0;
            if (pf[i].fd >= 0 && (uint32_t)pf[i].fd < PROC_MAX_FDS &&
                proc->fd_table->fds[pf[i].fd].ops) {
                const vfs_ops_t *ops = proc->fd_table->fds[pf[i].fd].ops;
                if (ops->poll)
                    pf[i].revents = ops->poll(proc->fd_table->fds[pf[i].fd].priv)
                                    & (pf[i].events | POLLERR | POLLHUP);
                else
                    pf[i].revents = pf[i].events & (POLLIN | POLLOUT);
            } else {
                pf[i].revents = POLLNVAL;
            }
            if (pf[i].revents) ready++;
        }
        if (ready > 0 || timeout_ms == 0) return ready;
        if (deadline && arch_get_ticks() >= deadline) return 0;

        /* Pinned for the duration — see fd_waitq.h and sys_poll above. */
        for (i = 0; i < nfds; i++) {
            fd_waitq_pin(pf[i].fd, &fd_pins[i]);
            fd_queues[i]           = fd_pins[i].q;
            fd_entries[i].task     = sched_current();
            fd_entries[i].next     = (void *)0;
            fd_entries[i].prev     = (void *)0;
            fd_entries[i].on_queue = 0;
            if (fd_queues[i]) waitq_add(fd_queues[i], &fd_entries[i]);
        }
        waitq_add(&g_timer_waitq, &timer_entry);
        sched_block();
        for (i = 0; i < nfds; i++) {
            if (fd_queues[i]) waitq_remove(fd_queues[i], &fd_entries[i]);
            fd_waitq_unpin(&fd_pins[i]);   /* drop the ref AFTER unlinking */
        }
        waitq_remove(&g_timer_waitq, &timer_entry);

        if (signal_check_pending()) return -EINTR;
    }
}

/* Shared core: fd_sets already resolved to a caller-provided timeout (ms). */
static uint64_t
do_select(uint64_t nfds, uint64_t rfds, uint64_t wfds, uint64_t efds,
          uint64_t timeout_ms)
{
    if ((int64_t)nfds < 0 || nfds > K_FD_SETSIZE) return SYS_ERR(EINVAL);
    uint64_t nbytes = (nfds + 7) / 8;

    k_fd_set R, W, E;
    fdset_zero(&R); fdset_zero(&W); fdset_zero(&E);
    if (rfds) { if (!user_ptr_valid(rfds, nbytes)) return SYS_ERR(EFAULT);
                copy_from_user(&R, (const void *)(uintptr_t)rfds, nbytes); }
    if (wfds) { if (!user_ptr_valid(wfds, nbytes)) return SYS_ERR(EFAULT);
                copy_from_user(&W, (const void *)(uintptr_t)wfds, nbytes); }
    if (efds) { if (!user_ptr_valid(efds, nbytes)) return SYS_ERR(EFAULT);
                copy_from_user(&E, (const void *)(uintptr_t)efds, nbytes); }

    k_pollfd_t pf[64];
    int m = 0;
    for (int fd = 0; fd < (int)nfds; fd++) {
        int wr = fdset_isset(&R, fd), ww = fdset_isset(&W, fd), we = fdset_isset(&E, fd);
        if (!(wr || ww || we)) continue;
        if (m >= 64) return SYS_ERR(EINVAL);
        pf[m].fd = fd;
        pf[m].events = (uint16_t)((wr ? POLLIN : 0) | (ww ? POLLOUT : 0));
        pf[m].revents = 0;
        m++;
    }

    int64_t rc = do_poll_k(pf, (uint64_t)m, timeout_ms);
    if (rc < 0) return SYS_ERR((int)(-rc));

    k_fd_set RO, WO, EO;
    fdset_zero(&RO); fdset_zero(&WO); fdset_zero(&EO);
    int count = 0;
    for (int j = 0; j < m; j++) {
        int fd = pf[j].fd; uint16_t re = pf[j].revents;
        if ((re & (POLLIN | POLLHUP | POLLERR)) && fdset_isset(&R, fd)) { fdset_set(&RO, fd); count++; }
        if ((re & (POLLOUT | POLLERR))         && fdset_isset(&W, fd)) { fdset_set(&WO, fd); count++; }
        if ((re & (POLLERR | POLLHUP))         && fdset_isset(&E, fd)) { fdset_set(&EO, fd); count++; }
    }
    if (rfds) copy_to_user((void *)(uintptr_t)rfds, &RO, nbytes);
    if (wfds) copy_to_user((void *)(uintptr_t)wfds, &WO, nbytes);
    if (efds) copy_to_user((void *)(uintptr_t)efds, &EO, nbytes);
    return (uint64_t)count;
}

/* select(2): timeout is `struct timeval { long tv_sec, tv_usec; }` (NULL = wait
 * forever). The kernel does not update it to the remaining time (Linux does;
 * musl copies it, callers rarely rely on the residual). */
uint64_t
sys_select(uint64_t nfds, uint64_t rfds, uint64_t wfds,
           uint64_t efds, uint64_t timeout)
{
    uint64_t timeout_ms = (uint64_t)-1;
    if (timeout) {
        struct { long tv_sec; long tv_usec; } tv;
        if (!user_ptr_valid(timeout, sizeof(tv))) return SYS_ERR(EFAULT);
        copy_from_user(&tv, (const void *)(uintptr_t)timeout, sizeof(tv));
        if (tv.tv_sec < 0 || tv.tv_usec < 0) return SYS_ERR(EINVAL);
        timeout_ms = (uint64_t)tv.tv_sec * 1000 + (uint64_t)tv.tv_usec / 1000;
    }
    return do_select(nfds, rfds, wfds, efds, timeout_ms);
}

/* pselect6(2): timeout is `struct timespec { long tv_sec, tv_nsec; }`; the 6th
 * arg (sigmask) is ignored — same as sys_ppoll, v1 has no poll-with-sigmask. */
uint64_t
sys_pselect6(uint64_t nfds, uint64_t rfds, uint64_t wfds,
             uint64_t efds, uint64_t ts_ptr, uint64_t sigmask)
{
    (void)sigmask;
    uint64_t timeout_ms = (uint64_t)-1;
    if (ts_ptr) {
        struct { long tv_sec; long tv_nsec; } ts;
        if (!user_ptr_valid(ts_ptr, sizeof(ts))) return SYS_ERR(EFAULT);
        copy_from_user(&ts, (const void *)(uintptr_t)ts_ptr, sizeof(ts));
        if (ts.tv_sec < 0 || ts.tv_nsec < 0) return SYS_ERR(EINVAL);
        timeout_ms = (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
    }
    return do_select(nfds, rfds, wfds, efds, timeout_ms);
}

/* ── sys_epoll_create1 ──────────────────────────────────────────────────── */

uint64_t
sys_epoll_create1(uint64_t flags)
{
    (void)flags;
    int eid = epoll_alloc();
    if (eid < 0) return SYS_ERR(EMFILE);
    aegis_process_t *proc = current_proc();
    int fd = epoll_open_fd((uint32_t)eid, proc);
    if (fd < 0) { epoll_free((uint32_t)eid); return SYS_ERR(EMFILE); }
    return (uint64_t)fd;
}

/* ── sys_epoll_ctl ──────────────────────────────────────────────────────── */

uint64_t
sys_epoll_ctl(uint64_t epfd, uint64_t op, uint64_t fd, uint64_t event_ptr)
{
    aegis_process_t *proc = current_proc();
    uint32_t eid = epoll_id_from_fd((int)epfd, proc);
    if (eid == EPOLL_NONE) return SYS_ERR(EBADF);

    k_epoll_event_t ev;
    __builtin_memset(&ev, 0, sizeof(ev));
    if (event_ptr)
        COPY_FROM_USER(&ev, event_ptr);

    int r = epoll_ctl_impl(eid, (int)op, (int)fd, &ev);
    return r < 0 ? (uint64_t)(int64_t)r : 0;
}

/* ── sys_epoll_wait ──────────────────────────────────────────────────────── */

uint64_t
sys_epoll_wait(uint64_t epfd, uint64_t events_ptr, uint64_t maxevents, uint64_t timeout_ms)
{
    aegis_process_t *proc = current_proc();
    uint32_t eid = epoll_id_from_fd((int)epfd, proc);
    if (eid == EPOLL_NONE) return SYS_ERR(EBADF);
    /* maxevents is the capacity of the caller's OUTPUT buffer, not a bound on
     * how many fds an epoll set may watch. Linux requires only that it be
     * positive. Rejecting anything above EPOLL_MAX_WATCHES conflated the two,
     * and it killed every Go program at startup: the Go netpoller waits with a
     * 128-entry array, got EINVAL back, and turned that into the unrecoverable
     * "fatal error: runtime: netpoll failed" — a Go server would print that it
     * was listening and then die before serving a single request.
     *
     * Clamp instead of rejecting. epoll_wait_impl delivers at most one event
     * per live watch, so it can never fill more than EPOLL_MAX_WATCHES entries
     * however large the caller's buffer is; the excess is slack we never touch.
     * Clamping BEFORE the user_ptr_valid below also means we only require the
     * prefix we might actually write to be mapped, which is what Linux does —
     * and it keeps the size computation far from overflowing. */
    if ((int64_t)maxevents <= 0) return SYS_ERR(EINVAL);
    if (maxevents > EPOLL_MAX_WATCHES) maxevents = EPOLL_MAX_WATCHES;
    if (!user_ptr_valid(events_ptr, (uint64_t)maxevents * sizeof(k_epoll_event_t)))
        return SYS_ERR(EFAULT);

    uint32_t ticks = (timeout_ms == (uint64_t)-1) ? 0xFFFFFFFFU :
                     (timeout_ms == 0) ? 0 :
                     (uint32_t)(timeout_ms / 10);
    int r = epoll_wait_impl(eid, events_ptr, (int)maxevents, ticks);
    return r < 0 ? (uint64_t)(int64_t)r : (uint64_t)r;
}

/* ── sys_epoll_pwait / sys_epoll_pwait2 ──────────────────────────────────
 *
 * epoll_wait with a signal mask applied for the duration of the wait.
 * Required by Go: its netpoller calls epoll_pwait2 (441) and falls back to
 * epoll_pwait (281). Aegis implemented only epoll_wait (232), so the netpoller
 * could not initialise and every network operation blocked forever — a Go
 * server would start, serve nothing, and accept nothing.
 *
 * The sigmask is REFUSED rather than ignored when non-NULL. Silently dropping
 * it would be an authority-shape lie of the same kind as the *at flags: the
 * caller believes those signals cannot interrupt the wait, and they would.
 * Go always passes NULL, so this costs it nothing, and a caller that genuinely
 * wants atomic mask-and-wait gets a clear ENOSYS instead of a wait that
 * quietly does not honour its mask.
 */
uint64_t
sys_epoll_pwait(uint64_t epfd, uint64_t events_ptr, uint64_t maxevents,
                uint64_t timeout_ms, uint64_t sigmask)
{
    if (sigmask != 0)
        return SYS_ERR(ENOSYS);   /* atomic mask-and-wait not implemented */
    return sys_epoll_wait(epfd, events_ptr, maxevents, timeout_ms);
}

uint64_t
sys_epoll_pwait2(uint64_t epfd, uint64_t events_ptr, uint64_t maxevents,
                 uint64_t ts_ptr, uint64_t sigmask)
{
    if (sigmask != 0)
        return SYS_ERR(ENOSYS);

    /* epoll_pwait2 takes a `const struct timespec *`, not milliseconds.
     * NULL means block indefinitely. */
    uint64_t timeout_ms;
    if (ts_ptr == 0) {
        timeout_ms = (uint64_t)-1;
    } else {
        struct { int64_t tv_sec; int64_t tv_nsec; } ts;
        if (!user_ptr_valid(ts_ptr, sizeof(ts)))
            return SYS_ERR(EFAULT);
        if (copy_from_user(&ts, (const void *)(uintptr_t)ts_ptr, sizeof(ts)) != 0)
            return SYS_ERR(EFAULT);
        if (ts.tv_sec < 0 || ts.tv_nsec < 0 || ts.tv_nsec >= 1000000000L)
            return SYS_ERR(EINVAL);
        /* Clamp rather than overflow: a caller asking for a ~300-million-year
         * timeout gets the longest finite wait we can express, not a wrapped
         * tiny one. */
        if (ts.tv_sec > 4000000LL)
            timeout_ms = (uint64_t)-1;
        else
            timeout_ms = (uint64_t)ts.tv_sec * 1000ULL +
                         (uint64_t)(ts.tv_nsec / 1000000L);
    }
    return sys_epoll_wait(epfd, events_ptr, maxevents, timeout_ms);
}
