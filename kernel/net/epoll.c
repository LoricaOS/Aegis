/* kernel/net/epoll.c — epoll implementation */
#include "epoll.h"
#include "proc.h"
#include "vfs.h"
#include "uaccess.h"
#include "syscall_util.h"   /* user_ptr_valid */
#include "arch.h"
#include "printk.h"
#include "spinlock.h"
#include "waitq.h"
#include "fd_waitq.h"
#include "socket.h"
#include "tcp.h"
#include "signal.h"
#include "../lib/refcount.h"
#include "fd_resolve.h"
#include "../include/aegis_errno.h"
#include <stdint.h>

static epoll_fd_t s_epoll[EPOLL_MAX_INSTANCES];
static spinlock_t epoll_lock = SPINLOCK_INIT;

/* ── epoll VFS ops ───────────────────────────────────────────────────────── */

static void epoll_vfs_close(void *priv)
{
    /* Drop this fd's reference; free the instance only on the last close.
     * dup/fork share the slot, so an unconditional epoll_free here double-freed
     * it and handed a reused slot to the surviving fd (same UAF class as
     * sock_t). The decrement runs under epoll_lock (the lock that serialises
     * epoll_free), then we drop the lock before epoll_free re-takes it — safe,
     * epoll_free re-checks bounds/in_use itself. */
    uint32_t id = (uint32_t)(uintptr_t)priv;
    irqflags_t fl = spin_lock_irqsave(&epoll_lock);
    if (id >= EPOLL_MAX_INSTANCES || !s_epoll[id].in_use) {
        spin_unlock_irqrestore(&epoll_lock, fl);
        return;  /* already gone */
    }
    bool last = refcount_dec_and_test(&s_epoll[id].refcount);
    spin_unlock_irqrestore(&epoll_lock, fl);
    if (last)
        epoll_free(id);
}

static void epoll_vfs_dup(void *priv)
{
    /* A second fd now points at this instance (dup/dup2/fcntl F_DUPFD, or fork
     * via fd_table_copy). Take another reference under epoll_lock — the same
     * lock that serialises epoll_free — so the slot cannot go free across the
     * inc. Mirrors sock_vfs_dup / unix_vfs_dup. */
    uint32_t id = (uint32_t)(uintptr_t)priv;
    irqflags_t fl = spin_lock_irqsave(&epoll_lock);
    if (id < EPOLL_MAX_INSTANCES && s_epoll[id].in_use)
        refcount_inc(&s_epoll[id].refcount);
    spin_unlock_irqrestore(&epoll_lock, fl);
}

/*
 * epoll_vfs_poll — readiness of an epoll fd itself (nested epoll). Aegis does
 * not implement nested epoll readiness (it would require a recursive sweep
 * with cycle detection). We deliberately report 0 (never ready) rather than
 * inherit the permissive POLLIN|POLLOUT default: the default would make an
 * OUTER epoll/poll spin (always "readable"), which is strictly worse than a
 * benign "no events". If real nested-epoll support is ever needed, implement
 * a recursive ready-count here with a depth guard.
 */
static uint16_t epoll_vfs_poll(void *priv)
{
    (void)priv;
    return 0;
}

static const vfs_ops_t s_epoll_ops = {
    .read    = (void *)0,
    .write   = (void *)0,
    .close   = epoll_vfs_close,
    .readdir = (void *)0,
    .dup     = epoll_vfs_dup,
    .stat    = (void *)0,
    .poll    = epoll_vfs_poll,
};

/* ── Public API ─────────────────────────────────────────────────────────── */

int epoll_alloc(void)
{
    irqflags_t fl = spin_lock_irqsave(&epoll_lock);
    uint32_t i;
    for (i = 0; i < EPOLL_MAX_INSTANCES; i++) {
        if (!s_epoll[i].in_use) {
            __builtin_memset(&s_epoll[i], 0, sizeof(s_epoll[i]));
            s_epoll[i].in_use = 1;
            /* One reference for the creating fd (memset zeroed the count). */
            refcount_init(&s_epoll[i].refcount, 1);
            spin_unlock_irqrestore(&epoll_lock, fl);
            return (int)i;
        }
    }
    spin_unlock_irqrestore(&epoll_lock, fl);
    return -1;
}

epoll_fd_t *epoll_get(uint32_t epoll_id)
{
    irqflags_t fl = spin_lock_irqsave(&epoll_lock);
    if (epoll_id >= EPOLL_MAX_INSTANCES) {
        spin_unlock_irqrestore(&epoll_lock, fl);
        return (epoll_fd_t *)0;
    }
    if (!s_epoll[epoll_id].in_use) {
        spin_unlock_irqrestore(&epoll_lock, fl);
        return (epoll_fd_t *)0;
    }
    epoll_fd_t *ep = &s_epoll[epoll_id];
    spin_unlock_irqrestore(&epoll_lock, fl);
    return ep;
}

void epoll_free(uint32_t epoll_id)
{
    irqflags_t fl = spin_lock_irqsave(&epoll_lock);
    if (epoll_id >= EPOLL_MAX_INSTANCES) {
        spin_unlock_irqrestore(&epoll_lock, fl);
        return;
    }
    s_epoll[epoll_id].in_use = 0;
    spin_unlock_irqrestore(&epoll_lock, fl);
}

int epoll_ctl_impl(uint32_t epoll_id, int op, int fd, k_epoll_event_t *ev)
{
    epoll_fd_t *ep = epoll_get(epoll_id);
    if (!ep) return -EBADF;

    /*
     * The watches[]/nwatches mutation MUST run under epoll_lock: epoll_wait_impl
     * snapshots the same watches[] array (and writes back oneshot_disabled)
     * under epoll_lock, and on SMP a concurrent epoll_ctl on another CPU would
     * be a data race. The entire body holds the lock — it is inversion-free
     * because nothing here takes another lock or blocks: `ev` is a kernel-side
     * copy (sys_epoll_ctl already did copy_from_user), the only writes are to
     * the static s_epoll[] array, and there is no sched_wake / waitq /
     * fault-prone access inside the region. Every return path releases the lock.
     */
    irqflags_t fl = spin_lock_irqsave(&epoll_lock);

    if (op == EPOLL_CTL_ADD) {
        if (ep->nwatches >= EPOLL_MAX_WATCHES) {
            spin_unlock_irqrestore(&epoll_lock, fl);
            return -ENOMEM;
        }
        uint8_t i;
        for (i = 0; i < EPOLL_MAX_WATCHES; i++) {
            if (ep->watches[i].in_use && ep->watches[i].fd == (uint32_t)fd) {
                spin_unlock_irqrestore(&epoll_lock, fl);
                return -EEXIST;
            }
        }
        /* Find a free slot */
        for (i = 0; i < EPOLL_MAX_WATCHES; i++) {
            if (!ep->watches[i].in_use) {
                ep->watches[i].fd               = (uint32_t)fd;
                ep->watches[i].events           = ev->events;
                ep->watches[i].data             = ev->data;
                ep->watches[i].in_use           = 1;
                ep->watches[i].oneshot_disabled = 0;
                ep->nwatches++;
                spin_unlock_irqrestore(&epoll_lock, fl);
                return 0;
            }
        }
        spin_unlock_irqrestore(&epoll_lock, fl);
        return -ENOMEM;
    }

    if (op == EPOLL_CTL_DEL || op == EPOLL_CTL_MOD) {
        uint8_t i;
        for (i = 0; i < EPOLL_MAX_WATCHES; i++) {
            if (ep->watches[i].in_use && ep->watches[i].fd == (uint32_t)fd) {
                if (op == EPOLL_CTL_DEL) {
                    ep->watches[i].in_use = 0;
                    ep->nwatches--;
                } else {
                    ep->watches[i].events = ev->events;
                    ep->watches[i].data   = ev->data;
                    /* EPOLL_CTL_MOD re-arms a one-shot watch (Linux: a
                     * disabled EPOLLONESHOT fd is re-enabled by MOD). */
                    ep->watches[i].oneshot_disabled = 0;
                }
                spin_unlock_irqrestore(&epoll_lock, fl);
                return 0;
            }
        }
        spin_unlock_irqrestore(&epoll_lock, fl);
        return -ENOENT;
    }

    spin_unlock_irqrestore(&epoll_lock, fl);
    return -EINVAL;
}

/*
 * epoll_notify — legacy notification hook, retained for ABI compatibility
 * with the TCP/UDP producers that call it (tcp.c, udp.c).
 *
 * HISTORICAL BUG (fixed by the on-demand rewrite below): the old body
 * compared the producer-supplied *sock_id* against watches[].fd, which
 * stores the *userspace fd number*. Those two namespaces are unrelated, so
 * the match almost never fired — AF_INET sockets were effectively never
 * reported ready by epoll except by coincidence (fd == sock_id). It also
 * pushed the matched watch index into a ready[] array that epoll_wait_impl
 * then indexed even for watches that had since been EPOLL_CTL_DEL'd
 * (stale-index UAF-class bug).
 *
 * The rewrite makes epoll readiness *pull-based*: epoll_wait_impl recomputes
 * each watched fd's readiness from live object state on every call (Linux
 * level-triggered semantics). Wakeup of a blocked epoll_wait is handled
 * authoritatively by the per-fd waitq (each producer already calls
 * waitq_wake_all on its object's poll_waiters / read_waiters / write_waiters,
 * and epoll_wait_impl registers on every watched fd's waitq before blocking).
 *
 * Therefore epoll_notify no longer needs to do anything: the waitq wake that
 * accompanies every producer-side epoll_notify call already unblocks the
 * waiter, and the waiter recomputes readiness itself. Kept as a no-op rather
 * than removed so the producers compile unchanged and so future direct-wake
 * optimisations have a hook. Do NOT reintroduce the sock_id-vs-fd match or a
 * ready[] index array here.
 */
void epoll_notify(uint32_t sock_id, uint32_t events)
{
    (void)sock_id;
    (void)events;
}

/*
 * epoll_compute_readiness — return the live readiness bitmask for one
 * watched fd, in EPOLL* terms. Mirrors the sys_poll readiness logic, with
 * the nonblocking-connect fixes (CONNECTING is not yet writable; a connect
 * that failed → CLOSED reports EPOLLOUT|EPOLLERR|EPOLLHUP so the event loop
 * wakes and reads SO_ERROR).
 *
 * Called WITHOUT epoll_lock held: it acquires sock_lock / tcp_lock /
 * per-object locks via sock_get / tcp_conn_get / tcp_conn_recv / ops->poll,
 * and epoll_lock must never be held across those (lock ordering + blocking).
 *
 * Returns raw readiness bits (EPOLLIN/OUT/ERR/HUP/RDHUP). The caller masks
 * against the watch's interest set.
 */
static uint32_t
epoll_compute_readiness(uint32_t fd, aegis_process_t *proc)
{
    /* AF_INET sockets carry a vfs_ops_t (s_sock_ops) whose .poll is
     * sock_vfs_poll — the single source of truth for AF_INET readiness, shared
     * with sys_poll. It returns POLL* bits, which share values with EPOLL*
     * (IN=1, OUT=4, ERR=8, HUP=0x10, RDHUP=0x2000). So sockets fall through to
     * the generic ops->poll path below, exactly like AF_UNIX/pipe/tty/memfd.
     * This replaced a near-identical inline block that had already diverged
     * from sys_poll on CLOSE_WAIT/HUP semantics. */

    /* VFS fd — AF_INET / AF_UNIX sockets, pipe, tty, console, memfd, etc. */
    if (fd < PROC_MAX_FDS && proc->fd_table->fds[fd].ops) {
        const vfs_ops_t *ops = proc->fd_table->fds[fd].ops;
        if (ops->poll) {
            /* ops->poll returns POLL* bits, which share values with the
             * EPOLL* readiness bits (IN=1, OUT=4, ERR=8, HUP=0x10). */
            return (uint32_t)ops->poll(proc->fd_table->fds[fd].priv);
        }
        /* No .poll callback — treat as always ready for IN/OUT (permissive
         * default, matching sys_poll). */
        return EPOLLIN | EPOLLOUT;
    }

    /* fd not a socket and not an open VFS fd → invalid. epoll on Linux
     * reports EPOLLERR for such; the watch will keep firing until DEL'd. */
    return EPOLLERR;
}

int epoll_wait_impl(uint32_t epoll_id, uint64_t events_uptr,
                    int maxevents, uint32_t timeout_ticks)
{
    epoll_fd_t *ep = epoll_get(epoll_id);
    if (!ep) return -EBADF;
    if (maxevents <= 0) return -EINVAL;

    aegis_process_t *proc = current_proc();

    /* Deadline in absolute ticks. arch_get_ticks() is a 64-bit monotonic
     * counter at 100 Hz; keep the whole 64-bit value so the comparison can
     * never wrap inside any realistic timeout. */
    uint64_t now0 = arch_get_ticks();
    uint64_t deadline = 0;
    uint8_t  has_deadline = 0;
    if (timeout_ticks != 0 && timeout_ticks != 0xFFFFFFFFU) {
        deadline = now0 + (uint64_t)timeout_ticks;
        has_deadline = 1;
    }

    for (;;) {
        /*
         * Phase 1: snapshot the watch list under epoll_lock, then compute
         * readiness with the lock released (sock/tcp/vfs poll take their own
         * locks; epoll_lock must not be held across them). We snapshot fd,
         * events, data and the slot index so EPOLLONESHOT disarm + delivery
         * can write back safely afterwards.
         */
        struct {
            uint8_t  slot;
            uint32_t fd;
            uint32_t events;
            uint64_t data;
        } snap[EPOLL_MAX_WATCHES];
        int nsnap = 0;

        irqflags_t efl = spin_lock_irqsave(&epoll_lock);
        for (uint8_t w = 0; w < EPOLL_MAX_WATCHES; w++) {
            if (!ep->watches[w].in_use) continue;
            if (ep->watches[w].oneshot_disabled) continue;
            snap[nsnap].slot   = w;
            snap[nsnap].fd     = ep->watches[w].fd;
            snap[nsnap].events = ep->watches[w].events;
            snap[nsnap].data   = ep->watches[w].data;
            nsnap++;
        }
        spin_unlock_irqrestore(&epoll_lock, efl);

        /* Re-validate the user events buffer on EVERY iteration, not just once
         * in the sys_epoll_wait wrapper. epoll_wait is the kernel's
         * longest-blocking syscall; between the wrapper's check and a post-block
         * copy_to_user here, a sibling thread (CLONE_VM — e.g. a multithreaded
         * client) can munmap the buffer. copy_to_user is a raw memcpy with no
         * fault fixup, so writing to the now-unmapped page would #PF in ring 0
         * and panic the kernel. Re-checking before each delivery sweep closes
         * that TOCTOU (cheap: one page-table walk per wake). */
        if (!user_ptr_valid(events_uptr,
                            (uint64_t)maxevents * sizeof(k_epoll_event_t)))
            return -EFAULT;

        /* Phase 2: compute readiness + deliver matching events. */
        int delivered = 0;
        for (int i = 0; i < nsnap && delivered < maxevents; i++) {
            uint32_t ready = epoll_compute_readiness(snap[i].fd, proc);
            /* Linux always reports EPOLLERR/EPOLLHUP if present; EPOLLRDHUP
             * and the rest only if the caller asked for them. */
            uint32_t interest = (snap[i].events & ~EPOLL_BEHAVIOUR_FLAGS)
                              | EPOLL_ALWAYS_REPORT;
            uint32_t revents = ready & interest;
            if (!revents) continue;

            k_epoll_event_t kev;
            /* Linux returns the readiness bits in .events, NOT the interest
             * mask; .data round-trips the user's cookie unchanged. */
            kev.events = revents;
            kev.data   = snap[i].data;
            /* copy_to_user returns void — no fault recovery without extable. */
            copy_to_user((void *)(uintptr_t)(events_uptr +
                         (uint64_t)delivered * sizeof(k_epoll_event_t)),
                         &kev, sizeof(kev));
            delivered++;

            /* EPOLLONESHOT: disarm the watch after the first delivery. The
             * slot may have been DEL'd/MOD'd while the lock was dropped, so
             * re-validate fd + in_use before mutating. */
            if (snap[i].events & EPOLLONESHOT) {
                irqflags_t dfl = spin_lock_irqsave(&epoll_lock);
                uint8_t wslot = snap[i].slot;
                if (ep->watches[wslot].in_use &&
                    ep->watches[wslot].fd == snap[i].fd)
                    ep->watches[wslot].oneshot_disabled = 1;
                spin_unlock_irqrestore(&epoll_lock, dfl);
            }
            /* EPOLLET (edge-triggered): note. We recompute readiness from
             * live state every call, so a level condition that persists
             * (e.g. unread data) is reported again on the next epoll_wait
             * even with EPOLLET set. True edge semantics would require
             * remembering the last-reported state per watch and only
             * reporting transitions; we do not, so EPOLLET degrades to
             * level-triggered. This is safe (never misses an event, may
             * over-report) but a real consumer relying on ET to suppress
             * repeats will see extra wakeups. Documented limitation. */
        }

        if (delivered > 0)
            return delivered;

        /* Nothing ready. */
        if (timeout_ticks == 0)
            return 0;  /* non-blocking poll */
        if (has_deadline && arch_get_ticks() >= deadline)
            return 0;  /* timed out */

        /*
         * Phase 3: block. Register on each watched fd's waitq (and the timer
         * waitq if a deadline is set) BEFORE the final readiness re-check is
         * implied by the loop, so a producer that signals readiness after our
         * Phase-2 sweep but before sched_block still finds our entry and wakes
         * us (no lost wakeup). waitq_add/remove take each queue's own leaf
         * lock; we hold no other lock here.
         *
         * We do NOT use ep->waiter_task for wakeup anymore — the waitq path is
         * authoritative and race-free, and a single waiter_task slot could not
         * support multiple concurrent epoll_wait callers anyway.
         */
        waitq_entry_t fd_entries[EPOLL_MAX_WATCHES];
        waitq_t      *fd_queues[EPOLL_MAX_WATCHES];
        waitq_entry_t timer_entry;
        int n = 0;

        for (int i = 0; i < nsnap; i++) {
            fd_queues[n]           = fd_get_waitq((int)snap[i].fd);
            fd_entries[n].task     = sched_current();
            fd_entries[n].next     = (void *)0;
            fd_entries[n].prev     = (void *)0;
            fd_entries[n].on_queue = 0;
            if (fd_queues[n]) waitq_add(fd_queues[n], &fd_entries[n]);
            n++;
        }
        if (has_deadline) {
            timer_entry.task     = sched_current();
            timer_entry.next     = (void *)0;
            timer_entry.prev     = (void *)0;
            timer_entry.on_queue = 0;
            waitq_add(&g_timer_waitq, &timer_entry);
        }

        /*
         * Interruptibility: if a signal is pending that will run a handler or
         * terminate the process, abandon the wait and return -EINTR. This check
         * must happen AFTER the waitq registrations above and BEFORE
         * sched_block(), and it must unregister every entry we just added so the
         * EINTR exit leaks no waitq entry (the entries are stack-allocated and
         * would dangle on the queues after we return). Mirror the post-block
         * unregister bracket exactly.
         */
        if (signal_check_pending()) {
            for (int i = 0; i < n; i++)
                if (fd_queues[i]) waitq_remove(fd_queues[i], &fd_entries[i]);
            if (has_deadline) waitq_remove(&g_timer_waitq, &timer_entry);
            return -EINTR;
        }

        sched_block();

        for (int i = 0; i < n; i++)
            if (fd_queues[i]) waitq_remove(fd_queues[i], &fd_entries[i]);
        if (has_deadline) waitq_remove(&g_timer_waitq, &timer_entry);

        /* Loop: recompute readiness after wake. */
    }
}

int epoll_open_fd(uint32_t epoll_id, aegis_process_t *proc)
{
    uint32_t fd;
    for (fd = 0; fd < PROC_MAX_FDS; fd++) {
        if (!proc->fd_table->fds[fd].ops) {
            proc->fd_table->fds[fd].ops    = &s_epoll_ops;
            proc->fd_table->fds[fd].priv   = (void *)(uintptr_t)epoll_id;
            proc->fd_table->fds[fd].offset = 0;
            proc->fd_table->fds[fd].size   = 0;
            proc->fd_table->fds[fd].flags  = 0;
            return (int)fd;
        }
    }
    return -1;
}

uint32_t epoll_id_from_fd(int fd, aegis_process_t *proc)
{
    vfs_file_t *f = fd_resolve(proc, fd, &s_epoll_ops);
    return f ? (uint32_t)(uintptr_t)f->priv : EPOLL_NONE;
}
