/* kernel/net/unix_socket.c — AF_UNIX domain sockets */
#include "unix_socket.h"
#include "../lib/string.h"
#include "trace.h"
#include "proc.h"
#include "printk.h"
#include "kva.h"
#include "spinlock.h"
#include "signal.h"
#include "../sched/wait_event.h"
#include "../fs/fd_resolve.h"
#include "../include/aegis_errno.h"
#include <stdint.h>

/* ── Static tables ─────────────────────────────────────────────────────── */

static unix_sock_t s_unix[UNIX_SOCK_MAX];
static spinlock_t  unix_lock = SPINLOCK_INIT;

/* Name table: path → sock_id for bound sockets */
#define UNIX_NAME_MAX 32
typedef struct {
    char     path[UNIX_PATH_MAX];
    uint32_t sock_id;
    uint8_t  in_use;
} unix_name_t;

static unix_name_t s_names[UNIX_NAME_MAX];

/* ── Local helpers ─────────────────────────────────────────────────────── */


static int _streq(const char *a, const char *b)
{
    while (*a && *a == *b) { a++; b++; }
    return *a == *b;
}

static void _strcpy(char *dst, const char *src, uint32_t max)
{
    uint32_t i = 0;
    while (i < max - 1 && src[i]) { dst[i] = src[i]; i++; }
    dst[i] = '\0';
}

static uint16_t ring_used(unix_sock_t *s)
{
    return (uint16_t)((s->ring_head - s->ring_tail) & (UNIX_BUF_SIZE - 1));
}

static uint16_t ring_free(unix_sock_t *s)
{
    return (uint16_t)(UNIX_BUF_SIZE - 1 - ring_used(s));
}

/* ── Name table ────────────────────────────────────────────────────────── */

static int name_register(const char *path, uint32_t sock_id)
{
    for (int i = 0; i < UNIX_NAME_MAX; i++) {
        if (s_names[i].in_use && _streq(s_names[i].path, path))
            return -EADDRINUSE;
    }
    for (int i = 0; i < UNIX_NAME_MAX; i++) {
        if (!s_names[i].in_use) {
            _strcpy(s_names[i].path, path, UNIX_PATH_MAX);
            s_names[i].sock_id = sock_id;
            s_names[i].in_use  = 1;
            return 0;
        }
    }
    return -ENOSPC;
}

static void name_unregister(const char *path)
{
    for (int i = 0; i < UNIX_NAME_MAX; i++) {
        if (s_names[i].in_use && _streq(s_names[i].path, path)) {
            s_names[i].in_use = 0;
            return;
        }
    }
}

static uint32_t name_lookup(const char *path)
{
    for (int i = 0; i < UNIX_NAME_MAX; i++) {
        if (s_names[i].in_use && _streq(s_names[i].path, path))
            return s_names[i].sock_id;
    }
    return UNIX_NONE;
}

/* ── VFS ops ───────────────────────────────────────────────────────────── */

/* VFS read/write ops receive user-space pointers from sys_read/sys_write.
 * With SMAP enabled, the kernel cannot access them directly. Bounce
 * through a stack buffer, same pattern as pipe and console VFS ops. */

#include "uaccess.h"

static int unix_vfs_read(void *priv, void *buf, uint64_t off, uint64_t len)
{
    (void)off;
    uint32_t id = (uint32_t)(uintptr_t)priv;
    uint8_t kbuf[1024];
    uint32_t want = (uint32_t)len;
    if (want > 1024) want = 1024;
    int n = unix_sock_read(id, kbuf, want, 0);  /* read() honors us->nonblocking */
    if (n > 0)
        copy_to_user(buf, kbuf, (uint32_t)n);
    return n;
}

static int unix_vfs_write(void *priv, const void *buf, uint64_t len)
{
    uint32_t id = (uint32_t)(uintptr_t)priv;
    uint8_t kbuf[1024];
    uint32_t want = (uint32_t)len;
    if (want > 1024) want = 1024;
    copy_from_user(kbuf, buf, want);
    return unix_sock_write(id, kbuf, want);
}

static void unix_vfs_close(void *priv)
{
    uint32_t id = (uint32_t)(uintptr_t)priv;
    unix_sock_free(id);
}

static void unix_vfs_dup(void *priv)
{
    uint32_t id = (uint32_t)(uintptr_t)priv;
    irqflags_t fl = spin_lock_irqsave(&unix_lock);
    if (id < UNIX_SOCK_MAX && s_unix[id].in_use)
        refcount_inc(&s_unix[id].refcount);
    spin_unlock_irqrestore(&unix_lock, fl);
}

static int unix_vfs_stat(void *priv, k_stat_t *st)
{
    (void)priv;
    kmemset(st, 0, sizeof(*st));
    st->st_mode = 0140000U | 0666U;  /* S_IFSOCK | 0666 */
    st->st_blksize = 4096;
    return 0;
}

static struct waitq *
unix_vfs_get_waitq(void *priv)
{
    uint32_t id = (uint32_t)(uintptr_t)priv;
    return unix_sock_get_waitq(id);
}

static uint16_t unix_vfs_poll(void *priv)
{
    uint32_t id = (uint32_t)(uintptr_t)priv;
    irqflags_t fl = spin_lock_irqsave(&unix_lock);
    unix_sock_t *us = unix_sock_get(id);
    if (!us) { spin_unlock_irqrestore(&unix_lock, fl); return 0; }

    uint16_t events = 0;

    switch (us->state) {
    case UNIX_LISTENING:
        if (us->accept_head != us->accept_tail)
            events |= 1;  /* POLLIN: pending connection */
        break;
    case UNIX_CONNECTED: {
        uint32_t peer_id = us->peer_id;
        unix_sock_t *peer = (peer_id != UNIX_NONE) ? unix_sock_get(peer_id) : (void *)0;
        if (peer && peer->ring_head != peer->ring_tail)
            events |= 1;  /* POLLIN: data in peer's tx ring */
        /* POLLOUT iff our tx ring has free space. The old test
         * `(uint16_t)(head - tail) < UNIX_BUF_SIZE` was always true: the
         * unmasked difference never exceeds UNIX_BUF_SIZE-1 (writes are
         * bounded by ring_free), so a *full* ring (ring_free()==0) still
         * reported POLLOUT — a poller waiting to write spun on a false
         * "writable" or, worse, raced an EAGAIN after select said go.
         * Use ring_free() so a full ring correctly clears POLLOUT. */
        if (peer && peer->state != UNIX_CLOSED && ring_free(us) > 0)
            events |= 4;  /* POLLOUT: space in our tx ring */
        if (!peer || peer->state == UNIX_CLOSED)
            events |= 16; /* POLLHUP: peer disconnected */
        break;
    }
    case UNIX_CLOSED:
        events |= 16; /* POLLHUP */
        break;
    default:
        events |= 4;  /* POLLOUT: writable (not yet connected) */
        break;
    }

    spin_unlock_irqrestore(&unix_lock, fl);
    return events;
}

const vfs_ops_t g_unix_sock_ops = {
    .read       = unix_vfs_read,
    .write      = unix_vfs_write,
    .close      = unix_vfs_close,
    .readdir    = (void *)0,
    .dup        = unix_vfs_dup,
    .stat       = unix_vfs_stat,
    .poll       = unix_vfs_poll,
    .get_waitq  = unix_vfs_get_waitq,
};

/* ── Alloc / Get / Free ────────────────────────────────────────────────── */

int unix_sock_alloc(void)
{
    /* Any ring freed here is freed AFTER dropping unix_lock: kva_free_pages
     * issues a cross-CPU TLB shootdown, and a CPU spinning for unix_lock with
     * IRQs disabled (e.g. unix_sock_read) can't ACK the shootdown IPI — doing
     * the free under the lock deadlocks the whole machine. */
    void *orphan = (void *)0;
    int ret = -1;
    irqflags_t fl = spin_lock_irqsave(&unix_lock);
    for (int i = 0; i < UNIX_SOCK_MAX; i++) {
        if (!s_unix[i].in_use) {
            orphan = s_unix[i].ring;   /* orphaned ring from a prior connection */
            kmemset(&s_unix[i], 0, sizeof(unix_sock_t));
            s_unix[i].in_use   = 1;
            s_unix[i].state    = UNIX_CREATED;
            s_unix[i].peer_id  = UNIX_NONE;
            refcount_init(&s_unix[i].refcount, 1);
            waitq_init(&s_unix[i].poll_waiters);
            ret = i;
            break;
        }
    }
    spin_unlock_irqrestore(&unix_lock, fl);
    if (orphan) kva_free_pages(orphan, UNIX_BUF_PAGES);
    return ret;
}

unix_sock_t *unix_sock_get(uint32_t id)
{
    if (id >= UNIX_SOCK_MAX) return (void *)0;
    if (!s_unix[id].in_use) return (void *)0;
    return &s_unix[id];
}

/* unix_sock_pair — create two pre-connected AF_UNIX stream sockets (socketpair).
 * Mirrors the connect/accept setup: each socket owns a tx ring the PEER reads
 * from, both CONNECTED, cross-linked by peer_id.  Returns 0 and sets the two out
 * params to the two sock ids, or a negative errno.  Replaces the old (wrong)
 * socketpair
 * that handed back AF_INET DGRAM loopback sockets — those routed send() through
 * the UDP path and died with ENETDOWN when there was no NIC, silently breaking
 * every IPC transport (Ladybird's send_thread). */
int unix_sock_pair(uint32_t *a, uint32_t *b)
{
    int id0 = unix_sock_alloc();
    if (id0 < 0) return -EMFILE;
    int id1 = unix_sock_alloc();
    if (id1 < 0) { unix_sock_free((uint32_t)id0); return -EMFILE; }

    /* One tx ring per direction (kva_alloc_pages may sleep — no lock held). */
    uint8_t *ring0 = (uint8_t *)kva_alloc_pages(UNIX_BUF_PAGES);  /* id0 writes; id1 reads */
    uint8_t *ring1 = (uint8_t *)kva_alloc_pages(UNIX_BUF_PAGES);  /* id1 writes; id0 reads */
    if (!ring0 || !ring1) {
        if (ring0) kva_free_pages(ring0, UNIX_BUF_PAGES);
        if (ring1) kva_free_pages(ring1, UNIX_BUF_PAGES);
        unix_sock_free((uint32_t)id0);
        unix_sock_free((uint32_t)id1);
        return -ENOMEM;
    }

    irqflags_t fl = spin_lock_irqsave(&unix_lock);
    unix_sock_t *s0 = &s_unix[id0];
    unix_sock_t *s1 = &s_unix[id1];
    s0->state = UNIX_CONNECTED; s0->peer_id = (uint32_t)id1;
    s0->ring = ring0; s0->ring_head = 0; s0->ring_tail = 0;
    s1->state = UNIX_CONNECTED; s1->peer_id = (uint32_t)id0;
    s1->ring = ring1; s1->ring_head = 0; s1->ring_tail = 0;
    {
        aegis_process_t *proc = current_proc();
        s0->peer_pid = s1->peer_pid = (uint32_t)proc->pid;
        s0->peer_uid = s1->peer_uid = (uint32_t)proc->uid;
        s0->peer_gid = s1->peer_gid = (uint32_t)proc->gid;
    }
    spin_unlock_irqrestore(&unix_lock, fl);

    *a = (uint32_t)id0;
    *b = (uint32_t)id1;
    return 0;
}

void unix_sock_free(uint32_t id)
{
    irqflags_t fl = spin_lock_irqsave(&unix_lock);
    if (id >= UNIX_SOCK_MAX || !s_unix[id].in_use) {
        spin_unlock_irqrestore(&unix_lock, fl);
        return;
    }
    unix_sock_t *us = &s_unix[id];
    if (!refcount_dec_and_test(&us->refcount)) {
        spin_unlock_irqrestore(&unix_lock, fl);
        return;
    }

    /* Close any staged fds that were never received */
    for (uint8_t i = 0; i < us->passed_fd_count; i++) {
        if (us->passed_fds[i].ops && us->passed_fds[i].ops->close)
            us->passed_fds[i].ops->close(us->passed_fds[i].priv);
    }
    us->passed_fd_count = 0;

    /* Unregister name if bound */
    if (us->path[0]) {
        name_unregister(us->path);
        us->path[0] = '\0';
    }

    uint32_t peer = us->peer_id;
    unix_sock_t *p = (peer != UNIX_NONE && peer < UNIX_SOCK_MAX &&
                      s_unix[peer].in_use) ? &s_unix[peer] : (void *)0;

    if (p && p->state != UNIX_CLOSED) {
        /* Peer still alive: LINGER. Keep this slot occupied (in_use=1,
         * state=UNIX_CLOSED) so the allocators cannot hand it to a new
         * connection while the peer's peer_id still references it. The
         * peer drains any remaining data from our ring and reads EOF
         * once it's empty (state==UNIX_CLOSED); both slots and rings
         * are fully released when the PEER closes (branch below).
         *
         * History: this slot used to be freed (in_use=0) immediately,
         * with EOF detected via !in_use. unix_sock_alloc could then
         * reuse the slot for a brand-new connection while the living
         * peer still pointed at it — the stale peer fd then read
         * (stole) the new connection's data. Hit deterministically by
         * the 1.2.0 Applications launcher (invoke-then-exit: Lumen's
         * not-yet-reaped server fd consumed the next client's
         * CREATE_WINDOW, hanging every post-launcher app spawn). */
        us->state = UNIX_CLOSED;
        /* Capture the peer's waitq, drop the lock, then wake: a blocked peer
         * (read/write) and the peer's pollers all live on poll_waiters and
         * re-check their condition (now state==UNIX_CLOSED → EOF/EPIPE/POLLHUP)
         * after the wait returns.  Wake AFTER unlock — waitq_wake_all takes
         * sched_lock and the order is sched_lock > waitq > unix_lock. */
        waitq_t *peer_wq = &p->poll_waiters;
        spin_unlock_irqrestore(&unix_lock, fl);
        waitq_wake_all(peer_wq);
        return;
    }

    /* Peer gone (never connected) or lingering in UNIX_CLOSED: fully
     * release this slot, the peer's lingering slot, and both rings. Detach the
     * rings under the lock but free them AFTER unlocking — kva_free_pages does
     * a TLB shootdown, which must never run while holding unix_lock (a CPU
     * spinning for unix_lock with IRQs off can't ACK the IPI → deadlock). */
    void *free_a = us->ring, *free_b = (void *)0;
    us->ring = (void *)0;
    if (p && p->state == UNIX_CLOSED) {
        free_b = p->ring;
        p->ring = (void *)0;
        p->in_use = 0;
    }
    us->in_use = 0;
    spin_unlock_irqrestore(&unix_lock, fl);
    if (free_a) kva_free_pages(free_a, UNIX_BUF_PAGES);
    if (free_b) kva_free_pages(free_b, UNIX_BUF_PAGES);
}

/* unix_sock_wake: wake everything blocked on this socket — blocking accept/
 * read/write (registered via wait_event) and sys_poll/sys_epoll_wait — by
 * waking the single poll_waiters queue.  A thin wrapper now that blocking I/O
 * and polling share one waitq.  Do NOT call under unix_lock (waitq_wake_all
 * takes sched_lock; order is sched_lock > waitq > unix_lock). */
void unix_sock_wake(uint32_t id)
{
    if (id >= UNIX_SOCK_MAX || !s_unix[id].in_use) return;
    waitq_wake_all(&s_unix[id].poll_waiters);
}

/* ── Bind ──────────────────────────────────────────────────────────────── */

int unix_sock_bind(uint32_t id, const char *path)
{
    irqflags_t fl = spin_lock_irqsave(&unix_lock);
    unix_sock_t *us = unix_sock_get(id);
    if (!us || us->state != UNIX_CREATED) {
        spin_unlock_irqrestore(&unix_lock, fl);
        return -EINVAL;
    }

    int rc = name_register(path, id);
    if (rc < 0) {
        spin_unlock_irqrestore(&unix_lock, fl);
        return rc;
    }

    _strcpy(us->path, path, UNIX_PATH_MAX);
    us->state = UNIX_BOUND;
    spin_unlock_irqrestore(&unix_lock, fl);
    return 0;
}

/* ── Listen ────────────────────────────────────────────────────────────── */

int unix_sock_listen(uint32_t id)
{
    irqflags_t fl = spin_lock_irqsave(&unix_lock);
    unix_sock_t *us = unix_sock_get(id);
    if (!us || us->state != UNIX_BOUND) {
        spin_unlock_irqrestore(&unix_lock, fl);
        return -EINVAL;
    }
    us->state = UNIX_LISTENING;
    spin_unlock_irqrestore(&unix_lock, fl);
    return 0;
}

/* ── Connect ───────────────────────────────────────────────────────────── */

int unix_sock_connect(uint32_t id, const char *path)
{
    irqflags_t fl = spin_lock_irqsave(&unix_lock);
    unix_sock_t *client = unix_sock_get(id);
    if (!client || client->state != UNIX_CREATED) {
        spin_unlock_irqrestore(&unix_lock, fl);
        return -EINVAL;
    }

    /* Look up listening socket */
    uint32_t listener_id = name_lookup(path);
    if (listener_id == UNIX_NONE) {
        spin_unlock_irqrestore(&unix_lock, fl);
        return -ECONNREFUSED;  /* silent: callers retry on this */
    }
    unix_sock_t *listener = unix_sock_get(listener_id);
    if (!listener || listener->state != UNIX_LISTENING) {
        spin_unlock_irqrestore(&unix_lock, fl);
        return -ECONNREFUSED;
    }

    /* Check accept queue capacity. accept_head/accept_tail are uint8_t
     * counters indexed into accept_queue[8] via `& 7`; the true number of
     * pending connections is the UNMASKED 8-bit difference (0..255), and the
     * 8-slot ring is full at 8. The old code masked the difference with `& 7`
     * BEFORE the `>= 8` test, so qlen was always in [0,7] and the check never
     * fired: the 9th concurrent connect computed head-tail==8 (`& 7`==0, looks
     * empty), wrote server_id into slot 0 over an un-accepted connection, and
     * advanced head — silently losing/leaking that earlier connection. Compare
     * the unmasked count against the real ring depth instead. */
    uint8_t qlen = (uint8_t)(listener->accept_head - listener->accept_tail);
    if (qlen >= 8) {
        spin_unlock_irqrestore(&unix_lock, fl);
        return -ECONNREFUSED;  /* queue full */
    }

    /* Allocate server-side socket */
    int server_id = -1;
    void *orphan = (void *)0;   /* prior connection's ring; freed after unlock */
    for (int i = 0; i < UNIX_SOCK_MAX; i++) {
        if (!s_unix[i].in_use) {
            orphan = s_unix[i].ring;
            kmemset(&s_unix[i], 0, sizeof(unix_sock_t));
            s_unix[i].in_use   = 1;
            s_unix[i].state    = UNIX_CONNECTED;
            s_unix[i].peer_id  = id;  /* points to client */
            refcount_init(&s_unix[i].refcount, 1);
            waitq_init(&s_unix[i].poll_waiters);
            server_id = i;
            break;
        }
    }
    if (server_id < 0) {
        spin_unlock_irqrestore(&unix_lock, fl);
        return -EMFILE;
    }

    /* Allocate ring buffers (one per direction). kva_alloc_pages can fail
     * (OOM) and may sleep/touch other allocators, so drop unix_lock across
     * it — the server slot is already reserved (in_use=1) so it can't be
     * stolen. */
    spin_unlock_irqrestore(&unix_lock, fl);
    /* Free the orphaned ring now that the lock is dropped (TLB shootdown must
     * not run under unix_lock — see unix_sock_alloc). */
    if (orphan) kva_free_pages(orphan, UNIX_BUF_PAGES);
    uint8_t *ring_a = (uint8_t *)kva_alloc_pages(UNIX_BUF_PAGES);  /* client→server */
    uint8_t *ring_b = (uint8_t *)kva_alloc_pages(UNIX_BUF_PAGES);  /* server→client */
    fl = spin_lock_irqsave(&unix_lock);

    /* Re-validate after the lock gap: another thread sharing this fd table
     * (CLONE_VM) could have closed the client fd, and the listener could have
     * stopped listening or been freed, while we were in kva_alloc_pages.
     * Re-resolve the listener by id (the cached pointer may now reference a
     * freed/reused slot). */
    client   = unix_sock_get(id);
    listener = unix_sock_get(listener_id);

    /* One unwind path for every post-gap failure (client gone / listener gone /
     * queue now full / ring OOM): free whatever rings we hold, release the
     * reserved server slot, leave the client untouched (still CREATED). */
    int fail = 0;
    if (!client || client->state != UNIX_CREATED)
        fail = -22;                                   /* EINVAL: client gone */
    else if (!listener || listener->state != UNIX_LISTENING)
        fail = -111;                                  /* ECONNREFUSED */
    else if ((uint8_t)(listener->accept_head - listener->accept_tail) >= 8)
        fail = -111;                                  /* ECONNREFUSED: full */
    else if (!ring_a || !ring_b)
        fail = -12;                                   /* ENOMEM */
    if (fail) {
        s_unix[server_id].ring   = (void *)0;
        s_unix[server_id].in_use = 0;  /* release the reserved slot */
        spin_unlock_irqrestore(&unix_lock, fl);
        /* Free the rings after unlocking (TLB shootdown — never under
         * unix_lock; see unix_sock_alloc). */
        if (ring_a) kva_free_pages(ring_a, UNIX_BUF_PAGES);
        if (ring_b) kva_free_pages(ring_b, UNIX_BUF_PAGES);
        return fail;
    }

    /* Client's tx_ring = ring the server reads from */
    client->ring      = ring_a;
    client->ring_head = 0;
    client->ring_tail = 0;

    /* Server's tx_ring = ring the client reads from */
    s_unix[server_id].ring      = ring_b;
    s_unix[server_id].ring_head = 0;
    s_unix[server_id].ring_tail = 0;

    /* Cross-link */
    client->peer_id = (uint32_t)server_id;
    client->state   = UNIX_CONNECTED;

    /* Capture client credentials into server-side socket */
    aegis_process_t *proc = current_proc();
    s_unix[server_id].peer_pid = (uint32_t)proc->pid;
    s_unix[server_id].peer_uid = proc->uid;
    s_unix[server_id].peer_gid = proc->gid;

    /* Capture server-side credentials into client socket
     * (will be the listener's process — available via accept caller).
     * For now set to 0, accept() will fill from accepting process. */
    client->peer_pid = 0;
    client->peer_uid = 0;
    client->peer_gid = 0;

    /* Enqueue server-side sock_id into listener's accept queue */
    listener->accept_queue[listener->accept_head & 7] = (uint32_t)server_id;
    listener->accept_head++;

    /* Wake whatever is parked on the listener — a blocking accept (registered
     * on poll_waiters via wait_event) and any sys_poll/epoll waiter (POLLIN
     * signals a pending accept).  Capture the waitq, drop the lock, then wake
     * (sched_lock > waitq > unix_lock); the woken accepter re-checks the queue
     * under unix_lock after the wait returns. */
    waitq_t *listener_wq = &listener->poll_waiters;
    spin_unlock_irqrestore(&unix_lock, fl);
    waitq_wake_all(listener_wq);
    return 0;
}

/* ── Accept ────────────────────────────────────────────────────────────── */

int unix_sock_accept(uint32_t id)
{
    irqflags_t fl = spin_lock_irqsave(&unix_lock);
    unix_sock_t *listener = unix_sock_get(id);
    if (!listener || listener->state != UNIX_LISTENING) {
        spin_unlock_irqrestore(&unix_lock, fl);
        return -EINVAL;
    }

    /* Block until accept queue non-empty */
    while (listener->accept_head == listener->accept_tail) {
        if (listener->nonblocking) {
            spin_unlock_irqrestore(&unix_lock, fl);
            return -EAGAIN;
        }
        /* Block on poll_waiters until a connection is queued.  Drop unix_lock
         * first — wait_event's condition is a lockless hint (re-validated
         * authoritatively under unix_lock at the top of this loop).  unix_lock
         * < sched_lock, so it must not be held across the block.  Interruptible
         * so a pending signal (handler or terminate) aborts with -EINTR.
         * wait_event registers on poll_waiters BEFORE re-checking the queue, so
         * a connection that lands in the gap is not lost. */
        spin_unlock_irqrestore(&unix_lock, fl);
        int rc;
        wait_event_interruptible(&listener->poll_waiters,
            listener->accept_head != listener->accept_tail, rc);
        if (rc == BLOCK_EINTR)
            return -EINTR;
        fl = spin_lock_irqsave(&unix_lock);
        listener = unix_sock_get(id);
        if (!listener || listener->state != UNIX_LISTENING) {
            spin_unlock_irqrestore(&unix_lock, fl);
            return -EBADF;
        }
    }

    /* Dequeue */
    uint32_t server_id = listener->accept_queue[listener->accept_tail & 7];
    listener->accept_tail++;

    /* Fill peer credentials from accepting process */
    aegis_process_t *proc = current_proc();
    unix_sock_t *server = unix_sock_get(server_id);
    if (server && server->peer_id != UNIX_NONE) {
        unix_sock_t *client = unix_sock_get(server->peer_id);
        if (client) {
            client->peer_pid = (uint32_t)proc->pid;
            client->peer_uid = proc->uid;
            client->peer_gid = proc->gid;
        }
    }

    spin_unlock_irqrestore(&unix_lock, fl);
    return (int)server_id;
}

/* ── Read (from peer's tx_ring) ────────────────────────────────────────── */

/* Lockless "read can make progress" hint for wait_event in unix_sock_read:
 * true once the peer has data to drain, has closed, or is gone (any of which
 * ends the block). Stale reads only cost one extra loop; the authoritative
 * re-check runs under unix_lock at the top of the read loop. Kept a plain
 * function (not a statement-expression) to stay clear of GCC extensions. */
static int unix_read_ready(uint32_t peer)
{
    unix_sock_t *p = (peer != UNIX_NONE && peer < UNIX_SOCK_MAX)
                     ? &s_unix[peer] : (void *)0;
    return !p || !p->in_use || !p->ring ||
           p->state == UNIX_CLOSED || ring_used(p) > 0;
}

int unix_sock_read(uint32_t id, void *buf, uint32_t len, int force_nb)
{
    if (len == 0) return 0;
    irqflags_t fl = spin_lock_irqsave(&unix_lock);
    unix_sock_t *us = unix_sock_get(id);
    if (!us || us->state != UNIX_CONNECTED) {
        spin_unlock_irqrestore(&unix_lock, fl);
        return us ? -EPIPE : -EBADF;
    }

    /* Pin this socket for the whole (possibly blocking) read. We hold unix_lock
     * and have validated `us` in_use, so the inc is race-free. Without it, a
     * sibling thread (CLONE_FILES shares the fd table) closing this same fd while
     * we are parked on s_unix[id].poll_waiters would drop the last ref, free the
     * slot, and unix_sock_alloc could re-init the waitq under our still-linked
     * waiter — a use-after-free. The matching unix_sock_free at every exit below
     * defers the real teardown to whichever putter is last. */
    refcount_inc(&us->refcount);

    uint32_t peer = us->peer_id;

    for (;;) {
        /* Read from PEER's tx_ring. A closed peer lingers in_use=1 with
         * state==UNIX_CLOSED (slot + ring kept alive, unallocatable)
         * until we close too — so the ring stays valid for draining and
         * the slot can never be reused out from under us. */
        unix_sock_t *p = (peer != UNIX_NONE && peer < UNIX_SOCK_MAX)
                         ? &s_unix[peer] : (void *)0;
        if (!p || !p->in_use || !p->ring) {
            /* Never connected / fully released — EOF */
            spin_unlock_irqrestore(&unix_lock, fl);
            unix_sock_free(id);   /* drop the read pin */
            return 0;
        }

        uint16_t avail = ring_used(p);
        if (avail > 0) {
            if (len > avail) len = avail;
            uint8_t *dst = (uint8_t *)buf;
            trace_emit(TRACE_UNIX_RECV, len, p->ring_head, p->ring_tail);
            /* Two-segment memcpy out of the power-of-two ring (was a byte loop).
             * ring_tail stays free-running; only the physical index wraps. */
            uint32_t toff  = p->ring_tail & (UNIX_BUF_SIZE - 1);
            uint32_t first = UNIX_BUF_SIZE - toff;
            if (first > len) first = len;
            __builtin_memcpy(dst, &p->ring[toff], first);
            if (first < len)
                __builtin_memcpy(dst + first, &p->ring[0], len - first);
            p->ring_tail += len;
            /* Draining the peer's tx ring frees space in it, so the peer
             * becomes writable (POLLOUT). Wake a peer blocked in write() AND
             * any peer poll()/epoll_wait() waiting for POLLOUT — both live on
             * the peer's poll_waiters now.  Capture the waitq, drop unix_lock,
             * then wake (sched_lock > waitq > unix_lock); the woken writer
             * re-validates ring_free under unix_lock. */
            waitq_t *peer_wq = &p->poll_waiters;
            spin_unlock_irqrestore(&unix_lock, fl);
            waitq_wake_all(peer_wq);
            unix_sock_free(id);   /* drop the read pin */
            return (int)len;
        }

        /* Empty — if peer closed (lingering), that's EOF: drained. */
        if (p->state == UNIX_CLOSED) {
            spin_unlock_irqrestore(&unix_lock, fl);
            unix_sock_free(id);   /* drop the read pin */
            return 0;  /* EOF */
        }
        /* Empty — block (unless the socket is O_NONBLOCK, or this call passed
         * force_nb for a per-call MSG_DONTWAIT recv — Ladybird's IPC drain loop
         * relies on MSG_DONTWAIT returning EAGAIN to terminate). */
        if (us->nonblocking || force_nb) {
            spin_unlock_irqrestore(&unix_lock, fl);
            unix_sock_free(id);   /* drop the read pin */
            return -EAGAIN;
        }
        /* Block on OUR poll_waiters until the peer writes data or closes — the
         * peer's writer/close paths wake us via this queue.  Drop unix_lock
         * first (unix_lock < sched_lock); wait_event registers BEFORE the cond
         * check so a write/close landing in the gap is not lost.  Interruptible:
         * a pending signal aborts with -EINTR (Linux returns EINTR from a read
         * that has transferred no bytes; this is the zero-bytes-so-far case).
         * The lockless cond mirrors the authoritative checks at the top of the
         * loop (data available, or peer closed/gone → EOF); it is re-validated
         * under unix_lock after the wait returns. */
        spin_unlock_irqrestore(&unix_lock, fl);
        int rc;
        wait_event_interruptible(&s_unix[id].poll_waiters,
            unix_read_ready(peer), rc);
        if (rc == BLOCK_EINTR) {
            unix_sock_free(id);   /* drop the read pin (lock already released) */
            return -EINTR;
        }
        fl = spin_lock_irqsave(&unix_lock);
        us = unix_sock_get(id);
        if (!us || us->state != UNIX_CONNECTED) {
            spin_unlock_irqrestore(&unix_lock, fl);
            unix_sock_free(id);   /* drop the read pin */
            return 0;  /* EOF */
        }
        peer = us->peer_id;
    }
}

/* ── Write (to own tx_ring, peer reads from it) ────────────────────────── */

/* Lockless "write can make progress" hint for wait_event in unix_sock_write:
 * true once our tx ring has free space, or the peer/connection is gone (EPIPE).
 * Stale reads only cost one extra loop; the authoritative re-check runs under
 * unix_lock at the top of the write loop. */
static int unix_write_ready(uint32_t id, uint32_t peer)
{
    unix_sock_t *us = (id < UNIX_SOCK_MAX) ? &s_unix[id] : (void *)0;
    if (!us || !us->in_use || us->state != UNIX_CONNECTED || !us->ring)
        return 1;  /* connection gone → unblock, loop returns EPIPE */
    unix_sock_t *p = (peer != UNIX_NONE && peer < UNIX_SOCK_MAX)
                     ? &s_unix[peer] : (void *)0;
    if (!p || !p->in_use || p->state == UNIX_CLOSED)
        return 1;  /* peer gone/closed → unblock, loop returns EPIPE */
    return ring_free(us) > 0;
}

int unix_sock_write(uint32_t id, const void *buf, uint32_t len)
{
    if (len == 0) return 0;
    irqflags_t fl = spin_lock_irqsave(&unix_lock);
    unix_sock_t *us = unix_sock_get(id);
    if (!us || us->state != UNIX_CONNECTED || !us->ring) {
        spin_unlock_irqrestore(&unix_lock, fl);
        return -EPIPE;
    }

    uint32_t peer = us->peer_id;
    if (peer == UNIX_NONE) {
        spin_unlock_irqrestore(&unix_lock, fl);
        return -EPIPE;
    }

    uint32_t written = 0;
    const uint8_t *src = (const uint8_t *)buf;

    while (written < len) {
        /* Writing to a closed (lingering) peer is EPIPE — nobody will
         * ever drain our ring. */
        unix_sock_t *p = unix_sock_get(peer);
        if (!p || p->state == UNIX_CLOSED) {
            spin_unlock_irqrestore(&unix_lock, fl);
            return written > 0 ? (int)written : -EPIPE;
        }

        uint16_t space = ring_free(us);
        if (space > 0) {
            uint32_t chunk = len - written;
            if (chunk > space) chunk = space;
            trace_emit(TRACE_UNIX_SEND, chunk, us->ring_head, us->ring_tail);
            /* Two-segment memcpy into the power-of-two ring (was a byte loop).
             * ring_head stays free-running; only the physical index wraps. */
            uint32_t hoff  = us->ring_head & (UNIX_BUF_SIZE - 1);
            uint32_t first = UNIX_BUF_SIZE - hoff;
            if (first > chunk) first = chunk;
            __builtin_memcpy(&us->ring[hoff], src + written, first);
            if (first < chunk)
                __builtin_memcpy(&us->ring[0], src + written + first, chunk - first);
            us->ring_head += chunk;
            written += chunk;

            /* Deposited data — wake the peer (a blocked read AND any sys_poll/
             * epoll waiter, both on the peer's poll_waiters) AFTER dropping
             * unix_lock (sched_lock > waitq > unix_lock); the woken reader
             * re-validates ring_used under unix_lock.  If fully written, return
             * here so the wake happens with the lock released; otherwise
             * re-acquire and continue toward the blocking path below. */
            waitq_t *peer_wq = &p->poll_waiters;
            spin_unlock_irqrestore(&unix_lock, fl);
            waitq_wake_all(peer_wq);
            if (written >= len)
                return (int)written;
            fl = spin_lock_irqsave(&unix_lock);
            /* Re-resolve after the lock gap (a CLONE_VM sibling could have
             * closed us, or the peer could have gone). */
            us = unix_sock_get(id);
            if (!us || us->state != UNIX_CONNECTED || !us->ring ||
                us->peer_id == UNIX_NONE) {
                spin_unlock_irqrestore(&unix_lock, fl);
                return written > 0 ? (int)written : -EPIPE;
            }
            peer = us->peer_id;
            continue;  /* re-check space at the top before blocking */
        }

        /* Ring full — block */
        if (us->nonblocking) break;
        /* Block on OUR poll_waiters until a reader drains space (the peer's
         * read path wakes us via this queue) or the peer closes.  Drop
         * unix_lock first (unix_lock < sched_lock); wait_event registers BEFORE
         * the cond check so a drain/close in the gap is not lost.  Interruptible:
         * if we already wrote some bytes, return the short count (POSIX: a write
         * interrupted after a partial transfer reports the bytes written); only
         * a zero-progress interrupt returns -EINTR — matching the nonblocking
         * `break` path's `written > 0 ? written : ...` convention. */
        spin_unlock_irqrestore(&unix_lock, fl);
        int rc;
        wait_event_interruptible(&s_unix[id].poll_waiters,
            unix_write_ready(id, peer), rc);
        if (rc == BLOCK_EINTR)
            return written > 0 ? (int)written : -EINTR;
        fl = spin_lock_irqsave(&unix_lock);
        us = unix_sock_get(id);
        if (!us || us->state != UNIX_CONNECTED || us->peer_id == UNIX_NONE) {
            spin_unlock_irqrestore(&unix_lock, fl);
            return written > 0 ? (int)written : -EPIPE;
        }
        peer = us->peer_id;
    }

    spin_unlock_irqrestore(&unix_lock, fl);
    return (int)written;
}

/* ── Peer credentials ──────────────────────────────────────────────────── */

int unix_sock_peercred(uint32_t id, uint32_t *pid, uint32_t *uid, uint32_t *gid)
{
    irqflags_t fl = spin_lock_irqsave(&unix_lock);
    unix_sock_t *us = unix_sock_get(id);
    if (!us || us->state != UNIX_CONNECTED) {
        spin_unlock_irqrestore(&unix_lock, fl);
        return -ENOTCONN;
    }
    *pid = us->peer_pid;
    *uid = us->peer_uid;
    *gid = us->peer_gid;
    spin_unlock_irqrestore(&unix_lock, fl);
    return 0;
}

/* ── fd passing (SCM_RIGHTS) ───────────────────────────────────────────── */

int unix_sock_stage_fds(uint32_t peer_id, unix_passed_fd_t *fds, uint8_t count)
{
    irqflags_t fl = spin_lock_irqsave(&unix_lock);
    unix_sock_t *p = unix_sock_get(peer_id);
    if (!p || p->state == UNIX_CLOSED) {
        spin_unlock_irqrestore(&unix_lock, fl);
        return p ? -32 : -9;  /* EPIPE (lingering peer) or EBADF */
    }
    if (p->passed_fd_count + count > UNIX_PASSED_FD_MAX) {
        spin_unlock_irqrestore(&unix_lock, fl);
        return -105;  /* ENOBUFS */
    }
    for (uint8_t i = 0; i < count; i++)
        p->passed_fds[p->passed_fd_count++] = fds[i];
    spin_unlock_irqrestore(&unix_lock, fl);
    return 0;
}

int unix_sock_recv_fds(uint32_t id, int *fd_out, int max_fds)
{
    irqflags_t fl = spin_lock_irqsave(&unix_lock);
    unix_sock_t *us = unix_sock_get(id);
    if (!us || us->passed_fd_count == 0) {
        spin_unlock_irqrestore(&unix_lock, fl);
        return 0;
    }

    aegis_process_t *proc = current_proc();
    int installed = 0;

    for (uint8_t i = 0; i < us->passed_fd_count && installed < max_fds; i++) {
        /* Find free fd slot */
        int free_fd = -1;
        for (int f = 0; f < PROC_MAX_FDS; f++) {
            if (!proc->fd_table->fds[f].ops) { free_fd = f; break; }
        }
        if (free_fd < 0) break;  /* fd table full */

        proc->fd_table->fds[free_fd].ops    = us->passed_fds[i].ops;
        proc->fd_table->fds[free_fd].priv   = us->passed_fds[i].priv;
        proc->fd_table->fds[free_fd].offset = 0;
        proc->fd_table->fds[free_fd].size   = 0;
        /* Received fds carry no filesystem/device authority (sys_sendmsg's
         * scm_fd_passable allowlist permits only memfd/pipe/unix-socket), so
         * the receiver's fd holds no authority marker. Set kflags explicitly
         * rather than trust the reused slot to have been left clean. */
        proc->fd_table->fds[free_fd].kflags = 0;
        /* Inherit the sender's file *status* flags (O_NONBLOCK etc., which
         * belong to the shared open file description) but NOT FD_CLOEXEC,
         * which is a per-fd-table property the receiver owns. Linux clears
         * close-on-exec on received SCM_RIGHTS fds unless the receiver asked
         * for MSG_CMSG_CLOEXEC; carrying the sender's bit through could close
         * a passed fd across the receiver's next execve. */
        proc->fd_table->fds[free_fd].flags  =
            us->passed_fds[i].flags & ~VFS_FD_CLOEXEC;
        fd_out[installed++] = free_fd;
    }

    /* Clear staging area (drop any fds that couldn't be installed) */
    for (uint8_t i = (uint8_t)installed; i < us->passed_fd_count; i++) {
        if (us->passed_fds[i].ops && us->passed_fds[i].ops->close)
            us->passed_fds[i].ops->close(us->passed_fds[i].priv);
    }
    us->passed_fd_count = 0;

    spin_unlock_irqrestore(&unix_lock, fl);
    return installed;
}

/* ── fd helpers ────────────────────────────────────────────────────────── */

int unix_sock_open_fd(uint32_t sock_id, void *proc_ptr)
{
    aegis_process_t *proc = (aegis_process_t *)proc_ptr;
    for (int i = 0; i < PROC_MAX_FDS; i++) {
        if (!proc->fd_table->fds[i].ops) {
            proc->fd_table->fds[i].ops    = &g_unix_sock_ops;
            proc->fd_table->fds[i].priv   = (void *)(uintptr_t)sock_id;
            proc->fd_table->fds[i].offset = 0;
            proc->fd_table->fds[i].size   = 0;
            proc->fd_table->fds[i].flags  = VFS_O_RDWR;
            return i;
        }
    }
    return -1;
}

uint32_t unix_sock_id_from_fd(int fd, void *proc_ptr)
{
    vfs_file_t *f = fd_resolve((aegis_process_t *)proc_ptr, fd, &g_unix_sock_ops);
    return f ? (uint32_t)(uintptr_t)f->priv : UNIX_NONE;
}

waitq_t *
unix_sock_get_waitq(uint32_t id)
{
    if (id >= UNIX_SOCK_MAX || !s_unix[id].in_use) return (waitq_t *)0;
    return &s_unix[id].poll_waiters;
}
