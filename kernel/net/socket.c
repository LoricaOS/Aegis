/* kernel/net/socket.c — socket table */
#include "socket.h"
#include "proc.h"
#include "vfs.h"
#include "printk.h"
#include "tcp.h"
#include "udp.h"
#include "sched.h"
#include "wait_event.h"
#include "signal.h"
#include "uaccess.h"
#include "spinlock.h"
#include "../lib/refcount.h"
#include "../fs/fd_resolve.h"
#include "../include/aegis_errno.h"
#include <stdint.h>
#include <stddef.h>

static sock_t s_socks[SOCK_TABLE_SIZE];  /* zero-initialized by C runtime */
static spinlock_t sock_lock = SPINLOCK_INIT;

/* ── Socket VFS ops ─────────────────────────────────────────────────────── */

/* poll(2) event bits — mirror Linux <poll.h> / sys_socket.c so the readiness
 * mask sock_vfs_poll returns is interpreted identically by sys_poll, epoll,
 * and the vfs_ops_t.poll contract. EPOLL* share these values. */
#define SOCK_POLLIN     0x0001
#define SOCK_POLLOUT    0x0004
#define SOCK_POLLERR    0x0008
#define SOCK_POLLHUP    0x0010
#define SOCK_POLLRDHUP  0x2000

static int      sock_vfs_read(void *priv, void *buf, uint64_t off, uint64_t len);
static int      sock_vfs_write(void *priv, const void *buf, uint64_t len);
static void     sock_vfs_close(void *priv);
static void     sock_vfs_dup(void *priv);
static int      sock_vfs_stat(void *priv, k_stat_t *st);
static uint16_t sock_vfs_poll(void *priv);
static waitq_t *sock_vfs_get_waitq(void *priv);

static const vfs_ops_t s_sock_ops = {
    .read      = sock_vfs_read,
    .write     = sock_vfs_write,
    .close     = sock_vfs_close,
    .readdir   = (void *)0,
    .dup       = sock_vfs_dup,
    .stat      = sock_vfs_stat,
    .poll      = sock_vfs_poll,
    .get_waitq = sock_vfs_get_waitq,
};

static int sock_vfs_read(void *priv, void *buf, uint64_t off, uint64_t len)
{
    (void)off;
    uint32_t sock_id = (uint32_t)(uintptr_t)priv;
    sock_t *s = sock_get(sock_id);
    if (!s) return -EBADF;

    if (s->type == SOCK_TYPE_STREAM) {
        /* TCP: blocking recv.  Returns byte count, 0=EOF, -EPIPE on close.
         *
         * avail > 0  → data available: read it.
         * avail == 0 → no data in rbuf; must check TCP state:
         *   ESTABLISHED/SYN_RCVD: block (or EAGAIN if nonblocking).
         *   CLOSE_WAIT/CLOSED:    return 0 (EOF — FIN received).
         */
        for (;;) {
            int avail = tcp_conn_recv(s->tcp_conn_id, (void *)0, 0);  /* peek */
            if (avail > 0) {
                uint32_t want = (uint32_t)len < (uint32_t)avail ? (uint32_t)len : (uint32_t)avail;
                if (want > 8192) want = 8192;
                return tcp_conn_recv(s->tcp_conn_id, buf, (uint16_t)want);
            }
            /* avail <= 0.  tcp_conn_recv peek returns -11 ONLY while the
             * connection is alive but empty (the one case we block on); 0
             * (FIN/closed + empty) or -1 (dead conn_id) mean no more data will
             * ever arrive — both are EOF, matching the old explicit state check
             * (CLOSE_WAIT/CLOSED/TIME_WAIT or !tc). */
            if (avail != -11)
                return 0;  /* EOF */
            if (s->nonblocking)
                return -EAGAIN;
            /* Block until data arrives or the connection closes (peek != -11),
             * interruptible so Ctrl-C against a parked recv delivers.  The
             * authoritative peek + EOF/data decision is re-run at the top of
             * this loop after the wait returns. */
            int rc;
            wait_event_interruptible(&s->poll_waiters,
                tcp_conn_recv(s->tcp_conn_id, (void *)0, 0) != -11, rc);
            if (rc == BLOCK_EINTR)
                return -EINTR;
        }
    }
    /* UDP: peek from ring buffer — kernel buf already filled via recvfrom */
    return -ENOSYS;  /* UDP via read() — use recvfrom */
}

/* sock_stream_send — blocking TCP send.  Chunk a user buffer through
 * tcp_conn_send (one MSS each); when the retransmit ring fills (a write larger
 * than TCP_SBUF_SIZE), block on the socket's poll_waiters until ACKs drain it,
 * then continue — so large writes are segmented over time instead of truncated
 * at ~8 KB.  Honors O_NONBLOCK (EAGAIN).  `ubuf` is a user pointer.
 * Returns bytes sent (>=0) or -errno.  Shared by sock_vfs_write (write()) and
 * sys_send (send()/sendto()). */
int64_t sock_stream_send(sock_t *s, uint64_t ubuf, uint64_t len)
{
    uint8_t sndbuf[1460];
    uint64_t sent = 0;
    while (sent < len) {
        uint64_t rem = len - sent;
        uint32_t chunk = (uint32_t)(rem > 1460 ? 1460 : rem);
        copy_from_user(sndbuf, (const void *)(uintptr_t)(ubuf + sent), chunk);
        int n = tcp_conn_send(s->tcp_conn_id, sndbuf, (uint16_t)chunk);
        if (n > 0) { sent += (uint64_t)n; continue; }
        if (n < 0) return sent > 0 ? (int64_t)sent : n;       /* EPIPE etc. */
        /* n == 0: send ring full (would-block). */
        if (s->nonblocking) return sent > 0 ? (int64_t)sent : -EAGAIN;
        int rc = 0;
        wait_event_interruptible(&s->poll_waiters,
                                 tcp_conn_send_ready(s->tcp_conn_id) != 0, rc);
        if (rc < 0) return sent > 0 ? (int64_t)sent : rc;     /* -EINTR */
        if (tcp_conn_send_ready(s->tcp_conn_id) < 0)
            return sent > 0 ? (int64_t)sent : -EPIPE;          /* conn died */
        /* space available — retry the same chunk */
    }
    return (int64_t)sent;
}

static int sock_vfs_write(void *priv, const void *buf, uint64_t len)
{
    uint32_t sock_id = (uint32_t)(uintptr_t)priv;
    sock_t *s = sock_get(sock_id);
    if (!s) return -EBADF;

    if (s->type == SOCK_TYPE_STREAM) {
        if (s->state != SOCK_CONNECTED) return -ENOTCONN;
        return (int)sock_stream_send(s, (uint64_t)(uintptr_t)buf, len);
    }
    return -ENOSYS;  /* UDP via write() — use sendto */
}

static void sock_vfs_close(void *priv)
{
    uint32_t sock_id = (uint32_t)(uintptr_t)priv;

    /* Drop this fd's reference. The slot is torn down only when the LAST fd
     * closes — dup/fork share the slot, so an unconditional teardown here
     * double-freed it (double tcp_conn_close/udp_unbind) and handed a reused
     * slot to the surviving fd (cross-connection UAF). */
    irqflags_t fl = spin_lock_irqsave(&sock_lock);
    if (sock_id >= SOCK_TABLE_SIZE || s_socks[sock_id].state == SOCK_FREE) {
        spin_unlock_irqrestore(&sock_lock, fl);
        return;  /* already gone */
    }
    if (!refcount_dec_and_test(&s_socks[sock_id].refcount)) {
        spin_unlock_irqrestore(&sock_lock, fl);
        return;  /* other fds still reference this slot */
    }

    /* Last reference. Capture what teardown needs WHILE holding sock_lock,
     * then drop the lock BEFORE calling udp_unbind / tcp_conn_close: those take
     * udp_lock / tcp_lock and sock_lock must stay a leaf (the canonical lock
     * order keeps udp/tcp above sock here). Doing the teardown after the unlock
     * matches the prior discipline (sock_get released the lock before the old
     * udp_unbind/tcp_conn_close calls). */
    uint8_t  type   = s_socks[sock_id].type;
    uint16_t lport  = s_socks[sock_id].local_port;
    uint32_t connid = s_socks[sock_id].tcp_conn_id;
    spin_unlock_irqrestore(&sock_lock, fl);

    /* Release the UDP port binding (if any). Without this, every closed UDP
     * socket leaks its port forever and the next bind() to the same port
     * returns EADDRINUSE. The DHCP client retry loop caught this. */
    if (type == SOCK_TYPE_DGRAM && lport != 0)
        udp_unbind(lport);
    /* Tear down the TCP connection slot on close().  Most apps (curl, the
     * herald package client) close() without an explicit shutdown(), so
     * tcp_conn_close was previously only reached via sys_shutdown — every
     * close()'d STREAM socket leaked one tcp_conn_t slot (pool of
     * TCP_MAX_CONNS). After ~32 connections the pool exhausted and new
     * connects failed. tcp_conn_close sends our FIN (ESTABLISHED→FIN_WAIT_1,
     * CLOSE_WAIT→LAST_ACK) and is a safe no-op in every other state; the slot
     * is reclaimed once it reaches TCP_CLOSED (ACK-of-FIN, or the
     * retransmit-limit RST in tcp_tick). */
    if (type == SOCK_TYPE_STREAM && connid != SOCK_NONE)
        tcp_conn_close(connid);
    sock_free(sock_id);
}

static void sock_vfs_dup(void *priv)
{
    /* A second fd now points at this slot (dup/dup2/fcntl F_DUPFD, or fork via
     * fd_table_copy). Take another reference so the slot is not torn down until
     * the LAST fd closes. Inc under sock_lock — the same lock that serialises
     * sock_free — so the slot cannot transition to SOCK_FREE across the inc.
     * Mirrors unix_vfs_dup. */
    uint32_t sock_id = (uint32_t)(uintptr_t)priv;
    irqflags_t fl = spin_lock_irqsave(&sock_lock);
    if (sock_id < SOCK_TABLE_SIZE && s_socks[sock_id].state != SOCK_FREE)
        refcount_inc(&s_socks[sock_id].refcount);
    spin_unlock_irqrestore(&sock_lock, fl);
}

static int sock_vfs_stat(void *priv, k_stat_t *st)
{
    (void)priv;
    __builtin_memset(st, 0, sizeof(*st));
    st->st_mode = 0140666;  /* S_IFSOCK | 0666 */
    return 0;
}

/* ── Public API ─────────────────────────────────────────────────────────── */

int sock_alloc(uint8_t type)
{
    irqflags_t fl = spin_lock_irqsave(&sock_lock);
    uint32_t i;
    for (i = 0; i < SOCK_TABLE_SIZE; i++) {
        if (s_socks[i].state == SOCK_FREE) {
            __builtin_memset(&s_socks[i], 0, sizeof(s_socks[i]));
            s_socks[i].state       = SOCK_CREATED;
            s_socks[i].type        = type;
            s_socks[i].tcp_conn_id = SOCK_NONE;
            s_socks[i].epoll_id    = SOCK_NONE;
            /* One reference for the creating fd. The memset above zeroed the
             * count; this explicit init sets it to 1 (a 0 count would make the
             * first .dup inc-from-0 and refcount_inc_not_zero refuse). */
            refcount_init(&s_socks[i].refcount, 1);
            waitq_init(&s_socks[i].poll_waiters);
            spin_unlock_irqrestore(&sock_lock, fl);
            return (int)i;
        }
    }
    spin_unlock_irqrestore(&sock_lock, fl);
    return -1;
}

sock_t *sock_get(uint32_t sock_id)
{
    irqflags_t fl = spin_lock_irqsave(&sock_lock);
    if (sock_id >= SOCK_TABLE_SIZE) {
        spin_unlock_irqrestore(&sock_lock, fl);
        return (sock_t *)0;
    }
    if (s_socks[sock_id].state == SOCK_FREE) {
        spin_unlock_irqrestore(&sock_lock, fl);
        return (sock_t *)0;
    }
    sock_t *s = &s_socks[sock_id];
    spin_unlock_irqrestore(&sock_lock, fl);
    return s;
}

/* sock_get_nolock: return pointer without acquiring sock_lock.
 * Only safe when caller holds a lock that prevents concurrent sock_free
 * (e.g. tcp_lock or udp_lock — the binding/conn table references keep
 * the socket alive).  Used to avoid lock ordering inversions. */
sock_t *sock_get_nolock(uint32_t sock_id)
{
    if (sock_id >= SOCK_TABLE_SIZE)
        return (sock_t *)0;
    if (s_socks[sock_id].state == SOCK_FREE)
        return (sock_t *)0;
    return &s_socks[sock_id];
}

void sock_free(uint32_t sock_id)
{
    irqflags_t fl = spin_lock_irqsave(&sock_lock);
    if (sock_id >= SOCK_TABLE_SIZE) {
        spin_unlock_irqrestore(&sock_lock, fl);
        return;
    }
    s_socks[sock_id].state = SOCK_FREE;
    spin_unlock_irqrestore(&sock_lock, fl);
}

/* sock_wake: wake everything blocked on this socket — blocking accept/connect/
 * recv (registered via wait_event) and sys_poll/sys_epoll_wait — by waking the
 * single poll_waiters queue.  A thin wrapper now that blocking I/O and polling
 * share one waitq.  Safe to call from any context EXCEPT under tcp_lock/
 * sock_lock (waitq_wake_all takes sched_lock; order is sched_lock > all). The
 * tcp.c/udp.c producers already call this in their deferred post-lock sections. */
void sock_wake(uint32_t sock_id)
{
    sock_t *s = sock_get(sock_id);
    if (!s) return;
    waitq_wake_all(&s->poll_waiters);
}

int sock_open_fd(uint32_t sock_id, aegis_process_t *proc)
{
    uint32_t fd;
    for (fd = 0; fd < PROC_MAX_FDS; fd++) {
        if (!proc->fd_table->fds[fd].ops) {
            proc->fd_table->fds[fd].ops    = &s_sock_ops;
            proc->fd_table->fds[fd].priv   = (void *)(uintptr_t)sock_id;
            proc->fd_table->fds[fd].offset = 0;
            proc->fd_table->fds[fd].size   = 0;
            proc->fd_table->fds[fd].flags  = 0;
            proc->fd_table->fds[fd].kflags = 0;
            return (int)fd;
        }
    }
    return -1;  /* EMFILE */
}

uint32_t sock_id_from_fd(int fd, aegis_process_t *proc)
{
    vfs_file_t *f = fd_resolve(proc, fd, &s_sock_ops);
    return f ? (uint32_t)(uintptr_t)f->priv : SOCK_NONE;
}

/* sock_get_waitq: return the embedded poll_waiters waitq for sock_id, or
 * NULL if the slot is free/invalid. fd_waitq dispatches sys_poll and
 * sys_epoll_wait waiters here. Producers in tcp.c / udp.c / socket.c
 * call waitq_wake_all(&s->poll_waiters) on rx, accept enqueue, and
 * TCP state→CLOSE_WAIT/CLOSED/TIME_WAIT. */
waitq_t *
sock_get_waitq(uint32_t id)
{
    sock_t *s = sock_get(id);
    return s ? &s->poll_waiters : NULL;
}

/* sock_vfs_get_waitq — vfs_ops_t.get_waitq for AF_INET fds. priv carries the
 * sock_id (see sock_open_fd). Lets fd_get_waitq treat sockets like any other
 * pollable vfs fd. */
static waitq_t *
sock_vfs_get_waitq(void *priv)
{
    return sock_get_waitq((uint32_t)(uintptr_t)priv);
}

/* sock_vfs_poll — vfs_ops_t.poll for AF_INET fds: the single source of truth
 * for AF_INET readiness, used by BOTH sys_poll and sys_epoll_wait (via the
 * generic ops->poll path). Returns the full readiness mask (the caller masks
 * against its interest set). This is the Linux-accurate behaviour formerly
 * duplicated — and divergent — between sys_poll and epoll_compute_readiness:
 * a peer FIN (CLOSE_WAIT) reports RDHUP and EOF-readable POLLIN but NOT POLLHUP
 * (the local send side is still open); only a fully torn-down connection
 * (CLOSED/TIME_WAIT) is POLLHUP. priv carries the sock_id. */
static uint16_t
sock_vfs_poll(void *priv)
{
    uint32_t sid = (uint32_t)(uintptr_t)priv;
    sock_t *s = sock_get(sid);
    if (!s) return SOCK_POLLERR;

    uint16_t r = 0;
    if (s->type == SOCK_TYPE_STREAM) {
        if (s->state == SOCK_CONNECTED) {
            tcp_conn_t *tc = tcp_conn_get(s->tcp_conn_id);
            int peek = tcp_conn_recv(s->tcp_conn_id, (void *)0, 0);
            /* POLLIN: data available OR EOF (recv will return 0). */
            if (peek > 0 || peek == 0) r |= SOCK_POLLIN;
            r |= SOCK_POLLOUT;            /* no per-socket TX flow control */
            if (tc) {
                /* Peer sent FIN → RDHUP (read side closed) even while our send
                 * side stays open (CLOSE_WAIT). */
                if (tc->state == TCP_CLOSE_WAIT
                    || tc->state == TCP_CLOSED
                    || tc->state == TCP_TIME_WAIT)
                    r |= SOCK_POLLRDHUP;
                /* Both directions down → HUP. CLOSE_WAIT is NOT HUP yet. */
                if (tc->state == TCP_CLOSED || tc->state == TCP_TIME_WAIT)
                    r |= SOCK_POLLHUP;
            }
        } else if (s->state == SOCK_LISTENING) {
            if (s->accept_head != s->accept_tail) r |= SOCK_POLLIN;
        } else if (s->state == SOCK_CONNECTING) {
            /* Nonblocking connect in flight. On the FAILURE path (RST in
             * SYN_SENT) tcp_rx sets the tcp_conn to TCP_CLOSED but never
             * updates s->state, so the sock can sit in SOCK_CONNECTING forever.
             * Inspect the tcp_conn directly so the poller wakes
             * (POLLOUT|POLLERR|POLLHUP) and reads SO_ERROR. */
            tcp_conn_t *tc = tcp_conn_get(s->tcp_conn_id);
            if (tc && tc->state == TCP_CLOSED)
                r |= SOCK_POLLOUT | SOCK_POLLERR | SOCK_POLLHUP;
        } else if (s->state == SOCK_CLOSED) {
            /* Connect failed (RST/timeout): writable + error so the loop wakes
             * and getsockopt(SO_ERROR) returns the failure. */
            r |= SOCK_POLLOUT | SOCK_POLLERR | SOCK_POLLHUP;
        }
        /* SOCK_CREATED / SOCK_BOUND: nothing ready. */
    } else if (s->type == SOCK_TYPE_DGRAM) {
        if (s->udp_rx_head != s->udp_rx_tail) r |= SOCK_POLLIN;
        r |= SOCK_POLLOUT;                /* UDP send never blocks here */
    }
    return r;
}
