/* sys_socket.c — POSIX socket API syscalls */
#include "sys_impl.h"
#include "sched.h"
#include "waitq.h"
#include "wait_event.h"
#include "proc.h"
#include "vfs.h"
#include "socket.h"
#include "epoll.h"
#include "arch.h"
#include "netdev.h"
#include "eth.h"
#include "udp.h"
#include "tcp.h"
#include "ip.h"
#include "unix_socket.h"
#include "fd_waitq.h"
#include "signal.h"

/* ── Constants ─────────────────────────────────────────────────────────── */

#define SOCK_STREAM    1
#define SOCK_DGRAM     2

#define SOL_SOCKET     1
#define SO_REUSEADDR   2
#define SO_BROADCAST   6
#define SO_PEERCRED    17
#define SO_RCVTIMEO    20
#define SO_SNDTIMEO    21

#define SO_ERROR       4
#define SO_TYPE        3
#define SO_SNDBUF      7
#define SO_RCVBUF      8
#define SO_KEEPALIVE   9

#define IPPROTO_TCP    6
#define TCP_NODELAY    1

/* send/recv flags (Linux ABI). Only MSG_DONTWAIT changes control flow; the
 * rest are accepted-and-ignored so that programs passing them (curl, musl)
 * don't fail. MSG_NOSIGNAL is implicitly always-on here (we never raise
 * SIGPIPE from the socket layer). MSG_PEEK/MSG_WAITALL are not yet honored —
 * see the per-call notes; ignoring them degrades gracefully (a normal
 * consuming read) rather than erroring. */
#define MSG_OOB        0x0001
#define MSG_PEEK       0x0002
#define MSG_DONTWAIT   0x0040
#define MSG_WAITALL    0x0100
#define MSG_NOSIGNAL   0x4000

/* sockaddr_un layout */
typedef struct {
    uint16_t sun_family;
    char     sun_path[UNIX_PATH_MAX];
} k_sockaddr_un_t;


/* net_get_config / net_set_config declared in ip.h (already included) */

/* ── Helpers ────────────────────────────────────────────────────────────── */

static uint64_t
get_proc_sock(uint64_t fd_arg, sock_t **s_out, uint32_t *sid_out)
{
    aegis_process_t *proc = current_proc();
    uint32_t sid = sock_id_from_fd((int)fd_arg, proc);
    if (sid == SOCK_NONE) return SYS_ERR(EBADF);
    sock_t *s = sock_get(sid);
    if (!s) return SYS_ERR(EBADF);
    *s_out   = s;
    *sid_out = sid;
    return 0;
}

/* ── sys_socket ────────────────────────────────────────────────────────── */

/* Linux/musl fold SOCK_NONBLOCK and SOCK_CLOEXEC into the type argument of
 * socket().  They must be masked off before validating the base socket type,
 * and SOCK_NONBLOCK applied to the new socket.  Without this, musl's DNS
 * resolver — which opens its UDP socket as SOCK_DGRAM|SOCK_CLOEXEC|SOCK_NONBLOCK
 * — got EPROTONOSUPPORT from socket() and getaddrinfo failed before ever
 * sending a query (only /etc/hosts names resolved). */
#define SOCK_FLAG_NONBLOCK 0x800u
#define SOCK_FLAG_CLOEXEC  0x80000u
#define SOCK_TYPE_MASK     (~((uint64_t)(SOCK_FLAG_NONBLOCK | SOCK_FLAG_CLOEXEC)))

/* Forward decl: implicit ephemeral source-port bind for UDP (defined below). */
static int udp_ensure_local_port(sock_t *s, uint32_t sid);

/* Rotating ephemeral-port cursor. A coarse tick-seeded start handed back-to-back
 * sockets the same port within a PIT tick, which let a late DNS reply for a
 * just-closed socket land in the next one (port reuse). Advancing the cursor on
 * every ephemeral allocation makes consecutive sockets get distinct ports.
 * Range is [49152, 65535] (the IANA ephemeral range, 0x4000 ports). */
#define EPHEM_PORT_BASE  49152u
#define EPHEM_PORT_COUNT 0x4000u
static uint16_t s_ephem_next = EPHEM_PORT_BASE;

/* Return the next ephemeral port and advance the cursor (wrapping in range). */
static uint16_t
ephem_port_next(void)
{
    uint16_t p = s_ephem_next;
    uint16_t off = (uint16_t)(p - EPHEM_PORT_BASE);
    off = (uint16_t)((off + 1u) & (EPHEM_PORT_COUNT - 1u));
    s_ephem_next = (uint16_t)(EPHEM_PORT_BASE + off);
    return p;
}

uint64_t
sys_socket(uint64_t domain, uint64_t type, uint64_t proto)
{
    (void)proto;

    int       nonblock  = (type & SOCK_FLAG_NONBLOCK) ? 1 : 0;
    uint64_t  base_type = type & SOCK_TYPE_MASK;

    /* AF_UNIX path */
    if (domain == AF_UNIX) {
        if (base_type != SOCK_STREAM) return SYS_ERR(EPROTONOSUPPORT);
        aegis_process_t *proc = current_proc();
        if (cap_check(proc->caps, CAP_TABLE_SIZE, CAP_KIND_IPC, CAP_RIGHTS_READ) != 0)
            return SYS_ERR(ENOCAP);
        int uid = unix_sock_alloc();
        if (uid < 0) return SYS_ERR(EMFILE);
        if (nonblock) {
            unix_sock_t *us = unix_sock_get((uint32_t)uid);
            if (us) us->nonblocking = 1;
        }
        int fd = unix_sock_open_fd((uint32_t)uid, proc);
        if (fd < 0) { unix_sock_free((uint32_t)uid); return SYS_ERR(EMFILE); }
        return (uint64_t)fd;
    }

    /* AF_INET path */
    if (domain != AF_INET) return SYS_ERR(EAFNOSUPPORT);
    if (base_type != SOCK_STREAM && base_type != SOCK_DGRAM)
        return SYS_ERR(EPROTONOSUPPORT);

    aegis_process_t *proc = current_proc();
    if (cap_check(proc->caps, CAP_TABLE_SIZE, CAP_KIND_NET_SOCKET, CAP_RIGHTS_READ) != 0)
        return SYS_ERR(ENOCAP);

    int sid = sock_alloc((uint8_t)(base_type == SOCK_STREAM ? SOCK_TYPE_STREAM : SOCK_TYPE_DGRAM));
    if (sid < 0) return SYS_ERR(EMFILE);
    if (nonblock) {
        sock_t *s = sock_get((uint32_t)sid);
        if (s) s->nonblocking = 1;
    }

    int fd = sock_open_fd((uint32_t)sid, proc);
    if (fd < 0) { sock_free((uint32_t)sid); return SYS_ERR(EMFILE); }

    return (uint64_t)fd;
}

/* ── sys_bind ──────────────────────────────────────────────────────────── */

uint64_t
sys_bind(uint64_t fd, uint64_t addr, uint64_t addrlen)
{
    aegis_process_t *proc = current_proc();

    /* AF_UNIX bind */
    uint32_t uid = unix_sock_id_from_fd((int)fd, proc);
    if (uid != UNIX_NONE) {
        if (addrlen < 4 || !user_ptr_valid(addr, addrlen))
            return SYS_ERR(EFAULT);
        k_sockaddr_un_t sun;
        __builtin_memset(&sun, 0, sizeof(sun));
        uint32_t copy_len = addrlen < sizeof(sun) ? (uint32_t)addrlen : (uint32_t)sizeof(sun);
        copy_from_user(&sun, (const void *)(uintptr_t)addr, copy_len);
        if (sun.sun_family != AF_UNIX) return SYS_ERR(EINVAL);
        sun.sun_path[UNIX_PATH_MAX - 1] = '\0';
        int rc = unix_sock_bind(uid, sun.sun_path);
        return rc < 0 ? sc_ret(rc) : 0;
    }

    /* AF_INET bind */
    if (addrlen < sizeof(k_sockaddr_in_t)) return SYS_ERR(EINVAL);
    if (!user_ptr_valid(addr, sizeof(k_sockaddr_in_t))) return SYS_ERR(EFAULT);

    sock_t *s; uint32_t sid;
    uint64_t err = get_proc_sock(fd, &s, &sid);
    if (err) return err;

    k_sockaddr_in_t sa;
    copy_from_user(&sa, (const void *)(uintptr_t)addr, sizeof(sa));
    if (sa.sin_family != AF_INET) return SYS_ERR(EINVAL);

    uint16_t port = ntohs(sa.sin_port);

    /* Privileged-port gate: binding a TCP socket to a port <1024 requires
     * CAP_KIND_NET_LISTEN, so an ordinary NET_SOCKET process can't grab :22 (or
     * :80) and impersonate sshd/httpd to harvest credentials. UDP is exempt
     * (DHCP client binds :68, etc.); port 0 is a wildcard/ephemeral bind. */
    if (s->type == SOCK_TYPE_STREAM && port != 0 && port < 1024) {
        if (cap_check(proc->caps, CAP_TABLE_SIZE,
                      CAP_KIND_NET_LISTEN, CAP_RIGHTS_WRITE) != 0)
            return SYS_ERR(EACCES);
    }

    s->local_ip = sa.sin_addr;

    /* Wildcard bind (port 0): assign an ephemeral port, as Linux does.  musl's
     * DNS resolver binds its UDP socket to 0.0.0.0:0 expecting an auto-assigned
     * source port; the old EINVAL here made the resolver close the socket and
     * every DNS lookup fail. */
    if (port == 0) {
        if (s->type == SOCK_TYPE_DGRAM) {
            if (udp_ensure_local_port(s, sid) != 0)
                return SYS_ERR(EADDRINUSE);  /* EADDRINUSE: no free port */
        } else {
            /* TCP: pick an ephemeral local port; not registered until
             * listen()/connect().  Use the rotating cursor so consecutive
             * binds get distinct ports (no tick-granularity reuse). */
            s->local_port = ephem_port_next();
        }
        s->state = SOCK_BOUND;
        return 0;
    }

    s->local_port = port;
    s->state      = SOCK_BOUND;

    /* Register with TCP or UDP binding layer */
    if (s->type == SOCK_TYPE_DGRAM) {
        return udp_bind(port, sid) == 0 ? 0 : SYS_ERR(EADDRINUSE);
    }
    /* TCP: binding is stored in sock_t; actual listen registration happens in sys_listen */
    return 0;
}

/* ── sys_listen ────────────────────────────────────────────────────────── */

uint64_t
sys_listen(uint64_t fd, uint64_t backlog)
{
    (void)backlog;
    aegis_process_t *proc = current_proc();
    uint32_t uid = unix_sock_id_from_fd((int)fd, proc);
    if (uid != UNIX_NONE) {
        int rc = unix_sock_listen(uid);
        return rc < 0 ? (uint64_t)(int64_t)rc : 0;
    }

    sock_t *s; uint32_t sid;
    uint64_t err = get_proc_sock(fd, &s, &sid);
    if (err) return err;
    if (s->type != SOCK_TYPE_STREAM) return SYS_ERR(EOPNOTSUPP);
    if (s->state < SOCK_BOUND) return SYS_ERR(EINVAL);  /* EINVAL: must bind first */

    s->state = SOCK_LISTENING;

    return tcp_listen(s->local_port, sid) == 0 ? 0 : SYS_ERR(EADDRINUSE);
}

/* ── sys_accept ────────────────────────────────────────────────────────── */

uint64_t
sys_accept(uint64_t fd, uint64_t addr, uint64_t addrlen)
{
    aegis_process_t *proc_a = current_proc();
    uint32_t uid = unix_sock_id_from_fd((int)fd, proc_a);
    if (uid != UNIX_NONE) {
        int server_id = unix_sock_accept(uid);
        if (server_id < 0) return (uint64_t)(int64_t)server_id;
        int new_fd = unix_sock_open_fd((uint32_t)server_id, proc_a);
        if (new_fd < 0) { unix_sock_free((uint32_t)server_id); return SYS_ERR(EMFILE); }
        return (uint64_t)new_fd;
    }

    sock_t *ls; uint32_t lsid;
    uint64_t err = get_proc_sock(fd, &ls, &lsid);
    if (err) return err;
    if (ls->state != SOCK_LISTENING) return SYS_ERR(EINVAL);

    aegis_process_t *proc = current_proc();

    for (;;) {
        /* Check accept queue */
        if (ls->accept_head != ls->accept_tail) {
            uint32_t conn_id = ls->accept_queue[ls->accept_head];
            ls->accept_head = (ls->accept_head + 1) & 7;

            /* Allocate a new sock_t for this connected peer */
            int new_sid = sock_alloc(SOCK_TYPE_STREAM);
            if (new_sid < 0) return SYS_ERR(ENOMEM);
            sock_t *ns = sock_get((uint32_t)new_sid);
            ns->state       = SOCK_CONNECTED;
            ns->tcp_conn_id = conn_id;

            /* Copy peer address from tcp_conn_t */
            tcp_conn_get_addr(conn_id, &ns->remote_ip, &ns->remote_port,
                              &ns->local_ip, &ns->local_port);

            /* Point tcp_conn back to this new socket */
            tcp_conn_set_sock(conn_id, (uint32_t)new_sid);

            /* Fill caller's addr struct */
            if (addr && addrlen) {
                if (!user_ptr_valid(addr, sizeof(k_sockaddr_in_t))) return SYS_ERR(EFAULT);
                if (!user_ptr_valid(addrlen, sizeof(uint32_t))) return SYS_ERR(EFAULT);
                k_sockaddr_in_t sa;
                sa.sin_family = AF_INET;
                sa.sin_port   = htons(ns->remote_port);
                sa.sin_addr   = ns->remote_ip;
                __builtin_memset(sa.sin_zero, 0, 8);
                uint32_t outlen = sizeof(sa);
                copy_to_user((void *)(uintptr_t)addrlen, &outlen, sizeof(uint32_t));
                copy_to_user((void *)(uintptr_t)addr, &sa, sizeof(sa));
            }

            int new_fd = sock_open_fd((uint32_t)new_sid, proc);
            if (new_fd < 0) { sock_free((uint32_t)new_sid); return SYS_ERR(ENOMEM); }
            return (uint64_t)new_fd;
        }

        if (ls->nonblocking)
            return SYS_ERR(EAGAIN);

        /* Block until a connection is queued.  Interruptible (Ctrl-C aborts).
         * wait_event registers on poll_waiters BEFORE re-checking the queue, so
         * a connection that completes in the gap is not lost; the loop then
         * re-runs the authoritative dequeue above. */
        int rc;
        wait_event_interruptible(&ls->poll_waiters,
            ls->accept_head != ls->accept_tail, rc);
        if (rc == BLOCK_EINTR)
            return SYS_ERR(EINTR);
    }
}

/* ── sys_accept4 ───────────────────────────────────────────────────────────
 * accept4(fd, addr, addrlen, flags): like accept(), but applies SOCK_NONBLOCK
 * and SOCK_CLOEXEC (folded into flags, same bit values as in socket()) to the
 * accepted fd. Previously routed straight to sys_accept, silently dropping
 * flags: an accepted fd intended close-on-exec leaked across execve (fd leak
 * into exec'd handlers — e.g. a forking+exec'ing server), and SOCK_NONBLOCK was
 * ignored so the new fd stayed blocking against the caller's intent. */
uint64_t
sys_accept4(uint64_t fd, uint64_t addr, uint64_t addrlen, uint64_t flags)
{
    uint64_t r = sys_accept(fd, addr, addrlen);
    if ((int64_t)r < 0)
        return r;   /* accept failed — propagate errno, nothing to flag */

    int new_fd = (int)r;
    aegis_process_t *proc = current_proc();
    if (new_fd < 0 || new_fd >= PROC_MAX_FDS)
        return r;   /* defensive: shouldn't happen */

    if (flags & SOCK_FLAG_CLOEXEC)
        proc->fd_table->fds[new_fd].flags |= VFS_FD_CLOEXEC;

    if (flags & SOCK_FLAG_NONBLOCK) {
        /* Set nonblocking on the underlying object (AF_UNIX or AF_INET),
         * mirroring how socket() applies SOCK_NONBLOCK at creation. */
        uint32_t uuid = unix_sock_id_from_fd(new_fd, proc);
        if (uuid != UNIX_NONE) {
            unix_sock_t *us = unix_sock_get(uuid);
            if (us) us->nonblocking = 1;
        } else {
            sock_t *s; uint32_t sid;
            if (get_proc_sock((uint64_t)new_fd, &s, &sid) == 0 && s)
                s->nonblocking = 1;
        }
    }
    return r;
}

/* ── sys_connect ───────────────────────────────────────────────────────── */

uint64_t
sys_connect(uint64_t fd, uint64_t addr, uint64_t addrlen)
{
    aegis_process_t *proc_c = current_proc();
    uint32_t uid = unix_sock_id_from_fd((int)fd, proc_c);
    if (uid != UNIX_NONE) {
        if (addrlen < 4 || !user_ptr_valid(addr, addrlen))
            return SYS_ERR(EFAULT);
        k_sockaddr_un_t sun;
        __builtin_memset(&sun, 0, sizeof(sun));
        uint32_t copy_len = addrlen < sizeof(sun) ? (uint32_t)addrlen : (uint32_t)sizeof(sun);
        copy_from_user(&sun, (const void *)(uintptr_t)addr, copy_len);
        sun.sun_path[UNIX_PATH_MAX - 1] = '\0';
        int rc = unix_sock_connect(uid, sun.sun_path);
        return rc < 0 ? (uint64_t)(int64_t)rc : 0;
    }

    if (addrlen < sizeof(k_sockaddr_in_t)) return SYS_ERR(EINVAL);
    if (!user_ptr_valid(addr, sizeof(k_sockaddr_in_t))) return SYS_ERR(EFAULT);

    sock_t *s; uint32_t sid;
    uint64_t err = get_proc_sock(fd, &s, &sid);
    if (err) return err;

    k_sockaddr_in_t sa;
    copy_from_user(&sa, (const void *)(uintptr_t)addr, sizeof(sa));

    s->remote_ip   = sa.sin_addr;
    s->remote_port = ntohs(sa.sin_port);

    if (s->type == SOCK_TYPE_DGRAM) {
        /* UDP connect: just set remote addr. No handshake. */
        s->state = SOCK_CONNECTED;
        return 0;
    }

    /* TCP: a second connect() on an already-established socket is EISCONN, and
     * on an in-flight one is EALREADY — matches Linux and stops a re-SYN that
     * would clobber tcp_conn_id. */
    if (s->state == SOCK_CONNECTED) return SYS_ERR(EISCONN);
    if (s->state == SOCK_CONNECTING) return SYS_ERR(EALREADY);

    /* TCP: initiate SYN. */
    uint32_t conn_id;
    int r = tcp_connect(sid, sa.sin_addr, ntohs(sa.sin_port), &conn_id);
    if (r < 0)
        return (uint64_t)(int64_t)r;
    s->tcp_conn_id = conn_id;
    s->state       = SOCK_CONNECTING;

    /* Nonblocking connect: return EINPROGRESS immediately. The handshake
     * completes asynchronously (tcp_rx → sock_wake). The app then polls for
     * POLLOUT and reads the result via getsockopt(SO_ERROR). Without this a
     * nonblocking socket would block here anyway, defeating the whole point and
     * hanging single-threaded event loops (the exact pattern curl/libcurl and
     * musl's async resolver use). */
    if (s->nonblocking)
        return SYS_ERR(EINPROGRESS);

    /* Block until the handshake resolves out of SOCK_CONNECTING (tcp_rx sets
     * SOCK_CONNECTED on success, SOCK_CLOSED on RST/refuse).  wait_event
     * registers on poll_waiters BEFORE checking state, so a handshake that
     * completed synchronously inside tcp_connect (state already != CONNECTING)
     * returns immediately and a wake landing in the gap is not lost.
     * Interruptible: a pending signal aborts with EINTR. */
    int rc;
    wait_event_interruptible(&s->poll_waiters, s->state != SOCK_CONNECTING, rc);
    if (rc == BLOCK_EINTR)
        return SYS_ERR(EINTR);
    if (s->state != SOCK_CONNECTED) return SYS_ERR(ECONNREFUSED);
    return 0;
}

/* udp_ensure_local_port — implicit ephemeral source-port bind for a UDP socket.
 *
 * Linux assigns a source port on the first send/connect of an unbound datagram
 * socket.  Aegis demultiplexes inbound UDP by destination port (udp_rx matches
 * s_udp[i].port == dst_port), so a socket that sends with local_port == 0 gets
 * its replies dropped — they come back to port 0, which is registered to no
 * socket.  This is exactly why DNS failed: musl's resolver sendto()s on an
 * unbound socket, so the nameserver's reply was never delivered.  DHCP worked
 * only because it bind()s port 68 explicitly.
 *
 * Assigns a free port from the ephemeral range [49152, 65535] and registers it.
 * Returns 0 on success, -1 if every ephemeral port is taken.  Caller must hold
 * a reference to the socket (sid).  No-op if the socket is already bound. */
static int
udp_ensure_local_port(sock_t *s, uint32_t sid)
{
    if (s->local_port != 0)
        return 0;
    /* Start from the rotating cursor and scan the whole ephemeral range,
     * keeping the udp_bind collision-retry loop so a port already registered to
     * another socket is skipped. The cursor advance (ephem_port_next) ensures
     * consecutive UDP sockets don't start from the same number — which is what
     * let a late DNS reply for a closed socket land in the next one. */
    uint16_t base = ephem_port_next();
    uint32_t i;
    for (i = 0; i < EPHEM_PORT_COUNT; i++) {
        uint16_t port = (uint16_t)(EPHEM_PORT_BASE +
                        (((uint32_t)base - EPHEM_PORT_BASE + i) & (EPHEM_PORT_COUNT - 1u)));
        if (udp_bind(port, sid) == 0) {
            s->local_port = port;
            return 0;
        }
    }
    return -1;
}

/* ── sys_sendto ────────────────────────────────────────────────────────── */

uint64_t
sys_sendto(uint64_t fd, uint64_t buf, uint64_t len,
           uint64_t flags, uint64_t addr, uint64_t addrlen)
{
    /* flags is intentionally ignored: neither the TCP nor UDP send path here
     * ever blocks (both copy into a static TX buffer and hand off to the NIC),
     * so MSG_DONTWAIT is a no-op; we never raise SIGPIPE so MSG_NOSIGNAL is
     * implicitly satisfied; MSG_OOB/MSG_MORE are unsupported but ignoring them
     * degrades to a normal send rather than erroring. */
    (void)flags;
    if (!user_ptr_valid(buf, len)) return SYS_ERR(EFAULT);

    /* AF_UNIX stream send: send()/sendto(NULL addr) on a connected AF_UNIX
     * socket. Without this the fd fell through to the AF_INET UDP path below
     * and returned ENETDOWN (no netdev on -machine pc) — which broke any app
     * using send()/recv() (not write()) on a UNIX socket, e.g. Ladybird's
     * TransportSocket data thread. addr is ignored (the socket is connected).
     * Mirror sys_sendmsg's AF_UNIX bounce-and-write loop. */
    {
        aegis_process_t *uproc = current_proc();
        uint32_t uuid = unix_sock_id_from_fd((int)fd, uproc);
        if (uuid != UNIX_NONE) {
            uint8_t kbuf[UNIX_BUF_SIZE]; /* bounce chunk == AF_UNIX ring size */
            uint64_t remain = len, off = 0, total = 0;
            while (remain > 0) {
                uint32_t chunk = remain > UNIX_BUF_SIZE ? UNIX_BUF_SIZE : (uint32_t)remain;
                copy_from_user(kbuf, (const void *)(uintptr_t)(buf + off), chunk);
                int n = unix_sock_write(uuid, kbuf, chunk);
                if (n < 0)
                    return total > 0 ? (uint64_t)total : (uint64_t)(int64_t)n;
                total  += (uint64_t)n;
                off    += (uint64_t)n;
                remain -= (uint64_t)n;
                if ((uint32_t)n < chunk) break; /* peer ring full — short send */
            }
            return total;
        }
    }

    sock_t *s; uint32_t sid;
    uint64_t err = get_proc_sock(fd, &s, &sid);
    if (err) return err;

    if (s->type == SOCK_TYPE_STREAM) {
        /* TCP send — blocking, segments large writes (shared helper). */
        if (s->state != SOCK_CONNECTED) return SYS_ERR(ENOTCONN);
        int64_t r = sock_stream_send(s, buf, len);
        return (uint64_t)r;  /* bytes (>=0), or -errno == SYS_ERR(errno) form */
    }

    /* UDP send */
    ip4_addr_t dst_ip;
    uint16_t   dst_port;
    if (addr && addrlen >= sizeof(k_sockaddr_in_t)) {
        /* Validate the user addr pointer before copy_from_user: uaccess has no
         * fault fixup, so an unmapped addr would panic the kernel (every other
         * sockaddr copy-in in this file guards it; this path was missed). */
        if (!user_ptr_valid(addr, sizeof(k_sockaddr_in_t))) return SYS_ERR(EFAULT);
        k_sockaddr_in_t sa;
        copy_from_user(&sa, (const void *)(uintptr_t)addr, sizeof(sa));
        dst_ip   = sa.sin_addr;
        dst_port = ntohs(sa.sin_port);
    } else if (s->state == SOCK_CONNECTED) {
        dst_ip   = s->remote_ip;
        dst_port = s->remote_port;
    } else {
        return SYS_ERR(EDESTADDRREQ);
    }

    if (len > 1472) len = 1472;  /* max UDP payload for 1500-byte MTU */
    /* STACK buffer, not a shared static: copy_from_user fills it here but
     * udp_send only reads it several calls later (netdev_get,
     * udp_ensure_local_port), a preemptible window in which a concurrent
     * sendto() would overwrite a static — caller A would then transmit
     * caller B's payload to A's destination (cross-socket corruption / leak).
     * 1472 B is safe on the 16 KB kernel stack. */
    uint8_t udpbuf[1472];
    copy_from_user(udpbuf, (const void *)(uintptr_t)buf, (uint32_t)len);

    netdev_t *dev = netdev_get("eth0");
    if (!dev) return SYS_ERR(ENETDOWN);

    /* Implicit ephemeral source-port bind so the reply can be demuxed back to
     * this socket (see udp_ensure_local_port).  Without it an unbound socket
     * sends with source port 0 and never receives a response. */
    if (udp_ensure_local_port(s, sid) != 0)
        return SYS_ERR(EADDRINUSE);  /* EADDRINUSE — no free ephemeral port */

    int r = udp_send(dev, s->local_port, dst_ip, dst_port, udpbuf, (uint16_t)len);
    return r < 0 ? SYS_ERR(ENETDOWN) : len;
}

/* ── sys_recvfrom ──────────────────────────────────────────────────────── */

uint64_t
sys_recvfrom(uint64_t fd, uint64_t buf, uint64_t len,
             uint64_t flags, uint64_t addr, uint64_t addrlen)
{
    if (!user_ptr_valid(buf, len)) return SYS_ERR(EFAULT);

    /* AF_UNIX stream recv: recv()/recvfrom() on a connected AF_UNIX socket.
     * Counterpart to the AF_UNIX sys_sendto path — without it recv() fell
     * through to the AF_INET path. unix_sock_read blocks per the socket's
     * O_NONBLOCK flag (set via FIONBIO/fcntl); MSG_DONTWAIT is not separately
     * honored here (apps that need nonblocking set the fd flag, as Ladybird
     * does). addr/addrlen are left untouched (UNIX peer addr is anonymous). */
    {
        aegis_process_t *uproc = current_proc();
        uint32_t uuid = unix_sock_id_from_fd((int)fd, uproc);
        if (uuid != UNIX_NONE) {
            uint8_t kbuf[UNIX_BUF_SIZE]; /* bounce chunk == AF_UNIX ring size */
            uint32_t want = (uint32_t)len > UNIX_BUF_SIZE ? UNIX_BUF_SIZE : (uint32_t)len;
            int n = unix_sock_read(uuid, kbuf, want, (flags & MSG_DONTWAIT) ? 1 : 0);
            if (n > 0)
                copy_to_user((void *)(uintptr_t)buf, kbuf, (uint32_t)n);
            return (n < 0) ? (uint64_t)(int64_t)n : (uint64_t)n;
        }
    }

    sock_t *s; uint32_t sid;
    uint64_t err = get_proc_sock(fd, &s, &sid);
    if (err) return err;

    /* MSG_DONTWAIT forces this single call to be nonblocking regardless of the
     * socket's O_NONBLOCK flag (Linux semantics). musl/curl pass it on their
     * "drain whatever is ready" reads; without honoring it a blocking socket
     * would sleep inside the syscall and stall the caller's event loop.
     * MSG_PEEK / MSG_WAITALL are not yet implemented; they are accepted and
     * ignored (a normal consuming read) — flagged for review, see report. */
    uint8_t nonblock = s->nonblocking || (flags & MSG_DONTWAIT) ? 1 : 0;

    uint32_t deadline = 0;
    uint8_t  has_timeout = 0;
    if (s->rcvtimeo_ticks > 0) {
        deadline = (uint32_t)arch_get_ticks() + s->rcvtimeo_ticks;
        has_timeout = 1;
    }

    if (s->type == SOCK_TYPE_STREAM) {
        for (;;) {
            int n = tcp_conn_recv(s->tcp_conn_id, (void *)0, 0);  /* peek */
            if (n > 0) {
                /* Bounce through a STACK buffer — NOT a shared static. A static
                 * bounce raced two concurrent recvfrom() calls: caller A
                 * consumes its bytes into the static, gets preempted before
                 * copy_to_user, caller B (different socket) overwrites the
                 * static, A resumes and copies out B's data — cross-socket data
                 * corruption + loss (a confidentiality bug across processes).
                 * A 2 KB stack buffer is also far safer than an 8 KB static on
                 * the 16 KB kernel stack (interrupts nest on it). Loop-drain the
                 * ring through the small buffer so one call can still return up
                 * to `len` bytes; the whole user range was validated up front
                 * and user pages are eager-mapped, so copy_to_user won't fault. */
                uint8_t rbuf[2048];
                uint32_t total = 0;
                while (total < (uint32_t)len && n > 0) {
                    uint32_t remain = (uint32_t)len - total;
                    uint32_t want   = remain < (uint32_t)n ? remain : (uint32_t)n;
                    if (want > sizeof(rbuf)) want = sizeof(rbuf);
                    int got = tcp_conn_recv(s->tcp_conn_id, rbuf, (uint16_t)want);
                    if (got <= 0) break;
                    copy_to_user((void *)(uintptr_t)(buf + total), rbuf,
                                 (uint32_t)got);
                    total += (uint32_t)got;
                    n = tcp_conn_recv(s->tcp_conn_id, (void *)0, 0);  /* re-peek */
                }
                if (total > 0)
                    return (uint64_t)total;
                /* total==0: nothing actually consumed (lost a race to another
                 * reader) — fall through to the block/EOF/EAGAIN logic. */
                n = tcp_conn_recv(s->tcp_conn_id, (void *)0, 0);
            }
            if (n == 0) return 0;  /* EOF / FIN */
            /* n < 0: -11 (alive, empty → block) or -1 (dead conn). */
            if (nonblock) return SYS_ERR(EAGAIN);
            if (has_timeout && (uint32_t)arch_get_ticks() >= deadline)
                return SYS_ERR(ETIMEDOUT);
            /* Block until data arrives or the connection closes (peek >= 0),
             * interruptible, with an optional SO_RCVTIMEO deadline.  The
             * authoritative peek + EOF/timeout decision re-runs at the top of
             * the loop after the wait returns (a timeout return hits the
             * deadline check above → ETIMEDOUT). */
            int rc;
            if (has_timeout)
                wait_event_timeout(&s->poll_waiters,
                    tcp_conn_recv(s->tcp_conn_id, (void *)0, 0) >= 0, deadline, rc);
            else
                wait_event_interruptible(&s->poll_waiters,
                    tcp_conn_recv(s->tcp_conn_id, (void *)0, 0) >= 0, rc);
            if (rc == BLOCK_EINTR) return SYS_ERR(EINTR);
        }
    }

    /* UDP recv */
    for (;;) {
        if (s->udp_rx_head != s->udp_rx_tail) {
            udp_rx_slot_t *slot = &s->udp_rx[s->udp_rx_head];
            s->udp_rx_head = (s->udp_rx_head + 1) & (UDP_RX_SLOTS - 1);
            uint32_t copy_len = slot->len < (uint32_t)len ? slot->len : (uint32_t)len;
            copy_to_user((void *)(uintptr_t)buf, slot->data, copy_len);
            if (addr && addrlen &&
                user_ptr_valid(addr, sizeof(k_sockaddr_in_t)) &&
                user_ptr_valid(addrlen, sizeof(uint32_t))) {
                k_sockaddr_in_t sa;
                sa.sin_family = AF_INET;
                sa.sin_port   = htons(slot->src_port);
                sa.sin_addr   = slot->src_ip;
                __builtin_memset(sa.sin_zero, 0, 8);
                uint32_t outlen = sizeof(sa);
                copy_to_user((void *)(uintptr_t)addrlen, &outlen, sizeof(uint32_t));
                copy_to_user((void *)(uintptr_t)addr, &sa, sizeof(sa));
            }
            slot->in_use = 0;
            return (uint64_t)copy_len;
        }
        if (nonblock) return SYS_ERR(EAGAIN);
        if (has_timeout && (uint32_t)arch_get_ticks() >= deadline)
            return SYS_ERR(ETIMEDOUT);
        /* Block until a datagram is queued, interruptible, with an optional
         * SO_RCVTIMEO deadline.  The authoritative dequeue + timeout decision
         * re-runs at the top of the loop after the wait returns. */
        int rc;
        if (has_timeout)
            wait_event_timeout(&s->poll_waiters,
                s->udp_rx_head != s->udp_rx_tail, deadline, rc);
        else
            wait_event_interruptible(&s->poll_waiters,
                s->udp_rx_head != s->udp_rx_tail, rc);
        if (rc == BLOCK_EINTR) return SYS_ERR(EINTR);
    }
}

/* ── sys_sendmsg / sys_recvmsg — AF_UNIX with SCM_RIGHTS ──────────────── */

/* Linux ABI structs for sendmsg/recvmsg */
typedef struct { void *iov_base; uint64_t iov_len; } k_iovec_t;
typedef struct {
    void      *msg_name;
    uint32_t   msg_namelen;
    uint32_t   _pad0;
    k_iovec_t *msg_iov;
    uint64_t   msg_iovlen;
    void      *msg_control;
    uint64_t   msg_controllen;
    int        msg_flags;
} k_msghdr_t;
typedef struct {
    uint64_t cmsg_len;
    int      cmsg_level;
    int      cmsg_type;
    /* payload follows */
} k_cmsghdr_t;

#define SCM_RIGHTS 1

uint64_t sys_sendmsg(uint64_t fd, uint64_t msg_ptr, uint64_t flags)
{
    aegis_process_t *proc = current_proc();
    uint32_t uid = unix_sock_id_from_fd((int)fd, proc);

    /* AF_INET sendmsg: gather the iovecs and route each through sys_sendto,
     * which already handles TCP/UDP, implicit ephemeral bind, MSG_* flags and
     * full user-pointer validation. Ancillary data (SCM_RIGHTS) is AF_UNIX-only;
     * we ignore msg_control for AF_INET. Returning ENOSYS here (the old
     * behavior) broke any program that uses sendmsg() on a network socket —
     * e.g. anything built on writev-over-socket or sendmmsg fallbacks. */
    if (uid == UNIX_NONE) {
        if (!user_ptr_valid(msg_ptr, sizeof(k_msghdr_t)))
            return SYS_ERR(EFAULT);
        k_msghdr_t imh;
        if (copy_from_user(&imh, (const void *)(uintptr_t)msg_ptr, sizeof(imh)))
            return SYS_ERR(EFAULT);  /* short copy → stale iov/name fields */
        uint64_t name    = (uint64_t)(uintptr_t)imh.msg_name;
        uint64_t namelen = imh.msg_namelen;
        int64_t  sent    = 0;
        for (uint64_t i = 0; i < imh.msg_iovlen && i < 8; i++) {
            k_iovec_t iov;
            if (!user_ptr_valid((uint64_t)(uintptr_t)imh.msg_iov + i * sizeof(k_iovec_t),
                                sizeof(k_iovec_t)))
                return SYS_ERR(EFAULT);
            if (copy_from_user(&iov,
                (const void *)((uintptr_t)imh.msg_iov + i * sizeof(k_iovec_t)),
                sizeof(iov)))
                return SYS_ERR(EFAULT);  /* short copy → stale iov_base/iov_len */
            if (iov.iov_len == 0) continue;
            uint64_t r = sys_sendto(fd, (uint64_t)(uintptr_t)iov.iov_base,
                                    iov.iov_len, flags, name, namelen);
            /* sys_sendto returns errno as a huge unsigned (>= -4095 wrapped). */
            if ((int64_t)r < 0)
                return sent > 0 ? (uint64_t)sent : r;
            sent += (int64_t)r;
            /* Short datagram/stream send: stop (don't reorder the stream). */
            if (r < iov.iov_len) break;
        }
        return (uint64_t)sent;
    }

    (void)flags;
    if (!user_ptr_valid(msg_ptr, sizeof(k_msghdr_t))) return SYS_ERR(EFAULT);
    k_msghdr_t mh;
    /* A partial copy (sibling CLONE_VM thread munmap'd the buffer mid-copy)
     * would leave mh's pointer/length fields holding stale stack bytes that
     * are then dereferenced — treat any short copy as EFAULT. */
    if (copy_from_user(&mh, (const void *)(uintptr_t)msg_ptr, sizeof(mh)))
        return SYS_ERR(EFAULT);

    /* Send iov data */
    int64_t total_sent = 0;
    for (uint64_t i = 0; i < mh.msg_iovlen && i < 8; i++) {
        k_iovec_t iov;
        if (!user_ptr_valid((uint64_t)(uintptr_t)mh.msg_iov + i * sizeof(k_iovec_t), sizeof(k_iovec_t)))
            return SYS_ERR(EFAULT);
        if (copy_from_user(&iov, (const void *)((uintptr_t)mh.msg_iov + i * sizeof(k_iovec_t)), sizeof(iov)))
            return SYS_ERR(EFAULT);  /* short copy → stale iov_base/iov_len */
        if (iov.iov_len == 0) continue;
        if (!user_ptr_valid((uint64_t)(uintptr_t)iov.iov_base, iov.iov_len))
            return SYS_ERR(EFAULT);
        /* Copy iov data to kernel buffer, then write to socket */
        uint8_t kbuf[UNIX_BUF_SIZE]; /* bounce chunk == AF_UNIX ring size */
        uint64_t remain = iov.iov_len;
        uint64_t off = 0;
        while (remain > 0) {
            uint32_t chunk = remain > UNIX_BUF_SIZE ? UNIX_BUF_SIZE : (uint32_t)remain;
            copy_from_user(kbuf, (const void *)((uintptr_t)iov.iov_base + off), chunk);
            int n = unix_sock_write(uid, kbuf, chunk);
            if (n < 0) return total_sent > 0 ? (uint64_t)total_sent : (uint64_t)(int64_t)n;
            total_sent += n;
            off += (uint64_t)n;
            remain -= (uint64_t)n;
        }
    }

    /* Process ancillary data (SCM_RIGHTS) */
    if (mh.msg_control && mh.msg_controllen >= sizeof(k_cmsghdr_t)) {
        if (!user_ptr_valid((uint64_t)(uintptr_t)mh.msg_control, mh.msg_controllen))
            return SYS_ERR(EFAULT);
        k_cmsghdr_t cm;
        if (copy_from_user(&cm, (const void *)(uintptr_t)mh.msg_control, sizeof(cm)))
            return SYS_ERR(EFAULT);  /* short copy → stale cmsg_len/level/type */

        if (cm.cmsg_level == SOL_SOCKET && cm.cmsg_type == SCM_RIGHTS) {
            /* cmsg_len underflow guard: cm.cmsg_len comes from userspace.
             * A value < sizeof(k_cmsghdr_t) would underflow payload_len to a
             * huge unsigned value, truncating nfds to a negative int that
             * slips past the upper clamp and turns the fd-array copy into a
             * ~4 GiB stack smash. Requiring cmsg_len <= msg_controllen keeps
             * the subsequent copy inside the already-validated user range. */
            if (cm.cmsg_len < sizeof(k_cmsghdr_t) || cm.cmsg_len > mh.msg_controllen)
                return SYS_ERR(EINVAL);
            uint64_t payload_len = cm.cmsg_len - sizeof(k_cmsghdr_t);
            /* Compute the fd count in unsigned, then clamp BEFORE narrowing to
             * int. The underflow guard above keeps payload_len >= 0, but
             * payload_len can still be enormous (msg_controllen, hence
             * cmsg_len, is only bounded by what user_ptr_valid accepts — an
             * 8 GiB user mapping would let payload_len/4 exceed INT_MAX). The
             * old code did `int nfds = (int)(payload_len / sizeof(int))` and
             * only clamped `nfds > UNIX_PASSED_FD_MAX`: a value >= 2^31 cast to
             * int became NEGATIVE, slipping past that upper clamp, and the
             * subsequent `(uint32_t)(nfds * sizeof(int))` copy length became a
             * huge wrapped value -> out-of-bounds copy into the 16-int stack
             * buffer. Clamping the unsigned quotient first makes the int cast
             * always land in [0, UNIX_PASSED_FD_MAX], so it cannot go negative
             * and the copy length cannot overflow. */
            uint64_t nfds_u = payload_len / sizeof(int);
            if (nfds_u > (uint64_t)UNIX_PASSED_FD_MAX) nfds_u = (uint64_t)UNIX_PASSED_FD_MAX;
            int nfds = (int)nfds_u;

            int sender_fds[UNIX_PASSED_FD_MAX];
            if (nfds > 0)
                copy_from_user(sender_fds,
                    (const void *)((uintptr_t)mh.msg_control + sizeof(k_cmsghdr_t)),
                    (uint32_t)((uint64_t)nfds * sizeof(int)));

            /* Dup each fd and stage for peer */
            unix_sock_t *us = unix_sock_get(uid);
            if (us && us->peer_id != UNIX_NONE) {
                unix_passed_fd_t staged[UNIX_PASSED_FD_MAX];
                uint8_t count = 0;
                for (int i = 0; i < nfds; i++) {
                    int sfd = sender_fds[i];
                    if (sfd < 0 || sfd >= PROC_MAX_FDS) continue;
                    vfs_file_t *f = &proc->fd_table->fds[sfd];
                    if (!f->ops) continue;
                    if (f->ops->dup) f->ops->dup(f->priv);
                    staged[count].ops   = f->ops;
                    staged[count].priv  = f->priv;
                    staged[count].flags = f->flags;
                    count++;
                }
                if (count > 0) {
                    int sr = unix_sock_stage_fds(us->peer_id, staged, count);
                    if (sr < 0) {
                        /* Staging failed (peer full or closed/lingering):
                         * release the refs we just dup'd, else they leak
                         * (the memfd/socket slot would never reach 0). */
                        for (uint8_t k = 0; k < count; k++)
                            if (staged[k].ops && staged[k].ops->close)
                                staged[k].ops->close(staged[k].priv);
                    }
                }
            }
        }
    }

    return (uint64_t)total_sent;
}

uint64_t sys_recvmsg(uint64_t fd, uint64_t msg_ptr, uint64_t flags)
{
    aegis_process_t *proc = current_proc();
    uint32_t uid = unix_sock_id_from_fd((int)fd, proc);

    /* AF_INET recvmsg: receive into the first non-empty iovec via sys_recvfrom,
     * which fills the source address into msg_name (a separate addrlen scratch
     * is required because sys_recvfrom writes a 4-byte length there). One recv
     * per call preserves datagram boundaries for UDP and is always a legal
     * (possibly short) read for TCP. No ancillary data for AF_INET — we zero
     * msg_controllen. Old behavior (ENOSYS) broke recvmsg() on net sockets. */
    if (uid == UNIX_NONE) {
        if (!user_ptr_valid(msg_ptr, sizeof(k_msghdr_t)))
            return SYS_ERR(EFAULT);
        k_msghdr_t imh;
        if (copy_from_user(&imh, (const void *)(uintptr_t)msg_ptr, sizeof(imh)))
            return SYS_ERR(EFAULT);  /* short copy → stale iov/name fields */

        uint64_t r = 0;
        for (uint64_t i = 0; i < imh.msg_iovlen && i < 8; i++) {
            k_iovec_t iov;
            if (!user_ptr_valid((uint64_t)(uintptr_t)imh.msg_iov + i * sizeof(k_iovec_t),
                                sizeof(k_iovec_t)))
                return SYS_ERR(EFAULT);
            if (copy_from_user(&iov,
                (const void *)((uintptr_t)imh.msg_iov + i * sizeof(k_iovec_t)),
                sizeof(iov)))
                return SYS_ERR(EFAULT);  /* short copy → stale iov_base/iov_len */
            if (iov.iov_len == 0) continue;

            /* sys_recvfrom needs a writable u32 at *addrlen; reuse the user
             * msg_namelen slot only if a name buffer was supplied. */
            uint64_t name = (uint64_t)(uintptr_t)imh.msg_name;
            uint64_t alen = name
                ? (uint64_t)(uintptr_t)msg_ptr + __builtin_offsetof(k_msghdr_t, msg_namelen)
                : 0;
            r = sys_recvfrom(fd, (uint64_t)(uintptr_t)iov.iov_base,
                             iov.iov_len, flags, name, alen);
            break;  /* one iovec per recvmsg call */
        }
        /* Clear msg_controllen — no ancillary data delivered for AF_INET. */
        if (imh.msg_control) {
            uint64_t zero = 0;
            copy_to_user((void *)((uintptr_t)msg_ptr +
                         __builtin_offsetof(k_msghdr_t, msg_controllen)),
                         &zero, sizeof(uint64_t));
        }
        return r;
    }

    (void)flags;
    if (!user_ptr_valid(msg_ptr, sizeof(k_msghdr_t))) return SYS_ERR(EFAULT);
    k_msghdr_t mh;
    if (copy_from_user(&mh, (const void *)(uintptr_t)msg_ptr, sizeof(mh)))
        return SYS_ERR(EFAULT);  /* short copy → stale iov/control fields */

    /* Recv iov data */
    int64_t total_recv = 0;
    for (uint64_t i = 0; i < mh.msg_iovlen && i < 8; i++) {
        k_iovec_t iov;
        if (!user_ptr_valid((uint64_t)(uintptr_t)mh.msg_iov + i * sizeof(k_iovec_t), sizeof(k_iovec_t)))
            return SYS_ERR(EFAULT);
        if (copy_from_user(&iov, (const void *)((uintptr_t)mh.msg_iov + i * sizeof(k_iovec_t)), sizeof(iov)))
            return SYS_ERR(EFAULT);  /* short copy → stale iov_base/iov_len */
        if (iov.iov_len == 0) continue;
        if (!user_ptr_valid((uint64_t)(uintptr_t)iov.iov_base, iov.iov_len))
            return SYS_ERR(EFAULT);
        uint8_t kbuf[UNIX_BUF_SIZE]; /* bounce chunk == AF_UNIX ring size */
        uint64_t remain = iov.iov_len;
        uint64_t off = 0;
        while (remain > 0) {
            uint32_t chunk = remain > UNIX_BUF_SIZE ? UNIX_BUF_SIZE : (uint32_t)remain;
            int n = unix_sock_read(uid, kbuf, chunk, (flags & MSG_DONTWAIT) ? 1 : 0);
            if (n <= 0) {
                if (total_recv > 0) goto done;
                return n == 0 ? 0 : (uint64_t)(int64_t)n;
            }
            copy_to_user((void *)((uintptr_t)iov.iov_base + off), kbuf, (uint32_t)n);
            total_recv += n;
            off += (uint64_t)n;
            remain -= (uint64_t)n;
            if ((uint32_t)n < chunk) goto done;  /* partial read: don't block for more */
        }
    }
done:

    /* Receive staged fds if msg_control provided */
    if (mh.msg_control && mh.msg_controllen >= sizeof(k_cmsghdr_t) + sizeof(int)) {
        /* SECURITY: validate the user-controlled msg_control pointer before any
         * copy_to_user into it.  Without this a caller can point msg_control at a
         * kernel VA and have the kernel write the cmsg header + fd ints there
         * (arbitrary kernel write -> privesc).  Mirrors the sendmsg path. */
        if (!user_ptr_valid((uint64_t)(uintptr_t)mh.msg_control, mh.msg_controllen))
            return SYS_ERR(EFAULT);
        /* Install only as many fds as the caller's control buffer can actually
         * report. unix_sock_recv_fds installs into the receiver's fd table
         * immediately; if we asked for UNIX_PASSED_FD_MAX but the buffer only
         * fits a few, the extra fds were installed yet never announced in a
         * cmsg (the copy block below was skipped on total_cm > controllen) —
         * a silent fd-table leak/exhaustion. Cap max_fds to what fits; any
         * staged fds beyond it are closed by unix_sock_recv_fds (Linux
         * discards truncated SCM_RIGHTS fds). The >= floor at the enclosing
         * check guarantees max_fds >= 1. */
        int max_fds = (int)((mh.msg_controllen - sizeof(k_cmsghdr_t)) / sizeof(int));
        if (max_fds > UNIX_PASSED_FD_MAX) max_fds = UNIX_PASSED_FD_MAX;
        int received_fds[UNIX_PASSED_FD_MAX];
        int nfds = unix_sock_recv_fds(uid, received_fds, max_fds);
        if (nfds > 0) {
            /* Build cmsghdr + fd array */
            k_cmsghdr_t cm;
            cm.cmsg_len   = sizeof(k_cmsghdr_t) + (uint64_t)(nfds * sizeof(int));
            cm.cmsg_level = SOL_SOCKET;
            cm.cmsg_type  = SCM_RIGHTS;

            uint64_t total_cm = sizeof(k_cmsghdr_t) + (uint64_t)(nfds * sizeof(int));
            if (total_cm <= mh.msg_controllen) {
                copy_to_user((void *)(uintptr_t)mh.msg_control, &cm, sizeof(cm));
                copy_to_user((void *)((uintptr_t)mh.msg_control + sizeof(k_cmsghdr_t)),
                    received_fds, (uint32_t)(nfds * sizeof(int)));
                /* Update msg_controllen in user struct */
                copy_to_user((void *)((uintptr_t)msg_ptr + __builtin_offsetof(k_msghdr_t, msg_controllen)),
                    &total_cm, sizeof(uint64_t));
            }
        } else {
            /* No fds — zero out controllen */
            uint64_t zero = 0;
            copy_to_user((void *)((uintptr_t)msg_ptr + __builtin_offsetof(k_msghdr_t, msg_controllen)),
                &zero, sizeof(uint64_t));
        }
    }

    return (uint64_t)total_recv;
}

/* ── sys_shutdown ──────────────────────────────────────────────────────── */

uint64_t
sys_shutdown(uint64_t fd, uint64_t how)
{
    (void)how;
    sock_t *s; uint32_t sid;
    uint64_t err = get_proc_sock(fd, &s, &sid);
    if (err) return err;

    if (s->type == SOCK_TYPE_STREAM && s->tcp_conn_id != SOCK_NONE) {
        tcp_conn_close(s->tcp_conn_id);
    }
    s->state = SOCK_CLOSED;
    return 0;
}

/* ── sys_getsockname / sys_getpeername ──────────────────────────────────── */

uint64_t
sys_getsockname(uint64_t fd, uint64_t addr, uint64_t addrlen)
{
    if (!user_ptr_valid(addr, sizeof(k_sockaddr_in_t))) return SYS_ERR(EFAULT);
    if (!addrlen) return SYS_ERR(EFAULT);
    if (!user_ptr_valid(addrlen, sizeof(uint32_t))) return SYS_ERR(EFAULT);
    sock_t *s; uint32_t sid;
    uint64_t err = get_proc_sock(fd, &s, &sid);
    if (err) return err;
    k_sockaddr_in_t sa;
    sa.sin_family = AF_INET;
    sa.sin_port   = htons(s->local_port);
    sa.sin_addr   = s->local_ip;
    __builtin_memset(sa.sin_zero, 0, 8);
    uint32_t outlen = sizeof(sa);
    copy_to_user((void *)(uintptr_t)addrlen, &outlen, sizeof(uint32_t));
    copy_to_user((void *)(uintptr_t)addr, &sa, sizeof(sa));
    return 0;
}

uint64_t
sys_getpeername(uint64_t fd, uint64_t addr, uint64_t addrlen)
{
    if (!user_ptr_valid(addr, sizeof(k_sockaddr_in_t))) return SYS_ERR(EFAULT);
    if (!addrlen) return SYS_ERR(EFAULT);
    if (!user_ptr_valid(addrlen, sizeof(uint32_t))) return SYS_ERR(EFAULT);
    sock_t *s; uint32_t sid;
    uint64_t err = get_proc_sock(fd, &s, &sid);
    if (err) return err;
    if (s->state != SOCK_CONNECTED) return SYS_ERR(ENOTCONN);
    k_sockaddr_in_t sa;
    sa.sin_family = AF_INET;
    sa.sin_port   = htons(s->remote_port);
    sa.sin_addr   = s->remote_ip;
    __builtin_memset(sa.sin_zero, 0, 8);
    uint32_t outlen = sizeof(sa);
    copy_to_user((void *)(uintptr_t)addrlen, &outlen, sizeof(uint32_t));
    copy_to_user((void *)(uintptr_t)addr, &sa, sizeof(sa));
    return 0;
}

/* ── sys_socketpair ────────────────────────────────────────────────────── */

uint64_t
sys_socketpair(uint64_t domain, uint64_t type, uint64_t proto, uint64_t sv_ptr)
{
    (void)proto;
    if (domain != AF_UNIX) return SYS_ERR(EAFNOSUPPORT);
    if (type != SOCK_STREAM && type != SOCK_DGRAM)
        return SYS_ERR(EPROTONOSUPPORT);
    if (!user_ptr_valid(sv_ptr, 2 * sizeof(int)))
        return SYS_ERR(EFAULT);

    aegis_process_t *proc = current_proc();
    if (cap_check(proc->caps, CAP_TABLE_SIZE, CAP_KIND_IPC, CAP_RIGHTS_READ) != 0)
        return SYS_ERR(ENOCAP);

    /* Create a REAL AF_UNIX socketpair (two cross-connected unix_sock_t with
     * ring buffers).  The old implementation handed back AF_INET DGRAM loopback
     * sockets, so send()/recv() on the pair routed through the AF_INET UDP path
     * and failed with ENETDOWN when there was no NIC — silently breaking every
     * IPC transport built on socketpair (Ladybird's WebContent/service IPC). */
    uint32_t sid0, sid1;
    SC_PROPAGATE(unix_sock_pair(&sid0, &sid1));

    int fd0 = unix_sock_open_fd(sid0, proc);
    int fd1 = unix_sock_open_fd(sid1, proc);
    if (fd0 < 0 || fd1 < 0) {
        if (fd0 >= 0) {
            proc->fd_table->fds[fd0].ops  = (const vfs_ops_t *)0;
            proc->fd_table->fds[fd0].priv = (void *)0;
        }
        if (fd1 >= 0) {
            proc->fd_table->fds[fd1].ops  = (const vfs_ops_t *)0;
            proc->fd_table->fds[fd1].priv = (void *)0;
        }
        unix_sock_free(sid0);
        unix_sock_free(sid1);
        return SYS_ERR(EMFILE);
    }
    int fds[2] = { fd0, fd1 };
    copy_to_user((void *)(uintptr_t)sv_ptr, fds, sizeof(fds));
    return 0;
}

/* ── sys_setsockopt ────────────────────────────────────────────────────── */

uint64_t
sys_setsockopt(uint64_t fd, uint64_t level, uint64_t optname,
               uint64_t optval, uint64_t optlen)
{
    if (optlen < sizeof(int)) return SYS_ERR(EINVAL);
    if (!user_ptr_valid(optval, sizeof(int))) return SYS_ERR(EFAULT);

    sock_t *s; uint32_t sid;
    uint64_t err = get_proc_sock(fd, &s, &sid);
    if (err) return err;

    int val;
    copy_from_user(&val, (const void *)(uintptr_t)optval, sizeof(int));

    if (level == SOL_SOCKET) {
        switch (optname) {
        case SO_REUSEADDR: s->reuseaddr = val ? 1 : 0; return 0;
        case SO_BROADCAST: s->broadcast = val ? 1 : 0; return 0;
        case SO_RCVTIMEO: {
            /* optval is struct timeval {tv_sec, tv_usec} — 16 bytes */
            if (optlen >= 16) {
                if (!user_ptr_valid(optval, 16))
                    return SYS_ERR(EFAULT);
                int64_t tv_sec;
                int64_t tv_usec;
                copy_from_user(&tv_sec,  (const void *)(uintptr_t)optval,     8);
                copy_from_user(&tv_usec, (const void *)(uintptr_t)(optval+8), 8);
                /* Clamp the user-supplied timeval before scaling: a negative
                 * value cast to uint32_t becomes a huge (near-infinite) timeout,
                 * and a large tv_sec overflows tv_sec*100 / the uint32_t cast to
                 * a garbage value. Upper bound keeps tv_sec*100 within uint32_t
                 * (~497 days). Recovered from the April audit (1d0528f). */
                if (tv_sec  < 0)        tv_sec  = 0;
                if (tv_sec  > 42949672) tv_sec  = 42949672;
                if (tv_usec < 0)        tv_usec = 0;
                if (tv_usec > 999999)   tv_usec = 999999;
                /* Convert to PIT ticks (100 Hz) */
                s->rcvtimeo_ticks = (uint32_t)(tv_sec * 100 + tv_usec / 10000);
            }
            return 0;
        }
        case SO_SNDTIMEO: {
            if (optlen >= 16) {
                if (!user_ptr_valid(optval, 16))
                    return SYS_ERR(EFAULT);
                int64_t tv_sec;
                int64_t tv_usec;
                copy_from_user(&tv_sec,  (const void *)(uintptr_t)optval,     8);
                copy_from_user(&tv_usec, (const void *)(uintptr_t)(optval+8), 8);
                /* Clamp before scaling — see SO_RCVTIMEO (April audit 1d0528f). */
                if (tv_sec  < 0)        tv_sec  = 0;
                if (tv_sec  > 42949672) tv_sec  = 42949672;
                if (tv_usec < 0)        tv_usec = 0;
                if (tv_usec > 999999)   tv_usec = 999999;
                s->sndtimeo_ticks = (uint32_t)(tv_sec * 100 + tv_usec / 10000);
            }
            return 0;
        }
        /* Accepted-and-ignored: we don't model these knobs, but returning
         * success (rather than ENOPROTOOPT) keeps real programs from aborting.
         * setsockopt(SO_REUSEADDR/SO_KEEPALIVE/SO_*BUF) is reflexive startup
         * code in most network apps; an error here would fail them at launch. */
        case SO_KEEPALIVE:
        case SO_SNDBUF:
        case SO_RCVBUF:
            return 0;
        default: return SYS_ERR(ENOPROTOOPT);
        }
    }
    if (level == IPPROTO_TCP && optname == TCP_NODELAY) {
        return 0;  /* TCP_NODELAY acknowledged but not implemented */
    }
    return SYS_ERR(ENOPROTOOPT);  /* ENOPROTOOPT: unknown level */
}

/* ── sys_getsockopt ────────────────────────────────────────────────────── */

/* struct ucred for SO_PEERCRED */
typedef struct { int pid; int uid; int gid; } k_ucred_t;

uint64_t
sys_getsockopt(uint64_t fd, uint64_t level, uint64_t optname,
               uint64_t optval, uint64_t optlen)
{
    if (!user_ptr_valid(optval, sizeof(int))) return SYS_ERR(EFAULT);

    /* AF_UNIX: SO_PEERCRED */
    aegis_process_t *proc_g = current_proc();
    uint32_t uid = unix_sock_id_from_fd((int)fd, proc_g);
    if (uid != UNIX_NONE && level == SOL_SOCKET && optname == SO_PEERCRED) {
        if (!user_ptr_valid(optval, sizeof(k_ucred_t))) return SYS_ERR(EFAULT);
        uint32_t p_pid, p_uid, p_gid;
        int rc = unix_sock_peercred(uid, &p_pid, &p_uid, &p_gid);
        if (rc < 0) return (uint64_t)(int64_t)rc;
        k_ucred_t uc = { .pid = (int)p_pid, .uid = (int)p_uid, .gid = (int)p_gid };
        copy_to_user((void *)(uintptr_t)optval, &uc, sizeof(uc));
        uint32_t outlen = sizeof(uc);
        if (optlen) {
            if (!user_ptr_valid(optlen, sizeof(uint32_t))) return SYS_ERR(EFAULT);
            copy_to_user((void *)(uintptr_t)optlen, &outlen, sizeof(uint32_t));
        }
        return 0;
    }

    sock_t *s; uint32_t sid;
    uint64_t err = get_proc_sock(fd, &s, &sid);
    if (err) return err;

    /* SO_RCVTIMEO / SO_SNDTIMEO read back a struct timeval (16 bytes), not an
     * int. Handle them before the int-sized common path so the caller's buffer
     * isn't truncated. */
    if (level == SOL_SOCKET &&
        (optname == SO_RCVTIMEO || optname == SO_SNDTIMEO)) {
        if (!user_ptr_valid(optval, 16)) return SYS_ERR(EFAULT);
        uint32_t t = (optname == SO_RCVTIMEO) ? s->rcvtimeo_ticks
                                              : s->sndtimeo_ticks;
        int64_t tv_sec  = (int64_t)(t / 100);
        int64_t tv_usec = (int64_t)((t % 100) * 10000);
        copy_to_user((void *)(uintptr_t)optval,       &tv_sec,  8);
        copy_to_user((void *)(uintptr_t)(optval + 8), &tv_usec, 8);
        uint32_t outlen16 = 16;
        if (optlen) {
            if (!user_ptr_valid(optlen, sizeof(uint32_t))) return SYS_ERR(EFAULT);
            copy_to_user((void *)(uintptr_t)optlen, &outlen16, sizeof(uint32_t));
        }
        return 0;
    }

    int val = 0;
    if (level == SOL_SOCKET) {
        switch (optname) {
        case SO_REUSEADDR: val = s->reuseaddr; break;
        case SO_BROADCAST: val = s->broadcast; break;
        /* SO_TYPE: report the original socket type (SOCK_STREAM/SOCK_DGRAM).
         * getsockopt is in terms of the userspace constants, which match
         * SOCK_TYPE_STREAM(1)/SOCK_TYPE_DGRAM(2). */
        case SO_TYPE:
            val = (s->type == SOCK_TYPE_STREAM) ? SOCK_STREAM : SOCK_DGRAM;
            break;
        /* SO_ERROR: retrieve-and-clear the pending socket error. This is how a
         * program completes a nonblocking connect() — after poll() reports the
         * fd writable it calls getsockopt(SO_ERROR) to learn success (0) vs.
         * failure (ECONNREFUSED, ...). We have no dedicated so_error field, so
         * derive it from the connection state: CONNECTED→0, still CONNECTING→
         * EINPROGRESS, CLOSED while we were connecting→ECONNREFUSED. Without
         * this, every nonblocking connect appears to fail and libcurl/openssl
         * event loops give up. */
        case SO_ERROR:
            if (s->type == SOCK_TYPE_STREAM) {
                if (s->state == SOCK_CONNECTED)        val = 0;
                else if (s->state == SOCK_CONNECTING)  val = 115; /* EINPROGRESS */
                else if (s->state == SOCK_CLOSED)      val = 111; /* ECONNREFUSED */
                else                                   val = 0;
            } else {
                val = 0;
            }
            break;
        /* Accepted-and-reported so option-probing code (which often reads back
         * what it set) sees sane values rather than ENOPROTOOPT. We don't model
         * these, so report benign defaults. */
        case SO_KEEPALIVE: val = 0;     break;
        case SO_SNDBUF:    val = 8192;  break;  /* TCP_SBUF_SIZE */
        case SO_RCVBUF:    val = 16384; break;  /* TCP_RBUF_SIZE */
        default: break;
        }
    } else if (level == IPPROTO_TCP && optname == TCP_NODELAY) {
        val = 0;  /* not implemented; report disabled */
    }
    copy_to_user((void *)(uintptr_t)optval, &val, sizeof(int));
    uint32_t outlen = sizeof(int);
    if (optlen) {
        if (!user_ptr_valid(optlen, sizeof(uint32_t))) return SYS_ERR(EFAULT);
        copy_to_user((void *)(uintptr_t)optlen, &outlen, sizeof(uint32_t));
    }
    return 0;
}

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
        if (copy_from_user(&ts, (const void *)(uintptr_t)ts_ptr, sizeof(ts)) != 0)
            return SYS_ERR(EFAULT);
        int64_t ms = ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
        if (ms < 0) ms = 0;
        timeout_ms = (uint64_t)ms;
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
        for (i = 0; i < nfds; i++) {
            fd_queues[i]           = fd_get_waitq(fds_cached[i]);
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

        for (i = 0; i < nfds; i++)
            if (fd_queues[i])
                waitq_remove(fd_queues[i], &fd_entries[i]);
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

        for (i = 0; i < nfds; i++) {
            fd_queues[i]           = fd_get_waitq(pf[i].fd);
            fd_entries[i].task     = sched_current();
            fd_entries[i].next     = (void *)0;
            fd_entries[i].prev     = (void *)0;
            fd_entries[i].on_queue = 0;
            if (fd_queues[i]) waitq_add(fd_queues[i], &fd_entries[i]);
        }
        waitq_add(&g_timer_waitq, &timer_entry);
        sched_block();
        for (i = 0; i < nfds; i++)
            if (fd_queues[i]) waitq_remove(fd_queues[i], &fd_entries[i]);
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
    if (maxevents > EPOLL_MAX_WATCHES) return SYS_ERR(EINVAL);
    if (!user_ptr_valid(events_ptr, (uint64_t)maxevents * sizeof(k_epoll_event_t)))
        return SYS_ERR(EFAULT);

    uint32_t ticks = (timeout_ms == (uint64_t)-1) ? 0xFFFFFFFFU :
                     (timeout_ms == 0) ? 0 :
                     (uint32_t)(timeout_ms / 10);
    int r = epoll_wait_impl(eid, events_ptr, (int)maxevents, ticks);
    return r < 0 ? (uint64_t)(int64_t)r : (uint64_t)r;
}

/* ── sys_netcfg ─────────────────────────────────────────────────────────── */

typedef struct {
    uint8_t  mac[6];
    uint8_t  pad[2];
    uint32_t ip;
    uint32_t mask;
    uint32_t gateway;
} netcfg_info_t;

/* WiFi control surface — implemented in kernel/drivers/iwl_ax200.c. The struct
 * mirrors wifi_net_pub_t there and in lumen-netman; keep the three in sync. */
typedef struct {
    char    ssid[33];
    uint8_t channel;
    uint8_t sec;         /* 0 = open, 1 = secured */
    uint8_t connected;   /* 1 = currently associated */
    uint8_t pad;
} wifi_net_pub_t;
extern int iwl_wifi_present(void);
extern int iwl_wifi_list(wifi_net_pub_t *out, int max);
extern int iwl_wifi_connect(const char *ssid);
extern int iwl_wifi_rescan(void);

uint64_t
sys_netcfg(uint64_t op, uint64_t arg1, uint64_t arg2, uint64_t arg3)
{
    aegis_process_t *proc = current_proc();

    if (op == 0) {
        /* op=0 (set IP/mask/gw) is privileged — requires NET_ADMIN. */
        if (cap_check(proc->caps, CAP_TABLE_SIZE,
                      CAP_KIND_NET_ADMIN, CAP_RIGHTS_WRITE) != 0)
            return SYS_ERR(ENOCAP);
        /* Set IP/mask/gw */
        net_set_config((ip4_addr_t)arg1, (ip4_addr_t)arg2, (ip4_addr_t)arg3);

        /* Proactively resolve gateway ARP so it's cached before any TCP
         * connections arrive.  Without this, the first inbound TCP SYN
         * triggers arp_resolve from the PIT ISR (via tcp_rx → ip_send),
         * which would deadlock if ARP isn't cached.  Safe to call here:
         * syscall context, interrupts enabled, no spinlocks held. */
        if (arg3 != 0) {
            netdev_t *dev = netdev_get("eth0");
            if (dev) {
                mac_addr_t gw_mac;
                arp_resolve(dev, (ip4_addr_t)arg3, &gw_mac);
            }
        }
        return 0;
    }
    if (op == 1) {
        /* Read current config + MAC. Requires NET_SOCKET: the host MAC/IP/gw is
         * network identity and shouldn't be readable by every baseline process
         * (op=0 already needs NET_ADMIN; the read path was ungated). Legit
         * readers (ip/ifconfig, dhcp, bastion greeter) carry NET_SOCKET. */
        if (cap_check(proc->caps, CAP_TABLE_SIZE,
                      CAP_KIND_NET_SOCKET, CAP_RIGHTS_READ) != 0)
            return SYS_ERR(ENOCAP);
        if (!user_ptr_valid(arg1, sizeof(netcfg_info_t))) return SYS_ERR(EFAULT);
        netdev_t *dev = netdev_get("eth0");
        if (!dev) return SYS_ERR(ENODEV);
        netcfg_info_t info;
        __builtin_memset(&info, 0, sizeof(info));
        uint32_t i;
        for (i = 0; i < 6; i++) info.mac[i] = dev->mac[i];
        ip4_addr_t ip, mask, gw;
        net_get_config(&ip, &mask, &gw);
        info.ip      = ip;
        info.mask    = mask;
        info.gateway = gw;
        copy_to_user((void *)(uintptr_t)arg1, &info, sizeof(info));
        return 0;
    }
#ifdef __x86_64__   /* WiFi ops need the AX200 driver (iwl_ax200.c), x86_64-only */
    if (op == 2) {
        /* op=2 (list WiFi networks): arg1 = user wifi_net_pub_t[], arg2 = max
         * entries. Returns the count. A read of scan state -> NET_SOCKET. */
        if (cap_check(proc->caps, CAP_TABLE_SIZE,
                      CAP_KIND_NET_SOCKET, CAP_RIGHTS_READ) != 0)
            return SYS_ERR(ENOCAP);
        if (!iwl_wifi_present()) return SYS_ERR(ENODEV);
        int max = (int)arg2;
        if (max <= 0) return SYS_ERR(EINVAL);
        if (max > 24) max = 24;                       /* WIFI_MAX_NETS */
        if (!user_ptr_valid(arg1, (uint64_t)max * sizeof(wifi_net_pub_t)))
            return SYS_ERR(EFAULT);
        wifi_net_pub_t tmp[24];
        __builtin_memset(tmp, 0, sizeof(tmp));
        int n = iwl_wifi_list(tmp, max);
        if (n > 0)
            copy_to_user((void *)(uintptr_t)arg1, tmp, (uint64_t)n * sizeof(wifi_net_pub_t));
        return (uint64_t)n;
    }
    if (op == 4) {
        /* op=4 (rescan): re-run the WiFi scan (blocking a few seconds), returns
         * the new count. Benign radio activity -> NET_SOCKET. */
        if (cap_check(proc->caps, CAP_TABLE_SIZE,
                      CAP_KIND_NET_SOCKET, CAP_RIGHTS_READ) != 0)
            return SYS_ERR(ENOCAP);
        if (!iwl_wifi_present()) return SYS_ERR(ENODEV);
        int n = iwl_wifi_rescan();
        return n < 0 ? SYS_ERR(EIO) : (uint64_t)n;
    }
    if (op == 3) {
        /* op=3 (connect to SSID): arg1 = user SSID string. Active control that
         * changes the host's network association -> NET_ADMIN (same class as
         * op=0), intentionally not held by the plain netman GUI. */
        if (cap_check(proc->caps, CAP_TABLE_SIZE,
                      CAP_KIND_NET_ADMIN, CAP_RIGHTS_WRITE) != 0)
            return SYS_ERR(ENOCAP);
        if (!iwl_wifi_present()) return SYS_ERR(ENODEV);
        if (!user_ptr_valid(arg1, 1)) return SYS_ERR(EFAULT);
        char ssid[33];
        __builtin_memset(ssid, 0, sizeof(ssid));
        if (copy_from_user(ssid, (const void *)(uintptr_t)arg1, sizeof(ssid) - 1) != 0)
            return SYS_ERR(EFAULT);
        ssid[32] = 0;
        int rc = iwl_wifi_connect(ssid);
        return rc == 0 ? 0 : SYS_ERR(EIO);
    }
#endif /* __x86_64__ */
    return SYS_ERR(EINVAL);
}
