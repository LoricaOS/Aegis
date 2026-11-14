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
#include "ipv6.h"
#include "unix_socket.h"
#include "fd_waitq.h"
#include "signal.h"
#include "memfd.h"
#include "pipe.h"
#include "fs_ops.h"

/* scm_fd_passable — may this fd cross a process boundary via SCM_RIGHTS?
 *
 * No-authority IPC/shared-memory primitives and explicitly confined ext2
 * directory capabilities may pass. Ordinary filesystem and device fds remain
 * blocked. A confined directory carries its root/rights metadata, while
 * AUTH/INSTALL are rechecked on every derived open. */
static int
scm_fd_passable(const vfs_file_t *f)
{
    if (f->ops == &g_memfd_ops ||
        f->ops == &g_pipe_read_ops || f->ops == &g_pipe_write_ops ||
        f->ops == &g_unix_sock_ops)
        return 1;
    if (!(f->kflags & VFS_KF_CAP_CONFINED))
        return 0;
    uint32_t ino = g_rootfs->ino_of(f->ops, f->priv);
    return ino != 0 && g_rootfs->is_dir(ino);
}

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

/* send/recv flags (Linux ABI). Receive calls support MSG_DONTWAIT only and
 * reject every other flag rather than silently changing its semantics. */
#define MSG_OOB        0x0001
#define MSG_PEEK       0x0002
#define MSG_CTRUNC     0x0008
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
get_sock_from_pin(fd_table_pin_t *pin, sock_t **s_out, uint32_t *sid_out)
{
    uint32_t sid = sock_id_from_file(&pin->file);
    if (sid == SOCK_NONE) return SYS_ERR(EBADF);
    sock_t *s = sock_get(sid);
    if (!s) return SYS_ERR(EBADF);
    *s_out   = s;
    *sid_out = sid;
    return 0;
}

static int
recv_flags_supported(uint64_t flags)
{
    return (flags & ~(uint64_t)MSG_DONTWAIT) == 0;
}

static uint64_t
get_proc_sock(uint64_t fd_arg, fd_table_pin_t *pin,
              sock_t **s_out, uint32_t *sid_out)
{
    aegis_process_t *proc = current_proc();
    if (!fd_table_pin(proc->fd_table, (int)fd_arg, pin))
        return SYS_ERR(EBADF);
    return get_sock_from_pin(pin, s_out, sid_out);
}

static uint32_t
get_proc_unix_sock(uint64_t fd_arg, fd_table_pin_t *pin)
{
    aegis_process_t *proc = current_proc();
    if (!fd_table_pin(proc->fd_table, (int)fd_arg, pin))
        return UNIX_NONE;
    return unix_sock_id_from_file(&pin->file);
}

#define SCOPED_FD_PIN(name) \
    fd_table_pin_t name __attribute__((cleanup(fd_table_unpin))) = {0}

static int
detach_unix_fd(fd_table_t *table, int fd, uint32_t sid)
{
    if (fd < 0 || fd >= PROC_MAX_FDS)
        return 0;
    irqflags_t fl = spin_lock_irqsave(&table->lock);
    vfs_file_t *slot = &table->fds[fd];
    int same = slot->ops == &g_unix_sock_ops &&
               (uint32_t)(uintptr_t)slot->priv == sid;
    if (same)
        __builtin_memset(slot, 0, sizeof(*slot));
    spin_unlock_irqrestore(&table->lock, fl);
    return same;
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
    irqflags_t fl = sock_lock_acquire();
    uint16_t p = s_ephem_next;
    s_ephem_next = (uint16_t)(EPHEM_PORT_BASE +
        ((p - EPHEM_PORT_BASE + 1u) & (EPHEM_PORT_COUNT - 1u)));
    sock_lock_release(fl);
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
        uint32_t fd_flags = (type & SOCK_FLAG_CLOEXEC) ? VFS_FD_CLOEXEC : 0;
        int fd = unix_sock_open_fd((uint32_t)uid, proc, fd_flags);
        if (fd < 0) { unix_sock_free((uint32_t)uid); return SYS_ERR(EMFILE); }
        return (uint64_t)fd;
    }

    /* Internet sockets: IPv6 currently exposes UDP over link-local/NDP. TCPv6
     * is rejected honestly until tcp.c has 128-bit endpoints. */
    if (domain != AF_INET && domain != AF_INET6) return SYS_ERR(EAFNOSUPPORT);
    if (base_type != SOCK_STREAM && base_type != SOCK_DGRAM)
        return SYS_ERR(EPROTONOSUPPORT);
    if (domain == AF_INET6 && base_type != SOCK_DGRAM)
        return SYS_ERR(EPROTONOSUPPORT);

    aegis_process_t *proc = current_proc();
    if (cap_check(proc->caps, CAP_TABLE_SIZE, CAP_KIND_NET_SOCKET, CAP_RIGHTS_READ) != 0)
        return SYS_ERR(ENOCAP);

    int sid = sock_alloc((uint8_t)(base_type == SOCK_STREAM ? SOCK_TYPE_STREAM : SOCK_TYPE_DGRAM));
    if (sid < 0) return SYS_ERR(EMFILE);
    {
        sock_t *s = sock_get((uint32_t)sid);
        if (s) s->domain = (uint8_t)domain;
    }
    if (nonblock) {
        sock_t *s = sock_get((uint32_t)sid);
        if (s) s->nonblocking = 1;
    }

    uint32_t fd_flags = (type & SOCK_FLAG_CLOEXEC) ? VFS_FD_CLOEXEC : 0;
    int fd = sock_open_fd((uint32_t)sid, proc, fd_flags);
    if (fd < 0) { sock_free((uint32_t)sid); return SYS_ERR(EMFILE); }

    return (uint64_t)fd;
}

/* ── sys_bind ──────────────────────────────────────────────────────────── */

uint64_t
sys_bind(uint64_t fd, uint64_t addr, uint64_t addrlen)
{
    aegis_process_t *proc = current_proc();
    SCOPED_FD_PIN(pin);

    /* AF_UNIX bind */
    uint32_t uid = get_proc_unix_sock(fd, &pin);
    if (uid != UNIX_NONE) {
        if (cap_check(proc->caps, CAP_TABLE_SIZE, CAP_KIND_IPC_BIND,
                      CAP_RIGHTS_WRITE) != 0)
            return SYS_ERR(ENOCAP);
        if (addrlen < 4 || !user_ptr_valid(addr, addrlen))
            return SYS_ERR(EFAULT);
        k_sockaddr_un_t sun;
        __builtin_memset(&sun, 0, sizeof(sun));
        uint32_t copy_len = addrlen < sizeof(sun) ? (uint32_t)addrlen : (uint32_t)sizeof(sun);
        if (copy_from_user(&sun, (const void *)(uintptr_t)addr, copy_len) != 0) return SYS_ERR(EFAULT);
        if (sun.sun_family != AF_UNIX) return SYS_ERR(EINVAL);
        sun.sun_path[UNIX_PATH_MAX - 1] = '\0';
        int rc = unix_sock_bind(uid, sun.sun_path);
        return rc < 0 ? sc_ret(rc) : 0;
    }

    sock_t *s; uint32_t sid;
    uint64_t err = get_sock_from_pin(&pin, &s, &sid);
    if (err) return err;
    if (s->state != SOCK_CREATED || s->local_port != 0) return SYS_ERR(EINVAL);

    if (s->domain == AF_INET6) {
        if (addrlen < sizeof(k_sockaddr_in6_t)) return SYS_ERR(EINVAL);
        if (!user_ptr_valid(addr, sizeof(k_sockaddr_in6_t))) return SYS_ERR(EFAULT);
        k_sockaddr_in6_t sa;
        if (copy_from_user(&sa, (const void *)(uintptr_t)addr, sizeof(sa)) != 0) return SYS_ERR(EFAULT);
        if (sa.sin6_family != AF_INET6) return SYS_ERR(EINVAL);
        static const ip6_addr_t any;
        ip6_addr_t local; ipv6_get_linklocal(&local);
        if (!ipv6_addr_equal(&sa.sin6_addr, &any) &&
            !ipv6_addr_equal(&sa.sin6_addr, &local)) return SYS_ERR(EADDRNOTAVAIL);
        uint16_t port = ntohs(sa.sin6_port);
        if (port == 0) {
            if (udp_ensure_local_port(s, sid) != 0) return SYS_ERR(EADDRINUSE);
        } else {
            if (udp_bind(port, sid) != 0) return SYS_ERR(EADDRINUSE);
        }
        s->local_ip6 = sa.sin6_addr;
        s->state = SOCK_BOUND;
        return 0;
    }

    /* AF_INET bind */
    if (addrlen < sizeof(k_sockaddr_in_t)) return SYS_ERR(EINVAL);
    if (!user_ptr_valid(addr, sizeof(k_sockaddr_in_t))) return SYS_ERR(EFAULT);

    k_sockaddr_in_t sa;
    if (copy_from_user(&sa, (const void *)(uintptr_t)addr, sizeof(sa)) != 0) return SYS_ERR(EFAULT);
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
        s->local_ip = sa.sin_addr;
        s->state = SOCK_BOUND;
        return 0;
    }

    if (s->type == SOCK_TYPE_DGRAM && udp_bind(port, sid) != 0)
        return SYS_ERR(EADDRINUSE);
    s->local_port = port;
    s->local_ip = sa.sin_addr;
    s->state = SOCK_BOUND;
    return 0;
}

/* ── sys_listen ────────────────────────────────────────────────────────── */

uint64_t
sys_listen(uint64_t fd, uint64_t backlog)
{
    (void)backlog;
    SCOPED_FD_PIN(pin);
    uint32_t uid = get_proc_unix_sock(fd, &pin);
    if (uid != UNIX_NONE) {
        int rc = unix_sock_listen(uid);
        return rc < 0 ? (uint64_t)(int64_t)rc : 0;
    }

    sock_t *s; uint32_t sid;
    uint64_t err = get_sock_from_pin(&pin, &s, &sid);
    if (err) return err;
    if (s->type != SOCK_TYPE_STREAM) return SYS_ERR(EOPNOTSUPP);
    if (s->state < SOCK_BOUND) return SYS_ERR(EINVAL);  /* EINVAL: must bind first */

    if (tcp_listen(s->local_port, sid) != 0) return SYS_ERR(EADDRINUSE);
    s->state = SOCK_LISTENING;
    return 0;
}

/* ── sys_accept ────────────────────────────────────────────────────────── */

static uint64_t
do_accept(uint64_t fd, uint64_t addr, uint64_t addrlen, uint64_t flags)
{
    aegis_process_t *proc_a = current_proc();
    SCOPED_FD_PIN(pin);
    uint32_t uid = get_proc_unix_sock(fd, &pin);
    if (uid != UNIX_NONE) {
        int server_id = unix_sock_accept(uid);
        if (server_id < 0) return (uint64_t)(int64_t)server_id;
        if (flags & SOCK_FLAG_NONBLOCK) {
            unix_sock_t *us = unix_sock_get((uint32_t)server_id);
            if (us) us->nonblocking = 1;
        }
        uint32_t fd_flags = (flags & SOCK_FLAG_CLOEXEC) ? VFS_FD_CLOEXEC : 0;
        int new_fd = unix_sock_open_fd((uint32_t)server_id, proc_a, fd_flags);
        if (new_fd < 0) { unix_sock_free((uint32_t)server_id); return SYS_ERR(EMFILE); }
        return (uint64_t)new_fd;
    }

    sock_t *ls; uint32_t lsid;
    uint64_t err = get_sock_from_pin(&pin, &ls, &lsid);
    if (err) return err;
    if (ls->state != SOCK_LISTENING) return SYS_ERR(EINVAL);

    /* Pin the listener across the accept: the loop blocks on ls->poll_waiters
     * and re-dereferences `ls` after waking. Without the pin, a sibling thread
     * closing the listening fd (CLONE_FILES) while we are parked would free the
     * slot and re-init the waitq under us — a use-after-free. Every return below
     * drops the pin via the comma operator. See sock_vfs_read. */
    sock_ref(lsid);

    aegis_process_t *proc = current_proc();

    for (;;) {
        if (tcp_accept_ready(lsid)) {
            int new_sid = sock_alloc(SOCK_TYPE_STREAM);
            if (new_sid < 0) return (sock_unref(lsid), SYS_ERR(ENOMEM));
            tcp_conn_t accepted;
            int conn_id = tcp_accept(lsid, (uint32_t)new_sid, &accepted);
            if (conn_id < 0) {
                sock_unref((uint32_t)new_sid);
                continue;  /* stale queue entries were discarded */
            }
            sock_t *ns = sock_get((uint32_t)new_sid);
            ns->state = SOCK_CONNECTED;
            ns->tcp_conn_id = (uint32_t)conn_id;
            ns->nonblocking = (flags & SOCK_FLAG_NONBLOCK) ? 1 : 0;
            ns->remote_ip = accepted.remote_ip;
            ns->remote_port = accepted.remote_port;
            ns->local_ip = accepted.local_ip;
            ns->local_port = accepted.local_port;

            if (addr && addrlen) {
                uint32_t capacity;
                if (!user_ptr_valid(addrlen, sizeof(capacity)) ||
                    copy_from_user(&capacity, (const void *)(uintptr_t)addrlen,
                                   sizeof(capacity)) != 0) {
                    tcp_conn_abort((uint32_t)new_sid, (uint32_t)conn_id);
                    sock_unref((uint32_t)new_sid);
                    return (sock_unref(lsid), SYS_ERR(EFAULT));
                }
                k_sockaddr_in_t sa = {0};
                sa.sin_family = AF_INET;
                sa.sin_port = htons(ns->remote_port);
                sa.sin_addr = ns->remote_ip;
                uint32_t outlen = sizeof(sa);
                uint32_t n = capacity < outlen ? capacity : outlen;
                if ((n && (!user_ptr_valid(addr, n) ||
                     copy_to_user((void *)(uintptr_t)addr, &sa, n) != 0)) ||
                    copy_to_user((void *)(uintptr_t)addrlen, &outlen,
                                 sizeof(outlen)) != 0) {
                    tcp_conn_abort((uint32_t)new_sid, (uint32_t)conn_id);
                    sock_unref((uint32_t)new_sid);
                    return (sock_unref(lsid), SYS_ERR(EFAULT));
                }
            }
            uint32_t fd_flags = (flags & SOCK_FLAG_CLOEXEC) ? VFS_FD_CLOEXEC : 0;
            int new_fd = sock_open_fd((uint32_t)new_sid, proc, fd_flags);
            if (new_fd < 0) {
                tcp_conn_abort((uint32_t)new_sid, (uint32_t)conn_id);
                sock_unref((uint32_t)new_sid);
                return (sock_unref(lsid), SYS_ERR(EMFILE));
            }
            return (sock_unref(lsid), (uint64_t)new_fd);
        }

        if (ls->nonblocking)
            return (sock_unref(lsid), SYS_ERR(EAGAIN));

        /* Block until a connection is queued.  Interruptible (Ctrl-C aborts).
         * wait_event registers on poll_waiters BEFORE re-checking the queue, so
         * a connection that completes in the gap is not lost; the loop then
         * re-runs the authoritative dequeue above. */
        int rc;
        wait_event_interruptible(&ls->poll_waiters,
            tcp_accept_ready(lsid), rc);
        if (rc == BLOCK_EINTR)
            return (sock_unref(lsid), SYS_ERR(EINTR));
    }
}

uint64_t
sys_accept(uint64_t fd, uint64_t addr, uint64_t addrlen)
{
    return do_accept(fd, addr, addrlen, 0);
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
    if (flags & ~(uint64_t)(SOCK_FLAG_NONBLOCK | SOCK_FLAG_CLOEXEC))
        return SYS_ERR(EINVAL);
    return do_accept(fd, addr, addrlen, flags);
}

/* ── sys_connect ───────────────────────────────────────────────────────── */

uint64_t
sys_connect(uint64_t fd, uint64_t addr, uint64_t addrlen)
{
    SCOPED_FD_PIN(pin);
    uint32_t uid = get_proc_unix_sock(fd, &pin);
    if (uid != UNIX_NONE) {
        if (addrlen < 4 || !user_ptr_valid(addr, addrlen))
            return SYS_ERR(EFAULT);
        k_sockaddr_un_t sun;
        __builtin_memset(&sun, 0, sizeof(sun));
        uint32_t copy_len = addrlen < sizeof(sun) ? (uint32_t)addrlen : (uint32_t)sizeof(sun);
        if (copy_from_user(&sun, (const void *)(uintptr_t)addr, copy_len) != 0)
            return SYS_ERR(EFAULT);
        if (sun.sun_family != AF_UNIX) return SYS_ERR(EINVAL);
        sun.sun_path[UNIX_PATH_MAX - 1] = '\0';
        int rc = unix_sock_connect(uid, sun.sun_path);
        return rc < 0 ? (uint64_t)(int64_t)rc : 0;
    }

    sock_t *s; uint32_t sid;
    uint64_t err = get_sock_from_pin(&pin, &s, &sid);
    if (err) return err;

    if (s->domain == AF_INET6) {
        if (addrlen < sizeof(k_sockaddr_in6_t)) return SYS_ERR(EINVAL);
        if (!user_ptr_valid(addr, sizeof(k_sockaddr_in6_t))) return SYS_ERR(EFAULT);
        k_sockaddr_in6_t sa6;
        if (copy_from_user(&sa6, (const void *)(uintptr_t)addr, sizeof(sa6)) != 0)
            return SYS_ERR(EFAULT);
        if (sa6.sin6_family != AF_INET6) return SYS_ERR(EINVAL);
        s->remote_ip6 = sa6.sin6_addr;
        s->remote_port = ntohs(sa6.sin6_port);
        if (ipv6_addr_equal(&s->local_ip6, &(ip6_addr_t){0}))
            ipv6_get_linklocal(&s->local_ip6);
        s->state = SOCK_CONNECTED;
        return 0;
    }

    if (addrlen < sizeof(k_sockaddr_in_t)) return SYS_ERR(EINVAL);
    if (!user_ptr_valid(addr, sizeof(k_sockaddr_in_t))) return SYS_ERR(EFAULT);

    k_sockaddr_in_t sa;
    if (copy_from_user(&sa, (const void *)(uintptr_t)addr, sizeof(sa)) != 0)
        return SYS_ERR(EFAULT);
    if (sa.sin_family != AF_INET) return SYS_ERR(EINVAL);

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
    /* Pin across the handshake block so a sibling close of this fd can't free
     * the slot / re-init s->poll_waiters under our parked connect (see
     * sock_vfs_read). */
    sock_ref(sid);
    wait_event_interruptible(&s->poll_waiters, s->state != SOCK_CONNECTING, rc);
    if (rc == BLOCK_EINTR) { sock_unref(sid); return SYS_ERR(EINTR); }
    if (s->state != SOCK_CONNECTED) { sock_unref(sid); return SYS_ERR(ECONNREFUSED); }
    sock_unref(sid);
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
        if (udp_bind(port, sid) == 0 || s->local_port != 0)
            return 0;
    }
    return -1;
}

/* Send one complete datagram from kernel memory. Both sendto and sendmsg
 * validate/copy their payload before reaching here, so failed copies cannot
 * publish a partial datagram. No fragmentation: oversized messages fail. */
static uint64_t
sock_send_datagram(sock_t *s, uint32_t sid, const void *data, uint64_t len,
                   uint64_t addr, uint64_t addrlen)
{
    if (s->domain == AF_INET6) {
        ip6_addr_t dst;
        uint16_t dst_port;
        if (addr && addrlen >= sizeof(k_sockaddr_in6_t)) {
            if (!user_ptr_valid(addr, sizeof(k_sockaddr_in6_t))) return SYS_ERR(EFAULT);
            k_sockaddr_in6_t sa;
            if (copy_from_user(&sa, (const void *)(uintptr_t)addr, sizeof(sa)) != 0)
                return SYS_ERR(EFAULT);
            if (sa.sin6_family != AF_INET6) return SYS_ERR(EINVAL);
            dst = sa.sin6_addr; dst_port = ntohs(sa.sin6_port);
        } else if (s->state == SOCK_CONNECTED) {
            dst = s->remote_ip6; dst_port = s->remote_port;
        } else return SYS_ERR(EDESTADDRREQ);
        if (len > 1452) return SYS_ERR(EMSGSIZE);
        netdev_t *dev = netdev_get("eth0");
        if (!dev) return SYS_ERR(ENETDOWN);
        if (udp_ensure_local_port(s, sid) != 0) return SYS_ERR(EADDRINUSE);
        if (ipv6_addr_equal(&s->local_ip6, &(ip6_addr_t){0}))
            ipv6_get_linklocal(&s->local_ip6);
        int r = udp6_send(dev, s->local_port, &dst, dst_port, data, (uint16_t)len);
        return r < 0 ? SYS_ERR(EHOSTUNREACH) : len;
    }

    ip4_addr_t dst_ip;
    uint16_t   dst_port;
    if (addr && addrlen >= sizeof(k_sockaddr_in_t)) {
        /* Validate the address and reject short copies before using fields. */
        if (!user_ptr_valid(addr, sizeof(k_sockaddr_in_t))) return SYS_ERR(EFAULT);
        k_sockaddr_in_t sa;
        if (copy_from_user(&sa, (const void *)(uintptr_t)addr, sizeof(sa)) != 0)
            return SYS_ERR(EFAULT);
        dst_ip   = sa.sin_addr;
        dst_port = ntohs(sa.sin_port);
    } else if (s->state == SOCK_CONNECTED) {
        dst_ip   = s->remote_ip;
        dst_port = s->remote_port;
    } else {
        return SYS_ERR(EDESTADDRREQ);
    }

    if (len > 1472) return SYS_ERR(EMSGSIZE);

    netdev_t *dev = netdev_get("eth0");
    if (!dev) return SYS_ERR(ENETDOWN);

    /* Implicit ephemeral source-port bind so the reply can be demuxed back to
     * this socket (see udp_ensure_local_port).  Without it an unbound socket
     * sends with source port 0 and never receives a response. */
    if (udp_ensure_local_port(s, sid) != 0)
        return SYS_ERR(EADDRINUSE);  /* EADDRINUSE — no free ephemeral port */

    int r = udp_send(dev, s->local_port, dst_ip, dst_port, data, (uint16_t)len);
    return r < 0 ? SYS_ERR(ENETDOWN) : len;
}

/* ── sys_sendto ────────────────────────────────────────────────────────── */

uint64_t
sys_sendto(uint64_t fd, uint64_t buf, uint64_t len,
           uint64_t flags, uint64_t addr, uint64_t addrlen)
{
    SCOPED_FD_PIN(pin);
    /* MSG_DONTWAIT is per-call: never change shared O_NONBLOCK state. */
    if (!user_ptr_valid(buf, len)) return SYS_ERR(EFAULT);

    /* AF_UNIX stream send: send()/sendto(NULL addr) on a connected AF_UNIX
     * socket. Without this the fd fell through to the AF_INET UDP path below
     * and returned ENETDOWN (no netdev on -machine pc) — which broke any app
     * using send()/recv() (not write()) on a UNIX socket, e.g. Ladybird's
     * TransportSocket data thread. addr is ignored (the socket is connected).
     * Mirror sys_sendmsg's AF_UNIX bounce-and-write loop. */
    {
        uint32_t uuid = get_proc_unix_sock(fd, &pin);
        if (uuid != UNIX_NONE) {
            uint8_t kbuf[UNIX_BUF_SIZE]; /* bounce chunk == AF_UNIX ring size */
            uint64_t remain = len, off = 0, total = 0;
            while (remain > 0) {
                uint32_t chunk = remain > UNIX_BUF_SIZE ? UNIX_BUF_SIZE : (uint32_t)remain;
                /* Faulting mid-loop must not hand the peer an unfilled kbuf
                 * (kernel stack, or the previous chunk's bytes). */
                if (copy_from_user(kbuf, (const void *)(uintptr_t)(buf + off), chunk) != 0)
                    return total > 0 ? (uint64_t)total : SYS_ERR(EFAULT);
                int n = unix_sock_write_nonblock(uuid, kbuf, chunk, (flags & MSG_DONTWAIT) != 0);
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
    uint64_t err = get_sock_from_pin(&pin, &s, &sid);
    if (err) return err;

    if (s->type == SOCK_TYPE_STREAM) {
        /* TCP send — blocking, segments large writes (shared helper). Pin the
         * socket across the block so a sibling thread closing this fd can't free
         * the slot / re-init s->poll_waiters under our parked sender (see
         * sock_vfs_read). */
        if (s->state != SOCK_CONNECTED) return SYS_ERR(ENOTCONN);
        sock_ref(sid);
        int64_t r = sock_stream_send(s, buf, len, (flags & MSG_DONTWAIT) != 0);
        sock_unref(sid);
        return (uint64_t)r;  /* bytes (>=0), or -errno == SYS_ERR(errno) form */
    }

    uint64_t max_payload = s->domain == AF_INET6 ? 1452 : 1472;
    if (len > max_payload) return SYS_ERR(EMSGSIZE);
    uint8_t udpbuf[1472];
    if (copy_from_user(udpbuf, (const void *)(uintptr_t)buf, len) != 0)
        return SYS_ERR(EFAULT);
    return sock_send_datagram(s, sid, udpbuf, len, addr, addrlen);
}

/* ── sys_recvfrom ──────────────────────────────────────────────────────── */

/* sys_recvfrom is the only UDP consumer (VFS UDP read is unsupported).
 * Keep the reserved head queued across faultable copies, then commit or abort.
 * RX cannot reuse that slot until the release-store of head. Never hold
 * sock_lock during usercopy or wakeup: those can enter MM/scheduler code. */
static void
udp_recv_finish(sock_t *s, uint32_t sid, int delivered)
{
    irqflags_t fl = sock_lock_acquire();
    if (delivered) {
        s->udp_rx[s->udp_rx_head].in_use = 0;
        __atomic_store_n(&s->udp_rx_head,
            (s->udp_rx_head + 1) & (UDP_RX_SLOTS - 1), __ATOMIC_RELEASE);
    }
    __atomic_store_n(&s->udp_rx_busy, 0, __ATOMIC_RELEASE);
    sock_lock_release(fl);
    sock_wake(sid);
}

uint64_t
sys_recvfrom(uint64_t fd, uint64_t buf, uint64_t len,
             uint64_t flags, uint64_t addr, uint64_t addrlen)
{
    if (!recv_flags_supported(flags)) return SYS_ERR(EOPNOTSUPP);
    SCOPED_FD_PIN(pin);
    if (!user_ptr_writable(buf, len)) return SYS_ERR(EFAULT);

    /* AF_UNIX stream recv: recv()/recvfrom() on a connected AF_UNIX socket.
     * Counterpart to the AF_UNIX sys_sendto path — without it recv() fell
     * through to the AF_INET path. unix_sock_read blocks per the socket's
     * O_NONBLOCK flag (set via FIONBIO/fcntl); MSG_DONTWAIT is not separately
     * honored here (apps that need nonblocking set the fd flag, as Ladybird
     * does). addr/addrlen are left untouched (UNIX peer addr is anonymous). */
    {
        uint32_t uuid = get_proc_unix_sock(fd, &pin);
        if (uuid != UNIX_NONE) {
            uint8_t kbuf[UNIX_BUF_SIZE]; /* bounce chunk == AF_UNIX ring size */
            uint32_t want = len > UNIX_BUF_SIZE ? UNIX_BUF_SIZE : (uint32_t)len;
            int n = unix_sock_read(uuid, kbuf, want, (flags & MSG_DONTWAIT) ? 1 : 0);
            if (n > 0) {
                uint64_t left = copy_to_user((void *)(uintptr_t)buf, kbuf, (uint32_t)n);
                if (left) return left < (uint64_t)n ? (uint64_t)n - left : SYS_ERR(EFAULT);
            }
            return (n < 0) ? (uint64_t)(int64_t)n : (uint64_t)n;
        }
    }

    sock_t *s; uint32_t sid;
    uint64_t err = get_sock_from_pin(&pin, &s, &sid);
    if (err) return err;

    /* Pin the socket for the whole recv: both the TCP and UDP loops below block
     * on s->poll_waiters and re-dereference `s` after waking. Without the pin, a
     * sibling thread closing this same fd (CLONE_FILES) while we are parked would
     * drop the last ref, free the slot, and re-init the waitq under our still-
     * linked waiter — a use-after-free. Every return past this point drops the
     * pin (via the comma operator) so teardown defers to the last putter. See
     * sock_vfs_read. */
    if (len == 0 && s->type == SOCK_TYPE_STREAM) return 0;
    sock_ref(sid);

    /* MSG_DONTWAIT forces this single call to be nonblocking regardless of the
     * socket's O_NONBLOCK flag (Linux semantics). musl/curl pass it on their
     * "drain whatever is ready" reads; without honoring it a blocking socket
     * would sleep inside the syscall and stall the caller's event loop. */
    uint8_t nonblock = s->nonblocking || (flags & MSG_DONTWAIT) ? 1 : 0;

    uint32_t deadline = 0;
    uint8_t  has_timeout = 0;
    if (s->rcvtimeo_ticks > 0) {
        deadline = (uint32_t)arch_get_ticks() + s->rcvtimeo_ticks;
        has_timeout = 1;
    }

    if (s->type == SOCK_TYPE_STREAM) {
        for (;;) {
            int n = tcp_conn_recv(s->sock_id, s->tcp_conn_id, (void *)0, 0);  /* peek */
            if (n > 0) {
                /* Bounce through a STACK buffer — NOT a shared static. A static
                 * bounce raced two concurrent recvfrom() calls: caller A
                 * consumes its bytes into the static, gets preempted before
                 * copy_to_user, caller B (different socket) overwrites the
                 * static, A resumes and copies out B's data — cross-socket data
                 * corruption + loss (a confidentiality bug across processes).
                 * A 2 KB stack buffer is also far safer than an 8 KB static on
                 * the 16 KB kernel stack (interrupts nest on it). Loop-drain the
                 * ring through the small buffer. A remap after validation can
                 * still fault: report only bytes actually copied. Do not copy
                 * under tcp_lock: lazy/COW faults can take MM locks or do I/O.
                 * The already-consumed chunk cannot safely be put back after
                 * another reader runs, so a racing fault may lose its suffix. */
                uint8_t rbuf[2048];
                uint64_t total = 0;
                while (total < len && n > 0) {
                    uint64_t remain = len - total;
                    uint32_t want = remain < (uint32_t)n ? (uint32_t)remain : (uint32_t)n;
                    if (want > sizeof(rbuf)) want = sizeof(rbuf);
                    int got = tcp_conn_recv(s->sock_id, s->tcp_conn_id, rbuf, (uint16_t)want);
                    if (got <= 0) break;
                    uint64_t left = copy_to_user((void *)(uintptr_t)(buf + total),
                                                 rbuf, (uint32_t)got);
                    total += (uint32_t)got - left;
                    if (left)
                        return (sock_unref(sid), total ? total : SYS_ERR(EFAULT));
                    n = tcp_conn_recv(s->sock_id, s->tcp_conn_id, (void *)0, 0);  /* re-peek */
                }
                if (total > 0)
                    return (sock_unref(sid), (uint64_t)total);
                /* total==0: nothing actually consumed (lost a race to another
                 * reader) — fall through to the block/EOF/EAGAIN logic. */
                n = tcp_conn_recv(s->sock_id, s->tcp_conn_id, (void *)0, 0);
            }
            if (n == 0) return (sock_unref(sid), 0);  /* EOF / FIN */
            /* n < 0: -11 (alive, empty → block) or -1 (dead conn). */
            if (nonblock) return (sock_unref(sid), SYS_ERR(EAGAIN));
            if (has_timeout && (uint32_t)arch_get_ticks() >= deadline)
                return (sock_unref(sid), SYS_ERR(ETIMEDOUT));
            /* Block until data arrives or the connection closes (peek >= 0),
             * interruptible, with an optional SO_RCVTIMEO deadline.  The
             * authoritative peek + EOF/timeout decision re-runs at the top of
             * the loop after the wait returns (a timeout return hits the
             * deadline check above → ETIMEDOUT). */
            int rc;
            if (has_timeout)
                wait_event_timeout(&s->poll_waiters,
                    tcp_conn_recv(s->sock_id, s->tcp_conn_id, (void *)0, 0) >= 0, deadline, rc);
            else
                wait_event_interruptible(&s->poll_waiters,
                    tcp_conn_recv(s->sock_id, s->tcp_conn_id, (void *)0, 0) >= 0, rc);
            if (rc == BLOCK_EINTR) return (sock_unref(sid), SYS_ERR(EINTR));
        }
    }

    /* UDP recv */
    for (;;) {
        /* Check all outputs before dequeue, including after a blocking wait.
         * In particular, reject RO/PROT_NONE and invalid address outputs
         * without discarding a queued datagram. Honour the caller's socklen. */
        uint32_t capacity = 0;
        uint32_t outlen = s->domain == AF_INET6 ? sizeof(k_sockaddr_in6_t)
                                               : sizeof(k_sockaddr_in_t);
        if (!user_ptr_writable(buf, len))
            return (sock_unref(sid), SYS_ERR(EFAULT));
        if (addr) {
            if (!addrlen || !user_ptr_valid(addrlen, sizeof(capacity)) ||
                !user_ptr_writable(addrlen, sizeof(capacity)) ||
                copy_from_user(&capacity, (const void *)(uintptr_t)addrlen,
                               sizeof(capacity)) != 0 ||
                !user_ptr_writable(addr, capacity < outlen ? capacity : outlen))
                return (sock_unref(sid), SYS_ERR(EFAULT));
        }
        udp_rx_slot_t packet;
        int have_packet = 0;
        irqflags_t fl = sock_lock_acquire();
        if (!s->udp_rx_busy &&
            s->udp_rx_head != __atomic_load_n(&s->udp_rx_tail, __ATOMIC_ACQUIRE)) {
            udp_rx_slot_t *slot = &s->udp_rx[s->udp_rx_head];
            __atomic_store_n(&s->udp_rx_busy, 1, __ATOMIC_RELEASE);
            packet = *slot;
            have_packet = 1;
        }
        sock_lock_release(fl);
        if (have_packet) {
            /* Neither RX nor another receiver can reuse our reserved slot.
             * A fault leaves the datagram queued, even on a concurrent remap.
             * Userspace may see a copied prefix on EFAULT; no delivery is
             * reported and retry can receive the complete datagram. */
            uint32_t copy_len = packet.len < len ? packet.len : (uint32_t)len;
            if (copy_to_user((void *)(uintptr_t)buf, packet.data, copy_len) != 0)
                return (udp_recv_finish(s, sid, 0), sock_unref(sid), SYS_ERR(EFAULT));
            uint32_t naddr = capacity < outlen ? capacity : outlen;
            if (addr && s->domain == AF_INET6) {
                k_sockaddr_in6_t sa;
                __builtin_memset(&sa, 0, sizeof(sa));
                sa.sin6_family = AF_INET6;
                sa.sin6_port = htons(packet.src_port);
                sa.sin6_addr = packet.src_ip6;
                if (copy_to_user((void *)(uintptr_t)addr, &sa, naddr) != 0)
                    return (udp_recv_finish(s, sid, 0), sock_unref(sid), SYS_ERR(EFAULT));
            } else if (addr) {
                k_sockaddr_in_t sa = {0};
                sa.sin_family = AF_INET;
                sa.sin_port = htons(packet.src_port);
                sa.sin_addr = packet.src_ip;
                if (copy_to_user((void *)(uintptr_t)addr, &sa, naddr) != 0)
                    return (udp_recv_finish(s, sid, 0), sock_unref(sid), SYS_ERR(EFAULT));
            }
            if (addr && copy_to_user((void *)(uintptr_t)addrlen, &outlen,
                                    sizeof(outlen)) != 0)
                return (udp_recv_finish(s, sid, 0), sock_unref(sid), SYS_ERR(EFAULT));
            udp_recv_finish(s, sid, 1);
            return (sock_unref(sid), (uint64_t)copy_len);
        }
        if (nonblock) return (sock_unref(sid), SYS_ERR(EAGAIN));
        if (has_timeout && (uint32_t)arch_get_ticks() >= deadline)
            return (sock_unref(sid), SYS_ERR(ETIMEDOUT));
        /* Block until a datagram is queued, interruptible, with an optional
         * SO_RCVTIMEO deadline.  The authoritative dequeue + timeout decision
         * re-runs at the top of the loop after the wait returns. */
        int rc;
        if (has_timeout)
            wait_event_timeout(&s->poll_waiters,
                !__atomic_load_n(&s->udp_rx_busy, __ATOMIC_ACQUIRE) &&
                s->udp_rx_head != s->udp_rx_tail, deadline, rc);
        else
            wait_event_interruptible(&s->poll_waiters,
                !__atomic_load_n(&s->udp_rx_busy, __ATOMIC_ACQUIRE) &&
                s->udp_rx_head != s->udp_rx_tail, rc);
        if (rc == BLOCK_EINTR) return (sock_unref(sid), SYS_ERR(EINTR));
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
    SCOPED_FD_PIN(pin);
    uint32_t uid = get_proc_unix_sock(fd, &pin);

    /* Datagram iovecs form one atomic message; stream iovecs may make
     * partial progress. Keep the original descriptor pin throughout. */
    if (uid == UNIX_NONE) {
        sock_t *s; uint32_t sid;
        uint64_t err = get_sock_from_pin(&pin, &s, &sid);
        if (err) return err;
        if (!user_ptr_valid(msg_ptr, sizeof(k_msghdr_t))) return SYS_ERR(EFAULT);
        k_msghdr_t imh;
        if (copy_from_user(&imh, (const void *)(uintptr_t)msg_ptr, sizeof(imh)))
            return SYS_ERR(EFAULT);
        if (imh.msg_iovlen > 8) return SYS_ERR(EINVAL);
        uint64_t name = (uint64_t)(uintptr_t)imh.msg_name;
        uint64_t namelen = imh.msg_namelen;
        uint64_t sent = 0;
        uint8_t datagram[1472];
        uint64_t max_payload = s->domain == AF_INET6 ? 1452 : 1472;
        if (s->type == SOCK_TYPE_STREAM && s->state != SOCK_CONNECTED)
            return SYS_ERR(ENOTCONN);
        for (uint64_t i = 0; i < imh.msg_iovlen; i++) {
            k_iovec_t iov;
            uint64_t iptr = (uint64_t)(uintptr_t)imh.msg_iov;
            if (iptr > UINT64_MAX - i * sizeof(iov)) return SYS_ERR(EFAULT);
            iptr += i * sizeof(iov);
            if (!user_ptr_valid(iptr, sizeof(iov)) ||
                copy_from_user(&iov, (const void *)(uintptr_t)iptr, sizeof(iov)) != 0)
                return SYS_ERR(EFAULT);
            if (s->type != SOCK_TYPE_STREAM) {
                if (iov.iov_len > max_payload - sent) return SYS_ERR(EMSGSIZE);
                if (iov.iov_len &&
                    (!user_ptr_valid((uint64_t)(uintptr_t)iov.iov_base, iov.iov_len) ||
                     copy_from_user(datagram + sent, iov.iov_base, iov.iov_len) != 0))
                    return SYS_ERR(EFAULT);
                sent += iov.iov_len;
            } else {
                if (!iov.iov_len) continue;
                if (!user_ptr_valid((uint64_t)(uintptr_t)iov.iov_base, iov.iov_len))
                    return sent ? sent : SYS_ERR(EFAULT);
                int64_t r = sock_stream_send(s, (uint64_t)(uintptr_t)iov.iov_base,
                                            iov.iov_len, (flags & MSG_DONTWAIT) != 0);
                if (r < 0) return sent ? sent : (uint64_t)r;
                sent += (uint64_t)r;
                if ((uint64_t)r < iov.iov_len) break;
            }
        }
        if (s->type != SOCK_TYPE_STREAM)
            return sock_send_datagram(s, sid, datagram, sent, name, namelen);
        return sent;
    }

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
            /* See the sys_sendto AF_UNIX loop: an unfilled kbuf reaching the
             * peer is a kernel-stack disclosure. */
            if (copy_from_user(kbuf, (const void *)((uintptr_t)iov.iov_base + off), chunk) != 0)
                return total_sent > 0 ? (uint64_t)total_sent : SYS_ERR(EFAULT);
            int n = unix_sock_write_nonblock(uid, kbuf, chunk, (flags & MSG_DONTWAIT) != 0);
            if (n < 0) {
                if (n == -EAGAIN && total_sent > 0) goto send_ancillary;
                return total_sent > 0 ? (uint64_t)total_sent : (uint64_t)(int64_t)n;
            }
            total_sent += n;
            off += (uint64_t)n;
            remain -= (uint64_t)n;
            /* A short nonblocking write must not retry/spin or skip attached
             * rights after publishing payload. Finish ancillary processing. */
            if ((uint32_t)n < chunk) goto send_ancillary;
        }
    }

send_ancillary:
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

            int sender_fds[UNIX_PASSED_FD_MAX] = {0};
            if (nfds > 0 &&
                copy_from_user(sender_fds,
                    (const void *)((uintptr_t)mh.msg_control + sizeof(k_cmsghdr_t)),
                    (uint32_t)((uint64_t)nfds * sizeof(int))) != 0)
                return SYS_ERR(EFAULT);

            /* Dup each fd and stage for peer.
             *
             * The whole validate → allowlist → dup → snapshot sequence runs
             * under fd_table.lock, per that lock's contract (fd_table.h): a
             * CLONE_FILES sibling closing sfd between the scm_fd_passable()
             * check and the dup would leave us ->dup'ing freed memory, or —
             * worse — reopening the slot in that window swaps a PASSABLE
             * object for the authority-bearing one we just cleared, sending an
             * fd the allowlist exists to refuse. ops->dup is a refcount bump
             * and is explicitly allowed under this lock; ops->close is NOT, so
             * every unwind happens after the unlock. */
            unix_sock_t *us = unix_sock_get(uid);
            if (us && us->peer_id != UNIX_NONE) {
                unix_passed_fd_t staged[UNIX_PASSED_FD_MAX];
                uint8_t count = 0;
                int denied = 0;
                irqflags_t ffl = spin_lock_irqsave(&proc->fd_table->lock);
                for (int i = 0; i < nfds; i++) {
                    int sfd = sender_fds[i];
                    if (sfd < 0 || sfd >= PROC_MAX_FDS) continue;
                    vfs_file_t *f = &proc->fd_table->fds[sfd];
                    if (!f->ops) continue;
                    /* Authority-laundering guard: refuse to pass an fd that
                     * carries filesystem/device authority (see scm_fd_passable).
                     * Unwind the refs already dup'd this message, then EPERM. */
                    if (!scm_fd_passable(f)) { denied = 1; break; }
                    if (f->ops->dup) f->ops->dup(f->priv);
                    staged[count].file = *f;
                    count++;
                }
                spin_unlock_irqrestore(&proc->fd_table->lock, ffl);
                if (denied) {
                    for (uint8_t k = 0; k < count; k++)
                        if (staged[k].file.ops && staged[k].file.ops->close)
                            staged[k].file.ops->close(staged[k].file.priv);
                    return SYS_ERR(EPERM);
                }
                if (count > 0) {
                    int sr = unix_sock_stage_fds(us->peer_id, staged, count);
                    if (sr < 0) {
                        /* Staging failed (peer full or closed/lingering):
                         * release the refs we just dup'd, else they leak
                         * (the memfd/socket slot would never reach 0). */
                        for (uint8_t k = 0; k < count; k++)
                            if (staged[k].file.ops && staged[k].file.ops->close)
                                staged[k].file.ops->close(staged[k].file.priv);
                    }
                }
            }
        }
    }

    return (uint64_t)total_sent;
}

typedef struct {
    uint64_t control;
    uint64_t controllen_ptr;
    uint64_t flags_ptr;
    int msg_flags;
} recv_rights_output_t;

/* Called with owned staged references but with NO object/fd-table lock held.
 * The helper publishes descriptors only after every output copy succeeds. */
static int
recv_rights_output(const int *fds, int nfds, int truncated, void *arg)
{
    recv_rights_output_t *out = arg;
    uint64_t total_cm = 0;
    if (nfds > 0) {
        k_cmsghdr_t cm = {
            .cmsg_len = sizeof(cm) + (uint64_t)nfds * sizeof(int),
            .cmsg_level = SOL_SOCKET,
            .cmsg_type = SCM_RIGHTS,
        };
        total_cm = cm.cmsg_len;
        if (copy_to_user((void *)(uintptr_t)out->control, &cm, sizeof(cm)) != 0 ||
            copy_to_user((void *)(uintptr_t)(out->control + sizeof(cm)),
                         fds, (uint64_t)nfds * sizeof(int)) != 0)
            return -EFAULT;
    }
    if (copy_to_user((void *)(uintptr_t)out->controllen_ptr,
                     &total_cm, sizeof(total_cm)) != 0)
        return -EFAULT;
    out->msg_flags = truncated ? MSG_CTRUNC : 0;
    if (copy_to_user((void *)(uintptr_t)out->flags_ptr,
                     &out->msg_flags, sizeof(out->msg_flags)) != 0)
        return -EFAULT;
    return 0;
}

/* Difference form is overflow-safe even before the range checks. */
static int
recv_ranges_overlap(uint64_t a, uint64_t an, uint64_t b, uint64_t bn)
{
    if (!an || !bn) return 0;
    return a <= b ? b - a < an : a - b < bn;
}

uint64_t sys_recvmsg(uint64_t fd, uint64_t msg_ptr, uint64_t flags)
{
    if (!recv_flags_supported(flags)) return SYS_ERR(EOPNOTSUPP);
    SCOPED_FD_PIN(pin);
    uint32_t uid = get_proc_unix_sock(fd, &pin);

    if (!user_ptr_valid(msg_ptr, sizeof(k_msghdr_t))) return SYS_ERR(EFAULT);
    k_msghdr_t mh;
    if (copy_from_user(&mh, (const void *)(uintptr_t)msg_ptr, sizeof(mh)))
        return SYS_ERR(EFAULT);  /* short copy → stale iov/control fields */

    recv_rights_output_t output = {
        .control = (uint64_t)(uintptr_t)mh.msg_control,
        .controllen_ptr = msg_ptr + __builtin_offsetof(k_msghdr_t, msg_controllen),
        .flags_ptr = msg_ptr + __builtin_offsetof(k_msghdr_t, msg_flags),
    };
    if (!user_ptr_writable(output.controllen_ptr, sizeof(uint64_t)) ||
        !user_ptr_writable(output.flags_ptr, sizeof(int)))
        return SYS_ERR(EFAULT);
    uint64_t max_fds = 0, control_len = 0;
    if (uid != UNIX_NONE && mh.msg_control &&
        mh.msg_controllen >= sizeof(k_cmsghdr_t) + sizeof(int)) {
        max_fds = (mh.msg_controllen - sizeof(k_cmsghdr_t)) / sizeof(int);
        if (max_fds > UNIX_PASSED_FD_MAX) max_fds = UNIX_PASSED_FD_MAX;
        control_len = sizeof(k_cmsghdr_t) + max_fds * sizeof(int);
        if (!user_ptr_writable(output.control, control_len))
            return SYS_ERR(EFAULT);
    }

    /* Phase 1: snapshot inputs and validate every output before waiting,
     * copying metadata, detaching rights or consuming data. Payload/control/
     * name writes must not overwrite the header or each other's output.
     * Payload iovecs may overlap each other (sequential writes are supported).
     * The iovec array may be an output alias because it is snapshotted first. */
    k_iovec_t iovs[8];
    uint64_t niov = mh.msg_iovlen < 8 ? mh.msg_iovlen : 8;
    int has_payload = 0;
    if (niov && !user_ptr_valid((uint64_t)(uintptr_t)mh.msg_iov,
                               niov * sizeof(k_iovec_t)))
        return SYS_ERR(EFAULT);
    for (uint64_t i = 0; i < niov; i++) {
        if (!user_ptr_valid((uint64_t)(uintptr_t)mh.msg_iov + i * sizeof(k_iovec_t), sizeof(k_iovec_t)))
            return SYS_ERR(EFAULT);
        if (copy_from_user(&iovs[i], (const void *)((uintptr_t)mh.msg_iov + i * sizeof(k_iovec_t)), sizeof(iovs[i])))
            return SYS_ERR(EFAULT);  /* short copy → stale iov_base/iov_len */
        if (iovs[i].iov_len &&
            !user_ptr_writable((uint64_t)(uintptr_t)iovs[i].iov_base, iovs[i].iov_len))
            return SYS_ERR(EFAULT);
        if (iovs[i].iov_len) has_payload = 1;
    }
    uint64_t name = 0, name_len = 0;
    if (uid == UNIX_NONE && mh.msg_name) {
        sock_t *s; uint32_t sid;
        uint64_t err = get_sock_from_pin(&pin, &s, &sid);
        if (err) return err;
        uint64_t size = s->domain == AF_INET6 ? sizeof(k_sockaddr_in6_t)
                                             : sizeof(k_sockaddr_in_t);
        name = (uint64_t)(uintptr_t)mh.msg_name;
        name_len = mh.msg_namelen < size ? mh.msg_namelen : size;
        if (!user_ptr_writable(name, name_len) ||
            !user_ptr_writable(msg_ptr + __builtin_offsetof(k_msghdr_t, msg_namelen),
                               sizeof(mh.msg_namelen)))
            return SYS_ERR(EFAULT);
    }
    if (recv_ranges_overlap(output.control, control_len, msg_ptr, sizeof(mh)) ||
        recv_ranges_overlap(name, name_len, msg_ptr, sizeof(mh)))
        return SYS_ERR(EINVAL);
    for (uint64_t i = 0; i < niov; i++) {
        uint64_t base = (uint64_t)(uintptr_t)iovs[i].iov_base;
        if (recv_ranges_overlap(base, iovs[i].iov_len, msg_ptr, sizeof(mh)) ||
            recv_ranges_overlap(base, iovs[i].iov_len, output.control, control_len) ||
            recv_ranges_overlap(base, iovs[i].iov_len, name, name_len))
            return SYS_ERR(EINVAL);
    }

    if (uid == UNIX_NONE) {
        /* Exactly one recvfrom, including zero-capacity/zero-iov UDP receives.
         * Retain the existing first-nonempty-iovec (short receive) behaviour. */
        uint64_t buf = 0, len = 0;
        for (uint64_t i = 0; i < niov; i++) {
            if (!iovs[i].iov_len) continue;
            buf = (uint64_t)(uintptr_t)iovs[i].iov_base;
            len = iovs[i].iov_len;
            break;
        }
        int rc = recv_rights_output(NULL, 0, 0, &output);
        if (rc < 0) return (uint64_t)(int64_t)rc;
        uint64_t alen = name ? msg_ptr + __builtin_offsetof(k_msghdr_t, msg_namelen) : 0;
        return sys_recvfrom(fd, buf, len, flags, name, alen);
    }

retry_receive:
    /* Phase 2: wait WITHOUT consuming. Recheck staged rights after the wait,
     * then resolve all output-copy/fd-slot failures before irreversible data.
     * Stolen readiness retries here, never in a blocking payload read.
     *
     * Existing sendmsg publishes bytes and rights separately; staging has no
     * stream offsets. This preserves its socket-wide/rights-only semantics,
     * not a byte-to-rights association guarantee under concurrent receivers. */
    if (has_payload) {
        int rc = unix_sock_wait_recv(uid, (flags & MSG_DONTWAIT) ? 1 : 0);
        if (rc < 0) return (uint64_t)(int64_t)rc;
    }
    int rights_recv = unix_sock_recv_fds(uid, (int)max_fds, recv_rights_output, &output);
    if (rights_recv < 0) return (uint64_t)(int64_t)rights_recv;
    int ancillary_progress = rights_recv > 0 || (output.msg_flags & MSG_CTRUNC);

    /* Phase 3: only nonblocking reads/copies, so rights arriving during a wait
     * can never be missed by a one-shot check before a blocking data read. */
    int64_t total_recv = 0;
    for (uint64_t i = 0; i < niov; i++) {
        k_iovec_t iov = iovs[i];
        uint8_t kbuf[UNIX_BUF_SIZE]; /* bounce chunk == AF_UNIX ring size */
        uint64_t remain = iov.iov_len;
        uint64_t off = 0;
        while (remain > 0) {
            uint32_t chunk = remain > UNIX_BUF_SIZE ? UNIX_BUF_SIZE : (uint32_t)remain;
            /* Installed rights are already successful receive progress. Do not
             * block after it or hide their valid cmsg behind a later error.
             * A zero-byte result with rights is also used by zero-iov recvmsg. */
            int n = unix_sock_read(uid, kbuf, chunk, 1);
            if (n <= 0) {
                if (total_recv > 0 || ancillary_progress) return (uint64_t)total_recv;
                if (n == -EAGAIN && !(flags & MSG_DONTWAIT)) goto retry_receive;
                return n == 0 ? 0 : (uint64_t)(int64_t)n;
            }
            uint64_t left = copy_to_user((void *)((uintptr_t)iov.iov_base + off),
                                         kbuf, (uint32_t)n);
            total_recv += n - left;
            if (left)
                return total_recv > 0 || ancillary_progress
                    ? (uint64_t)total_recv : SYS_ERR(EFAULT);
            off += (uint64_t)n;
            remain -= (uint64_t)n;
            if ((uint32_t)n < chunk) return (uint64_t)total_recv;
        }
    }
    return (uint64_t)total_recv;
}

/* ── sys_shutdown ──────────────────────────────────────────────────────── */

uint64_t
sys_shutdown(uint64_t fd, uint64_t how)
{
    (void)how;
    SCOPED_FD_PIN(pin);
    sock_t *s; uint32_t sid;
    uint64_t err = get_proc_sock(fd, &pin, &s, &sid);
    if (err) return err;

    if (s->type == SOCK_TYPE_STREAM && s->tcp_conn_id != SOCK_NONE) {
        tcp_conn_close(s->sock_id, s->tcp_conn_id);
    }
    s->state = SOCK_CLOSED;
    return 0;
}

/* ── sys_getsockname / sys_getpeername ──────────────────────────────────── */

uint64_t
sys_getsockname(uint64_t fd, uint64_t addr, uint64_t addrlen)
{
    if (!addrlen) return SYS_ERR(EFAULT);
    if (!user_ptr_valid(addrlen, sizeof(uint32_t))) return SYS_ERR(EFAULT);
    SCOPED_FD_PIN(pin);
    sock_t *s; uint32_t sid;
    uint64_t err = get_proc_sock(fd, &pin, &s, &sid);
    if (err) return err;
    if (s->domain == AF_INET6) {
        if (!user_ptr_valid(addr, sizeof(k_sockaddr_in6_t))) return SYS_ERR(EFAULT);
        k_sockaddr_in6_t sa; __builtin_memset(&sa, 0, sizeof(sa));
        sa.sin6_family = AF_INET6; sa.sin6_port = htons(s->local_port);
        sa.sin6_addr = s->local_ip6;
        uint32_t outlen = sizeof(sa);
        COPY_TO_USER(addrlen, &outlen);
        COPY_TO_USER(addr, &sa);
        return 0;
    }
    if (!user_ptr_valid(addr, sizeof(k_sockaddr_in_t))) return SYS_ERR(EFAULT);
    k_sockaddr_in_t sa;
    sa.sin_family = AF_INET;
    sa.sin_port   = htons(s->local_port);
    sa.sin_addr   = s->local_ip;
    __builtin_memset(sa.sin_zero, 0, 8);
    uint32_t outlen = sizeof(sa);
    COPY_TO_USER(addrlen, &outlen);
    COPY_TO_USER(addr, &sa);
    return 0;
}

uint64_t
sys_getpeername(uint64_t fd, uint64_t addr, uint64_t addrlen)
{
    if (!addrlen) return SYS_ERR(EFAULT);
    if (!user_ptr_valid(addrlen, sizeof(uint32_t))) return SYS_ERR(EFAULT);
    SCOPED_FD_PIN(pin);
    sock_t *s; uint32_t sid;
    uint64_t err = get_proc_sock(fd, &pin, &s, &sid);
    if (err) return err;
    if (s->state != SOCK_CONNECTED) return SYS_ERR(ENOTCONN);
    if (s->domain == AF_INET6) {
        if (!user_ptr_valid(addr, sizeof(k_sockaddr_in6_t))) return SYS_ERR(EFAULT);
        k_sockaddr_in6_t sa; __builtin_memset(&sa, 0, sizeof(sa));
        sa.sin6_family = AF_INET6; sa.sin6_port = htons(s->remote_port);
        sa.sin6_addr = s->remote_ip6;
        uint32_t outlen = sizeof(sa);
        COPY_TO_USER(addrlen, &outlen);
        COPY_TO_USER(addr, &sa);
        return 0;
    }
    if (!user_ptr_valid(addr, sizeof(k_sockaddr_in_t))) return SYS_ERR(EFAULT);
    k_sockaddr_in_t sa;
    sa.sin_family = AF_INET;
    sa.sin_port   = htons(s->remote_port);
    sa.sin_addr   = s->remote_ip;
    __builtin_memset(sa.sin_zero, 0, 8);
    uint32_t outlen = sizeof(sa);
    COPY_TO_USER(addrlen, &outlen);
    COPY_TO_USER(addr, &sa);
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
    if (!user_ptr_writable(sv_ptr, 2 * sizeof(int)))
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

    int fd0, fd1;
    if (unix_sock_open_pair_fds(sid0, sid1, proc, &fd0, &fd1) != 0) {
        unix_sock_free(sid0);
        unix_sock_free(sid1);
        return SYS_ERR(EMFILE);
    }
    int fds[2] = { fd0, fd1 };
    if (copy_to_user((void *)(uintptr_t)sv_ptr, fds, sizeof(fds)) != 0) {
        int own0 = detach_unix_fd(proc->fd_table, fd0, sid0);
        int own1 = detach_unix_fd(proc->fd_table, fd1, sid1);
        if (own0) unix_sock_free(sid0);
        if (own1) unix_sock_free(sid1);
        return SYS_ERR(EFAULT);
    }
    return 0;
}

/* ── sys_setsockopt ────────────────────────────────────────────────────── */

uint64_t
sys_setsockopt(uint64_t fd, uint64_t level, uint64_t optname,
               uint64_t optval, uint64_t optlen)
{
    if (optlen < sizeof(int)) return SYS_ERR(EINVAL);
    if (!user_ptr_valid(optval, sizeof(int))) return SYS_ERR(EFAULT);

    SCOPED_FD_PIN(pin);
    sock_t *s; uint32_t sid;
    uint64_t err = get_proc_sock(fd, &pin, &s, &sid);
    if (err) return err;

    int val;
    COPY_FROM_USER(&val, optval);

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
                COPY_FROM_USER(&tv_sec, optval);
                COPY_FROM_USER(&tv_usec, optval + 8);
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
                COPY_FROM_USER(&tv_sec, optval);
                COPY_FROM_USER(&tv_usec, optval + 8);
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
    SCOPED_FD_PIN(pin);
    if (!user_ptr_valid(optval, sizeof(int))) return SYS_ERR(EFAULT);

    /* AF_UNIX: SO_PEERCRED */
    uint32_t uid = get_proc_unix_sock(fd, &pin);
    if (uid != UNIX_NONE && level == SOL_SOCKET && optname == SO_PEERCRED) {
        if (!user_ptr_valid(optval, sizeof(k_ucred_t))) return SYS_ERR(EFAULT);
        uint32_t p_pid, p_uid, p_gid;
        int rc = unix_sock_peercred(uid, &p_pid, &p_uid, &p_gid);
        if (rc < 0) return (uint64_t)(int64_t)rc;
        k_ucred_t uc = { .pid = (int)p_pid, .uid = (int)p_uid, .gid = (int)p_gid };
        COPY_TO_USER(optval, &uc);
        uint32_t outlen = sizeof(uc);
        if (optlen) {
            if (!user_ptr_valid(optlen, sizeof(uint32_t))) return SYS_ERR(EFAULT);
            COPY_TO_USER(optlen, &outlen);
        }
        return 0;
    }

    sock_t *s; uint32_t sid;
    uint64_t err = get_sock_from_pin(&pin, &s, &sid);
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
        COPY_TO_USER(optval, &tv_sec);
        COPY_TO_USER(optval + 8, &tv_usec);
        uint32_t outlen16 = 16;
        if (optlen) {
            if (!user_ptr_valid(optlen, sizeof(uint32_t))) return SYS_ERR(EFAULT);
            COPY_TO_USER(optlen, &outlen16);
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
    COPY_TO_USER(optval, &val);
    uint32_t outlen = sizeof(int);
    if (optlen) {
        if (!user_ptr_valid(optlen, sizeof(uint32_t))) return SYS_ERR(EFAULT);
        COPY_TO_USER(optlen, &outlen);
    }
    return 0;
}

/* poll/ppoll, select/pselect6 and epoll_* live in sys_poll.c now — they are
 * general fd multiplexing (kept when CONFIG_NET is off), not socket API. */

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
extern int iwl_wifi_connect(const char *ssid,const char *pass,uint8_t pass_len);
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
        COPY_TO_USER(arg1, &info);
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
            if (!user_ptr_writable(arg1, (uint64_t)n * sizeof(wifi_net_pub_t)) ||
                copy_to_user((void *)(uintptr_t)arg1, tmp,
                             (uint64_t)n * sizeof(wifi_net_pub_t)) != 0)
                return SYS_ERR(EFAULT);
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
        /* op=3: arg1 points to {ssid[33], passphrase[64]}. Credentials never
         * leave this call and the driver wipes its temporary copy. Active control that
         * changes the host's network association -> NET_ADMIN (same class as
         * op=0), intentionally not held by the plain netman GUI. */
        if (cap_check(proc->caps, CAP_TABLE_SIZE,
                      CAP_KIND_NET_ADMIN, CAP_RIGHTS_WRITE) != 0)
            return SYS_ERR(ENOCAP);
        if (!iwl_wifi_present()) return SYS_ERR(ENODEV);
        struct { char ssid[33]; char pass[64]; } req;
        /* Validate the FULL range we copy, not just 1 byte — the exception-table
         * copy_from_user faults gracefully on the shipped arches, but the
         * validated and copied lengths must agree (and the generic memcpy
         * fallback would over-read). */
        if(!user_ptr_valid(arg1,sizeof(req)))return SYS_ERR(EFAULT);
        __builtin_memset(&req,0,sizeof(req));
        if(copy_from_user(&req,(const void *)(uintptr_t)arg1,sizeof(req))!=0)
            return SYS_ERR(EFAULT);
        req.ssid[32]=0;req.pass[63]=0;uint8_t plen=0;
        while(plen<63&&req.pass[plen])plen++;
        int rc=iwl_wifi_connect(req.ssid,req.pass,plen);
        __builtin_memset(&req,0,sizeof(req));
        return rc==0?0:SYS_ERR(rc==-4?EINVAL:rc==-5?EBUSY:EIO);
    }
#endif /* __x86_64__ */
    return SYS_ERR(EINVAL);
}
