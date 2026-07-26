/*
 * net_stub.c — compiled ONLY when CONFIG_NET is off (see Makefile).
 *
 * The Linux `sys_ni_syscall` pattern: rather than #ifdef the socket cases out
 * of the syscall dispatch table (and the fcntl/ioctl socket branches, and the
 * xHCI USB-ethernet gadget), we satisfy those symbols here so the core links
 * unchanged. Every socket syscall returns -ENOSYS; the fd->socket lookups
 * report "no socket" (none can exist, since none can be created), so the
 * socket-aware branches are simply never taken; NIC registration is inert.
 *
 * Including the real headers means the compiler checks these against the same
 * prototypes the callers use — a signature drift is a build error, not a
 * silent mismatch.
 */
#pragma GCC diagnostic ignored "-Wunused-parameter"

#include <stdint.h>
#include "../include/aegis_errno.h"
#include "sys_impl.h"
#include "socket.h"
#include "unix_socket.h"
#include "netdev.h"

#define NI ((uint64_t)-ENOSYS)

uint64_t sys_socket(uint64_t domain, uint64_t type, uint64_t proto) { return NI; }
uint64_t sys_bind(uint64_t fd, uint64_t addr, uint64_t addrlen) { return NI; }
uint64_t sys_listen(uint64_t fd, uint64_t backlog) { return NI; }
uint64_t sys_accept(uint64_t fd, uint64_t addr, uint64_t addrlen) { return NI; }
uint64_t sys_accept4(uint64_t fd, uint64_t addr, uint64_t addrlen, uint64_t flags) { return NI; }
uint64_t sys_connect(uint64_t fd, uint64_t addr, uint64_t addrlen) { return NI; }
uint64_t sys_sendto(uint64_t fd, uint64_t buf, uint64_t len,
                    uint64_t flags, uint64_t addr, uint64_t addrlen) { return NI; }
uint64_t sys_recvfrom(uint64_t fd, uint64_t buf, uint64_t len,
                      uint64_t flags, uint64_t addr, uint64_t addrlen) { return NI; }
uint64_t sys_sendmsg(uint64_t fd, uint64_t msg, uint64_t flags) { return NI; }
uint64_t sys_recvmsg(uint64_t fd, uint64_t msg, uint64_t flags) { return NI; }
uint64_t sys_shutdown(uint64_t fd, uint64_t how) { return NI; }
uint64_t sys_getsockname(uint64_t fd, uint64_t addr, uint64_t addrlen) { return NI; }
uint64_t sys_getpeername(uint64_t fd, uint64_t addr, uint64_t addrlen) { return NI; }
uint64_t sys_socketpair(uint64_t domain, uint64_t type, uint64_t proto, uint64_t sv) { return NI; }
uint64_t sys_setsockopt(uint64_t fd, uint64_t level, uint64_t optname,
                        uint64_t optval, uint64_t optlen) { return NI; }
uint64_t sys_getsockopt(uint64_t fd, uint64_t level, uint64_t optname,
                        uint64_t optval, uint64_t optlen) { return NI; }
uint64_t sys_netcfg(uint64_t op, uint64_t arg1, uint64_t arg2, uint64_t arg3) { return NI; }

/* fd -> socket lookups (fcntl/ioctl): always "not a socket". */
sock_t  *sock_get(uint32_t sock_id) { return 0; }
uint32_t sock_id_from_fd(int fd, aegis_process_t *proc) { return SOCK_NONE; }
unix_sock_t *unix_sock_get(uint32_t id) { return 0; }
uint32_t unix_sock_id_from_fd(int fd, void *proc) { return SOCK_NONE; }

/* NIC registration path (xHCI USB-ethernet gadget): inert. */
int       netdev_register(netdev_t *dev) { return -1; }
netdev_t *netdev_get(const char *name) { return 0; }
void      netdev_rx_deliver(netdev_t *dev, const void *frame, uint16_t len) { }
volatile int g_in_netdev_poll = 0;
