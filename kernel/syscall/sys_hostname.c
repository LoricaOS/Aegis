/* sys_hostname.c — kernel-managed hostname (sethostname/uname source) */
#include "sys_impl.h"
#include "sched.h"
#include "proc.h"
#include "spinlock.h"
#include "locked.h"
#include "cap.h"

/* HOSTNAME_MAX matches the utsname.nodename field (65 bytes incl. NUL).
 * Linux defines HOST_NAME_MAX as 64; the trailing byte is reserved for NUL. */
#define HOSTNAME_MAX 64

/* Hostname state bound to its guarding spinlock (locked.h) — the name buffer
 * and its length can only be reached together, under the lock, via WITH_LOCKED.
 * Leaf lock (nothing acquired while held), so left unranked. */
DEFINE_LOCKED(hostname_state_t, struct { char name[HOSTNAME_MAX + 1]; uint32_t len; });
static hostname_state_t s_host = LOCKED_INIT({ .name = "aegis", .len = 5 });

/*
 * hostname_get — copy current hostname into out (NUL-terminated).
 * out must point to at least n bytes; if n is too small the result is
 * truncated and still NUL-terminated.  Safe to call from any context.
 */
void
hostname_get(char *out, uint32_t n)
{
    if (n == 0) return;
    WITH_LOCKED(&s_host, h) {
        uint32_t copy = h->len;
        if (copy >= n) copy = n - 1;
        for (uint32_t i = 0; i < copy; i++)
            out[i] = h->name[i];
        out[copy] = '\0';
    }
}

/*
 * hostname_set — kernel-internal setter (no capability check). Used by boot-time
 * config sources (fw_cfg opt/aegis.hostname). len clamped to HOSTNAME_MAX.
 */
void
hostname_set(const char *name, uint32_t len)
{
    if (len > HOSTNAME_MAX) len = HOSTNAME_MAX;
    WITH_LOCKED(&s_host, h) {
        for (uint32_t i = 0; i < len; i++)
            h->name[i] = name[i];
        h->name[len] = '\0';
        h->len = len;
    }
}

/*
 * sys_sethostname — syscall 170
 *
 * arg1 = user pointer to new hostname bytes (not required to be NUL-terminated)
 * arg2 = length in bytes (not counting any NUL); must be <= HOSTNAME_MAX
 *
 * Requires CAP_KIND_POWER — same gate sys_reboot uses.  Hostname is
 * machine-identity state; only an authenticated admin should change it.
 *
 * Returns 0 on success; -EPERM if capability missing; -EINVAL if len > HOSTNAME_MAX;
 * -EFAULT if the user buffer is unreadable.
 */
uint64_t
sys_sethostname(uint64_t name_uptr, uint64_t len)
{
    aegis_process_t *proc = current_proc();
    if (cap_check(proc->caps, CAP_TABLE_SIZE,
                  CAP_KIND_POWER, CAP_RIGHTS_READ) != 0)
        return SYS_ERR(EPERM);

    if (len > HOSTNAME_MAX)
        return SYS_ERR(EINVAL);

    if (len > 0 && !user_ptr_valid(name_uptr, len))
        return SYS_ERR(EFAULT);

    char buf[HOSTNAME_MAX + 1];
    if (len > 0)
        copy_from_user(buf, (const void *)(uintptr_t)name_uptr, len);
    buf[len] = '\0';

    WITH_LOCKED(&s_host, h) {
        for (uint32_t i = 0; i < (uint32_t)len; i++)
            h->name[i] = buf[i];
        h->name[len] = '\0';
        h->len = (uint32_t)len;
    }

    return 0;
}
