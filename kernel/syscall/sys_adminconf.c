/* sys_adminconf.c — admin-gated system configuration writes.
 *
 * System-wide settings that boot services read before any user logs in
 * (autologin user for bastion, NTP enable for chronos) must live in the
 * install-protected /etc/aegis tree so they can't be forged. Userspace
 * (Settings) can't write there directly — that requires CAP_KIND_INSTALL,
 * which is intentionally narrow. Instead these narrow syscalls perform the
 * write in kernel context (which is trusted and bypasses the syscall-layer
 * INSTALL/DAC checks), gated on the caller being an authenticated root admin.
 *
 * v1 policy: caller must hold CAP_KIND_POWER (admin-tier, already implies
 * proc->authenticated) AND be bound to root (auth_uid == 0). A dedicated
 * administrative-session password gate is planned for v2 and will layer on
 * top of this same entry point without changing the storage format.
 */
#include "sys_impl.h"
#include "sched.h"
#include "proc.h"
#include "cap.h"
#include "vfs.h"
#include "../include/aegis_errno.h"

/* Write `len` bytes to `path` in kernel context (create + truncate). Returns 0
 * on success. Used only for tiny, fixed admin config files under /etc/aegis. */
static int
kfile_write(const char *path, const char *data, uint32_t len)
{
    vfs_file_t f;
    /* O_WRONLY(1) | O_CREAT | O_TRUNC — create or overwrite. */
    int rc = vfs_open(path, 1 | VFS_O_CREAT | VFS_O_TRUNC, 0644, &f);
    if (rc != 0)
        return rc;

    int ret = 0;
    if (len > 0) {
        if (f.ops->write == NULL)
            ret = -1;
        else if (f.ops->write(f.priv, data, len) != (int)len)
            ret = -1;
    }
    if (f.ops->close)
        f.ops->close(f.priv);
    return ret;
}

/* True if the caller is an authenticated root admin (the v1 gate). */
static int
admin_root(aegis_process_t *proc)
{
    if (cap_check(proc->caps, CAP_TABLE_SIZE,
                  CAP_KIND_POWER, CAP_RIGHTS_READ) != 0)
        return 0;
    return proc->auth_uid == 0;
}

/*
 * sys_set_autologin — syscall 501.  arg1: 1 = enable, 0 = disable.
 *
 * Enable writes the autologin user ("root") to /etc/aegis/autologin; disable
 * truncates it to empty. bastion reads this at boot and, if set, logs the
 * user in without a password prompt. The username is fixed to root by the
 * v1 root-only gate — there is no caller-supplied identity to forge.
 */
uint64_t
sys_set_autologin(uint64_t enable)
{
    aegis_process_t *proc = current_proc();
    if (!admin_root(proc))
        return SYS_ERR(EPERM);

    int rc = enable ? kfile_write("/etc/aegis/autologin", "root\n", 5)
                    : kfile_write("/etc/aegis/autologin", "", 0);
    return rc == 0 ? 0 : SYS_ERR(EIO);
}

/*
 * sys_set_ntp — syscall 502.  arg1: 1 = enable, 0 = disable.
 *
 * Writes "on"/"off" to /etc/aegis/ntp. chronos reads it and skips time
 * synchronization when disabled (default, no file = enabled).
 */
uint64_t
sys_set_ntp(uint64_t enable)
{
    aegis_process_t *proc = current_proc();
    if (!admin_root(proc))
        return SYS_ERR(EPERM);

    int rc = enable ? kfile_write("/etc/aegis/ntp", "on\n", 3)
                    : kfile_write("/etc/aegis/ntp", "off\n", 4);
    return rc == 0 ? 0 : SYS_ERR(EIO);
}
