/* sys_adminconf.c — admin-gated system configuration writes.
 *
 * System-wide settings that boot services read before any user logs in
 * (autologin user for bastion, NTP enable for chronos) must live in the
 * install-protected /etc/aegis tree so they can't be forged. Userspace
 * (Settings) can't write there directly — that requires CAP_KIND_INSTALL,
 * which is intentionally narrow. Instead these narrow syscalls perform the
 * write in kernel context (which is trusted and bypasses the syscall-layer
 * INSTALL/DAC checks), so the gate here is the ONLY thing standing between an
 * unprivileged caller and a forged /etc/aegis config file. It must therefore
 * match the authority that a direct INSTALL write demands.
 *
 * Policy: caller must hold a live sudo-style ADMIN SESSION (proc->admin_session)
 * — the same gate CAP_KIND_INSTALL / sys_install_commit enforce, granted only by
 * sys_admin_session after /bin/login verifies a SEPARATE admin credential. Mere
 * login (`authenticated`) or an admin-tier CAP_KIND_POWER cap is NOT enough:
 * POWER is authenticated-tier (even service-tier binaries such as /bin/reboot
 * carry it) and the cosmetic uid-0 `live` session already satisfies auth_uid==0,
 * so gating on POWER+auth_uid==0 would let any logged-in user drive a confused
 * deputy (e.g. /bin/aegisctl, which policy hands POWER) into writing here with
 * no admin password. Requiring the admin session closes that. Fail closed.
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
    /* O_WRONLY(1) | O_CREAT | O_TRUNC — create or overwrite. has_install=1: the
     * caller reached sys_adminconf only past the POWER admin gate, and this
     * writes deliberately into the protected /etc/aegis tree (that's its whole
     * purpose), so the ext2 create's install-tree check must let it through. */
    int rc = vfs_open_ex(path, 1 | VFS_O_CREAT | VFS_O_TRUNC, 0644, &f, 1);
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

/*
 * True if the caller holds a live admin session — the SAME authority
 * CAP_KIND_INSTALL / sys_install_commit require (see admin_session_active in
 * sys_cap.c, the single install-authority chokepoint). proc->admin_session is
 * granted ONLY by sys_admin_session after /bin/login checks a separate admin
 * credential; it is not implied by login or by any capability. Gating the
 * kernel-context /etc/aegis writes on this — rather than on POWER + auth_uid==0,
 * both of which an ordinary logged-in `live` session already satisfies —
 * prevents a confused-deputy escalation. Fail closed: no session, no write.
 */
static int
admin_root(aegis_process_t *proc)
{
    return proc->admin_session != 0;
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

/*
 * sys_admin_session_active — syscall 519 (Aegis-private)
 *
 * Returns 1 if the CALLER holds a live admin session (the sudo-style elevated
 * state set by sys_admin_session after /bin/login verifies /etc/aegis/admin),
 * else 0. Queries only the caller's own state and confers no authority, so it
 * needs no capability — a process may always ask about itself. Account tools
 * (passwd/useradd/userdel/usermod) use it to self-gate account-mutating ops
 * behind an admin session; the write itself is still independently gated by the
 * kernel's CAP_KIND_AUTH inode check on /etc/shadow, so this is defence in
 * depth for the tool's own policy, not the sole guard.
 */
uint64_t
sys_admin_session_active(void)
{
    aegis_process_t *proc = current_proc();
    return (proc && proc->admin_session) ? 1u : 0u;
}
