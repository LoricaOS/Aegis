/* sys_cap.c — Capability syscalls: auth_session, grant_runtime, query, install_commit */
#include "sys_impl.h"
#include "sched.h"
#include "proc.h"
#include "cap.h"    /* cap_policy_load (install-commit reload) */
#include "ext2.h"   /* ext2_anchors_reload (install-commit reload) */

/*
 * sys_auth_session — syscall 364
 *
 * Marks the calling process as authenticated AND binds the identity it is
 * authorized to assume.  Called by login/bastion AFTER verifying credentials,
 * with the just-authenticated user's uid/gid.  Two effects, both inherited by
 * fork/clone and surviving exec:
 *   1. proc->authenticated = 1 — admin-tier policy caps are granted at exec.
 *   2. proc->auth_uid/auth_gid = uid/gid — the ONLY values sys_setuid/setgid
 *      will subsequently permit.  This removes the "SETUID cap ⇒ become ANY
 *      uid including 0" ambient-authority hole: a SETUID holder can only drop
 *      to the identity whose credentials were actually checked.
 *
 * Requires: CAP_KIND_AUTH in caller's cap table (only login/bastion/installer
 * via policy — the trusted credential-checkers).
 */
uint64_t
sys_auth_session(uint64_t uid_arg, uint64_t gid_arg)
{
    aegis_process_t *proc = current_proc();
    if (!sched_current()->is_user)
        return SYS_ERR(EPERM);
    if (cap_check(proc->caps, CAP_TABLE_SIZE,
                  CAP_KIND_AUTH, CAP_RIGHTS_READ) != 0)
        return SYS_ERR(ENOCAP);
    proc->authenticated = 1;
    proc->auth_uid = (uint32_t)uid_arg;
    proc->auth_gid = (uint32_t)gid_arg;
    return 0;
}

/*
 * sys_cap_grant_runtime (syscall 363) was REMOVED here: retired in the Phase 46c
 * cap-policy redesign (caps now come from kernel policy at exec time), it had no
 * userspace callers, and a runtime "inject a capability into any PID" primitive
 * is exactly the kind of standing authority the capability model exists to avoid.
 * The dispatch entry is gone (falls through to ENOSYS).
 */

/*
 * sys_cap_query — syscall 362
 * Returns the capability table of a process.
 *   pid == 0: own caps (always allowed)
 *   pid != 0: target's caps (requires CAP_KIND_CAP_QUERY)
 * Copies cap_slot_t entries to user buffer.
 * Returns number of slots copied, or negative errno.
 */
uint64_t
sys_cap_query(uint64_t pid_arg, uint64_t buf_uptr, uint64_t buflen)
{
    aegis_process_t *caller = current_proc();
    if (!sched_current()->is_user)
        return SYS_ERR(EPERM);

    aegis_process_t *target;

    if (pid_arg == 0) {
        target = caller;
    } else {
        if (cap_check(caller->caps, CAP_TABLE_SIZE,
                      CAP_KIND_CAP_QUERY, CAP_RIGHTS_READ) != 0)
            return SYS_ERR(ENOCAP);

        target = proc_find_by_pid((uint32_t)pid_arg);
        if (!target)
            return SYS_ERR(ESRCH);
    }

    uint64_t copy_bytes = CAP_TABLE_SIZE * sizeof(cap_slot_t);
    if (buflen < copy_bytes)
        copy_bytes = buflen;

    uint64_t nslots = copy_bytes / sizeof(cap_slot_t);
    if (nslots == 0)
        return 0;

    copy_bytes = nslots * sizeof(cap_slot_t);

    if (!user_ptr_valid(buf_uptr, copy_bytes))
        return SYS_ERR(EFAULT);
    copy_to_user((void *)buf_uptr, target->caps, copy_bytes);

    return nslots;
}

/*
 * admin_session_active — the SINGLE chokepoint for "may this caller perform an
 * administrative install operation". Requires a sudo-style ADMIN SESSION
 * (proc->admin_session), granted by sys_admin_session only after /bin/login
 * -elevate verifies a SEPARATE admin credential — even root must elevate their
 * shell session. Deliberately does NOT accept mere login (`authenticated`): that
 * is the whole point — login authority and install authority are distinct. Keep
 * all admin-install gating routed through this one function.
 */
static int
admin_session_active(aegis_process_t *proc)
{
    return proc->admin_session != 0;
}

/*
 * sys_admin_session — syscall 517.  arg1: 1 = elevate, 0 = drop.
 *
 * The kernel HOLDS the admin-session privilege (proc->admin_session, inherited by
 * fork/clone, survives exec). It hands the privilege out through ONE trusted
 * authenticator — /bin/login — not the shell:
 *
 *   - DROP (on=0): self de-escalation. Always permitted, no cap, no credential —
 *     a session may always relinquish its own admin privilege.
 *
 *   - ELEVATE (on=1): requires CAP_KIND_ADMIN_AUTH, held ONLY by /bin/login, which
 *     must FIRST verify the separate admin credential in userspace (it already
 *     owns the credential machinery — libauth/crypt — for login itself; the kernel
 *     has no in-kernel crypt). login is fork/exec'd as the shell's child, so the
 *     grant targets the caller's DIRECT PARENT (the shell that invoked it). This
 *     concentrates the elevation authority + credential check in the one minimal
 *     authenticator instead of every shell, and the parent-only rule means login
 *     can elevate nothing but the session that asked. Mirrors login + CAP_KIND_AUTH
 *     + sys_auth_session for the login session itself.
 *
 * Returns 0 on success, -EPERM if unauthorized.
 */
uint64_t
sys_admin_session(uint64_t on)
{
    aegis_process_t *proc = current_proc();
    aegis_process_t *parent;

    if (!proc)
        return SYS_ERR(EPERM);

    if (!on) {
        proc->admin_session = 0;
        return 0;
    }

    if (cap_check(proc->caps, CAP_TABLE_SIZE,
                  CAP_KIND_ADMIN_AUTH, CAP_RIGHTS_WRITE) != 0)
        return SYS_ERR(EPERM);

    parent = proc_find_by_pid(proc->ppid);
    if (!parent)
        return SYS_ERR(EPERM);
    parent->admin_session = 1u;

    /* Re-derive the parent's cap table so the freshly granted admin session
     * takes effect IN-PROCESS, immediately. The admin_session-gated kinds
     * (DISK_ADMIN, INSTALL) are only granted by cap_apply_policy, which
     * otherwise runs exactly once — at execve/spawn — reading admin_session
     * as it was THEN (0). A process that elevates itself mid-run (e.g. the
     * installer fork/exec'ing `login -elevate`) would have its admin_session
     * flag flipped but its cap table frozen without DISK_ADMIN, so the
     * subsequent raw-disk write would still ENOCAP. Re-applying the policy
     * here closes that gap.
     *
     * This does NOT weaken the gate: elevation still required login's verified
     * separate-credential check + CAP_KIND_ADMIN_AUTH (checked above), and the
     * caps re-derived are exactly the parent binary's own trusted-path-anchored
     * policy — nothing more than it would have received had it been exec'd from
     * an already-elevated session. */
    cap_apply_policy(parent->caps, parent->exe_path,
                     (int)parent->authenticated, (int)parent->admin_session);
    return 0;
}

/*
 * sys_install_commit — syscall 516.
 *
 * Called by herald AFTER extracting a package, so install-time changes take
 * effect WITHOUT a reboot:
 *   1. cap_policy_load()    — re-read /etc/aegis/caps.d so new caps.d/<binary>
 *      policies a package wrote (e.g. an engine service's NET_SOCKET) apply now.
 *   2. ext2_anchors_reload() — re-read /etc/aegis/anchors so a path the package
 *      registered (e.g. /lib/<app>) becomes BOTH cap-granting (cap_policy) and
 *      write-protected (ext2), in lockstep — preserving the trusted==protected
 *      invariant.
 *
 * Gated by CAP_KIND_INSTALL (herald's admin cap) AND admin_session_active().
 * Returns 0 on success, -EPERM if unauthorized.
 */
uint64_t
sys_install_commit(void)
{
    aegis_process_t *proc = current_proc();

    if (!proc)
        return SYS_ERR(EPERM);
    if (cap_check(proc->caps, CAP_TABLE_SIZE,
                  CAP_KIND_INSTALL, CAP_RIGHTS_WRITE) != 0)
        return SYS_ERR(EPERM);
    if (!admin_session_active(proc))
        return SYS_ERR(EPERM);

    cap_policy_load();
    ext2_anchors_reload();
    return 0;
}
