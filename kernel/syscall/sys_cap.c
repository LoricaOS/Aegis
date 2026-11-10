/* sys_cap.c — Capability syscalls: auth_session, grant_runtime, query, install_commit */
#include "sys_impl.h"
#include "fs_ops.h"
#include "sched.h"
#include "proc.h"
#include "cap.h"    /* cap_policy_load (install-commit reload) */
#include "ext2.h"   /* ext2_anchors_reload (install-commit reload) */
#include "spinlock.h"

/* Guards the task list; PCBs found by walking it are only valid while held. */
extern spinlock_t sched_lock;

/*
 * sys_auth_session — syscall 364
 *
 * Marks the calling process as authenticated AND binds the identity it is
 * authorized to assume.  Called by login/bastion AFTER verifying credentials,
 * with the just-authenticated user's uid/gid. Two effects, both surviving
 * this process's exec and copied for CLONE_THREAD, never default-inherited
 * by an independent child:
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
    /* Reject out-of-domain IDs before narrowing; AUTH_ID_NONE represents
     * absence of a binding, never a verified ID. */
    if (uid_arg >= AUTH_ID_NONE || gid_arg >= AUTH_ID_NONE)
        return SYS_ERR(EINVAL);
    irqflags_t fl = spin_lock_irqsave(&sched_lock);
    if (cap_check(proc->caps, CAP_TABLE_SIZE,
                  CAP_KIND_AUTH, CAP_RIGHTS_READ) != 0) {
        spin_unlock_irqrestore(&sched_lock, fl);
        return SYS_ERR(ENOCAP);
    }
    proc->authenticated = 1;
    proc->auth_uid = (uint32_t)uid_arg;
    proc->auth_gid = (uint32_t)gid_arg;
    proc->authority_epoch++;
    spin_unlock_irqrestore(&sched_lock, fl);
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

    /* Snapshot of the target's table. The PCB has no refcount, so it must not
     * be dereferenced once sched_lock is dropped — and copy_to_user below can
     * fault, so it cannot run under the lock. Copy, then publish. */
    cap_slot_t snapshot[CAP_TABLE_SIZE];

    if (pid_arg == 0) {
        irqflags_t fl = spin_lock_irqsave(&sched_lock);
        __builtin_memcpy(snapshot, caller->caps, sizeof(snapshot));
        spin_unlock_irqrestore(&sched_lock, fl);
    } else {
        if (cap_check(caller->caps, CAP_TABLE_SIZE,
                      CAP_KIND_CAP_QUERY, CAP_RIGHTS_READ) != 0)
            return SYS_ERR(ENOCAP);

        irqflags_t fl = spin_lock_irqsave(&sched_lock);
        aegis_process_t *target = proc_find_by_pid_locked((uint32_t)pid_arg);
        if (!target) {
            spin_unlock_irqrestore(&sched_lock, fl);
            return SYS_ERR(ESRCH);
        }
        __builtin_memcpy(snapshot, target->caps, sizeof(snapshot));
        spin_unlock_irqrestore(&sched_lock, fl);
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
    copy_to_user((void *)buf_uptr, snapshot, copy_bytes);

    return nslots;
}

/*
 * admin_session_active — the SINGLE chokepoint for "may this caller perform an
 * administrative install operation". Requires a sudo-style ADMIN SESSION
 * (proc->admin_session), granted by sys_admin_session/sys_admin_self after /bin/login
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

/* sched_lock must be held. SELF is for trusted login after exec reduced its
 * group to one live thread. Per-thread authority snapshots cannot safely
 * represent issuance while another live thread shares the address space.
 * Scan the list: a nonleader can be the sole survivor, and the leader's
 * thread_count is not an authoritative test of which siblings are live. */
static int
admin_self_eligible_locked(aegis_process_t *proc)
{
    if (proc->task.state == TASK_ZOMBIE || proc->authority_busy ||
        proc->cap_ceiling_active || !proc->authenticated ||
        proc->auth_uid != 0 || proc->auth_gid != 0 ||
        proc->uid != 0 || proc->gid != 0 ||
        cap_check(proc->caps, CAP_TABLE_SIZE,
                  CAP_KIND_ADMIN_AUTH, CAP_RIGHTS_WRITE) != 0)
        return 0;

    for (aegis_task_t *t = proc->task.next; t != &proc->task; t = t->next) {
        if (t->is_user && t->state != TASK_ZOMBIE &&
            ((aegis_process_t *)t)->tgid == proc->tgid)
            return 0;
    }
    return 1;
}

/*
 * sys_admin_self — syscall 521, no arguments.
 *
 * Trusted login verifies the separate admin credential, binds the
 * administrative principal with AUTH and transitions uid/gid to 0 via the
 * checked SETUID operations, then explicitly elevates itself before an
 * allowlisted in-place exec. Numeric uid 0 alone grants nothing. This is fresh
 * credential issuance, not delegated/inherited authority; no ceiling widens.
 *
 * A separate number is essential: old kernels interpret sys_admin_session(2)
 * as PARENT elevation, so a new SELF caller could elevate the wrong principal.
 * Unknown syscall 521 instead fails with ENOSYS and no authority side effects.
 */
uint64_t
sys_admin_self(void)
{
    aegis_process_t *proc = current_proc();
    if (!proc || !sched_current()->is_user)
        return SYS_ERR(EPERM);

    char exe[sizeof(proc->exe_path)];
    uint64_t epoch;
    uint32_t session, tgid;
    int authenticated;
    irqflags_t fl = spin_lock_irqsave(&sched_lock);
    if (!admin_self_eligible_locked(proc)) {
        spin_unlock_irqrestore(&sched_lock, fl);
        return SYS_ERR(EPERM);
    }
    epoch = proc->authority_epoch;
    session = proc->sid;
    tgid = proc->tgid;
    authenticated = (int)proc->authenticated;
    __builtin_memcpy(exe, proc->exe_path, sizeof(exe));
    spin_unlock_irqrestore(&sched_lock, fl);

    /* Never publish a provisional flag or reserve busy: a concurrent drop
     * must remain possible and invalidate this request, not be retried. */
    cap_slot_t newcaps[CAP_TABLE_SIZE];
    cap_apply_policy(newcaps, exe, authenticated, 1 /* admin_session */);

    fl = spin_lock_irqsave(&sched_lock);
    if (proc->authority_epoch != epoch || proc->sid != session ||
        proc->tgid != tgid ||
        __builtin_memcmp(proc->exe_path, exe, sizeof(exe)) != 0 ||
        !admin_self_eligible_locked(proc)) {
        spin_unlock_irqrestore(&sched_lock, fl);
        return SYS_ERR(EPERM);
    }
    /* Epoch covers drop, exec, AUTH, session and competing elevation.
     * Eligibility rechecks live caps/binding, the unversioned numeric
     * uid/gid, ceiling/busy and the entire live thread group at commit. */
    proc->admin_session = 1u;
    proc->admin_session_firstboot = 0u;
    __builtin_memcpy(proc->caps, newcaps, sizeof(newcaps));
    proc->authority_epoch++;
    spin_unlock_irqrestore(&sched_lock, fl);
    return 0;
}

/*
 * sys_admin_session — syscall 517. arg1: AEGIS_ADMIN_SESSION_* selector.
 *
 * The kernel HOLDS the admin-session privilege (proc->admin_session, copied for
 * CLONE_THREAD and surviving in-place exec, not independent child creation).
 * It hands the privilege out through ONE trusted
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
 * SELF issuance uses the separate syscall 521; selector 2 here is invalid.
 *
 * Returns 0 on success, -EPERM if unauthorized, -EINVAL for unknown selectors.
 */
uint64_t
sys_admin_session(uint64_t on)
{
    if (on != AEGIS_ADMIN_SESSION_DROP && on != AEGIS_ADMIN_SESSION_PARENT)
        return SYS_ERR(EINVAL);

    aegis_process_t *proc = current_proc();
    if (!proc || !sched_current()->is_user)
        return SYS_ERR(EPERM);

    if (on == AEGIS_ADMIN_SESSION_DROP) {
        char exe[sizeof(proc->exe_path)];
        uint32_t ceiling[CAP_KIND_MAX + 1u];
        uint32_t held_ceiling[CAP_KIND_MAX + 1u];
        cap_slot_t held_caps[CAP_TABLE_SIZE];
        int authenticated, ceiling_active;
        uint64_t epoch;
        irqflags_t fl = spin_lock_irqsave(&sched_lock);
        if (proc->authority_busy) {
            spin_unlock_irqrestore(&sched_lock, fl);
            return SYS_ERR(EPERM);
        }
        if (!proc->admin_session && !proc->admin_session_firstboot) {
            /* A no-op drop is not an issuance/refresh syscall. In particular
             * an empty fork child must not recover policy caps via exe_path.
             * Still cancel any elevation derived before this drop. */
            proc->authority_epoch++;
            spin_unlock_irqrestore(&sched_lock, fl);
            return 0;
        }
        /* Invalidate every outstanding elevation BEFORE dropping the lock.
         * Revoke the old table immediately: dropping the label alone leaves
         * authority at cap-checking sinks while the policy files are read. */
        __builtin_memcpy(held_caps, proc->caps, sizeof(held_caps));
        cap_ceiling_from_table(held_ceiling, held_caps);
        proc->authority_busy = 1;
        epoch = ++proc->authority_epoch;
        proc->admin_session = 0;
        proc->admin_session_firstboot = 0;
        __builtin_memset(proc->caps, 0, sizeof(proc->caps));
        __builtin_memcpy(exe, proc->exe_path, sizeof(exe));
        authenticated = (int)proc->authenticated;
        ceiling_active = (int)proc->cap_ceiling_active;
        __builtin_memcpy(ceiling, proc->cap_ceiling, sizeof(ceiling));
        spin_unlock_irqrestore(&sched_lock, fl);

        cap_slot_t newcaps[CAP_TABLE_SIZE];
        cap_apply_policy(newcaps, exe, authenticated, 0);
        /* De-escalation may only REMOVE authority held at entry. A policy
         * reload or previously applied mask must not turn drop into a grant. */
        cap_apply_ceiling(newcaps, held_ceiling);
        if (ceiling_active)
            cap_apply_ceiling(newcaps, ceiling);
        for (uint32_t i = 0; i < CAP_TABLE_SIZE; i++) {
            /* The per-kind ceiling ORs duplicate slots; the live checker does
             * not combine rights across slots. Do not manufacture a combined
             * rights mask that no individual old slot actually authorized. */
            if (newcaps[i].kind != CAP_KIND_NULL &&
                cap_check(held_caps, CAP_TABLE_SIZE,
                          newcaps[i].kind, newcaps[i].rights) != 0) {
                newcaps[i].kind = CAP_KIND_NULL;
                newcaps[i].rights = 0;
            }
        }

        fl = spin_lock_irqsave(&sched_lock);
        if (!proc->authority_busy || proc->authority_epoch != epoch) {
            spin_unlock_irqrestore(&sched_lock, fl);
            return SYS_ERR(EPERM);
        }
        __builtin_memcpy(proc->caps, newcaps, sizeof(newcaps));
        proc->authority_busy = 0;
        proc->authority_epoch++;
        spin_unlock_irqrestore(&sched_lock, fl);
        return 0;
    }

    uint32_t parent_pid, session;
    uint64_t parent_epoch, caller_epoch;
    char parent_exe[sizeof(proc->exe_path)];
    int parent_auth;
    {
        irqflags_t fl = spin_lock_irqsave(&sched_lock);
        parent_pid = proc->ppid;
        session = proc->sid;
        aegis_process_t *parent = proc_find_by_pid_locked(parent_pid);
        if (parent_pid <= 1 || !parent ||
            parent->task.state == TASK_ZOMBIE || proc->authority_busy ||
            parent->authority_busy || parent->sid != session ||
            parent->cap_ceiling_active ||
            cap_check(proc->caps, CAP_TABLE_SIZE,
                      CAP_KIND_ADMIN_AUTH, CAP_RIGHTS_WRITE) != 0) {
            spin_unlock_irqrestore(&sched_lock, fl);
            /* Never elevate init, a changed session, or a spawn-attenuated
             * parent: the admin flag itself is authority at non-cap sinks. */
            return SYS_ERR(EPERM);
        }
        parent_epoch = parent->authority_epoch;
        caller_epoch = proc->authority_epoch;
        __builtin_memcpy(parent_exe, parent->exe_path, sizeof(parent_exe));
        parent_auth = (int)parent->authenticated;
        spin_unlock_irqrestore(&sched_lock, fl);
    }

    /* No authority is published before policy I/O. In particular direct
     * admin_session gates cannot observe a provisional elevation. Never keep
     * a parent PCB pointer outside sched_lock (the reaper can free it). */
    cap_slot_t newcaps[CAP_TABLE_SIZE];
    cap_apply_policy(newcaps, parent_exe, parent_auth, 1 /* admin_session */);

    /* Compare AND commit under the same lock as every live authority writer.
     * A drop, exec (even to the same pathname), auth/session change, competing
     * elevation, exit, or reparenting invalidates this request. Do not retry:
     * a stale credential-backed request must not resurrect dropped authority. */
    {
        irqflags_t fl = spin_lock_irqsave(&sched_lock);
        aegis_process_t *parent = proc_find_by_pid_locked(parent_pid);
        if (!parent || parent->task.state == TASK_ZOMBIE ||
            parent->authority_busy || parent->authority_epoch != parent_epoch ||
            proc->authority_busy || proc->authority_epoch != caller_epoch ||
            proc->ppid != parent_pid || proc->sid != session ||
            parent->sid != session || parent->cap_ceiling_active ||
            cap_check(proc->caps, CAP_TABLE_SIZE,
                      CAP_KIND_ADMIN_AUTH, CAP_RIGHTS_WRITE) != 0) {
            spin_unlock_irqrestore(&sched_lock, fl);
            return SYS_ERR(EPERM);
        }
        parent->admin_session = 1u;
        parent->admin_session_firstboot = 0u; /* credential-backed; survives exec */
        __builtin_memcpy(parent->caps, newcaps, sizeof(newcaps));
        parent->authority_epoch++;
        spin_unlock_irqrestore(&sched_lock, fl);
    }
    return 0;
}

/*
 * sys_install_commit — syscall 516.
 *
 * Called by herald AFTER extracting a package, so install-time changes take
 * effect WITHOUT a reboot:
 *   1. cap_policy_load()    — re-read /etc/aegis/caps.d so new caps.d/<binary>
 *      policies a package wrote (e.g. an engine service's NET_SOCKET) apply now.
 *   2. g_rootfs->anchors_reload() — re-read /etc/aegis/anchors so a path the package
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
    g_rootfs->anchors_reload();
    return 0;
}
