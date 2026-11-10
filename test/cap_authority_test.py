#!/usr/bin/env python3
"""Execute production admin/auth/exec authority blocks and policy parser on host.

Policy I/O is a deterministic interleaving point: callbacks run another syscall
or the actual exec transaction while the first syscall is outside sched_lock.
Only scheduler/FS services and the PCB's unrelated fields are stubbed. This is
not a full-kernel SMP test; it covers the publication protocol's race windows
and the actual exec/spawn AT_SECURE writes, including late in-place elevation.
"""
from pathlib import Path
import os
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def function(source, name):
    match = re.search(
        rf"(?m)^(?:static )?(?:uint32_t|uint64_t|int|void)\n{name}\(", source)
    assert match, name
    end = source.index("\n}\n", match.start()) + 3
    return source[match.start():end]


policy = (ROOT / "kernel/cap/cap_policy.c").read_text()
syscap = (ROOT / "kernel/syscall/sys_cap.c").read_text()
exec_source = (ROOT / "kernel/syscall/sys_exec.c").read_text()
identity = (ROOT / "kernel/syscall/sys_identity.c").read_text()
dispatch = (ROOT / "kernel/syscall/syscall.c").read_text()
assert dispatch.count("case AEGIS_SYS_ADMIN_SELF: return sys_admin_self();") == 1
assert "uint64_t sys_admin_self(void);" in (ROOT / "kernel/syscall/sys_impl.h").read_text()
begin = exec_source.split(
    "    /* Exclude remote elevation before tearing down the old image.", 1
)[1].split("    /* 3b. POSIX:", 1)[0]
begin = "    /* Exclude remote elevation before tearing down the old image." + begin
publish = exec_source.split("    int new_admin =", 1)[1].split(
    "    /* C2: Reset signal state", 1)[0]
publish = "    int new_admin =" + publish
cleanup = exec_source.split("\ndone:\n", 1)[1].split(
    "    if (ext2_buf)", 1)[0]
secure_auxv = exec_source.split(
    "        /* Request secure startup from the OS interpreter/libc. */", 1
)[1].split("        /* auxv: AT_NULL", 1)[0]
spawn_auxv = exec_source.split(
    "    /* Publish the final policy/attenuation result before the child can run. */", 1
)[1].split("    /* 13. File descriptor table.", 1)[0]
assert exec_source.index(begin) < exec_source.index("    thread_group_teardown();")

C = r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "cap.h"
#define printk(...) ((void)0)
#define TASK_ZOMBIE 2
typedef unsigned spinlock_t;
typedef unsigned irqflags_t;
static spinlock_t sched_lock;
static unsigned locked;
static irqflags_t spin_lock_irqsave(spinlock_t *lock) {
    assert(lock==&sched_lock && !locked); locked=1; return 0;
}
static void spin_unlock_irqrestore(spinlock_t *lock, irqflags_t flags) {
    (void)flags; assert(lock==&sched_lock && locked); locked=0;
}
typedef struct aegis_task {
    uint32_t is_user, state;
    struct aegis_task *next;
} aegis_task_t;
typedef struct {
    aegis_task_t task;
    uint64_t pml4_phys;
    cap_slot_t caps[CAP_TABLE_SIZE];
    uint32_t cap_ceiling[CAP_KIND_MAX+1u], cap_ceiling_active;
    uint64_t authority_epoch;
    uint32_t authority_busy, authenticated, admin_session, admin_session_firstboot;
    uint32_t auth_uid, auth_gid, uid, gid, pid, tgid, ppid, sid, pgid;
    char exe_path[256];
} aegis_process_t;
static aegis_process_t caller, parent;
static cap_slot_t self_entry_caps[CAP_TABLE_SIZE];
static uint64_t self_entry_epoch;
static aegis_process_t *running=&caller;
static int parent_exists=1;
static aegis_process_t *current_proc(void) { return running; }
#define sched_current() (&running->task)
static aegis_process_t *proc_find_by_pid_locked(uint32_t pid) {
    assert(locked);
    return parent_exists && parent.pid==pid ? &parent : NULL;
}
void serial_write_string(const char *s) { (void)s; }
static void (*during_policy)(void);
static void (*before_user_entry)(void);
static uint64_t secure_auxv[2];
static int vmm_write_user_u64(uint64_t pml4,uint64_t address,uint64_t value) {
    (void)pml4; assert(address==0 || address==8);
    secure_auxv[address/8]=value; return 0;
}
static int firstboot, session_only, privileged_policy;
static unsigned policy_io_calls;
static char policy_path[256];
static int policy_auth, policy_admin;
int cap_policy_is_firstboot(const char *path) {
    (void)path; assert(!locked); return firstboot;
}
static void cap_derive(cap_slot_t *caps, const char *path, int auth, int admin) {
    assert(!locked);
    policy_io_calls++;
    strcpy(policy_path,path); policy_auth=auth; policy_admin=admin;
    memset(caps,0,sizeof(cap_slot_t)*CAP_TABLE_SIZE);
    cap_grant(caps,CAP_TABLE_SIZE,CAP_KIND_VFS_READ,CAP_RIGHTS_READ);
    if (admin && !session_only)
        cap_grant(caps,CAP_TABLE_SIZE,CAP_KIND_INSTALL,CAP_RIGHTS_WRITE);
    if (auth) cap_grant(caps,CAP_TABLE_SIZE,CAP_KIND_POWER,CAP_RIGHTS_WRITE);
    if (!strcmp(path,"/bin/new"))
        cap_grant(caps,CAP_TABLE_SIZE,CAP_KIND_NET_SOCKET,CAP_RIGHTS_READ|CAP_RIGHTS_WRITE);
    if (privileged_policy) {
        cap_grant(caps,CAP_TABLE_SIZE,CAP_KIND_AUTH,CAP_RIGHTS_READ);
        cap_grant(caps,CAP_TABLE_SIZE,CAP_KIND_ADMIN_AUTH,CAP_RIGHTS_WRITE);
        cap_grant(caps,CAP_TABLE_SIZE,CAP_KIND_THREAD_CREATE,CAP_RIGHTS_READ);
    }
    if (during_policy) {
        void (*callback)(void)=during_policy;
        during_policy=NULL;
        callback();
    }
}
#define cap_apply_policy cap_derive
static void proc_trace_log(const char *op,uint32_t pid,uint32_t ppid,const char *path) {
    (void)op; (void)pid; (void)ppid; (void)path;
}
static void sched_exit(void) { abort(); }
static void kva_free_pages(void *ptr,unsigned pages) {
    (void)ptr; (void)pages; abort(); /* unexpected failure in auxv publication */
}
'''
C += re.search(r"(?m)^#define AUTH_ID_NONE[^\n]+",
               (ROOT / "kernel/proc/proc.h").read_text()).group(0) + "\n"
has_auth_sentinel_guard = "AUTH_ID_NONE" in function(syscap, "sys_auth_session")
if has_auth_sentinel_guard:
    C += "#define TEST_AUTH_SENTINEL\n"
C += re.sub(r"(?m)^#include[^\n]*\n", "", (ROOT / "kernel/cap/cap.c").read_text())
for name in ("cap_name_to_kind", "streq", "parse_policy"):
    C += function(policy, name)
for name in ("sys_auth_session", "admin_self_eligible_locked", "sys_admin_self",
             "sys_admin_session"):
    C += function(syscap, name)
C += function(identity, "sys_setsid")
C += function(identity, "sys_setpgid")
C += function(identity, "sys_setuid")
C += function(identity, "sys_setgid")
C += function(exec_source, "exec_gains_caps")
C += function(exec_source, "exec_requires_secure_start")
C += r'''
/* Run the exact production begin/derive/commit/abort blocks without loading
 * an ELF or destroying address-space pages. */
static void exec_transaction(const char *path,int fail_before_boundary) {
    aegis_process_t *proc=current_proc();
    cap_slot_t prior_caps[CAP_TABLE_SIZE];
    int prior_admin;
    uint64_t authority_epoch=0, ret=0;
    int authority_pending=0;
'''
C += begin
C += "    if(fail_before_boundary) goto done;\n"
C += publish
C += r'''
    uint64_t wp=0;
'''
C += secure_auxv
C += r'''
    assert(wp==16 && secure_auxv[0]==23);
    /* This models the real loader/stack/CLOEXEC work after AT_SECURE has
     * frozen, before SYSRET/ERET. It remains outside sched_lock. */
    if (before_user_entry) {
        void (*callback)(void)=before_user_entry;
        before_user_entry=NULL; callback();
    }
done:
'''
C += cleanup
C += r'''
    assert(!ret);
}
static void spawn_secure_start(aegis_process_t *parent,aegis_process_t *child) {
    uint64_t secure_auxv_va=8, result=0;
    void *kstack=NULL;
'''
C += spawn_auxv
C += r'''
    return;
fail_child:
    (void)result; abort();
}
static void reset(void) {
    assert(!locked);
    memset(&caller,0,sizeof(caller)); memset(&parent,0,sizeof(parent));
    caller.task.is_user=parent.task.is_user=1;
    caller.task.next=&parent.task; parent.task.next=&caller.task;
    caller.pid=20; caller.ppid=parent.pid=10; caller.sid=parent.sid=3;
    caller.tgid=20; parent.tgid=10;
    strcpy(parent.exe_path,"/bin/old");
    parent_exists=1; running=&caller; during_policy=before_user_entry=NULL; firstboot=0;
    session_only=privileged_policy=0; policy_io_calls=0;
    caller.auth_uid=caller.auth_gid=parent.auth_uid=parent.auth_gid=AUTH_ID_NONE;
    secure_auxv[0]=secure_auxv[1]=UINT64_MAX;
    cap_grant(caller.caps,CAP_TABLE_SIZE,CAP_KIND_ADMIN_AUTH,CAP_RIGHTS_WRITE);
    cap_grant(parent.caps,CAP_TABLE_SIZE,CAP_KIND_VFS_READ,CAP_RIGHTS_READ);
}
static void reset_self(void) {
    reset();
    strcpy(caller.exe_path,"/bin/login");
    caller.uid=caller.gid=1000;
    cap_grant(caller.caps,CAP_TABLE_SIZE,CAP_KIND_AUTH,CAP_RIGHTS_READ);
    cap_grant(caller.caps,CAP_TABLE_SIZE,CAP_KIND_SETUID,CAP_RIGHTS_WRITE);
    /* Execute the real issuer and checked identity transitions, not merely
     * fixture writes that assume numeric uid zero implies authentication. */
    assert(!sys_auth_session(0,0));
    assert(!sys_setgid(0) && !sys_setuid(0));
    assert(caller.authenticated && !caller.auth_uid && !caller.auth_gid);
    assert(!caller.uid && !caller.gid);
    memcpy(self_entry_caps,caller.caps,sizeof(self_entry_caps));
    self_entry_epoch=caller.authority_epoch;
    privileged_policy=1;
}
static int has_install(void) {
    return !cap_check(parent.caps,CAP_TABLE_SIZE,CAP_KIND_INSTALL,CAP_RIGHTS_WRITE);
}
static void do_exec(void) {
    assert(!parent.admin_session && !has_install());
    running=&parent; exec_transaction("/bin/new",0); running=&caller;
}
static void do_same_path_exec(void) {
    running=&parent; exec_transaction("/bin/old",0); running=&caller;
}
static void do_drop(void) {
    running=&parent; assert(!sys_admin_session(0)); running=&caller;
}
static void elevate_during_drop(void) {
    assert(parent.authority_busy && !parent.admin_session && !has_install());
    for(unsigned i=0;i<CAP_TABLE_SIZE;i++) assert(!parent.caps[i].kind);
    running=&caller; assert(sys_admin_session(1)==SYS_ERR(EPERM)); running=&parent;
}
static void elevate_during_exec(void) {
    assert(parent.authority_busy);
    running=&caller; assert(sys_admin_session(1)==SYS_ERR(EPERM)); running=&parent;
}
static void change_auth(void) {
    running=&parent;
    cap_grant(parent.caps,CAP_TABLE_SIZE,CAP_KIND_AUTH,CAP_RIGHTS_READ);
    assert(!sys_auth_session(42,43)); running=&caller;
}
static void change_session(void) {
    running=&parent; assert(sys_setsid()==10); running=&caller;
}
static void reparent(void) {
    irqflags_t fl=spin_lock_irqsave(&sched_lock);
    caller.ppid=1; spin_unlock_irqrestore(&sched_lock,fl);
}
static void exit_parent(void) {
    irqflags_t fl=spin_lock_irqsave(&sched_lock);
    parent.task.state=TASK_ZOMBIE; spin_unlock_irqrestore(&sched_lock,fl);
}
static void reap_parent(void) {
    irqflags_t fl=spin_lock_irqsave(&sched_lock);
    parent_exists=0; spin_unlock_irqrestore(&sched_lock,fl);
}
static void competing_elevation(void) { assert(!sys_admin_session(1)); }
static void late_elevation(void) {
    running=&caller; assert(!sys_admin_session(1)); running=&parent;
}
static void late_elevation_rejected(void) {
    running=&caller; assert(sys_admin_session(1)==SYS_ERR(EPERM)); running=&parent;
}
static void assert_no_caps(void) {
    for(unsigned i=0;i<CAP_TABLE_SIZE;i++) assert(!parent.caps[i].kind);
}
static void test_monotonic_drop(void) {
    /* An independent child retains exe_path, not authority. Even a privileged
     * service policy must not turn its ungated drop into a grant. */
    reset(); memset(parent.caps,0,sizeof(parent.caps));
    strcpy(parent.exe_path,"/bin/new"); privileged_policy=1; running=&parent;
    assert(!sys_admin_session(0)); assert_no_caps();
    assert(!sys_admin_session(0)); assert_no_caps();
    assert(!policy_io_calls && parent.authority_epoch==2);

    /* An already unelevated masked table is a true no-op, not a policy refresh
     * that can grow it back up to its broader persistent ceiling. */
    reset(); parent.cap_ceiling_active=1; privileged_policy=1; running=&parent;
    parent.cap_ceiling[CAP_KIND_VFS_READ]=CAP_RIGHTS_READ|CAP_RIGHTS_WRITE;
    parent.cap_ceiling[CAP_KIND_NET_SOCKET]=CAP_RIGHTS_READ|CAP_RIGHTS_WRITE;
    cap_slot_t saved[CAP_TABLE_SIZE]; memcpy(saved,parent.caps,sizeof(saved));
    assert(!sys_admin_session(0)); assert(!sys_admin_session(0));
    assert(!memcmp(saved,parent.caps,sizeof(saved)) && !policy_io_calls);

    /* An actual drop loses admin caps and only keeps nonadmin policy rights
     * that were held BEFORE revocation, even after policy widening. */
    reset(); parent.admin_session=1; parent.authenticated=1;
    privileged_policy=1; strcpy(parent.exe_path,"/bin/new"); running=&parent;
    cap_grant(parent.caps,CAP_TABLE_SIZE,CAP_KIND_INSTALL,CAP_RIGHTS_WRITE);
    cap_grant(parent.caps,CAP_TABLE_SIZE,CAP_KIND_NET_SOCKET,CAP_RIGHTS_READ);
    memcpy(saved,parent.caps,sizeof(saved));
    assert(!sys_admin_session(0)); assert(!parent.admin_session && !has_install());
    assert(!cap_check(parent.caps,CAP_TABLE_SIZE,CAP_KIND_VFS_READ,CAP_RIGHTS_READ));
    assert(!cap_check(parent.caps,CAP_TABLE_SIZE,CAP_KIND_NET_SOCKET,CAP_RIGHTS_READ));
    assert(cap_check(parent.caps,CAP_TABLE_SIZE,CAP_KIND_NET_SOCKET,CAP_RIGHTS_WRITE));
    assert(cap_check(parent.caps,CAP_TABLE_SIZE,CAP_KIND_AUTH,CAP_RIGHTS_READ));
    assert(cap_check(parent.caps,CAP_TABLE_SIZE,CAP_KIND_ADMIN_AUTH,CAP_RIGHTS_WRITE));
    assert(cap_check(parent.caps,CAP_TABLE_SIZE,CAP_KIND_THREAD_CREATE,CAP_RIGHTS_READ));
    assert(cap_check(parent.caps,CAP_TABLE_SIZE,CAP_KIND_POWER,CAP_RIGHTS_WRITE));
    for(unsigned i=0;i<CAP_TABLE_SIZE;i++) if(parent.caps[i].kind)
        assert(!cap_check(saved,CAP_TABLE_SIZE,parent.caps[i].kind,parent.caps[i].rights));
    memcpy(saved,parent.caps,sizeof(saved));
    assert(!sys_admin_session(0));
    assert(!memcmp(saved,parent.caps,sizeof(saved)) && policy_io_calls==1);

    /* Both the held table and persistent ceiling constrain an actual drop. */
    reset(); parent.admin_session=parent.cap_ceiling_active=1;
    parent.cap_ceiling[CAP_KIND_VFS_READ]=CAP_RIGHTS_READ;
    strcpy(parent.exe_path,"/bin/new"); running=&parent;
    cap_grant(parent.caps,CAP_TABLE_SIZE,CAP_KIND_NET_SOCKET,CAP_RIGHTS_READ);
    assert(!sys_admin_session(0));
    assert(cap_check(parent.caps,CAP_TABLE_SIZE,CAP_KIND_NET_SOCKET,CAP_RIGHTS_READ));
    assert(!cap_check(parent.caps,CAP_TABLE_SIZE,CAP_KIND_VFS_READ,CAP_RIGHTS_READ));

    reset(); parent.admin_session=1; memset(parent.caps,0,sizeof(parent.caps));
    privileged_policy=1; running=&parent;
    assert(!sys_admin_session(0)); assert_no_caps(); assert(policy_io_calls==1);

    /* Do not combine rights from separate old slots into a newly usable cap. */
    reset(); parent.admin_session=1; strcpy(parent.exe_path,"/bin/new"); running=&parent;
    cap_grant(parent.caps,CAP_TABLE_SIZE,CAP_KIND_NET_SOCKET,CAP_RIGHTS_READ);
    cap_grant(parent.caps,CAP_TABLE_SIZE,CAP_KIND_NET_SOCKET,CAP_RIGHTS_WRITE);
    assert(!sys_admin_session(0));
    assert(cap_check(parent.caps,CAP_TABLE_SIZE,CAP_KIND_NET_SOCKET,
                     CAP_RIGHTS_READ|CAP_RIGHTS_WRITE));

    reset(); parent.admin_session_firstboot=1; running=&parent;
    cap_grant(parent.caps,CAP_TABLE_SIZE,CAP_KIND_INSTALL,CAP_RIGHTS_WRITE);
    assert(!sys_admin_session(0));
    assert(!parent.admin_session && !parent.admin_session_firstboot && !has_install());
}
static void test_auth_sentinel(void) {
#ifdef TEST_AUTH_SENTINEL
    reset(); cap_grant(caller.caps,CAP_TABLE_SIZE,CAP_KIND_AUTH,CAP_RIGHTS_READ);
    aegis_process_t saved=caller;
    uint64_t invalid[]={AUTH_ID_NONE,(uint64_t)AUTH_ID_NONE+1,UINT64_MAX};
    for(unsigned i=0;i<sizeof(invalid)/sizeof(invalid[0]);i++) {
        assert(sys_auth_session(invalid[i],0)==SYS_ERR(EINVAL));
        assert(!memcmp(&saved,&caller,sizeof(caller)) && !locked);
        assert(sys_auth_session(0,invalid[i])==SYS_ERR(EINVAL));
        assert(!memcmp(&saved,&caller,sizeof(caller)) && !locked);
    }
    assert(!sys_auth_session((uint64_t)AUTH_ID_NONE-1,0));
    assert(caller.authenticated && caller.auth_uid==AUTH_ID_NONE-1 && !caller.auth_gid);
    puts("Auth sentinel boundary: ok");
#else
    puts("Auth sentinel boundary: SKIPPED (lifecycle guard not in this isolated worktree)");
#endif
}
static void self_unpublished(void) {
    assert(!locked && running==&caller && !caller.authority_busy);
    assert(!caller.admin_session && !caller.admin_session_firstboot);
    assert(!memcmp(self_entry_caps,caller.caps,sizeof(self_entry_caps)));
    assert(caller.authority_epoch==self_entry_epoch);
    assert(cap_check(caller.caps,CAP_TABLE_SIZE,CAP_KIND_INSTALL,CAP_RIGHTS_WRITE));
    assert(!strcmp(policy_path,"/bin/login") && policy_auth==1 && policy_admin==1);
    assert(!parent.admin_session && !has_install());
}
static void self_drop(void) {
    self_unpublished(); assert(!sys_admin_session(AEGIS_ADMIN_SESSION_DROP));
}
static void self_exec(void) {
    self_unpublished(); exec_transaction("/bin/new",0);
}
static void self_same_path_exec(void) {
    self_unpublished(); exec_transaction("/bin/login",0);
}
static void self_auth(void) {
    self_unpublished(); assert(!sys_auth_session(42,43));
}
static void self_same_auth(void) {
    self_unpublished(); assert(!sys_auth_session(0,0));
}
static void self_session(void) {
    self_unpublished(); assert(sys_setsid()==caller.pid);
}
/* These unversioned mutations prove that commit checks live conditions too,
 * rather than trusting an epoch alone (uid/gid writers do not bump it). */
static void self_uid(void) { self_unpublished(); caller.uid=1; }
static void self_gid(void) { self_unpublished(); caller.gid=1; }
static void self_auth_uid(void) { self_unpublished(); caller.auth_uid=1; }
static void self_auth_gid(void) { self_unpublished(); caller.auth_gid=AUTH_ID_NONE; }
static void self_unauth(void) { self_unpublished(); caller.authenticated=0; }
static void self_revoke(void) { self_unpublished(); memset(caller.caps,0,sizeof(caller.caps)); }
static void self_readonly(void) {
    self_unpublished();
    memset(caller.caps,0,sizeof(caller.caps));
    cap_grant(caller.caps,CAP_TABLE_SIZE,CAP_KIND_ADMIN_AUTH,CAP_RIGHTS_READ);
}
static void self_ceiling(void) { self_unpublished(); caller.cap_ceiling_active=1; }
static void self_busy(void) { self_unpublished(); caller.authority_busy=1; }
static void self_path(void) { self_unpublished(); strcpy(caller.exe_path,"/bin/new"); }
static void self_sid(void) { self_unpublished(); caller.sid++; }
static void self_tgid(void) { self_unpublished(); caller.tgid++; }
static void self_sibling(void) { self_unpublished(); parent.tgid=caller.tgid; }
static void self_exit(void) { self_unpublished(); caller.task.state=TASK_ZOMBIE; }
static void self_competing(void) {
    self_unpublished(); assert(!sys_admin_self());
}
static void self_admin_drop(void) {
    assert(caller.admin_session);
    assert(!sys_admin_session(AEGIS_ADMIN_SESSION_DROP));
    assert(!caller.admin_session && !caller.authority_busy);
    assert(cap_check(caller.caps,CAP_TABLE_SIZE,CAP_KIND_INSTALL,CAP_RIGHTS_WRITE));
}
static void self_deny_without_io(void) {
    aegis_process_t saved=caller, saved_parent=parent;
    unsigned calls=policy_io_calls;
    assert(sys_admin_self()==SYS_ERR(EPERM));
    assert(policy_io_calls==calls && !locked);
    assert(!memcmp(&saved,&caller,sizeof(caller)));
    assert(!memcmp(&saved_parent,&parent,sizeof(parent)));
}
static void test_self_mode(void) {
    _Static_assert(AEGIS_ADMIN_SESSION_DROP==0 && AEGIS_ADMIN_SESSION_PARENT==1 &&
                   AEGIS_SYS_ADMIN_SELF==521, "admin syscall ABI");
    reset_self();
    aegis_process_t saved_parent=parent;
    uint64_t epoch=caller.authority_epoch;
    /* No ceiling is synthesized or widened, even its inactive contents. */
    caller.cap_ceiling[CAP_KIND_VFS_READ]=CAP_RIGHTS_READ;
    uint32_t ceiling[CAP_KIND_MAX+1u];
    memcpy(ceiling,caller.cap_ceiling,sizeof(ceiling));
    during_policy=self_unpublished;
    assert(!sys_admin_self());
    assert(caller.admin_session && !caller.admin_session_firstboot);
    assert(!cap_check(caller.caps,CAP_TABLE_SIZE,CAP_KIND_INSTALL,CAP_RIGHTS_WRITE));
    assert(caller.authority_epoch==epoch+1 && !caller.authority_busy);
    assert(!caller.cap_ceiling_active && !memcmp(ceiling,caller.cap_ceiling,sizeof(ceiling)));
    assert(!memcmp(&saved_parent,&parent,sizeof(parent)) && policy_io_calls==1);
    /* The verified session survives in-place exec, not an independent child.
     * Its destination policy does NOT have to grant ADMIN_AUTH to operate. */
    privileged_policy=0;
    exec_transaction("/bin/new",0);
    assert(caller.admin_session && !caller.admin_session_firstboot);
    assert(!cap_check(caller.caps,CAP_TABLE_SIZE,CAP_KIND_INSTALL,CAP_RIGHTS_WRITE));
    assert(cap_check(caller.caps,CAP_TABLE_SIZE,CAP_KIND_ADMIN_AUTH,CAP_RIGHTS_WRITE));

    reset_self(); caller.admin_session=caller.admin_session_firstboot=1;
    assert(!sys_admin_self());
    assert(caller.admin_session && !caller.admin_session_firstboot);

    reset_self(); memset(caller.caps,0,sizeof(caller.caps)); self_deny_without_io();
    reset_self(); memset(caller.caps,0,sizeof(caller.caps));
    cap_grant(caller.caps,CAP_TABLE_SIZE,CAP_KIND_ADMIN_AUTH,CAP_RIGHTS_READ);
    self_deny_without_io();
    /* Raw uid/gid zero with no verified principal is never privilege. */
    reset(); caller.uid=caller.gid=0; self_deny_without_io();
    reset_self(); caller.authenticated=0; self_deny_without_io();
    reset_self(); caller.auth_uid=AUTH_ID_NONE; self_deny_without_io();
    reset_self(); caller.auth_gid=AUTH_ID_NONE; self_deny_without_io();
    reset_self(); caller.auth_uid=1; self_deny_without_io();
    reset_self(); caller.auth_gid=1; self_deny_without_io();
    reset_self(); caller.uid=1000; self_deny_without_io();
    reset_self(); caller.gid=1000; self_deny_without_io();
    reset_self(); caller.cap_ceiling_active=1; self_deny_without_io();
    reset_self(); caller.authority_busy=1; self_deny_without_io();
    reset_self(); caller.task.state=TASK_ZOMBIE; self_deny_without_io();
    reset_self(); caller.task.is_user=0; self_deny_without_io();
    /* Reject a multi-live-thread group even when caller is the correct leader,
     * and even when the sibling is stopped rather than runnable. */
    reset_self(); parent.tgid=caller.tgid; self_deny_without_io();
    parent.task.state=3; self_deny_without_io();
    reset_self(); caller.tgid=parent.tgid; self_deny_without_io();
    /* A sole live nonleader is valid; a zombie leader is not a live sibling. */
    parent.task.state=TASK_ZOMBIE;
    assert(!sys_admin_self());
    reset_self(); parent.tgid=caller.tgid; parent.task.is_user=0;
    assert(!sys_admin_self());

    void (*races[])(void)={self_drop,self_exec,self_same_path_exec,self_auth,
        self_same_auth,self_session,self_uid,self_gid,self_auth_uid,self_auth_gid,
        self_unauth,self_revoke,self_readonly,self_ceiling,self_busy,self_path,
        self_sid,self_tgid,self_sibling,self_exit};
    for(unsigned i=0;i<sizeof(races)/sizeof(races[0]);i++) {
        reset_self(); during_policy=races[i];
        assert(sys_admin_self()==SYS_ERR(EPERM));
        assert(!locked && !caller.admin_session && !caller.admin_session_firstboot);
        assert(cap_check(caller.caps,CAP_TABLE_SIZE,CAP_KIND_INSTALL,CAP_RIGHTS_WRITE));
        assert(!parent.admin_session && !has_install());
        /* Only a nested production exec may do a second policy read; failed
         * SELF never retries or restores authority revoked during policy I/O. */
        assert(policy_io_calls==(races[i]==self_exec || races[i]==self_same_path_exec ? 2u : 1u));
    }
    reset_self(); during_policy=self_competing;
    assert(sys_admin_self()==SYS_ERR(EPERM));
    assert(caller.admin_session && policy_io_calls==2);
    assert(!cap_check(caller.caps,CAP_TABLE_SIZE,CAP_KIND_INSTALL,CAP_RIGHTS_WRITE));
    reset_self(); assert(!sys_admin_self()); during_policy=self_admin_drop;
    assert(sys_admin_self()==SYS_ERR(EPERM));
    assert(!caller.admin_session && !caller.authority_busy && policy_io_calls==3);
    assert(cap_check(caller.caps,CAP_TABLE_SIZE,CAP_KIND_INSTALL,CAP_RIGHTS_WRITE));

    /* Not boolean selectors: upper bits and all undefined values (including
     * the rejected SELF=2 proposal) fail without entering legacy PARENT. */
    uint64_t invalid[]={2,3,4,UINT32_MAX,UINT64_MAX,UINT64_C(1)<<32,
                        (UINT64_C(1)<<32)|1,(UINT64_C(1)<<32)|2};
    for(unsigned i=0;i<sizeof(invalid)/sizeof(invalid[0]);i++) {
        reset_self();
        aegis_process_t saved=caller; saved_parent=parent;
        assert(sys_admin_session(invalid[i])==SYS_ERR(EINVAL));
        assert(!policy_io_calls && !memcmp(&saved,&caller,sizeof(caller)));
        assert(!memcmp(&saved_parent,&parent,sizeof(parent)));
    }
    puts("Admin SELF syscall 521: verified issuer, live single-thread checks, atomic publication and races: ok");
}
static void test_secure_start(void) {
    /* No gain at exec: the later parent-targeted grant still needs secure
     * startup. Exercise both capability-bearing and session-only elevation. */
    for(int only_session=0;only_session<2;only_session++) {
        reset(); session_only=only_session;
        running=&parent; before_user_entry=late_elevation;
        exec_transaction("/bin/old",0);
        assert(parent.admin_session && has_install()==!only_session);
        assert(secure_auxv[1]==1);
    }

    /* An inherited ceiling bars in-place elevation. No new authority can
     * preserve ordinary startup, but policy gains within that ceiling cannot. */
    reset(); parent.cap_ceiling_active=1; running=&parent;
    parent.cap_ceiling[CAP_KIND_VFS_READ]=CAP_RIGHTS_READ;
    before_user_entry=late_elevation_rejected;
    exec_transaction("/bin/old",0);
    assert(secure_auxv[1]==0 && !parent.admin_session);
    parent.cap_ceiling[CAP_KIND_NET_SOCKET]=CAP_RIGHTS_READ;
    exec_transaction("/bin/new",0);
    assert(secure_auxv[1]==1);

    /* Spawn uses its FINAL ceiling, after both inherited and mask-induced
     * attenuation, rather than the parent's eligibility. Execute the actual
     * production write, not a test reimplementation of its expression. */
    reset();
    aegis_process_t child=parent;
    spawn_secure_start(&parent,&child); assert(secure_auxv[1]==1);
    child.cap_ceiling_active=1;
    spawn_secure_start(&parent,&child); assert(secure_auxv[1]==0);
    parent.cap_ceiling_active=1; /* inherited ceiling, no gain */
    spawn_secure_start(&parent,&child); assert(secure_auxv[1]==0);
    cap_grant(child.caps,CAP_TABLE_SIZE,CAP_KIND_NET_SOCKET,CAP_RIGHTS_READ);
    spawn_secure_start(&parent,&child); assert(secure_auxv[1]==1);
    memcpy(child.caps,parent.caps,sizeof(child.caps));
    child.caps[0].rights|=CAP_RIGHTS_WRITE; /* a new right is also a gain */
    spawn_secure_start(&parent,&child); assert(secure_auxv[1]==1);
    memcpy(child.caps,parent.caps,sizeof(child.caps));
    child.admin_session=1; /* defend direct authority independently of caps */
    spawn_secure_start(&parent,&child); assert(secure_auxv[1]==1);
}
static void test_parser(void) {
    const char *bad[]={
        "disabled service POWER", "disabled admin INSTALL\n",
        "disabled firstboot AUTH\r\n",
        "xxxxxxxxxxxxxxxservice POWER\n",
        "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx service POWER\r",
        "servic", "adminX service POWER", "firstbootX admin INSTALL"
    };
    cap_policy_entry_t entry;
    for(unsigned i=0;i<sizeof(bad)/sizeof(bad[0]);i++) {
        assert(!parse_policy(bad[i],strlen(bad[i]),&entry)); assert(!entry.count);
        char joined[256];
        snprintf(joined,sizeof(joined),"%s\nservice VFS_READ\n",bad[i]);
        assert(!parse_policy(joined,strlen(joined),&entry));
        assert(entry.count==1 && entry.caps[0].kind==CAP_KIND_VFS_READ);
    }
    const char *valid="# comment\r\nservice POWER NET_SOCKET\r\nadmin INSTALL\nfirstboot AUTH";
    assert(!parse_policy(valid,strlen(valid),&entry)); assert(entry.count==4);
    assert(entry.caps[0].tier==CAP_TIER_SERVICE && entry.caps[0].kind==CAP_KIND_POWER);
    assert(entry.caps[2].tier==CAP_TIER_ADMIN && entry.caps[2].kind==CAP_KIND_INSTALL);
    assert(entry.caps[3].tier==CAP_TIER_FIRSTBOOT && entry.caps[3].kind==CAP_KIND_AUTH);
    char overlong[128]; memset(overlong,'x',31); strcpy(overlong+31,"POWER");
    char line[160]; snprintf(line,sizeof(line),"service %s VFS_READ",overlong);
    assert(!parse_policy(line,strlen(line),&entry));
    assert(entry.count==1 && entry.caps[0].kind==CAP_KIND_VFS_READ);
    const char nul_tier[]="service\0x POWER\nservice VFS_READ\n";
    assert(!parse_policy(nul_tier,sizeof(nul_tier)-1,&entry));
    assert(entry.count==1 && entry.caps[0].kind==CAP_KIND_VFS_READ);
    const char nul_cap[]="service POWER\0x VFS_READ\n";
    assert(!parse_policy(nul_cap,sizeof(nul_cap)-1,&entry));
    assert(entry.count==1 && entry.caps[0].kind==CAP_KIND_VFS_READ);
}
int main(void) {
    test_parser();
    test_monotonic_drop();
    test_auth_sentinel();
    test_self_mode();
    test_secure_start();
    reset(); assert(!sys_admin_session(1)); assert(parent.admin_session && has_install());
    assert(!parent.authority_busy && parent.authority_epoch==1);
    reset(); during_policy=do_exec; assert(sys_admin_session(1)==SYS_ERR(EPERM));
    assert(!strcmp(parent.exe_path,"/bin/new") && !parent.admin_session && !has_install());
    reset(); during_policy=do_same_path_exec;
    assert(sys_admin_session(1)==SYS_ERR(EPERM)); assert(!has_install());
    reset(); during_policy=do_drop; assert(sys_admin_session(1)==SYS_ERR(EPERM));
    assert(!parent.admin_session && !has_install());
    reset(); assert(!sys_admin_session(1)); during_policy=do_drop;
    assert(sys_admin_session(1)==SYS_ERR(EPERM)); assert(!has_install());
    reset(); assert(!sys_admin_session(1));
    running=&parent; during_policy=elevate_during_drop;
    assert(!sys_admin_session(0)); assert(!parent.authority_busy && !has_install());
    reset(); running=&parent; during_policy=elevate_during_exec;
    exec_transaction("/bin/new",0); assert(!parent.authority_busy && !has_install());
    assert(secure_auxv[1]==1); /* actual production auxv write retains secure_exec */
    reset(); running=&parent; exec_transaction("/bin/new",1);
    assert(!parent.authority_busy && !strcmp(parent.exe_path,"/bin/old"));
    reset(); assert(!sys_admin_session(1)); running=&parent;
    exec_transaction("/bin/new",0); assert(parent.admin_session && has_install());
    reset(); parent.admin_session=parent.admin_session_firstboot=1; running=&parent;
    exec_transaction("/bin/new",0); assert(!parent.admin_session && !has_install());
    reset(); firstboot=1; running=&parent; exec_transaction("/bin/new",0);
    assert(parent.admin_session && parent.admin_session_firstboot);
    void (*races[])(void)={change_auth,change_session,reparent,exit_parent,reap_parent};
    for(unsigned i=0;i<sizeof(races)/sizeof(races[0]);i++) {
        reset(); during_policy=races[i]; assert(sys_admin_session(1)==SYS_ERR(EPERM));
        assert(!parent.admin_session && !has_install());
    }
    reset(); during_policy=competing_elevation;
    assert(sys_admin_session(1)==SYS_ERR(EPERM)); assert(parent.admin_session && has_install());
    reset(); parent.cap_ceiling_active=1;
    assert(sys_admin_session(1)==SYS_ERR(EPERM)); assert(!parent.admin_session);
    parent.admin_session=1; running=&parent;
    parent.cap_ceiling[CAP_KIND_VFS_READ]=CAP_RIGHTS_READ;
    assert(!sys_admin_session(0)); assert(!has_install() && !parent.admin_session);
    reset(); parent.authority_busy=1;
    assert(sys_admin_session(1)==SYS_ERR(EPERM)); assert(!parent.admin_session);
    /* Process-level child ownership must also work from a nonleader thread. */
    reset(); caller.tgid=19; parent.ppid=19;
    assert(!sys_setpgid(parent.pid,0)); assert(parent.pgid==parent.pid);
    parent.ppid=caller.pid;
    assert(sys_setpgid(parent.pid,0)==SYS_ERR(EPERM));
    puts("Capability authority: parser, monotonic drop, authority races, secure startup and ceilings: ok");
}
'''
with tempfile.TemporaryDirectory(prefix="aegis-cap-authority-") as temp:
    source = Path(temp) / "test.c"
    source.write_text(C)
    exe = Path(temp) / "test"
    sanitizers = os.environ.get("SANITIZERS", "address,undefined")
    subprocess.run([os.environ.get("CC", "cc"), "-std=c11", "-O1", "-g",
                    "-Wall", "-Wextra", "-Werror",
                    *([f"-fsanitize={sanitizers}"] if sanitizers else []),
                    "-I", str(ROOT / "kernel/cap"), str(source), "-o", str(exe)],
                   check=True, timeout=30)
    subprocess.run([str(exe)], check=True, timeout=30)
