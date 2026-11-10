#!/usr/bin/env python3
"""Execute production child initialization, spawn delegation and cap policy.

Page tables/ELF loading are not needed: the spawn authority statement block is
compiled unchanged in a wrapper with the same error labels. Only policy
lookup, user-copy and scheduler locking are mocked; policy issuance, masks,
ceilings and cap checks use the kernel's actual C.
"""
from pathlib import Path
import re
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]


def function(path, name):
    source = (root / path).read_text()
    match = re.search(r"\n(?:static\s+)?(?:int|void|uint64_t)\s+" + name + r"\s*\(", source)
    assert match, name
    start = source.index("{", match.start())
    depth, end = 1, start + 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[match.start():end]


exec_source = (root / "kernel/syscall/sys_exec.c").read_text()
spawn_block = exec_source.split("/* 12. Fresh policy issuance", 1)[1]
spawn_block = spawn_block[spawn_block.index("\n    {"):]
spawn_block = spawn_block.split("    /* Publish the final policy/attenuation", 1)[0]
code = r'''
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "kernel/cap/cap.c"
#define AUTH_ID_NONE UINT32_MAX
#define CAP_AUTHENTICATOR_PATH "/bin/login"
typedef int irqflags_t;
typedef struct {
    cap_slot_t caps[CAP_TABLE_SIZE];
    uint32_t cap_ceiling[CAP_KIND_MAX + 1u], cap_ceiling_active;
    uint32_t authenticated, admin_session, admin_session_firstboot, auth_uid, auth_gid;
    uint32_t uid, gid;
    uint64_t authority_epoch;
} aegis_process_t;
typedef struct { int is_user; } aegis_task_t;
static aegis_task_t task = {1};
static aegis_task_t *sched_current(void) { return &task; }
static int sched_lock, bad_pointer, short_copy, first_boot;
static cap_policy_entry_t policy;
static aegis_process_t *mutate_parent;
static aegis_process_t *current;
static aegis_process_t *current_proc(void) { return current; }
void serial_write_string(const char *s) { (void)s; }
static irqflags_t spin_lock_irqsave(int *l) { assert(!*l); *l = 1; return 0; }
static void spin_unlock_irqrestore(int *l, irqflags_t f) { (void)f; assert(*l); *l = 0; }
static void printk(const char *fmt, ...) { (void)fmt; }
static int path_is(const char *a, const char *b) { return !strcmp(a, b); }
int cap_policy_lookup(const char *path, cap_policy_entry_t *out) {
    (void)path; assert(!sched_lock);
    if (out) *out = policy;
    return 1;
}
int cap_policy_is_firstboot(const char *path) {
    assert(!sched_lock); return first_boot && path_is(path, "/bin/configure");
}
static int user_ptr_valid(uint64_t p, unsigned n) {
    assert(!sched_lock && n == sizeof(cap_slot_t) * CAP_TABLE_SIZE);
    return p && !bad_pointer;
}
static unsigned copy_from_user(void *out, const void *in, unsigned n) {
    assert(!sched_lock);
    if (mutate_parent) {
        memset(mutate_parent->caps, 0, sizeof(mutate_parent->caps));
        mutate_parent->authenticated = mutate_parent->admin_session = 0;
        mutate_parent->auth_uid = mutate_parent->auth_gid = AUTH_ID_NONE;
        mutate_parent = 0;
    }
    memcpy(out, in, n);
    return short_copy ? 1 : 0;
}
static void kva_free_pages(void *p, unsigned n) {
    (void)p; assert(n == 4 && !sched_lock);
}
'''
code += function("kernel/cap/cap_policy.c", "cap_apply_policy")
code += function("kernel/syscall/sys_process.c", "init_child_authority")
code += function("kernel/syscall/sys_cap.c", "sys_auth_session")
code += function("kernel/syscall/sys_identity.c", "sys_setuid")
code += function("kernel/syscall/sys_identity.c", "sys_setgid")
code += r'''
static uint64_t spawn_authority(aegis_process_t *parent, aegis_process_t *child,
                                const char *path, const cap_slot_t *mask) {
    uint64_t cap_mask_uptr = (uintptr_t)mask, result = 0;
    void *kstack = 0;
'''
code += spawn_block
code += r'''
    return 0;
fail_child:
    return result;
}
/* Same policy/ceiling rule as exec; policy itself is production C, not a mock. */
static void reexec(aegis_process_t *p) {
    cap_apply_policy(p->caps, "/bin/tool", p->authenticated, p->admin_session);
    if (p->cap_ceiling_active) cap_apply_ceiling(p->caps, p->cap_ceiling);
}
static void grant(cap_slot_t *caps, uint32_t kind, uint32_t rights) {
    assert(cap_grant(caps, CAP_TABLE_SIZE, kind, rights) >= 0);
}
static void parent_init(aegis_process_t *p) {
    memset(p, 0, sizeof(*p));
    const uint32_t kinds[] = { CAP_KIND_VFS_READ, CAP_KIND_VFS_WRITE,
        CAP_KIND_VFS_OPEN, CAP_KIND_CAP_DELEGATE, CAP_KIND_AUTH, CAP_KIND_SETUID,
        CAP_KIND_INSTALL, CAP_KIND_THREAD_CREATE, CAP_KIND_NET_SOCKET, CAP_KIND_PROC_READ };
    for (unsigned i = 0; i < sizeof(kinds)/sizeof(kinds[0]); i++)
        grant(p->caps, kinds[i], CAP_RIGHTS_READ | CAP_RIGHTS_WRITE | CAP_RIGHTS_EXEC);
    p->authenticated = p->admin_session = p->admin_session_firstboot = 1;
    p->auth_uid = 1000; p->auth_gid = 1001;
}
static void no_session(const aegis_process_t *p) {
    assert(!p->authenticated && !p->admin_session && !p->admin_session_firstboot);
}
static void no_identity(const aegis_process_t *p) {
    assert(p->auth_uid == AUTH_ID_NONE && p->auth_gid == AUTH_ID_NONE);
}
static void empty_caps(const aegis_process_t *p) {
    for (unsigned i = 0; i < CAP_TABLE_SIZE; i++)
        assert(p->caps[i].kind == CAP_KIND_NULL && !p->caps[i].rights);
}
int main(void) {
    aegis_process_t parent, child, descendant;
    cap_slot_t mask[CAP_TABLE_SIZE] = {0};
    policy.count = 5;
    policy.caps[0] = (cap_policy_cap_t){CAP_KIND_NET_SOCKET, CAP_RIGHTS_READ, CAP_TIER_SERVICE};
    policy.caps[1] = (cap_policy_cap_t){CAP_KIND_SETUID, CAP_RIGHTS_WRITE, CAP_TIER_SERVICE};
    policy.caps[2] = (cap_policy_cap_t){CAP_KIND_INSTALL, CAP_RIGHTS_WRITE, CAP_TIER_ADMIN};
    policy.caps[3] = (cap_policy_cap_t){CAP_KIND_PROC_READ, CAP_RIGHTS_READ, CAP_TIER_ADMIN};
    policy.caps[4] = (cap_policy_cap_t){CAP_KIND_AUTH, CAP_RIGHTS_READ, CAP_TIER_FIRSTBOOT};
    parent_init(&parent);

    /* Both independent creation paths (fork and vfork/clone) initialize from
     * dirty memory without authority; no empty active ceiling is invented. */
    for (unsigned route = 0; route < 2; route++) {
        memset(&child, 0xa5, sizeof(child));
        init_child_authority(&child, &parent, 0);
        empty_caps(&child); no_session(&child); no_identity(&child);
        assert(!child.cap_ceiling_active);
        child.uid = child.gid = 0; current = &child;
        assert(sys_setuid(1000) == SYS_ERR(EACCES));
        assert(sys_setgid(1001) == SYS_ERR(EACCES));
        assert(sys_setuid(UINT32_MAX) == SYS_ERR(EACCES));
        assert(sys_setgid(UINT32_MAX) == SYS_ERR(EACCES));
        /* Real checker used at read/write/open/network syscall boundaries. */
        assert(cap_check(child.caps, CAP_TABLE_SIZE, CAP_KIND_VFS_READ, CAP_RIGHTS_READ) == -ENOCAP);
        assert(cap_check(child.caps, CAP_TABLE_SIZE, CAP_KIND_VFS_WRITE, CAP_RIGHTS_WRITE) == -ENOCAP);
        assert(cap_check(child.caps, CAP_TABLE_SIZE, CAP_KIND_NET_SOCKET, CAP_RIGHTS_READ) == -ENOCAP);
        reexec(&child);
        assert(cap_check(child.caps, CAP_TABLE_SIZE, CAP_KIND_VFS_READ, CAP_RIGHTS_READ) == 0);
        assert(cap_check(child.caps, CAP_TABLE_SIZE, CAP_KIND_NET_SOCKET, CAP_RIGHTS_READ) == 0);
        assert(cap_check(child.caps, CAP_TABLE_SIZE, CAP_KIND_INSTALL, CAP_RIGHTS_WRITE) != 0);
        assert(cap_check(child.caps, CAP_TABLE_SIZE, CAP_KIND_PROC_READ, CAP_RIGHTS_READ) != 0);
        /* Fresh SETUID policy does not recreate the parent's bound identity. */
        assert(sys_setuid(1000) == SYS_ERR(EPERM));
        assert(sys_setgid(1001) == SYS_ERR(EPERM));
        assert(sys_setuid(UINT32_MAX) == SYS_ERR(EPERM));
        assert(sys_setgid(UINT32_MAX) == SYS_ERR(EPERM));
        assert(!child.uid && !child.gid);
        no_session(&child); no_identity(&child);
    }

    /* Threads retain one coherent snapshot of caps, session, identity and
     * constraints, not a fresh independent security principal. */
    init_child_authority(&child, &parent, 1);
    assert(!memcmp(&child, &parent, offsetof(aegis_process_t, uid)));
    parent.cap_ceiling_active = 1;
    parent.cap_ceiling[CAP_KIND_VFS_READ] = CAP_RIGHTS_READ;
    init_child_authority(&child, &parent, 0);
    assert(child.cap_ceiling_active && !memcmp(child.cap_ceiling, parent.cap_ceiling, sizeof(parent.cap_ceiling)));
    empty_caps(&child); reexec(&child);
    assert(cap_check(child.caps, CAP_TABLE_SIZE, CAP_KIND_VFS_READ, CAP_RIGHTS_READ) == 0);
    assert(cap_check(child.caps, CAP_TABLE_SIZE, CAP_KIND_NET_SOCKET, CAP_RIGHTS_READ) != 0);
    init_child_authority(&descendant, &child, 0);
    empty_caps(&descendant); reexec(&descendant);
    assert(!memcmp(descendant.caps, child.caps, sizeof(child.caps)));
    init_child_authority(&child, &parent, 1);
    assert(!memcmp(&child, &parent, offsetof(aegis_process_t, uid)));

    /* Unmasked spawn gets independent unauthenticated policy plus inherited
     * restrictions, never bound identity/session/firstboot flags. */
    memset(&child, 0xa5, sizeof(child));
    assert(spawn_authority(&parent, &child, "/bin/tool", 0) == 0);
    no_session(&child); no_identity(&child);
    assert(child.cap_ceiling_active && !memcmp(child.cap_ceiling, parent.cap_ceiling, sizeof(parent.cap_ceiling)));
    assert(cap_check(child.caps, CAP_TABLE_SIZE, CAP_KIND_NET_SOCKET, CAP_RIGHTS_READ) != 0);
    parent_init(&parent);
    assert(spawn_authority(&parent, &child, "/bin/tool", 0) == 0);
    no_session(&child); no_identity(&child);
    assert(!child.cap_ceiling_active);
    assert(cap_check(child.caps, CAP_TABLE_SIZE, CAP_KIND_NET_SOCKET, CAP_RIGHTS_READ) == 0);
    assert(cap_check(child.caps, CAP_TABLE_SIZE, CAP_KIND_INSTALL, CAP_RIGHTS_WRITE) != 0);
    assert(cap_check(child.caps, CAP_TABLE_SIZE, CAP_KIND_PROC_READ, CAP_RIGHTS_READ) != 0);

    /* Explicit mask can select existing admin-qualified policy authority,
     * but no latent session survives and later exec cannot regenerate it. */
    grant(mask, CAP_KIND_INSTALL, CAP_RIGHTS_WRITE);
    grant(mask, CAP_KIND_VFS_READ, CAP_RIGHTS_READ);
    assert(spawn_authority(&parent, &child, "/bin/tool", mask) == 0);
    assert(cap_check(child.caps, CAP_TABLE_SIZE, CAP_KIND_INSTALL, CAP_RIGHTS_WRITE) == 0);
    assert(child.cap_ceiling_active);
    no_session(&child); no_identity(&child);
    reexec(&child);
    assert(cap_check(child.caps, CAP_TABLE_SIZE, CAP_KIND_INSTALL, CAP_RIGHTS_WRITE) != 0);
    assert(cap_check(child.caps, CAP_TABLE_SIZE, CAP_KIND_NET_SOCKET, CAP_RIGHTS_READ) != 0);
    assert(spawn_authority(&child, &descendant, "/bin/tool", 0) == 0);
    assert(descendant.cap_ceiling_active);
    assert(cap_check(descendant.caps, CAP_TABLE_SIZE, CAP_KIND_NET_SOCKET, CAP_RIGHTS_READ) != 0);
    no_session(&descendant); no_identity(&descendant);

    /* Identity is explicitly bound only with retained, usable SETUID.
     * A masked-out or ceiling-excluded SETUID cannot carry identity along. */
    memset(mask, 0, sizeof(mask));
    grant(mask, CAP_KIND_SETUID, CAP_RIGHTS_WRITE);
    assert(spawn_authority(&parent, &child, "/bin/tool", mask) == 0);
    assert(child.auth_uid == 1000 && child.auth_gid == 1001);
    no_session(&child);
    child.uid = child.gid = 0; current = &child;
    assert(sys_setuid(1002) == SYS_ERR(EPERM));
    assert(sys_setuid(UINT32_MAX) == SYS_ERR(EPERM));
    assert(sys_setgid(UINT32_MAX) == SYS_ERR(EPERM));
    assert(sys_setuid(1000) == 0 && sys_setgid(1001) == 0);
    parent.cap_ceiling_active = 1;
    parent.cap_ceiling[CAP_KIND_SETUID] = 0;
    assert(spawn_authority(&parent, &child, "/bin/tool", mask) == 0);
    no_identity(&child);
    assert(child.cap_ceiling_active && !child.cap_ceiling[CAP_KIND_SETUID]);
    parent_init(&parent);
    mask[0].rights = CAP_RIGHTS_READ; /* policy has WRITE only */
    assert(spawn_authority(&parent, &child, "/bin/tool", mask) == 0);
    no_identity(&child);

    /* Empty explicit mask intentionally creates an empty active ceiling;
     * ordinary fork's empty initial table does NOT do this. */
    memset(mask, 0, sizeof(mask));
    assert(spawn_authority(&parent, &child, "/bin/tool", mask) == 0);
    assert(child.cap_ceiling_active); empty_caps(&child); reexec(&child); empty_caps(&child);

    /* Delegation is checked, fail-closed on invalid/duplicate rights, short
     * reads and absent CAP_DELEGATE. A coherent snapshot survives copy I/O. */
    grant(mask, CAP_KIND_SETUID, CAP_RIGHTS_WRITE);
    mutate_parent = &parent;
    assert(spawn_authority(&parent, &child, "/bin/tool", mask) == 0);
    assert(child.auth_uid == 1000 && child.auth_gid == 1001);
    assert(spawn_authority(&parent, &child, "/bin/tool", mask) == SYS_ERR(ENOCAP));
    parent_init(&parent);
    short_copy = 1;
    assert(spawn_authority(&parent, &child, "/bin/tool", mask) == SYS_ERR(EFAULT));
    short_copy = 0; bad_pointer = 1;
    assert(spawn_authority(&parent, &child, "/bin/tool", mask) == SYS_ERR(EFAULT));
    bad_pointer = 0;
    mask[1] = mask[0];
    assert(spawn_authority(&parent, &child, "/bin/tool", mask) == SYS_ERR(EINVAL));
    mask[1] = (cap_slot_t){CAP_KIND_MAX + 1, CAP_RIGHTS_READ};
    assert(spawn_authority(&parent, &child, "/bin/tool", mask) == SYS_ERR(EINVAL));
    mask[1] = (cap_slot_t){CAP_KIND_POWER, CAP_RIGHTS_WRITE};
    assert(spawn_authority(&parent, &child, "/bin/tool", mask) == SYS_ERR(ENOCAP));

    /* Firstboot issuance must come from independently qualified policy, not
     * the parent's firstboot/session booleans. */
    first_boot = 0;
    init_child_authority(&child, &parent, 0);
    cap_apply_policy(child.caps, "/bin/configure", child.authenticated, child.admin_session);
    assert(cap_check(child.caps, CAP_TABLE_SIZE, CAP_KIND_AUTH, CAP_RIGHTS_READ) != 0);
    first_boot = 1;
    cap_apply_policy(child.caps, "/bin/configure", child.authenticated, child.admin_session);
    assert(cap_check(child.caps, CAP_TABLE_SIZE, CAP_KIND_AUTH, CAP_RIGHTS_READ) == 0);
    no_session(&child); no_identity(&child);

    /* The binding issuer must not accept the absence sentinel or truncate a
     * wider argument into an unintended identity. Validate before any write;
     * a valid binding still requires AUTH and permits only the bound IDs. */
    memset(&child, 0, sizeof(child)); current = &child;
    child.auth_uid = child.auth_gid = AUTH_ID_NONE;
    grant(child.caps, CAP_KIND_AUTH, CAP_RIGHTS_READ);
    aegis_process_t before_auth = child;
    const uint64_t invalid_ids[][2] = {
        {UINT32_MAX, 1001}, {1000, UINT32_MAX},
        {(uint64_t)UINT32_MAX + 1, 1001},
        {1000, (uint64_t)UINT32_MAX + 1}, {UINT64_MAX, UINT64_MAX}
    };
    for (unsigned i = 0; i < sizeof(invalid_ids)/sizeof(invalid_ids[0]); i++) {
        assert(sys_auth_session(invalid_ids[i][0], invalid_ids[i][1]) == SYS_ERR(EINVAL));
        assert(!memcmp(&child, &before_auth, sizeof(child)) && !sched_lock);
    }
    memset(child.caps, 0, sizeof(child.caps));
    assert(sys_auth_session(1000, 1001) == SYS_ERR(ENOCAP));
    assert(!child.authenticated); no_identity(&child);
    grant(child.caps, CAP_KIND_AUTH, CAP_RIGHTS_READ);
    assert(sys_auth_session(1000, 1001) == 0);
    assert(child.authenticated && child.auth_uid == 1000 && child.auth_gid == 1001);
    grant(child.caps, CAP_KIND_SETUID, CAP_RIGHTS_WRITE);
    assert(sys_setuid(UINT32_MAX) == SYS_ERR(EPERM));
    assert(sys_setgid(UINT32_MAX) == SYS_ERR(EPERM));
    assert(sys_setuid(1000) == 0 && sys_setgid(1001) == 0);
    puts("process authority: production child/spawn/policy/ceiling regressions passed");
}
'''

with tempfile.TemporaryDirectory(prefix="aegis-authority-test-") as tmp:
    path = Path(tmp) / "check.c"
    path.write_text(code)
    binary = Path(tmp) / "check"
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-I", str(root),
                    str(path), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True, timeout=10)

clone = function("kernel/syscall/sys_process.c", "sys_clone")
fork = function("kernel/syscall/sys_process.c", "sys_fork")
vfork = function("kernel/syscall/sys_process.c", "sys_vfork")
assert "init_child_authority(child, parent, (cl & CLONE_THREAD) != 0);" in clone
assert "init_child_authority(child, parent, 0);" in fork
assert "CLONE_VM | CLONE_VFORK" in vfork
assert "return sys_fork(frame, flags, child_stack, ptid);" in clone


def check_exec_issuance(body):
    """Recognize the isolated direct form or integrated guarded transaction.

    Unknown derivation/publication forms must fail rather than silently
    skipping the check when independent authority/secure-start changes merge.
    """
    if "cap_slot_t newcaps[CAP_TABLE_SIZE];" in body:
        derive = body.index("cap_apply_policy(newcaps, path, proc->authenticated, new_admin);")
        ceiling = re.search(
            r"if \(proc->cap_ceiling_active\)\s+"
            r"cap_apply_ceiling\(newcaps, proc->cap_ceiling\);", body
        )
        assert ceiling, "exec transaction must attenuate its derived table"
        guard = body.index(
            "if (!proc->authority_busy || proc->authority_epoch != authority_epoch)"
        )
        lock = body.rindex("spin_lock_irqsave(&sched_lock)", 0, guard)
        commit = body.index("__builtin_memcpy(proc->caps, newcaps, sizeof(newcaps));")
        clear = body.index("proc->authority_busy = 0;", commit)
        advance = body.index("proc->authority_epoch++;", clear)
        finish = body.index("authority_pending = 0;", advance)
        unlock = body.index("spin_unlock_irqrestore(&sched_lock, fl)", finish)
        assert derive < ceiling.start() < lock < guard < commit < clear < advance < finish < unlock
        # The failed generation/busy guard exits, not falls through to commit.
        rejection = body[guard:commit]
        assert "spin_unlock_irqrestore(&sched_lock, fl)" in rejection
        assert "sched_exit();" in rejection and "__builtin_unreachable();" in rejection
        assert "proc->admin_session = (uint32_t)new_admin;" in rejection
        assert "proc->admin_session_firstboot = (uint32_t)new_firstboot;" in rejection
        secure = body.index("int secure_exec = exec_requires_secure_start(", unlock)
        assert secure > unlock
        return "guarded transaction"

    derive = body.index(
        "cap_apply_policy(proc->caps, path, proc->authenticated, proc->admin_session);"
    )
    ceiling = re.search(
        r"if \(proc->cap_ceiling_active\)\s+"
        r"cap_apply_ceiling\(proc->caps, proc->cap_ceiling\);", body
    )
    assert ceiling, "direct exec issuance must retain its attenuation ceiling"
    secure = body.index("int secure_exec = exec_gains_caps(prior_caps, proc->caps)")
    assert derive < ceiling.start() < secure
    assert "newcaps" not in body
    return "isolated direct form"


exec_form = check_exec_issuance(function("kernel/syscall/sys_exec.c", "sys_execve"))
print(f"process authority: fork/clone/vfork routes and exec issuance wiring passed ({exec_form})")
