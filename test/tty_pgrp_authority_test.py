#!/usr/bin/env python3
"""Run production TIOCSPGRP, fd dispatch, cap and uaccess checks on the host.

Run: python3 test/tty_pgrp_authority_test.py
Requires a host C compiler. Scheduler, fd pins, VMA snapshots and fault-contained
copies are harness services, not a boot/SMP test. The tty/session/group checks,
console/input-fd gate, capability checks and sys_ioctl dispatch are production
bodies. PROT_NONE uses a real protected host mapping plus a VMA snapshot; copy
faults after validation are injected as nonzero residuals.
HOST_SANITIZERS selects compiler sanitizers (default: address,undefined; empty
disables them for hosts without a working sanitizer runtime).
"""
from pathlib import Path
import os
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def function(path, name):
    source = (ROOT / path).read_text()
    match = re.search(
        rf"(?m)^(?:static )?[\w *]+\s*{name}\([^;]*?\)\n\{{", source)
    assert match, name
    return source[match.start():source.index("\n}", match.end()) + 2] + "\n"


# tty_ioctl includes a window-size notification branch even though these tests
# target process groups. Use the kernel ABI constant rather than a host header.
C = re.search(r"(?m)^#define SIGWINCH\s+\d+",
              (ROOT / "kernel/signal/signal.h").read_text()).group(0) + "\n" + r"""
#define _DEFAULT_SOURCE
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include "cap.h"
#include "tty.h"
#include "vmm.h"
#define USER_ADDR_MAX 0x7fffffffffffULL
#define PROC_MAX_FDS 8
#define VFS_O_RDONLY 0
#define VFS_O_WRONLY 1
#define VFS_O_RDWR 2
#define VFS_O_ACCMODE 3
#define VFS_O_NONBLOCK 04000
typedef unsigned spinlock_t;
typedef unsigned irqflags_t;
static spinlock_t sched_lock, tty_global_lock;
static unsigned held, membership_walks, copies;
static tty_t *reclaim_on_lock;
static irqflags_t spin_lock_irqsave(spinlock_t *lock) {
    assert(!*lock);
    /* In particular, sched_lock must never nest inside the tty lock. */
    if (lock == &sched_lock) {
        assert(!tty_global_lock);
        membership_walks++;
    }
    if (lock == &tty_global_lock && reclaim_on_lock) {
        reclaim_on_lock->session_id = 99;
        reclaim_on_lock = NULL;
    }
    *lock = 1; held++; return 0;
}
static void spin_unlock_irqrestore(spinlock_t *lock, irqflags_t flags) {
    (void)flags; assert(*lock && held); *lock = 0; held--;
}
typedef struct aegis_task {
    int is_user;
    uint32_t state;
    struct aegis_task *next;
} aegis_task_t;
typedef struct { int unused; } vfs_ops_t;
typedef struct {
    const vfs_ops_t *ops;
    void *priv;
    unsigned flags;
} vfs_file_t;
typedef struct { spinlock_t lock; vfs_file_t fds[PROC_MAX_FDS]; } fd_table_t;
typedef struct {
    aegis_task_t task;
    uint32_t pid, sid, pgid, uid, authenticated, admin_session;
    uint64_t pml4_phys;
    cap_slot_t caps[CAP_TABLE_SIZE];
    fd_table_t *fd_table;
} aegis_process_t;
static aegis_process_t caller, job, stranger;
static aegis_task_t kernel_task, *running;
static aegis_task_t *sched_current(void) { return running; }
static aegis_process_t *current_proc(void) { return (aegis_process_t *)running; }
static fd_table_t table;
static tty_t console, other;
static tty_t *s_console_tty = &console;
static const vfs_ops_t s_kbd_ops = {1}, slave_ops = {2}, master_ops = {3}, plain_ops = {4};
typedef struct { tty_t tty; int index, locked; } pty_pair_t;
static pty_pair_t pair;
tty_t *tty_console(void) { return s_console_tty; }
static tty_t *pty_find_by_session(uint32_t sid) {
    return pair.tty.session_id == sid ? &pair.tty : NULL;
}
static int pty_is_slave(const vfs_file_t *f) { return f->ops == &slave_ops; }
static int pty_is_master(const vfs_file_t *f) { return f->ops == &master_ops; }
static tty_t *pty_get_tty(const vfs_file_t *f) { return &((pty_pair_t *)f->priv)->tty; }
typedef struct { vfs_file_t file; int active; } fd_table_pin_t;
static unsigned pins;
static int fd_table_pin(fd_table_t *t, int fd, fd_table_pin_t *pin) {
    assert(!held);
    if (fd < 0 || fd >= PROC_MAX_FDS || !t->fds[fd].ops) return 0;
    pin->file = t->fds[fd]; pin->active = 1; pins++; return 1;
}
static void fd_table_unpin(fd_table_pin_t *pin) {
    if (pin->active) { assert(!held && pins); pins--; pin->active = 0; }
}
/* Unrelated sys_ioctl branches must not be entered by these tests. */
static int fd_table_update_flags(fd_table_t *t, int fd, fd_table_pin_t *p,
                                 unsigned clear, unsigned set) {
    (void)t; (void)fd; (void)p; (void)clear; (void)set; abort();
}
typedef struct { unsigned count; } pipe_t;
static const vfs_ops_t g_pipe_read_ops = {5};
typedef struct { int nonblocking; } sock_t;
typedef sock_t unix_sock_t;
#define SOCK_NONE UINT32_MAX
#define UNIX_NONE UINT32_MAX
static uint32_t sock_id_from_file(vfs_file_t *f) { (void)f; abort(); }
static uint32_t unix_sock_id_from_file(vfs_file_t *f) { (void)f; abort(); }
static sock_t *sock_get(uint32_t id) { (void)id; abort(); }
static unix_sock_t *unix_sock_get(uint32_t id) { (void)id; abort(); }
static void signal_send_pgrp(uint32_t pgid, int sig) { (void)pgid; (void)sig; abort(); }
static void signal_send_pid(uint32_t pid, int sig) { (void)pid; (void)sig; abort(); }
static void kbd_set_tty_pgrp(uint32_t pgid) { (void)pgid; abort(); }
typedef struct { uint64_t base, len; uint32_t prot; } vma_entry_t;
static vma_entry_t region;
static unsigned pte_lookups;
static int vma_find_copy(aegis_process_t *p, uint64_t va, vma_entry_t *out) {
    (void)p; assert(!held);
    if (va >= region.base && va - region.base < region.len) {
        *out = region; return 1;
    }
    return 0;
}
uint64_t vmm_pte_of_user_raw(uint64_t pml4, uint64_t va) {
    (void)pml4; (void)va; assert(!held); pte_lookups++;
    /* Deliberately stale accessible PTE: a PROT_NONE VMA must take precedence. */
    return VMM_FLAG_PRESENT | VMM_FLAG_USER | VMM_FLAG_WRITABLE;
}
static unsigned residual;
static uint64_t copy_from_user(void *to, const void *from, uint64_t n) {
    assert(!held && residual <= n); copies++;
    memcpy(to, from, n - residual);
    return residual;
}
static uint64_t copy_to_user(void *to, const void *from, uint64_t n) {
    assert(!held); memcpy(to, from, n); return 0;
}
#define COPY_FROM_USER(to, from) do { \
    if (copy_from_user((to), (const void *)(uintptr_t)(from), sizeof(*(to)))) \
        return SYS_ERR(EFAULT); \
} while (0)
#define COPY_TO_USER(to, from) do { \
    if (copy_to_user((void *)(uintptr_t)(to), (from), sizeof(*(from)))) \
        return SYS_ERR(EFAULT); \
} while (0)
"""
for state in ("TASK_RUNNING", "TASK_ZOMBIE", "TASK_STOPPED"):
    C += re.search(rf"(?m)^#define {state}\s+[^\n]+",
                   (ROOT / "kernel/sched/sched.h").read_text()).group(0) + "\n"
C += function("kernel/syscall/uaccess_check.c", "uaccess_range_accessible")
C += function("kernel/syscall/uaccess_check.c", "uaccess_range_mapped")
C += re.sub(r"(?m)^#include[^\n]*\n", "",
            (ROOT / "kernel/syscall/syscall_util.h").read_text())
for path, names in (
    ("kernel/cap/cap.c", ("cap_grant", "cap_check")),
    ("kernel/fs/kbd_vfs.c", ("kbd_vfs_is_tty", "kbd_vfs_has_input_fd")),
    ("kernel/tty/tty.c", ("tty_pgrp_in_session", "tty_find_controlling",
                        "tty_claim", "tty_console_allowed", "tty_ioctl")),
    ("kernel/syscall/sys_file.c", ("sys_ioctl",)),
    ("kernel/syscall/sys_signal.c", ("sys_setfg", "sys_kill")),
):
    for name in names:
        C += function(path, name)
C += r"""
static void reset(void) {
    assert(!held && !pins);
    memset(&caller, 0, sizeof(caller));
    memset(&job, 0, sizeof(job));
    memset(&stranger, 0, sizeof(stranger));
    memset(&table, 0, sizeof(table));
    memset(&console, 0, sizeof(console));
    memset(&pair, 0, sizeof(pair));
    other = (tty_t){.session_id=99, .fg_pgrp=99};
    caller.task = (aegis_task_t){1, TASK_RUNNING, &job.task};
    job.task = (aegis_task_t){1, TASK_RUNNING, &stranger.task};
    stranger.task = (aegis_task_t){1, TASK_RUNNING, &kernel_task};
    kernel_task = (aegis_task_t){0, TASK_RUNNING, &caller.task};
    caller.pid=caller.sid=caller.pgid=11;
    caller.fd_table=&table;
    job.pid=22; job.sid=11; job.pgid=22;
    stranger.pid=33; stranger.sid=99; stranger.pgid=33;
    running=&caller.task;
    pair.tty.session_id=console.session_id=11;
    pair.tty.fg_pgrp=console.fg_pgrp=11;
    table.fds[0]=(vfs_file_t){&slave_ops, &pair, VFS_O_RDWR};
    table.fds[1]=(vfs_file_t){&s_kbd_ops, NULL, VFS_O_RDONLY};
    table.fds[2]=(vfs_file_t){&master_ops, &pair, VFS_O_RDWR};
    table.fds[3]=(vfs_file_t){&plain_ops, &other, VFS_O_RDWR};
    residual=copies=membership_walks=pte_lookups=0;
    region=(vma_entry_t){0};
    reclaim_on_lock=NULL;
}
static void ipc(unsigned rights) {
    memset(caller.caps, 0, sizeof(caller.caps));
    assert(cap_grant(caller.caps, CAP_TABLE_SIZE, CAP_KIND_IPC, rights)>=0);
}
static int set(int fd, uint32_t pgid) {
    int rc=(int64_t)sys_ioctl(fd, TIOCSPGRP, (uintptr_t)&pgid);
    assert(!held && !pins);
    return rc;
}
static void unchanged(void) {
    assert(pair.tty.fg_pgrp==11 && console.fg_pgrp==11 && other.fg_pgrp==99);
    assert(!held && !pins);
}
int main(void) {
    reset();
    /* Fresh service identity: neither authenticated/admin nor PROC_READ. */
    ipc(CAP_RIGHTS_READ);
    assert(!caller.authenticated && !caller.admin_session);
    assert(cap_check(caller.caps,CAP_TABLE_SIZE,CAP_KIND_PROC_READ,CAP_RIGHTS_READ)<0);
    assert(cap_check(caller.caps,CAP_TABLE_SIZE,CAP_KIND_PROC_READ,CAP_RIGHTS_WRITE)<0);
    assert(set(0,22)==0 && pair.tty.fg_pgrp==22);
    assert(console.fg_pgrp==11 && other.fg_pgrp==99);
    assert(set(0,11)==0 && pair.tty.fg_pgrp==11); /* restore shell */
    assert((int64_t)sys_setfg(33)==-EPERM);
    assert((int64_t)sys_kill(33,2)==-EPERM);
    assert((int64_t)sys_kill((uint64_t)-33,2)==-EPERM);
    unchanged();
    /* Kernel task alone is not a user group member. */
    job.task.is_user=0;
    assert(set(0,22)==-EPERM);
    job.task.is_user=1;
    assert(set(0,0)==-EPERM);       /* cannot clear foreground */
    assert(set(0,999)==-EPERM);     /* empty group */
    job.pid=23;
    assert(set(0,job.pid)==-EPERM); /* a live PID is not necessarily a pgid */
    assert(set(0,33)==-EPERM);      /* real group, other session */
    assert(set(0,UINT32_MAX)==-EPERM);
    pair.tty.session_id=99;
    assert(set(0,22)==-EPERM);      /* fd possession doesn't cross sessions */
    pair.tty.session_id=0;
    assert(set(0,22)==-EPERM);      /* unclaimed is not controlling */
    pair.tty.session_id=11;
    caller.sid=0;
    assert(set(0,22)==-EPERM);
    caller.sid=11;
    unchanged();
    assert(set(2,22)==-ENOTTY);    /* PTY master is not a tty control handle */
    assert(set(3,22)==-ENOTTY);    /* unrelated fd's priv cannot select a tty */
    assert(set(7,22)==-EBADF && set(-1,22)==-EBADF);
    /* Pointer-sized arg is data, never a tty/process selector. */
    assert((int64_t)sys_ioctl(0,TIOCSPGRP,UINT64_MAX)==-EFAULT);
    unchanged();
    puts("IPC-only own-session PTY handoff/restore and fd/group scope: ok");

    reset(); ipc(CAP_RIGHTS_READ);
    job.task.state=TASK_ZOMBIE;
    assert(set(0,22)==-EPERM); /* zombie-only group is not live */
    unchanged();
    job.task.state=TASK_STOPPED;
    assert(set(0,22)==0 && pair.tty.fg_pgrp==22); /* resumable job */
    assert(set(0,11)==0);
    job.task.state=TASK_ZOMBIE;
    stranger.sid=11; stranger.pgid=22;
    assert(set(0,22)==0 && pair.tty.fg_pgrp==22); /* zombie + running member */
    assert(set(0,11)==0);
    stranger.task.state=TASK_ZOMBIE;
    assert(set(0,22)==-EPERM); /* multiple zombies still do not qualify */
    unchanged();
    puts("Zombie-only groups denied; stopped and mixed live groups allowed: ok");

    reset();
    for (unsigned uid=0; uid<=1000; uid+=1000) {
        caller.uid=uid;
        memset(caller.caps,0,sizeof(caller.caps));
        assert(set(0,22)==-EPERM && set(1,22)==-EPERM);
        ipc(CAP_RIGHTS_WRITE); /* wrong IPC rights */
        assert(set(0,22)==-EPERM);
        memset(caller.caps,0,sizeof(caller.caps));
        assert(cap_grant(caller.caps,CAP_TABLE_SIZE,CAP_KIND_PROC_READ,
                         CAP_RIGHTS_READ|CAP_RIGHTS_WRITE)>=0);
        assert(cap_grant(caller.caps,CAP_TABLE_SIZE,CAP_KIND_FB,CAP_RIGHTS_WRITE)>=0);
        assert(set(0,22)==-EPERM && set(1,22)==-EPERM); /* IPC is required */
        unchanged();
    }
    ipc(CAP_RIGHTS_READ);
    running=NULL;
    uint32_t pgid=22;
    assert(tty_ioctl(&pair.tty,TIOCSPGRP,(uintptr_t)&pgid)==-EPERM);
    running=&kernel_task;
    assert(tty_ioctl(&pair.tty,TIOCSPGRP,(uintptr_t)&pgid)==-EPERM);
    running=&caller.task;
    unchanged();
    puts("No-cap, wrong-rights, uid0, broad-cap-only and non-user denials: ok");

    reset(); ipc(CAP_RIGHTS_READ);
    /* Console same-session gate needs neither FB nor PROC_READ nor input fd. */
    table.fds[1].flags=VFS_O_WRONLY;
    assert(!kbd_vfs_has_input_fd() && tty_console_allowed());
    assert(set(1,22)==0 && console.fg_pgrp==22 && pair.tty.fg_pgrp==11);
    assert(set(1,11)==0);
    console.session_id=99;
    assert(!tty_console_allowed() && set(1,22)==-ENOCAP);
    table.fds[1].flags=VFS_O_RDONLY; /* explicitly delegated console input */
    assert(tty_console_allowed() && set(1,22)==-EPERM);
    table.fds[1].flags=VFS_O_WRONLY;
    assert(cap_grant(caller.caps,CAP_TABLE_SIZE,CAP_KIND_FB,CAP_RIGHTS_WRITE)>=0);
    assert(tty_console_allowed() && set(1,22)==-EPERM);
    console.session_id=0;
    assert(set(1,22)==-EPERM);
    unchanged();
    puts("Console gate preserves same-session use without IPC-based global access: ok");

    reset(); ipc(CAP_RIGHTS_READ);
    for (residual=1; residual<=sizeof(pgid); residual++) {
        unsigned walks=membership_walks;
        assert(set(0,22)==-EFAULT && membership_walks==walks);
        unchanged(); /* no partially copied pgid may be used */
    }
    residual=0;
    unsigned before=copies;
    long pagesize=sysconf(_SC_PAGESIZE);
    assert(pagesize>=4096);
    void *none=mmap(NULL,(size_t)pagesize,PROT_READ|PROT_WRITE,
                    MAP_PRIVATE|MAP_ANON,-1,0);
    assert(none!=MAP_FAILED);
    *(uint32_t *)none=22;
    assert(mprotect(none,(size_t)pagesize,PROT_READ)==0);
    region=(vma_entry_t){(uintptr_t)none,(uint64_t)pagesize,1};
    assert((int64_t)sys_ioctl(0,TIOCSPGRP,(uintptr_t)none)==0);
    assert(pair.tty.fg_pgrp==22 && set(0,11)==0);
    before=copies;
    assert(mprotect(none,(size_t)pagesize,PROT_NONE)==0);
    region=(vma_entry_t){(uintptr_t)none,(uint64_t)pagesize,0};
    assert((int64_t)sys_ioctl(0,TIOCSPGRP,(uintptr_t)none)==-EFAULT);
    assert(copies==before);
    /* No stale-PTE fallback on this explicit PROT_NONE VMA. */
    unsigned lookups=pte_lookups;
    assert((int64_t)sys_ioctl(0,TIOCSPGRP,(uintptr_t)none)==-EFAULT);
    assert(pte_lookups==lookups && copies==before);
    assert(munmap(none,(size_t)pagesize)==0);
    region=(vma_entry_t){0};
    unchanged();
    /* Ownership changes during scheduler validation must fail at commit. */
    reclaim_on_lock=&pair.tty;
    assert(set(0,22)==-EPERM && pair.tty.session_id==99);
    unchanged();
    puts("Short/total copy faults, PROT_NONE and tty-session commit recheck: ok");
}
"""

with tempfile.TemporaryDirectory(prefix="aegis-tty-pgrp-") as tmp:
    source = Path(tmp) / "test.c"
    binary = Path(tmp) / "test"
    source.write_text(C)
    sanitizers = os.environ.get("HOST_SANITIZERS", "address,undefined")
    flags = [f"-fsanitize={sanitizers}"] if sanitizers else []
    subprocess.run(
        [os.environ.get("HOSTCC", "cc"), "-std=c11", "-O1", "-g",
         "-Wall", "-Wextra", "-Werror", "-Wno-unused-function", *flags,
         "-I" + str(ROOT / "kernel/cap"),
         "-I" + str(ROOT / "kernel/tty"), "-I" + str(ROOT / "kernel/mm"),
         str(source), "-o", str(binary)],
        check=True,
    )
    subprocess.run([str(binary)], check=True, timeout=15)
