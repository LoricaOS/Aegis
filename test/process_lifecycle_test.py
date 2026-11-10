#!/usr/bin/env python3
"""Run production wait/reparent/wakeup C with a deterministic mocked scheduler.

No boot image or userland is needed. The harness executes the real functions,
including scan -> locked block -> retry and competing parent-thread reaps.
Creation-path assertions cover the ownership/publication sites that need real
address spaces and an architecture return frame to execute.
"""
from pathlib import Path
import re
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]


def function(path, name):
    source = (root / path).read_text()
    match = re.search(
        r"\n(?:static\s+)?(?:int|void|uint64_t)\s+" + name + r"\s*\(", source
    )
    assert match, name
    start = source.index("{", match.start())
    depth, end = 1, start + 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[match.start():end]


process = "kernel/syscall/sys_process.c"
scheduler = "kernel/sched/sched.c"
source = r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "kernel/include/aegis_errno.h"
#include "kernel/signal/signal.h"
#define TASK_RUNNING 0
#define TASK_BLOCKED 1
#define TASK_ZOMBIE 2
#define TASK_STOPPED 3
#define WNOHANG 1
#define WUNTRACED 2
typedef int irqflags_t;
typedef struct aegis_task {
    struct aegis_task *next;
    struct aegis_task *next_run, *prev_run;
    int is_user, state, on_cpu, wake_pending;
    int sched_rq_cpu, sched_queued, is_idle;
    int16_t last_cpu;
    uint64_t sched_exec_start, sched_vruntime;
    uint32_t waiting_for;
    uint8_t *stack_base;
    uint64_t stack_pages;
} aegis_task_t;
typedef struct {
    aegis_task_t task;
    uint32_t pid, tgid, ppid, pgid, stop_signum, term_signal;
    uint64_t exit_status, pml4_phys;
    uint64_t pending_signals, signal_mask;
    k_sigaction_t sigactions[64];
    void *fd_table, *vfork_parent;
} aegis_process_t;
typedef void fd_table_t;
static aegis_process_t tasks[12];
static aegis_task_t *current;
static int sched_lock, blocked, wakes, freed_pcbs, freed_pml4;
static unsigned s_task_count;
static int bad_pointer;
static uint32_t s_fork_count;
static void (*block_action)(void);
static aegis_task_t *sched_current(void) { return current; }
static aegis_process_t *current_proc(void) { return (aegis_process_t *)current; }
static struct { unsigned cpu_id; } cpu;
#define percpu_self() (&cpu)
static void percpu_set_current(aegis_task_t *t) { current = t; }
static void run_list_insert_locked(aegis_task_t *t) { (void)t; assert(sched_lock); }
static irqflags_t spin_lock_irqsave(int *lock) {
    assert(!*lock); *lock = 1; return 0;
}
static void spin_unlock_irqrestore(int *lock, irqflags_t flags) {
    (void)flags; assert(*lock); *lock = 0;
}
static void sched_wake_locked(aegis_task_t *task) {
    assert(sched_lock); assert(task->state != TASK_ZOMBIE);
    task->state = TASK_RUNNING; wakes++;
}
static int user_ptr_valid(uint64_t ptr, unsigned size) {
    assert(size == 4); return ptr && !bad_pointer;
}
static int copy_to_user(void *to, const void *from, unsigned size) {
    assert(!sched_lock); memcpy(to, from, size); return 0;
}
static void sched_block_locked(irqflags_t flags) {
    assert(sched_lock && block_action && blocked++ < 3);
    current->state = TASK_BLOCKED;
    spin_unlock_irqrestore(&sched_lock, flags);
    block_action();
    assert(current->state == TASK_RUNNING);
}
static void arch_pause(void) { assert(0 && "fixture still on CPU"); }
static void fd_table_unref(void *table) { (void)table; assert(0); }
static void printk(const char *fmt, ...) { (void)fmt; assert(0); }
static void kva_free_pages(void *ptr, uint64_t pages) {
    assert(!sched_lock);
    if (pages == 2) {
        aegis_process_t *p = ptr;
        p->pid = 0xdead; freed_pcbs++;
    }
}
static void vma_free(aegis_process_t *p) { (void)p; assert(!sched_lock); }
static void vmm_free_user_pml4(uint64_t p) {
    (void)p; assert(!sched_lock); freed_pml4++;
}
'''
source += function("kernel/signal/signal.c", "signal_send_pid_locked")
source += function("kernel/signal/signal.c", "signal_check_pending")
source += function(scheduler, "sched_add")
source += function(scheduler, "sched_wake_child_waiters_locked")
source += function(scheduler, "notify_parent_locked")
source += function(scheduler, "reparent_children_locked")
source += function(scheduler, "notify_stopped_parent_locked")
source += function(process, "reap_group_zombies")
source += function(process, "sys_waitpid")
source += r'''
static aegis_process_t *add(unsigned i, uint32_t pid, uint32_t tgid,
                            uint32_t ppid, int state) {
    aegis_process_t *p = &tasks[i];
    p->pid = pid; p->tgid = tgid; p->ppid = ppid; p->pgid = 7;
    p->task.is_user = 1; p->task.on_cpu = -1; p->task.state = state;
    p->task.stack_pages = 4;
    p->task.next = current->next; current->next = &p->task;
    return p;
}
static void reset(void) {
    memset(tasks, 0, sizeof(tasks));
    current = &tasks[0].task; current->next = current;
    tasks[0].pid = tasks[0].tgid = 10; tasks[0].pgid = 7;
    current->is_user = 1; current->on_cpu = -1;
    sched_lock = blocked = wakes = freed_pcbs = freed_pml4 = 0;
    bad_pointer = 0; s_fork_count = 10; block_action = 0;
}
static uint64_t wait_for(int32_t pid, uint32_t *status, unsigned options) {
    return sys_waitpid((uint64_t)(int64_t)pid, (uintptr_t)status, options);
}
static void child_exits(void) {
    irqflags_t fl = spin_lock_irqsave(&sched_lock);
    tasks[1].task.state = TASK_ZOMBIE;
    sched_wake_child_waiters_locked(10);
    spin_unlock_irqrestore(&sched_lock, fl);
}
static void last_sibling_exits(void) {
    irqflags_t fl = spin_lock_irqsave(&sched_lock);
    tasks[2].task.state = TASK_ZOMBIE;
    sched_wake_child_waiters_locked(10);
    spin_unlock_irqrestore(&sched_lock, fl);
}
static void other_waiter_reaps(void) {
    aegis_task_t *saved = current;
    tasks[1].task.state = TASK_ZOMBIE;
    current = &tasks[2].task;
    assert(wait_for(20, 0, 0) == 20);
    current = saved;
}
static void child_handler(int sig) { (void)sig; }
int main(void) {
    uint32_t status = 0;
    reset();
    assert(wait_for(-1, 0, 0) == SYS_ERR(ECHILD));
    assert(wait_for(-1, 0, WNOHANG) == SYS_ERR(ECHILD));
    assert(wait_for(123, 0, 0) == SYS_ERR(ECHILD));
    assert(!blocked);

    /* Live/stopped children count even when no reportable event exists.
     * Unrelated children, own threads, and unrequested PIDs do not count. */
    add(1, 20, 20, 10, TASK_RUNNING);
    assert(wait_for(20, 0, WNOHANG) == 0);
    assert(wait_for(21, 0, 0) == SYS_ERR(ECHILD));
    tasks[1].ppid = 99;
    assert(wait_for(-1, 0, 0) == SYS_ERR(ECHILD));
    tasks[1].ppid = 10; tasks[1].tgid = 10;
    assert(wait_for(20, 0, 0) == SYS_ERR(ECHILD));
    assert(wait_for(-1, 0, WNOHANG) == SYS_ERR(ECHILD));
    tasks[1].tgid = 20;
    tasks[1].task.state = TASK_STOPPED; tasks[1].stop_signum = 19;
    assert(wait_for(20, 0, WNOHANG) == 0);
    assert(wait_for(20, &status, WUNTRACED) == 20);
    assert(status == ((19U << 8) | 0x7f));
    assert(wait_for(20, 0, WUNTRACED | WNOHANG) == 0); /* consumed once */

    /* Positive, zero and negative-pgid selectors share the existence rule. */
    tasks[1].task.state = TASK_RUNNING;
    assert(wait_for(0, 0, WNOHANG) == 0);
    assert(wait_for(-7, 0, WNOHANG) == 0);
    assert(wait_for(-8, 0, 0) == SYS_ERR(ECHILD));
    assert(wait_for(INT32_MIN, 0, 0) == SYS_ERR(ECHILD));
    tasks[1].pgid = 8;
    assert(wait_for(0, 0, 0) == SYS_ERR(ECHILD));
    assert(wait_for(-8, 0, WNOHANG) == 0);

    /* Cross-thread blocking wait works with a zombie parent leader too. */
    reset();
    tasks[0].pid = 11; /* running worker of process 10 */
    add(1, 20, 20, 10, TASK_RUNNING)->exit_status = 42;
    add(2, 10, 10, 1, TASK_ZOMBIE);
    block_action = child_exits;
    assert(wait_for(20, &status, 0) == 20);
    assert(status == 42U << 8 && blocked == 1 && wakes == 1);
    assert(freed_pcbs == 1 && freed_pml4 == 1 && !current->waiting_for);
    assert(wait_for(20, 0, 0) == SYS_ERR(ECHILD));

    /* A zombie leader with a live worker is still a matching child; wait
     * until the final sibling exits, then free its shared PML4 only once. */
    reset();
    add(1, 20, 20, 10, TASK_ZOMBIE)->term_signal = 9;
    add(2, 21, 20, 10, TASK_RUNNING);
    assert(wait_for(20, 0, WNOHANG) == 0);
    block_action = last_sibling_exits;
    assert(wait_for(20, &status, 0) == 20 && status == 9);
    assert(blocked == 1 && freed_pcbs == 2 && freed_pml4 == 1);

    /* Competing thread reaps the only child while this waiter is blocked:
     * production unlink must wake this thread so retry returns ECHILD. */
    reset();
    add(1, 20, 20, 10, TASK_ZOMBIE);
    add(2, 11, 10, 1, TASK_RUNNING);
    /* Force a block by leaving a live child for the initial scan. */
    tasks[1].task.state = TASK_RUNNING;
    block_action = other_waiter_reaps;
    assert(wait_for(20, 0, 0) == SYS_ERR(ECHILD));
    assert(current->state == TASK_RUNNING && wakes == 1 && blocked == 1);

    /* Bad status address leaves a zombie untouched. Borrowed vfork PML4
     * must not be freed when the child exits without exec. */
    reset();
    add(1, 20, 20, 10, TASK_ZOMBIE)->vfork_parent = current;
    bad_pointer = 1;
    assert(wait_for(20, &status, 0) == SYS_ERR(EFAULT));
    assert(!freed_pcbs);
    bad_pointer = 0;
    assert(wait_for(20, &status, 0) == 20);
    assert(freed_pcbs == 1 && !freed_pml4);

    /* Leader/creator exit must not orphan while a worker survives. Final
     * worker exit (including the fatal-signal common path) adopts children
     * and wakes all init waiters for already-zombie adoptees. */
    reset();
    tasks[0].task.state = TASK_ZOMBIE;
    add(1, 11, 10, 1, TASK_RUNNING);
    add(2, 20, 20, 10, TASK_ZOMBIE);
    add(3, 21, 20, 10, TASK_ZOMBIE);
    add(4, 1, 1, 0, TASK_BLOCKED);
    add(5, 2, 1, 0, TASK_BLOCKED);
    irqflags_t fl = spin_lock_irqsave(&sched_lock);
    assert(!reparent_children_locked(&tasks[0]));
    assert(tasks[2].ppid == 10 && !tasks[4].pending_signals && !wakes);
    current = &tasks[1].task;
    current->state = TASK_ZOMBIE;
    assert(reparent_children_locked(&tasks[1]));
    assert(tasks[2].ppid == 1 && tasks[3].ppid == 1);
    assert(tasks[4].pending_signals == (1ULL << SIGCHLD));
    assert(!tasks[5].pending_signals && wakes == 2);
    spin_unlock_irqrestore(&sched_lock, fl);

    /* An unpublished clone may have copied ppid before its process was
     * adopted. Refresh at publication so the new sibling agrees with it. */
    reset();
    tasks[0].ppid = 1;
    tasks[1].pid = 11; tasks[1].tgid = 10; tasks[1].ppid = 99;
    tasks[1].task.is_user = 1;
    sched_add(&tasks[1].task);
    assert(tasks[1].ppid == 1);

    /* Stop notifications wake nonleader parent waiters after state publish. */
    reset();
    current->state = TASK_BLOCKED;
    add(1, 11, 10, 1, TASK_BLOCKED);
    add(2, 20, 20, 10, TASK_STOPPED);
    fl = spin_lock_irqsave(&sched_lock);
    notify_stopped_parent_locked(&tasks[2].task);
    assert(wakes == 2 && tasks[0].pending_signals == (1ULL << SIGCHLD));
    spin_unlock_irqrestore(&sched_lock, fl);

    /* Real signal enqueue/deliverability, not a notification counter: both
     * stop and final-exit notifications must reach a surviving worker when
     * its leader is zombie or stopped. Neither leader may be resumed. */
    const int leader_states[] = { TASK_ZOMBIE, TASK_STOPPED };
    for (unsigned i = 0; i < 2; i++) {
        for (unsigned event = 0; event < 2; event++) {
            reset();
            tasks[0].task.state = leader_states[i];
            add(1, 11, 10, 1, TASK_RUNNING);
            add(2, 20, 20, 10, TASK_STOPPED);
            tasks[1].sigactions[SIGCHLD].sa_handler = child_handler;
            current = &tasks[2].task;
            fl = spin_lock_irqsave(&sched_lock);
            if (event == 0)
                notify_stopped_parent_locked(current);
            else
                notify_parent_locked(10); /* sched_exit's process event */
            spin_unlock_irqrestore(&sched_lock, fl);
            assert(tasks[0].task.state == leader_states[i]);
            assert(!tasks[0].pending_signals && !tasks[0].task.wake_pending);
            assert(tasks[1].pending_signals == (1ULL << SIGCHLD));
            assert(tasks[1].task.wake_pending && !wakes);
            current = &tasks[1].task;
            assert(signal_check_pending());
        }
    }

    /* A masked live leader must not capture an unmasked worker's signal. */
    reset();
    tasks[0].signal_mask = 1ULL << SIGCHLD;
    add(1, 11, 10, 1, TASK_BLOCKED);
    tasks[1].sigactions[SIGCHLD].sa_handler = child_handler;
    fl = spin_lock_irqsave(&sched_lock);
    notify_parent_locked(10);
    spin_unlock_irqrestore(&sched_lock, fl);
    assert(!tasks[0].pending_signals);
    assert(tasks[0].signal_mask == (1ULL << SIGCHLD));
    assert(tasks[1].pending_signals == (1ULL << SIGCHLD));
    assert(tasks[1].task.state == TASK_RUNNING && wakes == 1);
    current = &tasks[1].task;
    assert(signal_check_pending());

    /* If everyone masks it, retain one pending signal without unmasking.
     * Existing SIG_DFL/SIG_IGN behavior must still suppress interruption. */
    reset();
    tasks[0].signal_mask = 1ULL << SIGCHLD;
    tasks[0].sigactions[SIGCHLD].sa_handler = child_handler;
    add(1, 11, 10, 1, TASK_RUNNING)->signal_mask = 1ULL << SIGCHLD;
    fl = spin_lock_irqsave(&sched_lock);
    notify_parent_locked(10);
    spin_unlock_irqrestore(&sched_lock, fl);
    assert(tasks[0].pending_signals == (1ULL << SIGCHLD));
    assert(!tasks[1].pending_signals && !signal_check_pending());
    tasks[0].signal_mask = 0;
    assert(signal_check_pending());
    tasks[0].sigactions[SIGCHLD].sa_handler = SIG_DFL;
    assert(!signal_check_pending());
    tasks[0].sigactions[SIGCHLD].sa_handler = SIG_IGN;
    assert(!signal_check_pending());

    /* All-stopped process: keep SIGCHLD pending until continued, never wake
     * it. All-zombie process: no recipient and no queued signal at all. */
    reset();
    tasks[0].task.state = TASK_STOPPED;
    add(1, 11, 10, 1, TASK_STOPPED);
    fl = spin_lock_irqsave(&sched_lock);
    notify_parent_locked(10);
    spin_unlock_irqrestore(&sched_lock, fl);
    assert(tasks[0].pending_signals == (1ULL << SIGCHLD) && !wakes);
    assert(tasks[0].task.state == TASK_STOPPED);
    assert(tasks[1].task.state == TASK_STOPPED && !tasks[1].pending_signals);
    tasks[0].pending_signals = 0;
    tasks[0].task.state = tasks[1].task.state = TASK_ZOMBIE;
    fl = spin_lock_irqsave(&sched_lock);
    notify_parent_locked(10);
    spin_unlock_irqrestore(&sched_lock, fl);
    assert(!tasks[0].pending_signals && !tasks[1].pending_signals && !wakes);
    puts("process lifecycle: production wait/reparent/wakeup and SIGCHLD regressions passed");
}
'''

with tempfile.TemporaryDirectory(prefix="aegis-process-test-") as tmp:
    path = Path(tmp) / "check.c"
    binary = Path(tmp) / "check"
    path.write_text(source)
    subprocess.run(
        ["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-I", str(root),
         str(path), "-o", str(binary)], check=True,
    )
    subprocess.run([str(binary)], check=True, timeout=10)

clone = function(process, "sys_clone")
fork = function(process, "sys_fork")
spawn = function("kernel/syscall/sys_exec.c", "sys_spawn")
assert "child->ppid      = (cl & CLONE_THREAD) ? parent->ppid : parent->tgid;" in clone
assert "child->ppid            = parent->tgid;" in fork
assert "child->ppid            = parent->tgid;" in spawn
for create in (clone, fork, spawn):
    assert create.index("uint32_t child_pid = child->pid;") < create.index("sched_add(")
    assert "return (uint64_t)child_pid;" in create
assert "proc_find_by_pid_locked(child_pid)" in clone
assert "init_child_authority(child, parent, (cl & CLONE_THREAD) != 0);" in clone
assert "init_child_authority(child, parent, 0);" in fork
authority = function(process, "init_child_authority")
assert authority.index("spin_lock_irqsave(&sched_lock)") < authority.index("child->cap_ceiling")
assert authority.index("spin_unlock_irqrestore(&sched_lock, fl)") > authority.index("child->auth_gid")
for exit_name in ("sys_exit", "sys_exit_group"):
    assert "child->ppid =" not in function(process, exit_name)
exit_body = function(scheduler, "sched_exit")
assert exit_body.index("s_cur->state = TASK_ZOMBIE") < exit_body.index("reparent_children_locked(dying)")
assert "notify_parent_locked(dying->ppid);" in exit_body
assert "signal_send_pid_locked(" not in exit_body
stop_body = function(scheduler, "sched_stop")
assert stop_body.index("old->state = TASK_STOPPED") < stop_body.index("notify_stopped_parent_locked(old)")
assert "signal_send_pid(proc->ppid, SIGCHLD)" not in (root / "kernel/signal/signal.c").read_text()
print("process lifecycle: creation ownership/publication and common-exit checks passed")
