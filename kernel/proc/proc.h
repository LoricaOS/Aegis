#ifndef AEGIS_PROC_H
#define AEGIS_PROC_H

#include "sched.h"
#include "vfs.h"
#include "fd_table.h"
#include "cap.h"
#include "signal.h"
#include "vma.h"
#include "spinlock.h"
#include <stdint.h>
#include <stddef.h>

#define MMAP_FREE_MAX 64

/* Sentinel for an unbound authenticated identity (proc->auth_uid/auth_gid).
 * sys_setuid/sys_setgid only permit a transition to the bound value, so an
 * unbound process (never authenticated) cannot change its uid/gid at all. */
#define AUTH_ID_NONE ((uint32_t)0xFFFFFFFFU)

typedef struct {
    uint64_t base;
    uint64_t len;
} mmap_free_t;

/*
 * aegis_process_t — user process control block.
 *
 * task MUST be the first member: the scheduler stores all tasks as
 * aegis_task_t * pointers. When task.is_user == 1, the scheduler casts
 * the pointer to aegis_process_t * to reach pml4_phys. This cast is
 * safe only because task is at offset 0 (guaranteed by this layout).
 * Never use this cast when is_user == 0 — kernel tasks are not
 * aegis_process_t instances and the memory past the aegis_task_t fields
 * is unrelated.
 */
typedef struct aegis_process {
    aegis_task_t  task;                    /* MUST be first — scheduler casts to aegis_task_t * */
    uint64_t      pml4_phys;              /* physical address of this process's PML4 */
    fd_table_t   *fd_table;               /* shared, refcounted fd table (Phase 29) */
    cap_slot_t    caps[CAP_TABLE_SIZE];   /* Phase 11 — capability table */
    uint32_t      authenticated;          /* 1 if session passed login auth; survives exec */
    uint32_t      admin_session;          /* sudo-style admin session: even root must authenticate
                                           * THIS shell session (a SEPARATE credential, distinct from
                                           * login `authenticated`) before it can wield admin caps
                                           * (INSTALL → herald). Granted by sys_admin_session, which
                                           * only /bin/login -elevate may request (CAP_KIND_ADMIN_AUTH)
                                           * after verifying the credential — it targets its parent
                                           * shell. Inherited by fork/clone, survives exec. */
    uint32_t      auth_uid;               /* uid bound at sys_auth_session; AUTH_ID_NONE = unbound */
    uint32_t      auth_gid;               /* gid bound at sys_auth_session; AUTH_ID_NONE = unbound */
    uint64_t      brk;                    /* current heap limit (user VA); grows up */
    uint64_t      brk_base;               /* initial brk (ELF end); shrink floor */
    uint64_t      mmap_base;              /* next anonymous mmap VA; bump allocator */
    mmap_free_t   mmap_free[MMAP_FREE_MAX]; /* VA freelist for munmap→mmap reuse */
    uint32_t      mmap_free_count;          /* number of entries in mmap_free[]  */
    spinlock_t    mmap_free_lock;           /* M2: guards mmap_free[] for CLONE_VM threads on SMP */
    vma_entry_t  *vma_table;              /* kva-allocated VMA table; NULL until vma_init */
    uint32_t      vma_capacity;           /* max entries (constant; count lives in the shared table header) */
    /* The CLONE_VM sharer count lives in the tail of the vma_table page itself
     * (see kernel/mm/vma.c vma_rc()), not here — a per-process field could not
     * be a correct shared counter. */
    /* vfork donor: when this process was created via clone(CLONE_VM|CLONE_VFORK)
     * it BORROWS the parent's pml4 + vma_table (no copy) and the parent is
     * suspended. Set to the parent task; execve/_exit allocates a fresh address
     * space, drops the borrowed vma ref, and wakes this task. NULL = not a live
     * vfork child. Must be NULL on every other creation path (fork/spawn/thread)
     * or execve would wrongly skip freeing its own pages. */
    struct aegis_task_t *vfork_parent;
    char          exe_path[256];          /* binary path, set at execve */
    uint32_t      pid;          /* unique process ID; 1 = init */
    uint32_t      tgid;         /* thread group ID (= leader's PID) */
    uint32_t      thread_count; /* live threads in this group (leader tracks) */
    uint32_t      ppid;         /* parent PID; 0 = no parent   */
    uint32_t      uid;          /* user ID; 0 = root */
    uint32_t      gid;          /* group ID; 0 = root */
    uint32_t      pgid;         /* process group ID; init = own pid      */
    uint32_t      sid;          /* session ID; == pid for session leaders */
    uint32_t      umask;        /* file creation mask; init = 022        */
    uint32_t      stop_signum;  /* signal that caused TASK_STOPPED; 0 = not stopped */
    uint32_t      term_signal;  /* signal that terminated the process; 0 = normal exit */
    char          cwd[256];     /* current working directory; init = "/" */
    /* Optional VFS confinement (sys_vfs_confine): when vfs_scope_len != 0, this
     * process may only touch paths within vfs_scope[] (a canonical absolute
     * subtree). Voluntary + one-way (tightening only), inherited across fork and
     * sticky across exec, so a confined process and its descendants cannot
     * escape. Purely ADDITIVE — it only ever removes authority, never grants —
     * so it cannot weaken the model. 0 = unconfined (default). */
    char          vfs_scope[128];
    uint32_t      vfs_scope_len; /* strlen(vfs_scope); 0 = unconfined */
    uint64_t      exit_status;  /* lower 8 bits = exit code; written before zombie */
    /* Alternate signal stack (sigaltstack). altstack_size == 0 means none is
     * installed; a SA_ONSTACK handler is then delivered on the normal stack.
     * Reset on execve; per-process (shared by a thread group). */
    uint64_t      altstack_sp;       /* ss_sp (base of the alt stack) */
    uint64_t      altstack_size;     /* ss_size; 0 = disabled */
    /* Phase 17 — signal subsystem */
    uint64_t      pending_signals;   /* bitmask; bit N = signal N pending */
    uint64_t      signal_mask;       /* blocked signals; 0 = nothing blocked */
    k_sigaction_t sigactions[64];    /* per-signal handler/mask/flags */
} aegis_process_t;

/* The current process. aegis_process_t embeds aegis_task_t as its first member,
 * so the running task pointer IS the process pointer (cast-safe). Replaces the
 * (aegis_process_t *)sched_current() cast open-coded at ~90 syscall sites. */
static inline aegis_process_t *
current_proc(void)
{
    return (aegis_process_t *)sched_current();
}

/* Allocate and return the next unique process ID (monotonically increasing). */
uint32_t proc_alloc_pid(void);

/* Load elf_data into a new user process and add it to the scheduler run queue.
 * Called from kernel_main before sched_start. */
void proc_spawn(const uint8_t *elf_data, size_t elf_len);

/* Convenience wrapper: spawn the embedded init binary (init_elf / init_elf_len).
 * These symbols are generated by xxd in user/init/init_bin.c. */
void proc_spawn_init(void);

/* Find a user process by PID. Walks the scheduler circular task list.
 * Returns NULL if no matching process found. */
aegis_process_t *proc_find_by_pid(uint32_t pid);


/* Demand-paging: populate a lazy user page (anon mmap). 0=present, -1=fault.
 * Defined in kernel/syscall/sys_memory.c. */
int mm_populate_fault(struct aegis_process *proc, uint64_t va);

/* Copy-on-write fork: DEFAULT-ON; the kernel cmdline `nocow` forces eager
 * full-page copy. The graphical + installed-NVMe corruption that previously
 * kept COW off was root-caused + fixed (2026-06-28): it was NOT a COW refcount
 * bug — sys_fb_map published the virtio-gpu framebuffer (WB-cached system RAM
 * owned by the GPU driver) into every GUI process with plain owned PTEs, so COW
 * fork copied it and process teardown freed it, recycling the live framebuffer
 * into a kernel stack (the random #GP / reserved-bit faults). Fixed by marking
 * such mappings VMM_FLAG_SHARED and exempting them from COW + teardown (vmm.h).
 * Full analysis: research/cow-mm/03-cow-graphical-nvme-corruption.md deep-dive 7.
 * Defined in sys_process.c. */
extern int g_cow_fork;

/* Perf instrumentation: when set (kernel cmdline `perfbench_mm`), sys_fork
 * prints a [PERFMM] line with the address-space-duplication cycle cost and
 * page count. Default 0 (oracle-safe). Defined in sys_process.c. */
extern int g_perfbench_mm;

/* Demand-paged file-backed mmap: DEFAULT 1 — a MAP_PRIVATE mmap of an ext2
 * file records the backing inode+offset in the VMA and leaves pages
 * not-present; mm_populate_fault reads each file page on first touch instead of
 * eager-copying the whole file at mmap time. `nolazyfile` forces the legacy
 * eager path (A/B / safety escape). Defined in sys_memory.c. */
extern int g_lazyfile;

#endif /* AEGIS_PROC_H */