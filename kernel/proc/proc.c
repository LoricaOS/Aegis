#include "proc.h"
#include "elf.h"
#include "vmm.h"
#include "pmm.h"
#include "kva.h"
#include "printk.h"
#include "arch.h"
#include "console.h"
#include "kbd_vfs.h"
#include "kbd.h"
#include "vma.h"
#include "spinlock.h"
#include "random.h"
#include "initrd.h"
#include "fb.h"
#include "vfs.h"
#include "../limits.h"
#include <stdint.h>
#include <stddef.h>

static uint32_t s_next_pid = 1;
static spinlock_t pid_lock = SPINLOCK_INIT;

/* sched_lock protects the circular task list — defined in sched.c */
extern spinlock_t sched_lock;

uint32_t
proc_alloc_pid(void)
{
    irqflags_t fl = spin_lock_irqsave(&pid_lock);
    uint32_t pid = s_next_pid++;
    spin_unlock_irqrestore(&pid_lock, fl);
    return pid;
}

_Static_assert(offsetof(aegis_process_t, task) == 0,
               "aegis_process_t: task must be at offset 0 for safe cast");

/* Every PCB allocation site (proc_spawn / sys_fork / sys_clone / sys_spawn)
 * uses kva_alloc_pages(2).  Guard the budget — the 512-byte FXSAVE area in
 * aegis_task_t made the PCB noticeably bigger. */
_Static_assert(sizeof(aegis_process_t) <= 2 * 4096,
               "aegis_process_t must fit in the 2 kva pages every PCB allocation uses");

/* Init is loaded from the root filesystem at boot — the kernel embeds NO
 * userland (Linux model). proc_spawn_init() reads /bin/vigil from the
 * already-mounted rootfs (ramdisk module → ext2, mounted in kernel_main
 * before this runs) and spawns it. See proc_spawn_init below. */
#define INIT_PATH "/bin/vigil"


/* 16KB kernel stack for the user process (4 pages, matching sched task stacks).
 * The PIT ISR fires while the process is in user mode and uses the kernel stack
 * (via TSS RSP0). TCP RX processing through virtio-net -> ip_rx -> tcp_rx needs
 * more than 4KB of stack depth; 4 pages avoids double-fault on deep call chains. */
/* Values single-sourced in limits.h (AEGIS_STACK_PAGES / AEGIS_STACK_SIZE);
 * same 16KB kernel stack used by sched.c task stacks. */
#define STACK_PAGES  AEGIS_STACK_PAGES
#define STACK_SIZE   AEGIS_STACK_SIZE

/*
 * User stack layout:
 *   top  = USER_STACK_TOP  (= 0x7FFFFFFF000, 16-byte aligned)
 *   base = [USER_STACK_BASE, USER_STACK_TOP) — USER_STACK_NPAGES pages
 * 0x7FFFFFFF000 ends in 0x000 — 4096-byte aligned → 16-byte aligned. ✓
 * Per AMD64 ABI, RSP on entry to _start must be 16-byte aligned.
 */
/* Canonical values single-sourced in limits.h (AEGIS_USER_STACK_*); these are
 * the init-path aliases. sys_impl.h has the matching exec/spawn aliases. */
#define USER_STACK_TOP     AEGIS_USER_STACK_TOP
#define USER_STACK_NPAGES  AEGIS_USER_STACK_PAGES
#define USER_STACK_BASE    AEGIS_USER_STACK_BASE

/* Arch-specific user-mode entry trampoline.
 * x86-64: bare iretq label in syscall_entry.asm.
 * ARM64: ERET trampoline in proc_enter.S.
 * Used as a return-address slot in the initial kernel stack frame. */
extern void proc_enter_user(void);

void
proc_spawn(const uint8_t *elf_data, size_t elf_len)
{
    /* Allocate process control block (2 kva pages — PCB exceeds 4KB with
     * CAP_TABLE_SIZE=64 caps + sigactions[64] + mmap_free[64]). */
    aegis_process_t *proc = kva_alloc_pages(2);
    if (!proc) return;
    __builtin_memset(proc, 0, sizeof(*proc));

    /* Allocate kernel stack (STACK_PAGES kva pages — per-process higher-half VA).
     * kva pages are mapped into pd_hi (shared with user PML4s), so this
     * stack VA is reachable regardless of which PML4 is loaded in CR3.
     * Each proc_spawn call gets a distinct kva-mapped VA.
     * 4 pages (16KB) matches the sched task stack size and is sufficient to
     * handle deep PIT ISR → virtio → tcp_rx call chains from user mode. */
    uint8_t *kstack = kva_alloc_pages(STACK_PAGES);

    /* Create per-process page tables (kernel high entries shared) */
    proc->pml4_phys = vmm_create_user_pml4();

    /* Load ELF into the user address space */
    elf_load_result_t er;
    elf_load_result_t interp_er;
    int has_interp = 0;
    __builtin_memset(&interp_er, 0, sizeof(interp_er));

    if (elf_load(proc, proc->pml4_phys, elf_data, elf_len, 0, &er) != 0) {
        printk("[PROC] FAIL: ELF parse error\n");
        panic_halt("[PROC] FAIL: ELF parse error");
    }

    /* If the ELF has a PT_INTERP (dynamically linked), load the interpreter
     * at INTERP_BASE. Without this, _start jumps through an unresolved PLT
     * stub to address 0x0 — the root cause of the q35-without-NVMe crash. */
    has_interp = (er.interp[0] != '\0');
    if (has_interp) {
        const uint8_t *interp_data;
        uint64_t interp_size;
        void    *interp_buf   = (void *)0;
        uint64_t interp_pages = 0;

        vfs_file_t interp_f;
        if (initrd_open(er.interp, &interp_f) == 0) {
            interp_data = (const uint8_t *)initrd_get_data(&interp_f);
            interp_size = (uint64_t)initrd_get_size(&interp_f);
        } else {
            vfs_file_t vf;
            int vr = vfs_open(er.interp, 0, 0, &vf);
            if (vr != 0) {
                printk("[PROC] FAIL: interpreter not found: %s\n", er.interp);
                panic_halt("[PROC] FAIL: interpreter not found: ...");
            }
            interp_pages = (vf.size + 4095ULL) / 4096ULL;
            interp_buf = kva_alloc_pages(interp_pages);
            if (!interp_buf) {
                printk("[PROC] FAIL: OOM loading interpreter\n");
                panic_halt("[PROC] FAIL: OOM loading interpreter");
            }
            int rr = vf.ops->read(vf.priv, interp_buf, 0, vf.size);
            /* Close immediately — ext2 fds come from a 32-slot pool freed
             * only via ops->close; this open would otherwise leak a slot. */
            if (vf.ops->close) vf.ops->close(vf.priv);
            if (rr < 0) {
                printk("[PROC] FAIL: error reading interpreter\n");
                panic_halt("[PROC] FAIL: error reading interpreter");
            }
            interp_data = (const uint8_t *)interp_buf;
            interp_size = vf.size;
        }

        if (elf_load(proc, proc->pml4_phys, interp_data, (size_t)interp_size,
                     INTERP_BASE, &interp_er) != 0) {
            printk("[PROC] FAIL: interpreter ELF parse error\n");
            panic_halt("[PROC] FAIL: interpreter ELF parse error");
        }
        if (interp_buf)
            kva_free_pages(interp_buf, interp_pages);
    }

    uint64_t entry_rip = has_interp ? interp_er.entry : er.entry;
    uint64_t brk_start = er.brk;

    /* Allocate and map user stack page.
     * vmm_zero_page ensures the initial stack contents are zero.
     * We then write a minimal argv so that "init" is argv[0]:
     *   [RSP+0]  = argc = 1
     *   [RSP+8]  = argv[0] pointer → string near top of stack
     *   [RSP+16] = 0 (argv NULL terminator)
     *   [RSP+24] = 0 (envp NULL)
     *   [RSP+32] = 0 (AT_NULL)
     * The string ""init"\0" is placed at USER_STACK_TOP - 16 (within page). */
    {
        uint64_t pn;
        for (pn = 0; pn < USER_STACK_NPAGES; pn++) {
            uint64_t user_stack_phys = pmm_alloc_page();
            if (!user_stack_phys) {
                printk("[PROC] FAIL: OOM allocating user stack\n");
                panic_halt("[PROC] FAIL: OOM allocating user stack");
            }
            vmm_zero_page(user_stack_phys);
            vmm_map_user_page(proc->pml4_phys,
                              USER_STACK_BASE + pn * 4096ULL, user_stack_phys,
                              VMM_FLAG_PRESENT | VMM_FLAG_USER | VMM_FLAG_WRITABLE);
        }
    }

    /* Build SysV ABI initial stack.
     * Layout (top → bottom): argv string, AT_RANDOM data, pointer table.
     * Matches the layout used by sys_execve. */
    uint64_t rsp_init;
    {
        uint64_t sp_va = USER_STACK_TOP;

        /* Write argv[0] string "- init" (login shell prefix) at top of stack */
        char login_name[16];
        login_name[0] = '-';
        __builtin_memcpy(login_name + 1, "init", 5); /* includes '\0' */
        uint64_t slen = __builtin_strlen(login_name) + 1;
        sp_va -= slen;
        vmm_write_user_bytes(proc->pml4_phys, sp_va, login_name, slen);
        uint64_t str_va = sp_va;

        /* Write 16 random bytes for AT_RANDOM */
        sp_va -= 16;
        {
            uint8_t rand_bytes[16];
            random_get_bytes(rand_bytes, 16);
            vmm_write_user_bytes(proc->pml4_phys, sp_va, rand_bytes, 16);
        }
        uint64_t at_random_va = sp_va;

        /* Align to 8 bytes for pointer table */
        sp_va &= ~7ULL;

        /* Pointer table: argc + argv[0] + NULL + envp NULL + auxv pairs + AT_NULL.
         * Base: 4 + 10 + 2 = 16 qwords.  With interp: +4 = 20 qwords. */
        uint64_t auxv_qwords = has_interp ? 16 : 12;
        uint64_t table_qwords = 4 + auxv_qwords; /* argc,argv[0],NULL,envpNULL + auxv */
        uint64_t table_bytes  = table_qwords * 8;
        sp_va -= table_bytes;
        /* Ensure RSP % 16 == 8 at _start per SysV ABI */
        if ((sp_va % 16) != 8) sp_va -= 8;

        uint64_t wp = sp_va;
        vmm_write_user_u64(proc->pml4_phys, wp, 1ULL);        wp += 8; /* argc = 1 */
        vmm_write_user_u64(proc->pml4_phys, wp, str_va);      wp += 8; /* argv[0] */
        vmm_write_user_u64(proc->pml4_phys, wp, 0ULL);        wp += 8; /* argv NULL */
        vmm_write_user_u64(proc->pml4_phys, wp, 0ULL);        wp += 8; /* envp NULL */
        /* AT_PHDR (3) */
        vmm_write_user_u64(proc->pml4_phys, wp, 3ULL);        wp += 8;
        vmm_write_user_u64(proc->pml4_phys, wp, er.phdr_va);  wp += 8;
        /* AT_PHNUM (5) */
        vmm_write_user_u64(proc->pml4_phys, wp, 5ULL);        wp += 8;
        vmm_write_user_u64(proc->pml4_phys, wp, (uint64_t)er.phdr_count); wp += 8;
        /* AT_PAGESZ (6) */
        vmm_write_user_u64(proc->pml4_phys, wp, 6ULL);        wp += 8;
        vmm_write_user_u64(proc->pml4_phys, wp, 4096ULL);     wp += 8;
        /* AT_ENTRY (9) */
        vmm_write_user_u64(proc->pml4_phys, wp, 9ULL);        wp += 8;
        vmm_write_user_u64(proc->pml4_phys, wp, er.entry);    wp += 8;
        /* AT_RANDOM (25) */
        vmm_write_user_u64(proc->pml4_phys, wp, 25ULL);       wp += 8;
        vmm_write_user_u64(proc->pml4_phys, wp, at_random_va); wp += 8;
        if (has_interp) {
            /* AT_BASE (7) — interpreter load address */
            vmm_write_user_u64(proc->pml4_phys, wp, 7ULL);    wp += 8;
            vmm_write_user_u64(proc->pml4_phys, wp, INTERP_BASE); wp += 8;
            /* AT_PHENT (4) — program header entry size */
            vmm_write_user_u64(proc->pml4_phys, wp, 4ULL);    wp += 8;
            vmm_write_user_u64(proc->pml4_phys, wp, 56ULL);   wp += 8;
        }
        /* AT_NULL */
        vmm_write_user_u64(proc->pml4_phys, wp, 0ULL);        wp += 8;
        vmm_write_user_u64(proc->pml4_phys, wp, 0ULL);        wp += 8;

        /* rsp_va used for the iretq frame below */
        rsp_init = sp_va;
    }

    /*
     * Build initial kernel stack.
     *
     * ctx_switch pops: r15, r14, r13, r12, rbp, rbx, then ret.
     * The ret target is proc_enter_user (a bare iretq label).
     * iretq pops a ring-3 frame: RIP, CS, RFLAGS, RSP, SS.
     *
     * Stack layout from low (RSP) to high:
     *   [r15=0][r14=0][r13=0][r12=0][rbp=0][rbx=0]
     *   [proc_enter_user]
     *   [entry_rip][CS=ARCH_USER_CS][RFLAGS=0x202][user_RSP][SS=ARCH_USER_DS]
     *
     * Push order (high-to-low, decrementing sp):
     *   SS first (highest address), r15 last (lowest = task.sp value).
     */
    uint64_t *sp = (uint64_t *)(kstack + STACK_SIZE);

#ifdef __aarch64__
    /* ARM64: build a frame for proc_enter_user_arm64 trampoline.
     * The trampoline loads TTBR0, sets SP_EL0, ELR_EL1, SPSR, and ERETs.
     *
     * Stack layout (high → low):
     *   [user_pml4_phys]  — trampoline loads into TTBR0
     *   [user_sp]         — trampoline writes to SP_EL0
     *   [entry_rip]       — trampoline writes to ELR_EL1
     *   [spsr = 0]        — EL0, interrupts enabled (DAIF clear)
     * Then ctx_switch callee-saves (12 slots):
     *   [x29=0][x30=proc_enter_user] ... [x19=0][x20=0]
     */
    *--sp = proc->pml4_phys;
    *--sp = rsp_init;               /* user SP */
    *--sp = entry_rip;              /* ELR (entry point) */
    *--sp = 0;                      /* SPSR: EL0, all interrupts enabled */

    /* ctx_switch callee-save frame (matches ctx_switch.S pop order) */
    *--sp = 0;                          /* x20 */
    *--sp = 0;                          /* x19 */
    *--sp = 0;                          /* x22 */
    *--sp = 0;                          /* x21 */
    *--sp = 0;                          /* x24 */
    *--sp = 0;                          /* x23 */
    *--sp = 0;                          /* x26 */
    *--sp = 0;                          /* x25 */
    *--sp = 0;                          /* x28 */
    *--sp = 0;                          /* x27 */
    *--sp = (uint64_t)(uintptr_t)proc_enter_user; /* x30 (lr) → trampoline */
    *--sp = 0;                          /* x29 (fp) */
#else
    /* x86-64: iretq frame + ctx_switch callee-saves. */
    *--sp = (uint64_t)ARCH_USER_DS; /* SS  — user data | RPL=3    */
    *--sp = rsp_init;             /* RSP */
    *--sp = 0x202ULL;           /* RFLAGS — IF=1, reserved bit 1  */
    *--sp = (uint64_t)ARCH_USER_CS; /* CS  — user code | RPL=3     */
    *--sp = entry_rip;          /* RIP — ELF entry point          */
    *--sp = proc->pml4_phys;    /* user PML4 phys — popped by proc_enter_user */
    *--sp = (uint64_t)(uintptr_t)proc_enter_user; /* ret → CR3 switch + iretq */
    *--sp = 0;                  /* rbx */
    *--sp = 0;                  /* rbp */
    *--sp = 0;                  /* r12 */
    *--sp = 0;                  /* r13 */
    *--sp = 0;                  /* r14 */
    *--sp = 0;                  /* r15 ← task.sp */
#endif

    /* Initialize task fields */
    proc->task.sp               = (uint64_t)(uintptr_t)sp;
    proc->task.stack_base       = kstack;
    proc->task.kernel_stack_top = (uint64_t)(uintptr_t)(kstack + STACK_SIZE);
    proc->task.tid              = 0xFF;   /* placeholder TID for init process */
    proc->task.is_user          = 1;
    proc->task.stack_pages      = (uint32_t)STACK_PAGES;
    /* Valid default FPU state — the memset above zeroed the FXSAVE area,
     * and all-zeros (FCW=0/MXCSR=0) unmasks every x87/SSE exception.
     * fxrstor runs when this task is first switched in (no-op on non-x86). */
    fpu_state_init(&proc->task);

    /* Allocate refcounted fd table — all slots start as free (ops == NULL). */
    proc->fd_table = fd_table_alloc();
    if (!proc->fd_table) {
        printk("[PROC] FAIL: OOM allocating fd_table\n");
        panic_halt("[PROC] FAIL: OOM allocating fd_table");
    }

    /* Zero cap table — all slots start empty.
     * kva_alloc_pages maps raw physical frames without zeroing; the loop is
     * required to ensure all slots start as CAP_KIND_NULL (= 0).
     * fd_table_alloc() handles zeroing the fd table separately. */
    {
        uint32_t ci;
        for (ci = 0; ci < CAP_TABLE_SIZE; ci++) {
            proc->caps[ci].kind   = CAP_KIND_NULL;
            proc->caps[ci].rights = 0;
        }
    }

    proc->authenticated    = 0;  /* init is not authenticated until login succeeds */
    proc->admin_session    = 0;  /* no admin session until a future sudo-style auth */
    proc->auth_uid         = AUTH_ID_NONE;  /* no bound identity until auth_session */
    proc->auth_gid         = AUTH_ID_NONE;

    proc->pid              = proc_alloc_pid();   /* 1 for init */
    proc->tgid             = proc->pid;
    proc->thread_count     = 1;
    proc->ppid             = 0;
    proc->uid              = 0;
    proc->gid              = 0;
    proc->pgid             = proc->pid;
    proc->sid              = proc->pid;  /* init is its own session leader */
    proc->umask            = 022U;
    proc->stop_signum      = 0;
    proc->cwd[0]           = '/';
    proc->cwd[1]           = '\0';
    proc->exit_status      = 0;
    proc->mmap_free_count  = 0;

    /* Initialize VMA tracking */
    vma_init((struct aegis_process *)proc);
    /* Record user stack VMA. The table is freshly allocated and empty here,
     * so this cannot legitimately fail — but check anyway and treat a failure
     * as fatal, matching every other error in proc_spawn (init must come up
     * fully or the system is dead). */
    if (vma_insert((struct aegis_process *)proc, USER_STACK_BASE,
                   USER_STACK_NPAGES * 4096ULL,
                   0x01 | 0x02,  /* PROT_READ | PROT_WRITE */
                   VMA_STACK) != 0) {
        printk("[PROC] FAIL: VMA insert for init user stack\n");
        panic_halt("[PROC] FAIL: VMA insert for init user stack");
    }
    /* exe_path: set to /bin/init for the init process */
    __builtin_memcpy(proc->exe_path, "/bin/init", 10);

    proc->pending_signals  = 0;
    proc->signal_mask      = 0;
    __builtin_memset(proc->sigactions, 0, sizeof(proc->sigactions));
    proc->task.state       = TASK_RUNNING;
    proc->task.on_cpu      = -1;
    proc->task.waiting_for = 0;

    /* Grant initial capabilities to PID 1 (vigil/init).
     * Init receives the baseline caps plus PROC_READ with WRITE (for kill).
     * All other caps come from policy files via cap_policy_lookup at exec time.
     * Vigil itself needs the baseline to open files, read dirs, and signal children. */
    cap_grant(proc->caps, CAP_TABLE_SIZE, CAP_KIND_VFS_OPEN,      CAP_RIGHTS_READ);
    cap_grant(proc->caps, CAP_TABLE_SIZE, CAP_KIND_VFS_WRITE,     CAP_RIGHTS_WRITE);
    cap_grant(proc->caps, CAP_TABLE_SIZE, CAP_KIND_VFS_READ,      CAP_RIGHTS_READ);
    cap_grant(proc->caps, CAP_TABLE_SIZE, CAP_KIND_IPC,           CAP_RIGHTS_READ);
    cap_grant(proc->caps, CAP_TABLE_SIZE, CAP_KIND_PROC_READ,     CAP_RIGHTS_READ | CAP_RIGHTS_WRITE);
    cap_grant(proc->caps, CAP_TABLE_SIZE, CAP_KIND_THREAD_CREATE, CAP_RIGHTS_READ);
    cap_grant(proc->caps, CAP_TABLE_SIZE, CAP_KIND_POWER,         CAP_RIGHTS_READ);

    /* Pre-open fd 1 (stdout) to the console device.
     * User process inherits stdout without a sys_open call. */
    proc->fd_table->fds[1] = *console_open();

    /* Pre-open fd 0 (stdin) to keyboard device. */
    proc->fd_table->fds[0] = *kbd_vfs_open();

    /* Pre-open fd 2 (stderr) to console device. */
    proc->fd_table->fds[2] = *console_open();

    /* Honest access modes — sys_read/sys_write enforce them now. */
    proc->fd_table->fds[0].flags = VFS_O_RDONLY;
    proc->fd_table->fds[1].flags = VFS_O_RDWR;
    proc->fd_table->fds[2].flags = VFS_O_RDWR;

    /* Initialise heap break to top of ELF segments. */
    proc->brk      = brk_start;
    proc->brk_base = brk_start;

    /* Initialise mmap bump allocator base (112 TB — safely above heap, below stack). */
    proc->mmap_base = 0x0000700000000000ULL;

    /* FS base starts at zero; arch_prctl(ARCH_SET_FS) sets it at musl startup. */
    proc->task.fs_base = 0;

    /* Register init as the terminal foreground process group so that
     * TIOCGPGRP returns proc->pgid immediately on first access.
     * Without this, oksh's job-control startup loop sees pgid=0 != its own
     * pgid and sends itself SIGTTIN repeatedly. */
    kbd_set_tty_pgrp(proc->pgid);

    printk("[CAP] OK: 7 baseline capabilities granted to init\n");

    sched_add(&proc->task);
}

void
proc_spawn_init(void)
{
    /* Linux model: the kernel embeds no userland. Load the init binary from
     * the root filesystem (rootfs module → ext2), which kernel_main mounts
     * before calling us. No init on the root fs is fatal on x86 (exactly like
     * Linux "No init found"); on ARM64 (no userland yet) we idle instead. */
    vfs_file_t vf;
    int vr = vfs_open(INIT_PATH, 0, 0, &vf);
    if (vr != 0 || vf.size == 0) {
        if (vr == 0 && vf.ops->close) vf.ops->close(vf.priv);
        printk("[INIT] no init at %s on root filesystem\n", INIT_PATH);
        /* Fatal on every arch (Linux "No init found" semantics) — the
         * arm64 port boots a rootfs module via Limine now, so the old
         * "no userland yet, idle instead" fallback is gone. */
        panic_halt("[INIT] no init found on root filesystem");
    }

    uint64_t pages = (vf.size + 4095ULL) / 4096ULL;
    void *buf = kva_alloc_pages(pages);
    if (!buf) {
        if (vf.ops->close) vf.ops->close(vf.priv);
        panic_halt("[INIT] OOM loading init");
    }
    int rr = vf.ops->read(vf.priv, buf, 0, vf.size);
    if (vf.ops->close) vf.ops->close(vf.priv);   /* free the ext2 fd slot */
    if (rr < 0) {
        kva_free_pages(buf, pages);
        panic_halt("[INIT] error reading init from root filesystem");
    }

    proc_spawn((const uint8_t *)buf, (size_t)vf.size);
    kva_free_pages(buf, pages);   /* elf_load copied the segments; buffer done */
}

/* arch_get_current_pml4 — return current user process PML4 phys addr.
 * Used by ARM64 fork_child_return to load TTBR0. */
uint64_t arch_get_current_pml4(void) {
    aegis_task_t *t = sched_current();
    if (t && t->is_user)
        return ((aegis_process_t *)t)->pml4_phys;
    return 0;
}

uint64_t arch_get_current_fs_base(void) {
    aegis_task_t *t = sched_current();
    if (t)
        return t->fs_base;
    return 0;
}

void arch_save_current_fs_base(uint64_t val) {
    aegis_task_t *t = sched_current();
    if (t)
        t->fs_base = val;
}

aegis_process_t *
proc_find_by_pid(uint32_t pid)
{
    irqflags_t fl = spin_lock_irqsave(&sched_lock);

    aegis_task_t *cur = sched_current();
    if (!cur) {
        spin_unlock_irqrestore(&sched_lock, fl);
        return (aegis_process_t *)0;
    }

    /* Check current task first */
    if (cur->is_user) {
        aegis_process_t *p = (aegis_process_t *)cur;
        if (p->pid == pid) {
            spin_unlock_irqrestore(&sched_lock, fl);
            return p;
        }
    }

    /* Walk the circular list */
    aegis_task_t *t = cur->next;
    while (t != cur) {
        if (t->is_user) {
            aegis_process_t *p = (aegis_process_t *)t;
            if (p->pid == pid) {
                spin_unlock_irqrestore(&sched_lock, fl);
                return p;
            }
        }
        t = t->next;
    }
    spin_unlock_irqrestore(&sched_lock, fl);
    return (aegis_process_t *)0;
}
