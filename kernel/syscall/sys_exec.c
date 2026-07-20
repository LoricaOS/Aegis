/* sys_exec.c — exec-related syscalls: execve, spawn */
#include "sys_impl.h"
#include "trace.h"
#include "sched.h"
#include "proc.h"
#include "signal.h"
#include "vfs.h"
#include "initrd.h"
#include "ext2.h"
#include "elf.h"
#include "vmm.h"
#include "pmm.h"
#include "kva.h"
#include "tty.h"
#include "arch.h"
#include "random.h"
#include "vma.h"

/* Copy a NULL-terminated user array of C-strings into a FLAT kernel buffer:
 * up to `max` entries, appended NUL-separated into strbuf[strbuf_sz], with a
 * NULL-terminated pointer table ptrs[0..n] pointing into strbuf. Returns the
 * entry count, or -1 if a user pointer is invalid OR the strings don't fit
 * (caller maps -1 to EFAULT — a too-large argv/env fails the exec rather than
 * silently truncating an arg, which used to chop long `sh -c "<recipe>"` args).
 * Shared by sys_execve and sys_spawn for both argv and envp. Callers guard
 * arr_uptr==0 themselves (argv requires a valid array; envp treats 0 as empty). */
static int
copy_user_argv(uint64_t arr_uptr, char *strbuf, int strbuf_sz, char *ptrs[], int max)
{
    int n = 0, off = 0;
    uint64_t ptr_addr = arr_uptr;
    while (n < max) {
        if (!user_ptr_valid(ptr_addr, 8))
            return -1;
        uint64_t str_ptr;
        copy_from_user(&str_ptr, (const void *)(uintptr_t)ptr_addr, 8);
        if (!str_ptr)
            break;  /* NULL terminator */
        ptrs[n] = &strbuf[off];
        for (;;) {
            if (off >= strbuf_sz - 1)
                return -1;  /* arg strings exceed the buffer — fail, don't truncate */
            if (!user_ptr_valid(str_ptr, 1))
                return -1;
            char c;
            copy_from_user(&c, (const void *)(uintptr_t)str_ptr, 1);
            strbuf[off++] = c;
            str_ptr++;
            if (c == '\0')
                break;
        }
        n++;
        ptr_addr += 8;
    }
    ptrs[n] = (char *)0;
    return n;
}

/*
 * sys_execve — syscall 59
 *
 * arg1 = user pointer to null-terminated path
 * arg2 = user pointer to null-terminated argv[] array (NULL-terminated)
 * arg3 = user pointer to envp[] (NULL-terminated; may be NULL for empty env)
 *
 * Replaces the calling process image in place:
 *   1. Copy path and argv from user.
 *   2. Look up path in initrd.
 *   3. Free all user leaf pages; keep PML4 structure.
 *   4. Reset brk/mmap_base/fs_base.
 *   5. Load new ELF into the existing PML4.
 *   6. Allocate a fresh user stack (4 pages / 16 KB).
 *   7. Build x86-64 SysV ABI initial stack: argc, argv ptrs, NULL, envp
 *      ptrs, NULL, auxv (AT_PHDR, AT_PHNUM, AT_PAGESZ, AT_ENTRY, AT_NULL).
 *   8. Redirect SYSRET to new entry point.
 *
 * Stack layout on return:
 *   SP → argc
 *        argv[0] ... argv[argc-1]
 *        NULL (argv terminator)
 *        envp[0] ... envp[envc-1]
 *        NULL (envp terminator)
 *        AT_PHDR  / phdr_va
 *        AT_PHNUM / phdr_count
 *        AT_PAGESZ / 4096
 *        AT_ENTRY / er.entry
 *        AT_NULL  / 0
 *
 * Alignment: RSP % 16 == 8 on entry to _start, per SysV ABI.
 *
 * The argv/env working area (execve_argbuf_t) lives in a kva-allocated buffer
 * (not on the kernel stack) because its flat string buffers are far larger than
 * a per-process kernel stack.
 */
uint64_t
sys_execve(syscall_frame_t *frame,
           uint64_t path_uptr, uint64_t argv_uptr, uint64_t envp_uptr)
{
    aegis_process_t *proc = current_proc();
    /* Allocate argv working area from kva — too large for kernel stack. */
    execve_argbuf_t *abuf = kva_alloc_pages(EXECVE_ARGBUF_PAGES);
    if (!abuf)
        return SYS_ERR(ENOMEM);

    uint64_t ret = 0;  /* overwritten on error; 0 = success */
    /* For ext2-backed binaries: kva buffer holding the ELF image. */
    void    *ext2_buf   = (void *)0;
    uint64_t ext2_pages = 0;

    /* 1. Copy path from user (<=255 bytes) */
    char path[256];
    if (!user_ptr_valid(path_uptr, 1)) { ret = SYS_ERR(EFAULT); goto done; }
    {
        uint64_t i;
        for (i = 0; i < sizeof(path) - 1; i++) {
            if (!user_ptr_valid(path_uptr + i, 1))
                { ret = SYS_ERR(EFAULT); goto done; }
            char c;
            copy_from_user(&c, (const void *)(uintptr_t)(path_uptr + i), 1);
            path[i] = c;
            if (c == '\0') break;
        }
        path[sizeof(path) - 1] = '\0';
    }

    /* 1.5 Resolve a relative program path against the cwd (execve("./script")
     * or execve("bin/tool")). Absolute paths and the initrd lookup are
     * unaffected. Without this, `./configure`-style relative execs — and every
     * shebang script run as ./foo — fail ENOENT before the shebang is read. */
    if (path[0] != '/') {
        char resolved[256];
        if (resolve_path(path, proc->cwd, resolved, sizeof(resolved)) == 0) {
            uint64_t i;
            for (i = 0; i < sizeof(path) - 1 && resolved[i]; i++) path[i] = resolved[i];
            path[i] = '\0';
        }
    }

    /* 2. Copy argv (<=64) + envp (<=32) from user — shared helper. */
    {
        int argc = copy_user_argv(argv_uptr, abuf->argv_strs, EXECVE_ARGV_STRBYTES, abuf->argv_ptrs, EXECVE_MAX_ARGV);
        if (argc < 0) { ret = SYS_ERR(EFAULT); goto done; }
        /* argc is a block-local — capture it for the rest of the function */
        {
    int argc2 = argc;

    int envc = 0;
    if (envp_uptr != 0) {
        envc = copy_user_argv(envp_uptr, abuf->env_strs, EXECVE_ENV_STRBYTES, abuf->env_ptrs, EXECVE_MAX_ENV);
        if (envc < 0) { ret = SYS_ERR(EFAULT); goto done; }
    } else {
        abuf->env_ptrs[0] = (char *)0;
    }

    /* Shebang re-exec state: a #! script is re-exec'd with its interpreter,
     * looping back to the lookup below (bounded depth). Buffers live on the
     * stack for the whole call. */
    int  shebang_depth = 0;
    char shebang_interp[256];
    char shebang_arg[256];
    char script_path[256];

reload_binary:
    /* On a shebang reload, free the previous image before re-looking-up. */
    if (ext2_buf) { kva_free_pages(ext2_buf, ext2_pages); ext2_buf = (void *)0; ext2_pages = 0; }

    /* 3. Look up binary: initrd first, then VFS (ext2 on nvme0p1).
     *    Initrd binaries are always trusted (no permission check).
     *    ext2 binaries get an X_OK DAC check before loading. */
    vfs_file_t f;
    const uint8_t *elf_data;
    uint64_t       elf_size;
    if (initrd_open(path, &f) == 0) {
        elf_data = (const uint8_t *)initrd_get_data(&f);
        elf_size = (uint64_t)initrd_get_size(&f);
    } else {
        /* ext2 path: check execute permission before loading */
        {
            uint32_t elf_ino;
            if (ext2_open(path, &elf_ino) == 0) {
                int xperm = ext2_check_perm(elf_ino,
                    (uint16_t)proc->uid, (uint16_t)proc->gid, 1);
                if (xperm != 0)
                    { ret = SYS_ERR(EACCES); goto done; }
            }
        }
        vfs_file_t vf;
        int vr = vfs_open(path, 0, 0, &vf);
        if (vr != 0)
            { ret = (uint64_t)(int64_t)vr; goto done; }  /* ENOENT/ENOMEM/EACCES */
        if (vf.size == 0)
            { if (vf.ops->close) vf.ops->close(vf.priv);
              ret = SYS_ERR(ENOEXEC); goto done; }  /* ENOEXEC */
        ext2_pages = (vf.size + 4095ULL) / 4096ULL;
        ext2_buf = kva_alloc_pages(ext2_pages);
        if (!ext2_buf)
            { if (vf.ops->close) vf.ops->close(vf.priv);
              ret = SYS_ERR(ENOMEM); goto done; }  /* ENOMEM */
        int rr = vf.ops->read(vf.priv, ext2_buf, 0, vf.size);
        /* Close immediately: the ELF image is in ext2_buf now, and ext2 fds
         * come from a 32-slot pool freed only via ops->close — every exec
         * that skips this permanently leaks a slot until exec fails. */
        if (vf.ops->close) vf.ops->close(vf.priv);
        if (rr < 0)
            { ret = SYS_ERR(EIO); goto done; }   /* EIO */
        elf_data = (const uint8_t *)ext2_buf;
        elf_size = vf.size;
    }

    /* 3.5 Shebang: a "#!" script → re-exec with its interpreter. Done here,
     * before the point-of-no-return below, so a malformed script returns an
     * error instead of killing the caller. POSIX allows one optional arg after
     * the interpreter path. New argv = [interp, (arg,) scriptpath, orig_argv[1..]];
     * argv[0] of the original invocation is dropped. Nested shebangs bounded. */
    if (elf_size >= 2 && elf_data[0] == '#' && elf_data[1] == '!') {
        if (++shebang_depth > 4) { ret = SYS_ERR(ENOEXEC); goto done; }
        uint64_t p = 2;
        while (p < elf_size && (elf_data[p] == ' ' || elf_data[p] == '\t')) p++;
        uint64_t is = 0;
        while (p < elf_size && elf_data[p] != '\n' && elf_data[p] != ' ' &&
               elf_data[p] != '\t' && is < sizeof(shebang_interp) - 1)
            shebang_interp[is++] = (char)elf_data[p++];
        shebang_interp[is] = '\0';
        if (is == 0) { ret = SYS_ERR(ENOEXEC); goto done; }   /* "#!" with no interpreter */
        while (p < elf_size && (elf_data[p] == ' ' || elf_data[p] == '\t')) p++;
        uint64_t as = 0;
        while (p < elf_size && elf_data[p] != '\n' && as < sizeof(shebang_arg) - 1)
            shebang_arg[as++] = (char)elf_data[p++];
        while (as > 0 && (shebang_arg[as-1] == ' ' || shebang_arg[as-1] == '\t' ||
                          shebang_arg[as-1] == '\r')) as--;
        shebang_arg[as] = '\0';
        int has_arg = (as > 0);
        /* Rebuild argv. Snapshot the original pointers first (they index into
         * abuf->argv_strs, which stays valid) before overwriting the array. */
        for (uint64_t i = 0; i < sizeof(path); i++) script_path[i] = path[i];
        char *saved[EXECVE_MAX_ARGV];
        int saved_n = argc2;
        if (saved_n > EXECVE_MAX_ARGV) saved_n = EXECVE_MAX_ARGV;
        for (int i = 0; i < saved_n; i++) saved[i] = abuf->argv_ptrs[i];
        int na = 0;
        abuf->argv_ptrs[na++] = shebang_interp;
        if (has_arg) abuf->argv_ptrs[na++] = shebang_arg;
        abuf->argv_ptrs[na++] = script_path;
        for (int i = 1; i < saved_n && na < EXECVE_MAX_ARGV - 1; i++)
            abuf->argv_ptrs[na++] = saved[i];
        abuf->argv_ptrs[na] = (char *)0;
        argc2 = na;
        for (uint64_t i = 0; i < sizeof(shebang_interp) && i < sizeof(path); i++)
            path[i] = shebang_interp[i];
        goto reload_binary;
    }

    /* 4. Install a fresh address space for the new image.
     *
     * vfork child (CLONE_VM|CLONE_VFORK): our PML4 + vma_table are BORROWED
     * from the suspended parent. We must NOT free those pages (they are the
     * parent's image). Instead allocate a brand-new PML4 + vma_table — this is
     * the only place a graceful ENOMEM is still possible (nothing destroyed
     * yet) — then wake the parent: vfork semantics end at exec.
     *
     * Normal exec: free our own user leaf pages in place and reuse the PML4
     * structure. POINT OF NO RETURN: after this, the old image is gone; any
     * failure below must kill the process via sched_exit (returning an error
     * would SYSRET to unmapped memory). Matches Linux flush_old_exec. */
    if (proc->vfork_parent) {
        uint64_t new_pml4 = vmm_create_user_pml4();
        if (!new_pml4) { ret = SYS_ERR(ENOMEM); goto done; }
        proc->pml4_phys = new_pml4;
        vmm_switch_to(new_pml4);
        vma_free(proc);   /* drop our ref to the parent's shared vma_table */
        vma_init(proc);   /* fresh, independent table for the new image */
        aegis_task_t *vp = proc->vfork_parent;
        proc->vfork_parent = (void *)0;
        /* vfork window over: thaw the parent's thread group BEFORE waking it (a
         * frozen parent can't run). Self-locking (takes sched_lock internally). */
        vfork_freeze_remove(((aegis_process_t *)vp)->tgid);
        sched_wake(vp);   /* parent resumes: it no longer shares our VM */
    } else {
        vmm_free_user_pages(proc->pml4_phys);
        vmm_switch_to(proc->pml4_phys);   /* reload CR3 to flush stale TLBs */
    }

    /* 5. Reset heap/mmap/TLS state */
    proc->brk       = 0;
    proc->brk_base  = 0;
    proc->mmap_base = 0x0000700000000000ULL;
    proc->mmap_free_count = 0;
    /* execve must drop any inherited clear_child_tid (Linux flush_old_exec):
     * a stale VA would make the kernel write 0 (+futex_wake) into the NEW
     * image on exit, clobbering whatever the new program mapped there. This
     * matters for posix_spawn (clone+execve), which is how Ladybird launches
     * RequestServer/WebContent. */
    proc->task.clear_child_tid = 0;
    vma_clear(proc);
    {
        uint64_t pi;
        for (pi = 0; pi < sizeof(proc->exe_path) - 1 && path[pi]; pi++)
            proc->exe_path[pi] = path[pi];
        proc->exe_path[pi] = '\0';
    }
    proc_trace_log("exec", proc->pid, proc->ppid, proc->exe_path);
    proc->task.fs_base = 0;

    /* Reset capability table to baseline + policy on exec — exec is a
     * capability boundary. Login's AUTH/SETUID caps must not propagate to the
     * exec'd shell. Policy caps come from /etc/aegis/caps.d/ (see
     * cap_apply_policy — shared with sys_spawn / proc_spawn). */
    cap_apply_policy(proc->caps, path, proc->authenticated, proc->admin_session);

    /* C2: Reset signal state across exec — pending signals, mask, and all
     * signal dispositions must be cleared.  Matches POSIX exec semantics:
     * caught signals are reset to SIG_DFL, pending signals are discarded. */
    proc->pending_signals = 0;
    proc->signal_mask = 0;
    __builtin_memset(proc->sigactions, 0, sizeof(proc->sigactions));

    /* 6. Load new ELF */
    elf_load_result_t er;
    elf_load_result_t interp_er;
    int has_interp = 0;
    __builtin_memset(&interp_er, 0, sizeof(interp_er));

    if (elf_load(proc, proc->pml4_phys, elf_data, (size_t)elf_size, 0, &er) != 0) {
        /* Past point of no return -- old image destroyed. Kill process. */
        sched_exit();
        __builtin_unreachable();
    }
    /* Free ext2 buffer immediately after ELF is loaded (pages already mapped). */
    if (ext2_buf) {
        kva_free_pages(ext2_buf, ext2_pages);
        ext2_buf   = (void *)0;
        ext2_pages = 0;
    }
    proc->brk      = er.brk;
    proc->brk_base = er.brk;

    /* 6a. If PT_INTERP present, load the interpreter at INTERP_BASE */
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
            if (vr != 0) { sched_exit(); __builtin_unreachable(); }
            interp_pages = (vf.size + 4095ULL) / 4096ULL;
            interp_buf = kva_alloc_pages(interp_pages);
            if (!interp_buf) {
                if (vf.ops->close) vf.ops->close(vf.priv);
                sched_exit(); __builtin_unreachable();
            }
            int rr = vf.ops->read(vf.priv, interp_buf, 0, vf.size);
            if (vf.ops->close) vf.ops->close(vf.priv);  /* pool slot — see above */
            if (rr < 0) {
                kva_free_pages(interp_buf, interp_pages);
                sched_exit(); __builtin_unreachable();
            }
            interp_data = (const uint8_t *)interp_buf;
            interp_size = vf.size;
        }

        if (elf_load(proc, proc->pml4_phys, interp_data, (size_t)interp_size,
                     INTERP_BASE, &interp_er) != 0) {
            if (interp_buf) kva_free_pages(interp_buf, interp_pages);
            sched_exit(); __builtin_unreachable();
        }
        if (interp_buf) kva_free_pages(interp_buf, interp_pages);
    }

    /* 7. Allocate + map 4 user stack pages (16 KB) */
    {
        uint64_t pn;
        for (pn = 0; pn < USER_STACK_NPAGES; pn++) {
            uint64_t phys = pmm_alloc_page();
            if (!phys) {
                /* Past point of no return -- kill process */
                sched_exit();
                __builtin_unreachable();
            }
            vmm_zero_page(phys);
            vmm_map_user_page(proc->pml4_phys,
                              USER_STACK_BASE_EXEC + pn * 4096ULL, phys,
                              VMM_FLAG_PRESENT | VMM_FLAG_USER |
                              VMM_FLAG_WRITABLE);
        }
    }

    /* Record user stack VMA. Past the point of no return (old image already
     * destroyed at step 4), so a full VMA table is fatal to the process:
     * leaving the stack untracked would corrupt /proc/maps and defeat
     * teardown. Kill the process exactly like every other post-PNR failure
     * above — sched_exit frees the stack frames via the user-half walk. */
    if (vma_insert(proc, USER_STACK_BASE_EXEC, USER_STACK_NPAGES * 4096ULL,
                   0x01 | 0x02, VMA_STACK) != 0)
        { sched_exit(); __builtin_unreachable(); }

    /* 8. Build ABI initial stack at USER_STACK_TOP_EXEC.
     *
     * Pack argv strings first (working downward from top), then write the
     * pointer table below.  Stack pointer must satisfy RSP % 16 == 8 at
     * _start entry per the x86-64 SysV ABI.
     */
    uint64_t sp_va = USER_STACK_TOP_EXEC;

    /* 8a. Write env strings first, then argv strings (matches sys_spawn).
     *     Env ends up at higher addresses, argv at lower addresses.  Both
     *     are referenced by VA in the pointer table below. */
    {
        int i;
        for (i = envc - 1; i >= 0; i--) {
            uint64_t slen = 0;
            while (abuf->env_ptrs[i][slen]) slen++;
            slen++;  /* include null terminator */
            if (sp_va - slen < USER_STACK_BASE_EXEC)
                { sched_exit(); __builtin_unreachable(); }  /* E2BIG — past PNR */
            sp_va -= slen;
            if (vmm_write_user_bytes(proc->pml4_phys, sp_va,
                                     abuf->env_ptrs[i], slen) != 0)
                { sched_exit(); __builtin_unreachable(); }  /* EFAULT — past PNR */
            abuf->env_str_ptrs[i] = sp_va;
        }
    }
    {
        int i;
        for (i = argc2 - 1; i >= 0; i--) {
            uint64_t slen = 0;
            while (abuf->argv_ptrs[i][slen]) slen++;
            slen++;  /* include null terminator */
            if (sp_va - slen < USER_STACK_BASE_EXEC)
                { sched_exit(); __builtin_unreachable(); }  /* E2BIG — past PNR */
            sp_va -= slen;
            if (vmm_write_user_bytes(proc->pml4_phys, sp_va,
                                     abuf->argv_ptrs[i], slen) != 0)
                { sched_exit(); __builtin_unreachable(); }  /* EFAULT — past PNR */
            abuf->str_ptrs[i] = sp_va;
        }
    }

    /* Write 16 bytes of random data for AT_RANDOM, then align.
     * musl 1.2.x reads AT_RANDOM from auxv to seed its internal PRNG;
     * without it, musl dereferences a null pointer during CRT init. */
    sp_va -= 16;
    {
        uint8_t rnd[16];
        random_get_bytes(rnd, 16);
        if (vmm_write_user_bytes(proc->pml4_phys, sp_va, rnd, 16) != 0)
            { sched_exit(); __builtin_unreachable(); }  /* past PNR */
    }
    uint64_t at_random_va = sp_va;

    /* Align sp_va to 8 bytes for the pointer table */
    sp_va &= ~7ULL;

    /* Count pointer table entries:
     *   1 (argc)
     * + argc (argv pointers)
     * + 1 (argv NULL)
     * + envc (envp pointers)
     * + 1 (envp NULL)
     * + auxv pairs × 2 qwords each:
     *     7 base: PHDR, PHNUM, PAGESZ, ENTRY, RANDOM, PHENT, NULL
     *   + 1 if interp: AT_BASE
     */
    {
    uint64_t auxv_qwords = has_interp ? 16 : 14;
    uint64_t table_qwords = (uint64_t)(argc2) + (uint64_t)envc + 3 + auxv_qwords;
    uint64_t table_bytes  = table_qwords * 8ULL;

    /* Ensure RSP % 16 == 8 on entry to _start */
    sp_va -= table_bytes;
    if ((sp_va % 16) != 8)
        sp_va -= 8;
    if (sp_va < USER_STACK_BASE_EXEC)
        { sched_exit(); __builtin_unreachable(); }  /* E2BIG — past PNR */

    /* 8b. Write the pointer table */
    {
        int i;
        uint64_t wp = sp_va;

        if (vmm_write_user_u64(proc->pml4_phys, wp,
                               (uint64_t)argc2) != 0)
            { sched_exit(); __builtin_unreachable(); }
        wp += 8;

        for (i = 0; i < argc2; i++) {
            if (vmm_write_user_u64(proc->pml4_phys, wp,
                                   abuf->str_ptrs[i]) != 0)
                { sched_exit(); __builtin_unreachable(); }
            wp += 8;
        }

        /* argv NULL terminator */
        if (vmm_write_user_u64(proc->pml4_phys, wp, 0ULL) != 0)
            { sched_exit(); __builtin_unreachable(); }
        wp += 8;

        /* envp pointers (relocated to user VAs by 8a) */
        for (i = 0; i < envc; i++) {
            if (vmm_write_user_u64(proc->pml4_phys, wp,
                                   abuf->env_str_ptrs[i]) != 0)
                { sched_exit(); __builtin_unreachable(); }
            wp += 8;
        }

        /* envp NULL terminator */
        if (vmm_write_user_u64(proc->pml4_phys, wp, 0ULL) != 0)
            { sched_exit(); __builtin_unreachable(); }
        wp += 8;

        /* auxv: AT_PHDR */
        if (vmm_write_user_u64(proc->pml4_phys, wp, 3ULL) != 0)
            { sched_exit(); __builtin_unreachable(); }
        wp += 8;
        if (vmm_write_user_u64(proc->pml4_phys, wp, er.phdr_va) != 0)
            { sched_exit(); __builtin_unreachable(); }
        wp += 8;

        /* auxv: AT_PHNUM */
        if (vmm_write_user_u64(proc->pml4_phys, wp, 5ULL) != 0)
            { sched_exit(); __builtin_unreachable(); }
        wp += 8;
        if (vmm_write_user_u64(proc->pml4_phys, wp,
                               (uint64_t)er.phdr_count) != 0)
            { sched_exit(); __builtin_unreachable(); }
        wp += 8;

        /* auxv: AT_PAGESZ */
        if (vmm_write_user_u64(proc->pml4_phys, wp, 6ULL) != 0)
            { sched_exit(); __builtin_unreachable(); }
        wp += 8;
        if (vmm_write_user_u64(proc->pml4_phys, wp, 4096ULL) != 0)
            { sched_exit(); __builtin_unreachable(); }
        wp += 8;

        /* auxv: AT_ENTRY */
        if (vmm_write_user_u64(proc->pml4_phys, wp, 9ULL) != 0)
            { sched_exit(); __builtin_unreachable(); }
        wp += 8;
        if (vmm_write_user_u64(proc->pml4_phys, wp, er.entry) != 0)
            { sched_exit(); __builtin_unreachable(); }
        wp += 8;

        /* auxv: AT_RANDOM — pointer to 16 random bytes on user stack */
        if (vmm_write_user_u64(proc->pml4_phys, wp, 25ULL) != 0)
            { sched_exit(); __builtin_unreachable(); }
        wp += 8;
        if (vmm_write_user_u64(proc->pml4_phys, wp, at_random_va) != 0)
            { sched_exit(); __builtin_unreachable(); }
        wp += 8;

        /* auxv: AT_PHENT (4) — program header entry size. MUST be present for
         * every binary: musl's __init_tls strides the phdr table with
         * `p += aux[AT_PHENT]`, so a missing/zero AT_PHENT makes it walk garbage
         * and mis-size the initial TLS (TP lands in an unmapped gap → the first
         * TLS deref, e.g. errno in free(), faults). Was previously emitted only
         * for interp binaries, so every static binary that touched TLS crashed
         * on arm64. */
        vmm_write_user_u64(proc->pml4_phys, wp, 4ULL);  wp += 8;
        vmm_write_user_u64(proc->pml4_phys, wp, 56ULL); wp += 8;

        if (has_interp) {
            /* auxv: AT_BASE (7) — interpreter load address */
            vmm_write_user_u64(proc->pml4_phys, wp, 7ULL); wp += 8;
            vmm_write_user_u64(proc->pml4_phys, wp, INTERP_BASE); wp += 8;
        }

        /* auxv: AT_NULL (end sentinel) */
        if (vmm_write_user_u64(proc->pml4_phys, wp, 0ULL) != 0)
            { sched_exit(); __builtin_unreachable(); }
        wp += 8;
        if (vmm_write_user_u64(proc->pml4_phys, wp, 0ULL) != 0)
            { sched_exit(); __builtin_unreachable(); }
    }
    } /* table_qwords/table_bytes scope */

    /* 9. Close all O_CLOEXEC file descriptors before loading new image */
    {
        int cfd;
        for (cfd = 0; cfd < PROC_MAX_FDS; cfd++) {
            if (proc->fd_table->fds[cfd].ops &&
                (proc->fd_table->fds[cfd].flags & VFS_FD_CLOEXEC)) {
                proc->fd_table->fds[cfd].ops->close(proc->fd_table->fds[cfd].priv);
                __builtin_memset(&proc->fd_table->fds[cfd], 0, sizeof(vfs_file_t));
            }
        }
    }

    /* 10. Redirect return to new ELF entry point (or interpreter if present) */
    FRAME_IP(frame) = has_interp ? interp_er.entry : er.entry;
    FRAME_SP(frame) = sp_va;

    /* 10a. Reset FPU/SSE state for the new image (exec semantics, like the
     * C2 signal reset above): write ABI defaults into the TCB save area and
     * load them into the live registers, so the new program starts with
     * default x87/SSE control words and zeroed data registers instead of
     * inheriting the old image's.  Back-to-back init+restore is safe from
     * a ctx_switch fxsave overwriting the area in between because syscall
     * context runs with IF=0 (no preemption).  No-ops on non-x86. */
    fpu_state_init(&proc->task);
    fpu_state_restore_live(&proc->task);
    /* ret = 0 (success) */
        } /* argc2 scope */
    } /* argc scope */

done:
    if (ext2_buf) kva_free_pages(ext2_buf, ext2_pages);
    kva_free_pages(abuf, EXECVE_ARGBUF_PAGES);
    return ret;
}

/*
 * sys_spawn — syscall 514
 *
 * Create a new process from an ELF binary WITHOUT fork.
 * No page copy — fresh PML4 with ELF loaded directly.
 * Solves the lumen terminal problem: fork from a large process (3000+ pages)
 * takes 30+ seconds on bare metal due to eager page copy + vmm_window_lock
 * contention. sys_spawn creates the child instantly with a fresh address space.
 *
 * arg1 = user pointer to null-terminated path
 * arg2 = user pointer to argv[] (NULL-terminated)
 * arg3 = user pointer to envp[] (ignored; empty environment used)
 * arg4 = stdio_fd: if >= 0, child's fd 0/1/2 are copies of parent's fd[arg4]
 *         if (uint64_t)-1, child gets no open fds
 *
 * The child starts in a new session (sid = pid, pgid = pid).
 * Capabilities: baseline + policy-based caps from /etc/aegis/caps.d/.
 *
 * Returns child PID on success, negative errno on failure.
 */
uint64_t
sys_spawn(uint64_t path_uptr, uint64_t argv_uptr,
          uint64_t envp_uptr, uint64_t stdio_fd_arg,
          uint64_t cap_mask_uptr)
{

    aegis_process_t *parent = current_proc();
    if (!sched_current()->is_user)
        return SYS_ERR(EPERM);

    if (proc_fork_count() >= MAX_PROCESSES)
        return SYS_ERR(EAGAIN);

    /* Allocate argv working area from kva — too large for kernel stack. */
    execve_argbuf_t *abuf = kva_alloc_pages(EXECVE_ARGBUF_PAGES);
    if (!abuf)
        return SYS_ERR(ENOMEM);

    uint64_t result = 0;
    void    *ext2_buf   = (void *)0;
    uint64_t ext2_pages = 0;

    /* 1. Copy path from user (<=255 bytes) */
    char path[256];
    if (!user_ptr_valid(path_uptr, 1)) { result = SYS_ERR(EFAULT); goto fail_early; }
    {
        uint64_t i;
        for (i = 0; i < sizeof(path) - 1; i++) {
            if (!user_ptr_valid(path_uptr + i, 1))
                { result = SYS_ERR(EFAULT); goto fail_early; }
            char c;
            copy_from_user(&c, (const void *)(uintptr_t)(path_uptr + i), 1);
            path[i] = c;
            if (c == '\0') break;
        }
        path[sizeof(path) - 1] = '\0';
    }

    /* Resolve a relative spawn path against the cwd (parity with sys_execve). */
    if (path[0] != '/') {
        char resolved[256];
        if (resolve_path(path, parent->cwd, resolved, sizeof(resolved)) == 0) {
            uint64_t i;
            for (i = 0; i < sizeof(path) - 1 && resolved[i]; i++) path[i] = resolved[i];
            path[i] = '\0';
        }
    }

    /* 2. Copy argv (<=64) + envp (<=32) from user — shared helper. */
    int argc = copy_user_argv(argv_uptr, abuf->argv_strs, EXECVE_ARGV_STRBYTES, abuf->argv_ptrs, EXECVE_MAX_ARGV);
    if (argc < 0) { result = SYS_ERR(EFAULT); goto fail_early; }

    int envc = 0;
    if (envp_uptr != 0) {
        envc = copy_user_argv(envp_uptr, abuf->env_strs, EXECVE_ENV_STRBYTES, abuf->env_ptrs, EXECVE_MAX_ENV);
        if (envc < 0) { result = SYS_ERR(EFAULT); goto fail_early; }
    } else {
        abuf->env_ptrs[0] = (char *)0;
    }

    /* 3. Look up binary: initrd first, then VFS (ext2). */
    const uint8_t *elf_data;
    uint64_t       elf_size;
    {
        vfs_file_t f;
        if (initrd_open(path, &f) == 0) {
            elf_data = (const uint8_t *)initrd_get_data(&f);
            elf_size = (uint64_t)initrd_get_size(&f);
        } else {
            /* H1: ext2 path — check execute permission before loading. */
            {
                uint32_t elf_ino;
                if (ext2_open(path, &elf_ino) == 0) {
                    int xperm = ext2_check_perm(elf_ino,
                        (uint16_t)parent->uid, (uint16_t)parent->gid, 1);
                    if (xperm != 0)
                        { result = SYS_ERR(EACCES); goto fail_early; } /* EACCES */
                }
            }
            vfs_file_t vf;
            int vr = vfs_open(path, 0, 0, &vf);
            if (vr != 0) { result = (uint64_t)(int64_t)vr; goto fail_early; }
            if (vf.size == 0) {
                if (vf.ops->close) vf.ops->close(vf.priv);
                result = SYS_ERR(ENOEXEC); goto fail_early;
            }
            ext2_pages = (vf.size + 4095ULL) / 4096ULL;
            ext2_buf = kva_alloc_pages(ext2_pages);
            if (!ext2_buf) {
                if (vf.ops->close) vf.ops->close(vf.priv);
                result = SYS_ERR(ENOMEM); goto fail_early;
            }
            int rr = vf.ops->read(vf.priv, ext2_buf, 0, vf.size);
            /* Close immediately — ext2 fd pool slot (see sys_execve). */
            if (vf.ops->close) vf.ops->close(vf.priv);
            if (rr < 0) { result = SYS_ERR(EIO); goto fail_early; }
            elf_data = (const uint8_t *)ext2_buf;
            elf_size = vf.size;
        }
    }

    /* 4. Allocate child PCB */
    aegis_process_t *child = kva_alloc_pages(2);
    if (!child) { result = SYS_ERR(ENOMEM); goto fail_early; }
    __builtin_memset(child, 0, sizeof(*child));

    /* 5. Create fresh PML4 for child */
    child->pml4_phys = vmm_create_user_pml4();
    if (!child->pml4_phys) { kva_free_pages(child, 2); result = SYS_ERR(ENOMEM); goto fail_early; }

    /* 5a. Initialize the child's VMA table BEFORE loading its ELF, so that
     * elf_load records the child's PT_LOAD + interpreter segments into the
     * CHILD (not the spawner).  Previously vma_init ran after elf_load, leaving
     * child->vma_table NULL during the load; elf_load then fell back to
     * sched_current() (the spawner) and leaked the child's VMAs into the
     * spawner's table — an unbounded per-spawn VmSize leak that eventually
     * exhausted the spawner's vma_table.  vma_free runs on every fail path
     * below (fail_child, and the main-ELF inline cleanup). */
    vma_init((struct aegis_process *)child);

    /* 6. Load ELF into child's PML4 */
    elf_load_result_t er;
    elf_load_result_t interp_er;
    int has_interp = 0;
    __builtin_memset(&interp_er, 0, sizeof(interp_er));

    if (elf_load(child, child->pml4_phys, elf_data, (size_t)elf_size, 0, &er) != 0) {
        vma_free((struct aegis_process *)child);
        vmm_free_user_pml4(child->pml4_phys);
        kva_free_pages(child, 2);
        result = SYS_ERR(ENOEXEC);
        goto fail_early;
    }

    /* Free ext2 buffer now that ELF is loaded. */
    if (ext2_buf) {
        kva_free_pages(ext2_buf, ext2_pages);
        ext2_buf   = (void *)0;
        ext2_pages = 0;
    }

    /* 6a. If PT_INTERP present, load interpreter at INTERP_BASE. */
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
            if (vr != 0) goto fail_child;
            interp_pages = (vf.size + 4095ULL) / 4096ULL;
            interp_buf = kva_alloc_pages(interp_pages);
            if (!interp_buf) {
                if (vf.ops->close) vf.ops->close(vf.priv);
                goto fail_child;
            }
            int rr = vf.ops->read(vf.priv, interp_buf, 0, vf.size);
            /* Close immediately — ext2 fd pool slot (see sys_execve). */
            if (vf.ops->close) vf.ops->close(vf.priv);
            if (rr < 0) {
                kva_free_pages(interp_buf, interp_pages);
                goto fail_child;
            }
            interp_data = (const uint8_t *)interp_buf;
            interp_size = vf.size;
        }

        if (elf_load(child, child->pml4_phys, interp_data, (size_t)interp_size,
                     INTERP_BASE, &interp_er) != 0) {
            if (interp_buf) kva_free_pages(interp_buf, interp_pages);
            goto fail_child;
        }
        if (interp_buf) kva_free_pages(interp_buf, interp_pages);
    }

    /* 7. Allocate + map user stack pages */
    {
        uint64_t pn;
        for (pn = 0; pn < USER_STACK_NPAGES; pn++) {
            uint64_t phys = pmm_alloc_page();
            if (!phys) goto fail_child;
            vmm_zero_page(phys);
            vmm_map_user_page(child->pml4_phys,
                              USER_STACK_BASE_EXEC + pn * 4096ULL, phys,
                              VMM_FLAG_PRESENT | VMM_FLAG_USER | VMM_FLAG_WRITABLE);
        }
    }

    /* 8. Build ABI initial stack (same layout as execve) */
    uint64_t sp_va = USER_STACK_TOP_EXEC;

    /* Stack-underflow guards (mirrors execve): argc<=64 + envc<=32 strings of up
     * to 256 bytes each can total 24 KB, exceeding the 16 KB stack. execve kills
     * the process with E2BIG; sys_spawn was missing the check, so the writes ran
     * past USER_STACK_BASE_EXEC — vmm_write_user_bytes safely returns -1 on the
     * unmapped pages (no OOB), but the result was ignored, leaving the child with
     * a corrupt stack that segfaults on entry. Reject cleanly via fail_child
     * (the child isn't on the run queue until sched_add far below). */
    /* 8a. Write env strings (pushed first so argv strings are at lower addr) */
    {
        int i;
        for (i = envc - 1; i >= 0; i--) {
            uint64_t slen = 0;
            while (abuf->env_ptrs[i][slen]) slen++;
            slen++;
            if (sp_va - slen < USER_STACK_BASE_EXEC)
                { result = SYS_ERR(E2BIG); goto fail_child; }
            sp_va -= slen;
            vmm_write_user_bytes(child->pml4_phys, sp_va,
                                 abuf->env_ptrs[i], slen);
            abuf->env_str_ptrs[i] = sp_va;
        }
    }

    /* 8b. Write argv strings */
    {
        int i;
        for (i = argc - 1; i >= 0; i--) {
            uint64_t slen = 0;
            while (abuf->argv_ptrs[i][slen]) slen++;
            slen++;
            if (sp_va - slen < USER_STACK_BASE_EXEC)
                { result = SYS_ERR(E2BIG); goto fail_child; }
            sp_va -= slen;
            vmm_write_user_bytes(child->pml4_phys, sp_va,
                                 abuf->argv_ptrs[i], slen);
            abuf->str_ptrs[i] = sp_va;
        }
    }

    /* AT_RANDOM: 16 random bytes */
    if (sp_va - 16 < USER_STACK_BASE_EXEC)
        { result = SYS_ERR(E2BIG); goto fail_child; }
    sp_va -= 16;
    {
        uint8_t rnd[16];
        random_get_bytes(rnd, 16);
        vmm_write_user_bytes(child->pml4_phys, sp_va, rnd, 16);
    }
    uint64_t at_random_va = sp_va;

    sp_va &= ~7ULL;

    /* Pointer table: argc + argv + NULL + envp + NULL + auxv */
    {
        uint64_t auxv_qwords = has_interp ? 16 : 12;
        uint64_t table_qwords = (uint64_t)argc + 2 + (uint64_t)envc + 1 + auxv_qwords;
        uint64_t table_bytes  = table_qwords * 8ULL;

        if (sp_va < table_bytes + 8ULL ||
            sp_va - table_bytes - 8ULL < USER_STACK_BASE_EXEC)
            { result = SYS_ERR(E2BIG); goto fail_child; }
        sp_va -= table_bytes;
        if ((sp_va % 16) != 8) sp_va -= 8;

        uint64_t wp = sp_va;
        vmm_write_user_u64(child->pml4_phys, wp, (uint64_t)argc); wp += 8;

        {
            int i;
            for (i = 0; i < argc; i++) {
                vmm_write_user_u64(child->pml4_phys, wp, abuf->str_ptrs[i]);
                wp += 8;
            }
        }
        vmm_write_user_u64(child->pml4_phys, wp, 0ULL); wp += 8; /* argv NULL */

        /* envp pointers */
        {
            int i;
            for (i = 0; i < envc; i++) {
                vmm_write_user_u64(child->pml4_phys, wp, abuf->env_str_ptrs[i]);
                wp += 8;
            }
        }
        vmm_write_user_u64(child->pml4_phys, wp, 0ULL); wp += 8; /* envp NULL */

        /* auxv: AT_PHDR(3), AT_PHNUM(5), AT_PAGESZ(6), AT_ENTRY(9), AT_RANDOM(25) */
        vmm_write_user_u64(child->pml4_phys, wp, 3ULL);  wp += 8;
        vmm_write_user_u64(child->pml4_phys, wp, er.phdr_va); wp += 8;
        vmm_write_user_u64(child->pml4_phys, wp, 5ULL);  wp += 8;
        vmm_write_user_u64(child->pml4_phys, wp, (uint64_t)er.phdr_count); wp += 8;
        vmm_write_user_u64(child->pml4_phys, wp, 6ULL);  wp += 8;
        vmm_write_user_u64(child->pml4_phys, wp, 4096ULL); wp += 8;
        vmm_write_user_u64(child->pml4_phys, wp, 9ULL);  wp += 8;
        vmm_write_user_u64(child->pml4_phys, wp, er.entry); wp += 8;
        vmm_write_user_u64(child->pml4_phys, wp, 25ULL); wp += 8;
        vmm_write_user_u64(child->pml4_phys, wp, at_random_va); wp += 8;

        if (has_interp) {
            vmm_write_user_u64(child->pml4_phys, wp, 7ULL); wp += 8;  /* AT_BASE */
            vmm_write_user_u64(child->pml4_phys, wp, INTERP_BASE); wp += 8;
            vmm_write_user_u64(child->pml4_phys, wp, 4ULL); wp += 8;  /* AT_PHENT */
            vmm_write_user_u64(child->pml4_phys, wp, 56ULL); wp += 8;
        }

        vmm_write_user_u64(child->pml4_phys, wp, 0ULL); wp += 8;  /* AT_NULL */
        vmm_write_user_u64(child->pml4_phys, wp, 0ULL); wp += 8;
    }

    /* 9. Allocate kernel stack for child (4 pages / 16KB) */
    uint8_t *kstack = kva_alloc_pages(4);
    if (!kstack) goto fail_child;

    /* 10. Build initial kernel stack frame for proc_enter_user (iretq to ring-3).
     *     Same layout as proc_spawn — child starts fresh from ELF entry. */
    {
        uint64_t entry_rip = has_interp ? interp_er.entry : er.entry;
        uint64_t *ksp = (uint64_t *)(kstack + 4 * 4096);

        extern void proc_enter_user(void);

#ifdef __aarch64__
        *--ksp = child->pml4_phys;
        *--ksp = sp_va;
        *--ksp = entry_rip;
        *--ksp = 0;  /* SPSR: EL0, interrupts enabled */
        /* ctx_switch callee-save frame (12 slots) */
        *--ksp = 0; *--ksp = 0; *--ksp = 0; *--ksp = 0;
        *--ksp = 0; *--ksp = 0; *--ksp = 0; *--ksp = 0;
        *--ksp = 0; *--ksp = 0;
        *--ksp = (uint64_t)(uintptr_t)proc_enter_user;
        *--ksp = 0;
#else
        *--ksp = (uint64_t)ARCH_USER_DS;   /* SS */
        *--ksp = sp_va;                    /* RSP */
        *--ksp = 0x202ULL;                 /* RFLAGS — IF=1, reserved bit 1 */
        *--ksp = (uint64_t)ARCH_USER_CS;   /* CS */
        *--ksp = entry_rip;                /* RIP */
        *--ksp = child->pml4_phys;         /* PML4 phys — popped by proc_enter_user */
        *--ksp = (uint64_t)(uintptr_t)proc_enter_user; /* ret → CR3 switch + iretq */
        *--ksp = 0;  /* rbx */
        *--ksp = 0;  /* rbp */
        *--ksp = 0;  /* r12 */
        *--ksp = 0;  /* r13 */
        *--ksp = 0;  /* r14 */
        *--ksp = 0;  /* r15 ← child->task.sp */
#endif

        child->task.sp               = (uint64_t)(uintptr_t)ksp;
        child->task.stack_base       = kstack;
        child->task.kernel_stack_top = (uint64_t)(uintptr_t)(kstack + 4 * 4096);
    }

    /* 11. Initialize child PCB fields */
    child->task.is_user     = 1;
    child->task.state       = TASK_RUNNING;
    child->task.waiting_for = 0;
    child->task.tid         = 0;  /* set below */
    child->task.stack_pages = 4;
    child->task.fs_base     = 0;
    child->task.clear_child_tid = 0;
    child->task.sleep_deadline  = 0;
    /* Fresh image, fresh FPU state: ABI defaults (FCW=0x037F, MXCSR=0x1F80),
     * not the all-zeros the memset left (zeros unmask every x87/SSE
     * exception).  fxrstor'd when the child is first switched in. */
    fpu_state_init(&child->task);

    child->pid             = proc_alloc_pid();
    child->tgid            = child->pid;
    child->thread_count    = 1;
    child->ppid            = parent->pid;
    child->uid             = parent->uid;
    child->gid             = parent->gid;
    child->pgid            = child->pid;   /* new process group */
    child->sid             = child->pid;   /* new session leader */
    child->umask           = parent->umask;
    child->stop_signum     = 0;
    child->exit_status     = 0;
    child->term_signal     = 0;  /* PCB not memset; stale value would forge a signal death */
    child->task.tid        = child->pid;

    child->brk             = er.brk;
    child->brk_base        = er.brk;
    child->mmap_base       = 0x0000700000000000ULL;
    child->mmap_free_count = 0;

    /* exe_path */
    {
        uint64_t pi;
        for (pi = 0; pi < sizeof(child->exe_path) - 1 && path[pi]; pi++)
            child->exe_path[pi] = path[pi];
        child->exe_path[pi] = '\0';
    }
    proc_trace_log("spawn", child->pid, child->ppid, child->exe_path);

    /* cwd: inherit from parent */
    __builtin_memcpy(child->cwd, parent->cwd, sizeof(parent->cwd));

    /* VFS confinement: inherit the parent's scope, or spawn would be a
     * confinement-escape (a confined process could spawn an unconfined child). */
    __builtin_memcpy(child->vfs_scope, parent->vfs_scope, sizeof(parent->vfs_scope));
    child->vfs_scope_len = parent->vfs_scope_len;

    /* VMA tracking for the stack.  The table was already allocated in step 5a
     * (vma_init, before elf_load) and now also holds the child's ELF segments.
     * A failure here means the table is full — tear the half-built child down
     * via fail_child (which frees the fd table, PML4, VMA page and PCB) after
     * releasing the kernel stack, matching the other post-kstack error paths. */
    if (vma_insert((struct aegis_process *)child, USER_STACK_BASE_EXEC,
                   USER_STACK_NPAGES * 4096ULL, 0x01 | 0x02, VMA_STACK) != 0) {
        kva_free_pages(kstack, 4);
        result = SYS_ERR(ENOMEM);
        goto fail_child;
    }

    /* Signal state: default dispositions, no pending, no mask. */
    child->pending_signals = 0;
    child->signal_mask     = 0;
    __builtin_memset(child->sigactions, 0, sizeof(child->sigactions));

    /* 12. Capabilities: baseline + policy, OR cap_mask if provided.
     * Policy-based caps from /etc/aegis/caps.d/ replace the old exec_caps mechanism. */
    {
        uint32_t ci;
        /* Baseline + policy (the authenticated flag is inherited from the
         * parent for spawned children). Shared with execve / proc_spawn via
         * cap_apply_policy. The cap_mask path below further restricts this
         * computed set. */
        cap_apply_policy(child->caps, path, parent->authenticated, parent->admin_session);

        /* cap_mask restricts the computed cap set (baseline + policy).
         * If provided, only caps that appear in BOTH the computed set AND
         * the mask survive. */
        if (cap_mask_uptr != 0) {
            /* cap_mask mode: caller must hold CAP_DELEGATE */
            if (cap_check(parent->caps, CAP_TABLE_SIZE,
                          CAP_KIND_CAP_DELEGATE, CAP_RIGHTS_READ) != 0) {
                kva_free_pages(kstack, 4);
                result = SYS_ERR(ENOCAP);
                goto fail_child;
            }

            /* Copy cap_mask from userspace */
            cap_slot_t mask[CAP_TABLE_SIZE];
            if (!user_ptr_valid(cap_mask_uptr, sizeof(mask))) {
                kva_free_pages(kstack, 4);
                result = SYS_ERR(EFAULT);
                goto fail_child;
            }
            copy_from_user(mask, (const void *)cap_mask_uptr,
                           sizeof(mask));

            /* Validate and apply: caller can only grant caps it holds.
             * Zero the child's caps and re-grant only those in the mask
             * that the parent also holds. */
            cap_slot_t computed[CAP_TABLE_SIZE];
            for (ci = 0; ci < CAP_TABLE_SIZE; ci++)
                computed[ci] = child->caps[ci];
            for (ci = 0; ci < CAP_TABLE_SIZE; ci++) {
                child->caps[ci].kind   = CAP_KIND_NULL;
                child->caps[ci].rights = 0;
            }
            for (ci = 0; ci < CAP_TABLE_SIZE; ci++) {
                if (mask[ci].kind == CAP_KIND_NULL)
                    continue;
                /* Validate against the highest DEFINED cap kind (CAP_KIND_MAX),
                 * not CAP_TABLE_SIZE (the slot count). Kinds above CAP_KIND_MAX
                 * are undefined and must be rejected, else a CAP_DELEGATE holder
                 * could seed a child's table with bogus kinds. Using the
                 * CAP_KIND_MAX sentinel (vs the old literal CAP_KIND_INSTALL)
                 * fixes an off-by-one that rejected CAP_KIND_NET_LISTEN (18) —
                 * the bound wasn't bumped when that kind was added, so it was
                 * silently undelegatable. */
                if (mask[ci].kind == CAP_KIND_NULL ||
                    mask[ci].kind > CAP_KIND_MAX) {
                    kva_free_pages(kstack, 4);
                    result = SYS_ERR(EINVAL);
                    goto fail_child;
                }
                if (cap_check(parent->caps, CAP_TABLE_SIZE,
                              mask[ci].kind, mask[ci].rights) != 0) {
                    kva_free_pages(kstack, 4);
                    result = SYS_ERR(ENOCAP);
                    goto fail_child;
                }
                /* Only grant if it was in the computed set (baseline+policy) */
                if (cap_check(computed, CAP_TABLE_SIZE,
                              mask[ci].kind, mask[ci].rights) == 0) {
                    cap_grant(child->caps, CAP_TABLE_SIZE,
                              mask[ci].kind, mask[ci].rights);
                }
            }
        }

        /* Inherit authenticated flag + bound identity from parent */
        child->authenticated = parent->authenticated;
        child->admin_session = parent->admin_session;
        child->auth_uid      = parent->auth_uid;
        child->auth_gid      = parent->auth_gid;
    }

    /* 13. File descriptor table. */
    child->fd_table = fd_table_alloc();
    if (!child->fd_table) {
        kva_free_pages(kstack, 4);
        goto fail_child;
    }

    {
        int64_t sfd = (int64_t)stdio_fd_arg;
        if (sfd >= 0 && sfd < PROC_MAX_FDS &&
            parent->fd_table->fds[sfd].ops) {
            /* Copy the parent's fd to child's fd 0, 1, 2 */
            int fd_i;
            for (fd_i = 0; fd_i < 3; fd_i++) {
                child->fd_table->fds[fd_i] = parent->fd_table->fds[sfd];
                if (child->fd_table->fds[fd_i].ops->dup)
                    child->fd_table->fds[fd_i].ops->dup(
                        child->fd_table->fds[fd_i].priv);
            }
        }
    }

    /* 14. Add child to scheduler */
    sched_add(&child->task);
    proc_inc_fork_count();

    /* Success — free argv buffer and return child PID */
    kva_free_pages(abuf, EXECVE_ARGBUF_PAGES);
    return (uint64_t)child->pid;

fail_child:
    /* Tear the child's fd table down through fd_table_unref so each fd's
     * .close() handler runs — a raw kva_free_pages() (or skipping it, as the
     * old code did) leaks dup'd driver references (pipe/AF_UNIX/PTY peers,
     * ext2 fd-pool slots — the fd-pool-exhaustion class behind the 1.0.6
     * "ENOENT after N execs" bug). The error-path table is unshared
     * (refcount 1), so unref closes every fd and frees the page. NULL-guarded
     * because child is zero-initialized, so this is a no-op for failures that
     * occur before fd_table_alloc(). Mirrors sched_exit (kernel/sched/sched.c)
     * and the fork error paths in sys_process.c. */
    if (child->fd_table) {
        fd_table_unref(child->fd_table);
        child->fd_table = (fd_table_t *)0;  /* guard against double-unref */
    }
    /* Release the VMA tracking page if vma_init ran (it allocates a kva page
     * with refcount 1). NULL-guarded: child was memset to 0, so vma_table is
     * NULL for failures before vma_init and vma_free is then a no-op. Without
     * this, every fail_child reached after vma_init leaks one kva page. */
    vma_free((struct aegis_process *)child);
    vmm_free_user_pml4(child->pml4_phys);
    kva_free_pages(child, 2);
    if (!result) result = SYS_ERR(ENOMEM);

fail_early:
    if (ext2_buf) kva_free_pages(ext2_buf, ext2_pages);
    kva_free_pages(abuf, EXECVE_ARGBUF_PAGES);
    return result;
}
