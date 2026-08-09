/* sys_io.c — I/O syscall implementations: read, write, writev, close */
#include "sys_impl.h"
#include "sched.h"
#include "proc.h"
#include "vfs.h"
/* EISDIR comes from aegis_errno.h via sys_impl.h. */
#ifdef __x86_64__
#include "hda.h"      /* hda_set_volume — output volume (HDA only) */
#endif

/*
 * sys_audio_volume — syscall 503.  arg1 = output volume percent (0..100).
 *
 * Ungated: volume is a non-privileged user preference, not a security or
 * install concern. Clamped to 0..100. No-op when there is no HDA codec.
 */
uint64_t
sys_audio_volume(uint64_t pct)
{
    int v = (int)pct;
    if (v < 0)   v = 0;
    if (v > 100) v = 100;
#ifdef __x86_64__
    hda_set_volume(v);
#endif
    return 0;
}

/*
 * sys_audio_stop — syscall 504.  Stop /dev/audio playback immediately and
 * discard the buffered tail (the Tunes Stop button). Ungated. No-op without HDA.
 */
uint64_t
sys_audio_stop(void)
{
#ifdef __x86_64__
    hda_audio_stop();
#endif
    return 0;
}

/*
 * sys_audio_position — syscall 505.  Return the milliseconds of audio actually
 * played on the current /dev/audio stream (the A/V master clock a video player
 * syncs frames to). Ungated (a playback-progress query, no authority). 0 when
 * idle or no HDA.
 */
uint64_t
sys_audio_position(void)
{
#ifdef __x86_64__
    return hda_play_position_ms();
#else
    return 0;
#endif
}

/* vfs_read_nonblock — set by sys_read before calling f->ops->read() when the
 * fd has O_NONBLOCK set.  Blocking VFS read ops (PTY master, pipes) check this
 * global and return -EAGAIN instead of sleeping.  Reset to 0 after the call.
 * Safe on single-core: syscalls are non-preemptible. */
int vfs_read_nonblock = 0;

/*
 * sys_write — syscall 1
 *
 * arg1 = fd
 * arg2 = user virtual address of buffer
 * arg3 = byte count
 *
 * Returns bytes written on success, negative errno on failure.
 * Requires CAP_KIND_VFS_WRITE capability. Routes through fd table.
 */
uint64_t
sys_write(uint64_t arg1, uint64_t arg2, uint64_t arg3)
{
    aegis_process_t *proc = current_proc();

    /* Capability gate — must hold VFS_WRITE before touching any fd. */
    if (cap_check(proc->caps, CAP_TABLE_SIZE,
                  CAP_KIND_VFS_WRITE, CAP_RIGHTS_WRITE) != 0)
        return SYS_ERR(ENOCAP);

    if (arg1 >= PROC_MAX_FDS || !proc->fd_table->fds[arg1].ops ||
        !proc->fd_table->fds[arg1].ops->write)
        return SYS_ERR(EBADF);

    /* Enforce the fd's access mode: an O_RDONLY fd must never write. Found
     * the hard way — a service with stdout closed had its media file land on
     * fd 1, and stdio flushes overwrote the file's first block through the
     * read-only fd. */
    if ((proc->fd_table->fds[arg1].flags & VFS_O_ACCMODE) == VFS_O_RDONLY)
        return SYS_ERR(EBADF);

    /* Re-validate authority on USE — the write-side mirror of the check in
     * sys_read. An O_RDWR fd onto /etc/shadow or /etc/aegis/admin carries
     * VFS_KF_AUTH_GATED and survives execve (only FD_CLOEXEC fds are closed),
     * while the exec'd image's caps are re-derived from policy. Without this,
     * a capless child could not READ the inherited fd but could WRITE a forged
     * hash through it — the unprotected direction was the more damaging one. */
    if ((proc->fd_table->fds[arg1].kflags & VFS_KF_AUTH_GATED) &&
        cap_check(proc->caps, CAP_TABLE_SIZE, CAP_KIND_AUTH, CAP_RIGHTS_READ) != 0)
        return SYS_ERR(EACCES);

    if (!user_ptr_valid(arg2, arg3))
        return SYS_ERR(EFAULT);

    /* Copy user buffer to kernel staging area to prevent TOCTOU — the user
     * could modify or unmap the buffer between the user_ptr_valid check and
     * the actual write.  Copy in page-size chunks (same pattern as sys_writev):
     * a 4 KiB write used to be 16 × 256 B ops->write calls, each re-doing the
     * fd's cache lookups; one page per chunk keeps the stack cost bounded
     * (16 KiB kernel stacks) while cutting the per-chunk overhead 16x.
     *
     * For pipes, pipe_write_fn returns a positive partial count or a negative
     * errno (-EPIPE).  The loop handles both correctly:
     *   - partial positive: advance offset and retry the remainder.
     *   - zero or negative: break and return that value. */
    vfs_file_t *f = &proc->fd_table->fds[arg1];
    /* Per-task O_NONBLOCK flag for the write path (mirrors read_nonblock): the
     * ops->write callback only gets (priv, buf, len), so this is how the fd's
     * O_NONBLOCK reaches blocking writers (pipe_write_fn). Without it an
     * O_NONBLOCK write on a full pipe blocks forever instead of returning
     * EAGAIN. Set before dispatch, cleared on every return path below. */
    sched_current()->write_nonblock = (f->flags & VFS_O_NONBLOCK) ? 1 : 0;
    uint64_t total = 0;
    uint8_t staging[4096];
    while (total < arg3) {
        uint64_t chunk = arg3 - total;
        if (chunk > sizeof(staging)) chunk = sizeof(staging);
        /* `staging` is uninitialized kernel stack, and copy_from_user is
         * fault-tolerant (exception-table fixup): on a partial fault it
         * returns bytes-not-copied and leaves the tail of `staging` holding
         * whatever was on the stack before. Ignoring the return handed those
         * stale kernel-stack bytes to ops->write, persisting them into a file
         * or pipe the caller can read back — kernel pointers included.
         * Reachable by munmapping the source page from a CLONE_VM sibling
         * while this thread is blocked in a full pipe. */
        if (copy_from_user(staging, (const void *)(uintptr_t)(arg2 + total),
                           chunk) != 0) {
            sched_current()->write_nonblock = 0;
            f->offset += total;
            return (total > 0) ? total : SYS_ERR(EFAULT);
        }
        int r = f->ops->write(f->priv, staging, chunk);
        if (r <= 0) {
            sched_current()->write_nonblock = 0;
            f->offset += total;   /* advance by what succeeded (see below) */
            return (total > 0) ? total : (uint64_t)(int64_t)r;
        }
        total += (uint64_t)r;
        if ((uint64_t)r < chunk) break;  /* short write — don't retry */
    }
    sched_current()->write_nonblock = 0;
    /* Advance the file offset by the bytes written, mirroring sys_read. POSIX
     * requires write() to move the offset; without this a write-only fd keeps
     * f->offset==0, so a later lseek(SEEK_CUR) reports 0 and (via the fs seek
     * hook) resets the fs write position to 0 — musl stdio does exactly this
     * between writes, which made every multi-write tool (echo, cp) clobber
     * offset 0 and persist only its last byte. */
    f->offset += total;
    return total;
}

/*
 * sys_writev — syscall 20
 *
 * arg1 = fd
 * arg2 = user pointer to struct iovec array
 * arg3 = iovcnt (number of vectors)
 *
 * musl's __stdio_write uses writev instead of write for buffered I/O.
 * We implement it by iterating over the iovec array and calling the fd's
 * write op for each non-empty vector.
 *
 * struct iovec { void *iov_base; size_t iov_len; }  — 16 bytes on x86-64.
 * Returns total bytes written on success, negative errno on failure.
 * Requires CAP_KIND_VFS_WRITE.
 */
uint64_t
sys_writev(uint64_t arg1, uint64_t arg2, uint64_t arg3)
{
    aegis_process_t *proc = current_proc();

    if (cap_check(proc->caps, CAP_TABLE_SIZE,
                  CAP_KIND_VFS_WRITE, CAP_RIGHTS_WRITE) != 0)
        return SYS_ERR(ENOCAP);

    if (arg1 >= PROC_MAX_FDS || !proc->fd_table->fds[arg1].ops ||
        !proc->fd_table->fds[arg1].ops->write)
        return SYS_ERR(EBADF);

    if ((proc->fd_table->fds[arg1].flags & VFS_O_ACCMODE) == VFS_O_RDONLY)
        return SYS_ERR(EBADF);       /* fd not opened for writing */

    /* AUTH-gated fd re-check on use — see the comment in sys_write. */
    if ((proc->fd_table->fds[arg1].kflags & VFS_KF_AUTH_GATED) &&
        cap_check(proc->caps, CAP_TABLE_SIZE, CAP_KIND_AUTH, CAP_RIGHTS_READ) != 0)
        return SYS_ERR(EACCES);

    /* Reject unreasonable iovcnt before multiplying to avoid overflow. */
    if (arg3 > 1024)
        return SYS_ERR(EINVAL);

    /* Validate the iovec array itself is in user space */
    if (!user_ptr_valid(arg2, arg3 * sizeof(aegis_iovec_t)))
        return SYS_ERR(EFAULT);

    uint64_t total = 0;
    uint64_t i;
    for (i = 0; i < arg3; i++) {
        aegis_iovec_t iov;
        /* Copy the iovec descriptor from user space. On a fault `iov` would
         * otherwise keep stack garbage and be used as a base/length pair. */
        if (copy_from_user(&iov,
                           (const void *)(uintptr_t)(arg2 + i * sizeof(aegis_iovec_t)),
                           sizeof(aegis_iovec_t)) != 0)
            return (total > 0) ? total : SYS_ERR(EFAULT);

        if (iov.iov_len == 0)
            continue;

        if (!user_ptr_valid(iov.iov_base, iov.iov_len))
            return SYS_ERR(EFAULT);

        /* S8: Copy user buffer to kernel staging area to prevent TOCTOU.
         * The user could unmap the page between validation and use.
         * Copy in page-size chunks and write from kernel memory. */
        uint64_t vec_written = 0;
        while (vec_written < iov.iov_len) {
            uint8_t staging[4096];
            uint64_t remaining = iov.iov_len - vec_written;
            uint64_t chunk = remaining > sizeof(staging) ? sizeof(staging) : remaining;
            /* Same stale-stack leak as sys_write — see the comment there. */
            if (copy_from_user(staging,
                               (const void *)(uintptr_t)(iov.iov_base + vec_written),
                               chunk) != 0) {
                if (total == 0)
                    return SYS_ERR(EFAULT);
                goto done;
            }
            int r = proc->fd_table->fds[arg1].ops->write(
                        proc->fd_table->fds[arg1].priv,
                        staging,
                        chunk);
            if (r <= 0) {
                if (r < 0 && total == 0)
                    return (uint64_t)(int64_t)r;
                goto done;
            }
            vec_written += (uint64_t)r;
        }
        total += vec_written;
    }
done:
    /* Advance the file offset by bytes written — same reason as sys_write, and
     * this is the path musl's buffered stdio actually uses (__stdio_write ->
     * writev), so it is what makes redirected `echo`/`cp` persist correctly. */
    proc->fd_table->fds[arg1].offset += total;
    return total;
}

/*
 * sys_readv — syscall 19
 *
 * arg1 = fd
 * arg2 = user pointer to struct iovec array
 * arg3 = iovcnt
 *
 * musl's __stdio_read issues readv(fd, iov[2]) whenever the caller's
 * buffer is non-trivial (fread, fscanf, getline...) and only falls back
 * to plain read for the 1-byte getc path — so without readv, fread()
 * silently returns 0 while fgets() works. Went unnoticed until 1.2.0's
 * ps/free became the first bulk stdio readers in the userland.
 *
 * Each vector is delegated to sys_read, which already does the cap
 * check, fd validation, EFAULT checks, and per-device blocking. A
 * short read (EOF, or a device with no more data) ends the loop —
 * never block again after partial data, matching readv semantics.
 */
uint64_t
sys_readv(uint64_t arg1, uint64_t arg2, uint64_t arg3)
{
    if (arg3 > 1024)
        return SYS_ERR(EINVAL);
    if (!user_ptr_valid(arg2, arg3 * sizeof(aegis_iovec_t)))
        return SYS_ERR(EFAULT);

    uint64_t total = 0;
    uint64_t i;
    for (i = 0; i < arg3; i++) {
        aegis_iovec_t iov;
        if (copy_from_user(&iov,
                           (const void *)(uintptr_t)(arg2 + i * sizeof(aegis_iovec_t)),
                           sizeof(aegis_iovec_t)) != 0)
            return (total > 0) ? total : SYS_ERR(EFAULT);
        if (iov.iov_len == 0)
            continue;

        uint64_t r = sys_read(arg1, iov.iov_base, iov.iov_len);
        if ((int64_t)r < 0)
            return (total > 0) ? total : r;
        total += r;
        if (r < iov.iov_len)
            break;  /* short read — don't block for the next vector */
    }
    return total;
}

/*
 * sys_read — syscall 0
 *
 * arg1 = fd
 * arg2 = user pointer to buffer
 * arg3 = byte count
 *
 * Returns bytes read (0 = EOF), negative errno on failure.
 */
uint64_t
sys_read(uint64_t arg1, uint64_t arg2, uint64_t arg3)
{
    aegis_process_t *proc = current_proc();
    if (cap_check(proc->caps, CAP_TABLE_SIZE,
                  CAP_KIND_VFS_READ, CAP_RIGHTS_READ) != 0)
        return SYS_ERR(ENOCAP);

    if (arg1 >= PROC_MAX_FDS)
        return SYS_ERR(EBADF);
    vfs_file_t *f = &proc->fd_table->fds[arg1];
    if (!f->ops)
        return SYS_ERR(EBADF);
    if (!f->ops->read)
        return SYS_ERR(EISDIR);  /* directory fd, not readable */
    if ((f->flags & VFS_O_ACCMODE) == VFS_O_WRONLY)
        return SYS_ERR(EBADF);   /* fd not opened for reading */
    /* Re-validate authority on USE, not just at open: an fd onto /etc/shadow or
     * /etc/aegis/admin carries VFS_KF_AUTH_GATED. If it reached a process that
     * lacks CAP_KIND_AUTH — inherited across exec, or dup'd to a capless child —
     * that process must not read the secret through it. (SCM_RIGHTS passing of
     * such an fd is separately refused at the sender.) No ambient authority:
     * holding the fd is not holding the cap. */
    if ((f->kflags & VFS_KF_AUTH_GATED) &&
        cap_check(proc->caps, CAP_TABLE_SIZE, CAP_KIND_AUTH, CAP_RIGHTS_READ) != 0)
        return SYS_ERR(EACCES);
    if (!user_ptr_valid(arg2, arg3))
        return SYS_ERR(EFAULT);

    /* Single read call — return whatever the VFS gives us.
     * Pipe reads may block inside f->ops->read() via sched_block().
     * After unblocking, f->ops->read() returns the byte count and we
     * copy to user space and return normally via sysret.
     *
     * SYS_READ_BUF 4096: large enough for pipe PIPE_BUF_SIZE (4060) reads.
     * Stack budget: 4096 bytes here; sys_write path has ~4060 in pipe_write_fn.
     * These are separate syscall paths — they do not stack on each other.
     * Kernel stack is 16 KB; both are within budget. */
    #define SYS_READ_BUF 4096
    char kbuf[SYS_READ_BUF];
    /* Cap request to current page boundary so copy_to_user never crosses
     * into an unmapped page (e.g. the guard page just past USER_STACK_TOP).
     * Mirrors the same pattern in console_write_fn.  The caller (musl libc)
     * loops on short reads, so returning fewer bytes than requested is safe. */
    uint64_t page_off = arg2 & 0xFFFULL;
    uint64_t to_end   = 0x1000ULL - page_off;
    uint64_t n = arg3;
    if (n > SYS_READ_BUF) n = SYS_READ_BUF;
    if (n > to_end)       n = to_end;
    /* Per-task nonblock flag — safe under preemption (unlike the global). */
    sched_current()->read_nonblock = (f->flags & VFS_O_NONBLOCK) ? 1 : 0;
    vfs_read_nonblock = sched_current()->read_nonblock;  /* compat: kept for non-PTY readers */
    int64_t got = (int64_t)f->ops->read(f->priv, kbuf, f->offset, n);
    sched_current()->read_nonblock = 0;
    vfs_read_nonblock = 0;
    if (got < 0) return (uint64_t)got;   /* propagate -errno (e.g. -EPIPE) */
    if (got == 0) return 0;              /* clean EOF */
    /* Re-validate the user buffer before the copy: f->ops->read above may have
     * BLOCKED (pipe/tty/socket), and a sibling thread (CLONE_VM) could have
     * munmap'd arg2 during that block. copy_to_user is a raw memcpy with no
     * fault fixup, so writing to a now-unmapped page would #PF in ring 0 and
     * panic the kernel. The entry-time user_ptr_valid (line ~248) is stale after
     * a block; re-check the actually-copied range. (Data already drained from
     * the source is lost on EFAULT — a self-inflicted buggy-app case, and far
     * better than a kernel panic.) */
    if (!user_ptr_valid(arg2, (uint64_t)got))
        return SYS_ERR(EFAULT);
    copy_to_user((void *)(uintptr_t)arg2, kbuf, (uint64_t)got);
    f->offset += (uint64_t)got;
    return (uint64_t)got;
}

/* sys_pread64 — syscall 17: read at an explicit offset, leaving f->offset
 * unchanged (curl/RequestServer use pread on the cert/cache files). */
uint64_t
sys_pread64(uint64_t fd, uint64_t buf, uint64_t count, uint64_t off)
{
    aegis_process_t *proc = current_proc();
    if (cap_check(proc->caps, CAP_TABLE_SIZE,
                  CAP_KIND_VFS_READ, CAP_RIGHTS_READ) != 0)
        return SYS_ERR(ENOCAP);
    if (fd >= PROC_MAX_FDS) return SYS_ERR(EBADF);
    vfs_file_t *f = &proc->fd_table->fds[fd];
    if (!f->ops) return SYS_ERR(EBADF);
    if (!f->ops->read) return SYS_ERR(EISDIR);
    if ((f->flags & VFS_O_ACCMODE) == VFS_O_WRONLY)
        return SYS_ERR(EBADF);   /* fd not opened for reading */
    /* AUTH-gated secret (see sys_read): re-check the caller holds AUTH so a
     * laundered /etc/shadow fd can't be pread by a capless process. */
    if ((f->kflags & VFS_KF_AUTH_GATED) &&
        cap_check(proc->caps, CAP_TABLE_SIZE, CAP_KIND_AUTH, CAP_RIGHTS_READ) != 0)
        return SYS_ERR(EACCES);
    if (!user_ptr_valid(buf, count)) return SYS_ERR(EFAULT);
    char kbuf[4096];
    uint64_t page_off = buf & 0xFFFULL;
    uint64_t to_end   = 0x1000ULL - page_off;
    uint64_t n = count;
    if (n > 4096) n = 4096;
    if (n > to_end) n = to_end;
    int64_t got = (int64_t)f->ops->read(f->priv, kbuf, off, n);
    if (got < 0) return (uint64_t)got;
    if (got == 0) return 0;
    /* Re-validate after a possibly-blocking read (pread on a pipe/socket fd
     * blocks) — see sys_read: copy_to_user has no fault fixup, and a sibling
     * munmap during the block would otherwise panic the kernel. */
    if (!user_ptr_valid(buf, (uint64_t)got))
        return SYS_ERR(EFAULT);
    copy_to_user((void *)(uintptr_t)buf, kbuf, (uint64_t)got);
    return (uint64_t)got;   /* pread does NOT advance f->offset */
}

/* sys_pwrite64 — syscall 18: write at an explicit offset without changing the
 * fd's file offset (SQLite writes DB pages via pwrite; the whole "disk I/O
 * error" class needs this). The write op is offset-less (it uses the driver's
 * internal cursor), so seek that cursor to `off`, write, then re-sync it to the
 * fd's logical offset. f->offset is untouched (POSIX: pwrite leaves it alone).
 * ponytail: a program mixing lseek-less sequential write() with pwrite() on one
 * fd could be surprised by the cursor re-sync — SQLite uses pread/pwrite
 * exclusively (re-seeks every op), so this is correct where it matters. */
uint64_t
sys_pwrite64(uint64_t fd, uint64_t buf, uint64_t count, uint64_t off)
{
    aegis_process_t *proc = current_proc();
    if (cap_check(proc->caps, CAP_TABLE_SIZE,
                  CAP_KIND_VFS_WRITE, CAP_RIGHTS_WRITE) != 0)
        return SYS_ERR(ENOCAP);
    if (fd >= PROC_MAX_FDS) return SYS_ERR(EBADF);
    vfs_file_t *f = &proc->fd_table->fds[fd];
    if (!f->ops || !f->ops->write) return SYS_ERR(EBADF);
    if ((f->flags & VFS_O_ACCMODE) == VFS_O_RDONLY)
        return SYS_ERR(EBADF);           /* fd not opened for writing */
    /* AUTH-gated fd re-check on use — see the comment in sys_write. */
    if ((f->kflags & VFS_KF_AUTH_GATED) &&
        cap_check(proc->caps, CAP_TABLE_SIZE, CAP_KIND_AUTH, CAP_RIGHTS_READ) != 0)
        return SYS_ERR(EACCES);
    if (!f->ops->seek)
        return SYS_ERR(ESPIPE);          /* not positionable → can't pwrite */
    if (!user_ptr_valid(buf, count)) return SYS_ERR(EFAULT);
    char kbuf[4096];
    uint64_t page_off = buf & 0xFFFULL;
    uint64_t to_end   = 0x1000ULL - page_off;
    uint64_t n = count;
    if (n > 4096) n = 4096;
    if (n > to_end) n = to_end;
    /* Same stale-stack leak as sys_write, but written at an attacker-chosen
     * file offset — see the comment there. */
    if (copy_from_user(kbuf, (const void *)(uintptr_t)buf, n) != 0)
        return SYS_ERR(EFAULT);
    f->ops->seek(f->priv, off);
    int64_t wrote = (int64_t)f->ops->write(f->priv, kbuf, n);
    f->ops->seek(f->priv, f->offset);    /* restore driver cursor to fd offset */
    if (wrote < 0) return (uint64_t)wrote;
    return (uint64_t)wrote;              /* pwrite does NOT advance f->offset */
}

/*
 * sys_close — syscall 3
 *
 * arg1 = fd
 *
 * Returns 0 on success, -9 (EBADF) if fd is invalid or already closed.
 */
uint64_t
sys_close(uint64_t arg1)
{
    if (arg1 >= PROC_MAX_FDS)
        return SYS_ERR(EBADF);
    aegis_process_t *proc = current_proc();
    /* Detach the slot UNDER the table lock so a concurrent fd_table_copy
     * (fork/clone from a sibling sharing this table) cannot snapshot the slot
     * and then ->dup an object we are about to release. Close AFTER the
     * unlock: ops->close does real work and must not run under a spinlock. */
    irqflags_t fl = spin_lock_irqsave(&proc->fd_table->lock);
    vfs_file_t *f = &proc->fd_table->fds[arg1];
    if (!f->ops) {
        spin_unlock_irqrestore(&proc->fd_table->lock, fl);
        return SYS_ERR(EBADF);
    }
    const vfs_ops_t *ops = f->ops;
    void *priv = f->priv;
    f->ops    = (const vfs_ops_t *)0;
    f->priv   = (void *)0;
    f->kflags = 0;   /* clear authority markers (VFS_KF_*) so a REUSED slot can't
                      * inherit a stale AUTH_GATED/PROTECTED bit — invariant: a
                      * free slot (ops==NULL) has kflags==0. Creation paths that
                      * don't set kflags (memfd/pipe/socket) then stay clean. */
    spin_unlock_irqrestore(&proc->fd_table->lock, fl);
    ops->close(priv);
    return 0;
}
