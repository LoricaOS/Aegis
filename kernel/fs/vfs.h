#ifndef VFS_H
#define VFS_H

#include <stdint.h>
#include "../limits.h"

/* 64: Lumen spends ~2 fds per hosted window (client socket + window memfd),
 * so 16 capped the compositor at ~6 concurrent windows — a multi-window
 * desktop (dock + launcher + several apps + menus) hit EMFILE on the next
 * memfd_create (1.2.0). fd_table_t is allocated from KVA; fd_table_alloc
 * (fd_table.c) now sizes the allocation as ceil(PROC_MAX_FDS *
 * sizeof(vfs_file_t) / PAGE_SIZE) pages, so a future bump needs no alloc
 * change. 64 * sizeof(vfs_file_t=40) = 2560 B still fits one page today.
 * (Was 8 pre-Phase-16, 16 through 1.1.x.)
 * Value single-sourced in limits.h (AEGIS_PROC_MAX_FDS). */
#define PROC_MAX_FDS AEGIS_PROC_MAX_FDS

/* ── stat types and mode constants ──────────────────────────────────────── */

/* S_IF* constants — match Linux/POSIX values used in st_mode */
#define S_IFMT   0170000U
#define S_IFREG  0100000U  /* regular file */
#define S_IFDIR  0040000U  /* directory */
#define S_IFCHR  0020000U  /* character device */
#define S_IFIFO  0010000U  /* FIFO / pipe */
#define S_IFLNK  0120000U  /* symbolic link */

/* makedev — encode major/minor into rdev field (Linux encoding) */
#define makedev(maj, min) \
    (((uint64_t)(maj) << 8) | (uint64_t)((min) & 0xFF))

/*
 * k_stat_t — kernel-side stat structure. Layout MUST match Linux x86-64
 * struct stat exactly (musl passes a pointer to struct stat directly).
 * Verified against musl arch/x86_64/bits/stat.h: total = 144 bytes.
 */
typedef struct {
    uint64_t st_dev;        /*   0 */
    uint64_t st_ino;        /*   8 */
    uint64_t st_nlink;      /*  16 */
    uint32_t st_mode;       /*  24 */
    uint32_t st_uid;        /*  28 */
    uint32_t st_gid;        /*  32 */
    uint32_t __pad0;        /*  36 */
    uint64_t st_rdev;       /*  40 */
    int64_t  st_size;       /*  48 */
    int64_t  st_blksize;    /*  56 */
    int64_t  st_blocks;     /*  64 */
    int64_t  st_atime;      /*  72 */
    int64_t  st_atime_nsec; /*  80 */
    int64_t  st_mtime;      /*  88 */
    int64_t  st_mtime_nsec; /*  96 */
    int64_t  st_ctime;      /* 104 */
    int64_t  st_ctime_nsec; /* 112 */
    int64_t  __unused[3];   /* 120 */
} k_stat_t;

_Static_assert(sizeof(k_stat_t) == 144,
    "k_stat_t must be 144 bytes (Linux x86-64 struct stat)");

/* ── VFS operations vtable ───────────────────────────────────────────────── */

/* Forward decl — full type in kernel/sched/waitq.h. */
struct waitq;

/* File operations vtable. Each open file carries a pointer to its driver's ops. */
typedef struct {
    /* read — copy up to len bytes starting at off into buf (kernel buffer).
     * Returns bytes copied (0 = EOF, negative = error). */
    int (*read)(void *priv, void *buf, uint64_t off, uint64_t len);
    /* write — copy len bytes from user-space buf to device.
     * Returns bytes written, or negative errno. NULL = not writable. */
    int (*write)(void *priv, const void *buf, uint64_t len);
    /* close — release any driver-side resources for this file. */
    void (*close)(void *priv);
    /* readdir -- fill name_out (>=256 bytes) and type_out with the entry at index.
     * Returns 0 on success, -1 if index is past the last entry.
     * type: DT_REG=8, DT_DIR=4.
     * Set to NULL for non-directory fds (e.g. console, kbd). */
    int (*readdir)(void *priv, uint64_t index, char *name_out, uint8_t *type_out);
    /* dup — called when this fd is duplicated (dup/dup2/fork).
     * Increment any reference counts held by this driver.
     * NULL = stateless driver, no action needed (initrd, console, kbd). */
    void (*dup)(void *priv);
    /* stat — fill *st with file metadata.
     * NULL = driver has no stat; sys_fstat synthesizes a minimal stat.
     * Returns 0 on success. */
    int (*stat)(void *priv, k_stat_t *st);
    /* poll -- report current readiness events for this fd.
     * Returns a bitmask of POLLIN/POLLOUT/POLLHUP/POLLERR.
     * Called from sys_poll / epoll_wait with no locks held.
     * NULL = fd does not support polling (caller assumes POLLIN|POLLOUT). */
    uint16_t (*poll)(void *priv);
    /* get_waitq — return the wait queue for this fd, or NULL if the fd
     * type has no events to wait on (e.g. memfd is always ready).
     * Used by sys_poll / sys_epoll_wait to register on the right queue.
     * NULL is the default — caller falls back to PIT-tick polling for
     * fds without a waitq. */
    struct waitq *(*get_waitq)(void *priv);
    /* seek — reposition the driver's internal WRITE cursor to `offset`.
     * ops->write takes no offset (unlike ops->read, which gets f->offset), so a
     * driver that keeps its own sequential write position (ext2) needs lseek to
     * update it — otherwise a seek-then-write (e.g. `as` patching an ELF header
     * after writing sections) writes at the stale position and corrupts the
     * file. sys_lseek calls this after updating f->offset. NULL = writes ignore
     * lseek (streams; append-only ramfs). */
    void (*seek)(void *priv, uint64_t offset);
    /* seekable — 1 if this driver backs a byte-addressable regular file whose
     * f->offset is meaningful (ext2/ramfs/memfd/initrd). 0 (default) for stream
     * fds (pipes, console, kbd, char devices) where lseek must return ESPIPE.
     * Only consulted for empty (size==0) files: a size-0 regular file is still
     * seekable (e.g. `as` seeks around a freshly-created .o to lay out the ELF),
     * whereas a size-0 stream is not. */
    int seekable;
} vfs_ops_t;

/* Open file descriptor. Stored in fd_table_t.fds[].
 * ops == NULL means the slot is free. */
typedef struct {
    const vfs_ops_t *ops;    /* NULL = free slot */
    void            *priv;   /* driver-private data */
    uint64_t         offset; /* current read position */
    uint64_t         size;   /* file size in bytes; 0 for devices/directories */
    uint32_t         flags;  /* open flags: O_RDONLY(0)/O_WRONLY(1)/O_RDWR(2)/O_NONBLOCK */
    uint32_t         kflags; /* kernel-internal fd flags (VFS_KF_*); was _pad */
} vfs_file_t;

_Static_assert(sizeof(vfs_file_t) == 40, "vfs_file_t must be 40 bytes");

/* VFS_KF_PROTECTED — set in vfs_file_t.kflags at open time when the file
 * resolves under an install-protected tree (/bin,/sbin,/apps,/etc/aegis).
 * fd-based mutators (fchmod/fchown/ftruncate) require CAP_KIND_INSTALL when
 * this bit is set, so an O_RDONLY fd can't be used to bypass the path-based
 * install-protection gate. Copied across dup/dup2 with the rest of the struct. */
#define VFS_KF_PROTECTED 0x1U

/* VFS_KF_AUTH_GATED — set in vfs_file_t.kflags when a fd is opened onto a file
 * whose OPEN required CAP_KIND_AUTH (/etc/shadow, /etc/aegis/admin — secret
 * content). The AUTH cap is checked once, at open; the resulting fd carries no
 * further check, so passing it over SCM_RIGHTS to a process that lacks AUTH
 * would launder read-access to the secret. sys_recvmsg re-validates the
 * RECEIVER holds AUTH before installing such a fd (no ambient authority: you
 * cannot gain the secret by being handed an fd — you must hold the cap). */
#define VFS_KF_AUTH_GATED 0x2U

/* O_NONBLOCK flag value (Linux x86-64).  Stored in vfs_file_t.flags by
 * fcntl(F_SETFL).  sys_read sets vfs_read_nonblock before calling a VFS
 * read op so that blocking drivers (PTY master, pipes) can return -EAGAIN
 * instead of sleeping.  Single-core: no locking needed. */
/* Access-mode field of vfs_file_t.flags (POSIX low 2 bits). sys_read/pread
 * reject O_WRONLY fds; sys_write/writev reject O_RDONLY fds — the fd's mode
 * is enforced at the syscall boundary, not just capability-gated at open.
 * Every fd-creation site must set an honest mode (sockets/ptys/memfds/console
 * are O_RDWR; a pipe's read end is O_RDONLY, its write end O_WRONLY). */
#define VFS_O_ACCMODE  0x3U
#define VFS_O_RDONLY   0x0U
#define VFS_O_WRONLY   0x1U
#define VFS_O_RDWR     0x2U

#define VFS_O_NONBLOCK 0x800U
extern int vfs_read_nonblock;

/* vfs_init — print [VFS] OK line and register built-in drivers.
 * Called from kernel_main before sched_init. */
void vfs_init(void);

/* Linux open flag values (used by vfs_open for ext2) */
#define VFS_O_TRUNC  0x200U
#define VFS_O_APPEND 0x400U

/* Linux O_CREAT flag value (used by vfs_open for ext2 file creation) */
#define VFS_O_CREAT 0x40U

/* Linux O_EXCL: with O_CREAT, open MUST fail EEXIST if the file exists —
 * the atomic-create guarantee mkstemp/lockfiles depend on. Ignoring it let
 * two concurrent gcc's open the SAME /tmp temp file (interleaved asm). */
#define VFS_O_EXCL 0x80U

/* VFS_O_CLOEXEC — Linux O_CLOEXEC flag value, as passed in open/pipe2 flags arg.
 * Must match VFS_FD_CLOEXEC so that `flags & VFS_O_CLOEXEC` maps to the fd bit. */
#define VFS_O_CLOEXEC 0x80000U

/* FD_CLOEXEC — close-on-exec flag stored in vfs_file_t.flags.
 * Set when O_CLOEXEC is passed to open/pipe2; cleared on dup/dup2 (POSIX).
 * Same bit value as VFS_O_CLOEXEC by design — no shift needed at install time. */
#define VFS_FD_CLOEXEC 0x80000U

_Static_assert(VFS_O_CLOEXEC == VFS_FD_CLOEXEC,
    "VFS_O_CLOEXEC and VFS_FD_CLOEXEC must be the same bit value");

/* vfs_open — find a file by path across all registered drivers.
 * flags: open flags (e.g. VFS_O_CREAT to create the file if missing on ext2).
 * create_mode: permission bits (low 12, e.g. 0755) for a file newly created via
 *   O_CREAT; ignored when the file exists or O_CREAT is not set. Pass 0 for
 *   read-only opens (defaults to 0644 if a create unexpectedly happens).
 * Populates *out on success; returns 0 on success, -2 (ENOENT) if not found.
 * Called by sys_open to resolve path to a vfs_file_t. */
int vfs_open(const char *path, int flags, uint16_t create_mode, vfs_file_t *out);

/* vfs_ramfs_unlink / vfs_ramfs_rename — route /tmp and /run (ramfs) paths to
 * the ramfs delete/rename. Return 1 and set *out_rc if the path(s) are on a
 * ramfs mount; return 0 if the caller should fall through to ext2. */
int vfs_ramfs_unlink(const char *path, int *out_rc);
int vfs_ramfs_rename(const char *oldp, const char *newp, int *out_rc);
int vfs_ramfs_mkdir(const char *path, int *out_rc);

/* vfs_stat_path — stat a file by path.
 * Handles initrd files, directory paths (/,/etc,/bin), and /dev/ specials.
 * Returns 0 on success, -2 (ENOENT) if not found. */
int vfs_stat_path(const char *path, k_stat_t *out);

/* vfs_stat_path_ex — stat with symlink-follow control.
 * follow: 1 = follow symlinks (stat), 0 = no-follow (lstat).
 * For non-ext2 paths, delegates to vfs_stat_path (no symlinks).
 * Returns 0 on success, -2 (ENOENT) if not found. */
int vfs_stat_path_ex(const char *path, k_stat_t *out, int follow);

/* vfs_fchmod — change mode of an open ext2 file descriptor.
 * Returns 0 on success, -1 if not an ext2 fd. */
int vfs_fchmod(vfs_file_t *f, uint16_t mode);

/* vfs_fchown — change owner/group of an open ext2 file descriptor.
 * Returns 0 on success, -1 if not an ext2 fd. */
int vfs_fchown(vfs_file_t *f, uint16_t uid, uint16_t gid);

#endif /* VFS_H */
