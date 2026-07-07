/* kernel/fs/ramfs.h — in-memory filesystem, multi-instance.
 *
 * Design (rewritten 2026-06-24): the standard Unix split — inode (identity +
 * data) is separate from dentry (name).  A file's data lives in an INODE that
 * is never moved or reused while it is referenced (by a dentry or an open fd),
 * so rename() just re-points a name at the same inode and data can never be
 * lost.  The old design coupled a flat full-path name + one data page + an
 * in_use flag into a 32-slot array, with the vfs handle holding a raw pointer
 * into that slot — so any slot reuse aliased the wrong file (which lost
 * Ladybird's /tmp files and broke fontconfig's cache.TMP→rename pattern).
 *
 * Dentry names stay FLAT full relative paths ("lb/o.png") so the VFS routing in
 * vfs.c (which passes path-after-mount) and getdents need no changes.
 */
#ifndef AEGIS_RAMFS_H
#define AEGIS_RAMFS_H

#include "vfs.h"
#include "spinlock.h"
#include <stdint.h>

#define RAMFS_MAX_INODES     256
#define RAMFS_MAX_DENTS      256
#define RAMFS_MAX_NAMELEN    128
#define RAMFS_PAGES_PER_FILE 256                /* 256 * 4 KiB = 1 MiB max/file  */
#define RAMFS_MAX_SIZE       (RAMFS_PAGES_PER_FILE * 4096)

struct ramfs;

/* An inode: the file/dir object.  Identity + data live here, NOT in the name. */
typedef struct {
    uint8_t        in_use;
    uint8_t        is_dir;
    uint32_t       nlink;       /* # dentries naming this inode                */
    uint32_t       open_count;  /* # open fds (unlink-while-open keeps it live) */
    uint32_t       size;        /* byte count                                  */
    uint16_t       npages;      /* allocated data pages                        */
    uint8_t       *pages[RAMFS_PAGES_PER_FILE]; /* kva page ptrs; NULL = hole  */
    struct ramfs  *owner;       /* back-pointer for the close path             */
} ramfs_inode_t;

/* A dentry: a name → inode link.  The directory tree is flat-named here. */
typedef struct {
    uint8_t   in_use;
    char      name[RAMFS_MAX_NAMELEN];  /* flat relative path, e.g. "lb/o.png" */
    uint32_t  inode;                    /* index into inodes[]                 */
} ramfs_dent_t;

typedef struct ramfs {
    ramfs_inode_t inodes[RAMFS_MAX_INODES];
    ramfs_dent_t  dents[RAMFS_MAX_DENTS];
    spinlock_t    lock;
} ramfs_t;

/* ramfs_init — reset all inodes/dentries. Call from vfs_init() before any open. */
void ramfs_init(ramfs_t *inst);

/* ramfs_open — open or create (if flags & VFS_O_CREAT) a named file.
 * name: flat relative path without the mount prefix (e.g. "vigil.pid", "lb/o.png").
 * Returns 0 on success and fills *out; -2 (ENOENT) if not found and !O_CREAT;
 * -12 (ENOMEM) if the inode/dentry pools are full. */
int ramfs_open(ramfs_t *inst, const char *name, int flags, vfs_file_t *out);

/* ramfs_stat — fill *st for a ramfs file. Returns 0, or -2 (ENOENT). */
int ramfs_stat(ramfs_t *inst, const char *name, k_stat_t *st);

/* ramfs_opendir — open the instance as a directory for getdents64. */
int ramfs_opendir(ramfs_t *inst, vfs_file_t *out);

/* ramfs_populate — kernel-side write helper (no user_ptr_valid). kbuf may be
 * NULL (creates an empty file). Returns 0 or -12 (ENOMEM). */
int ramfs_populate(ramfs_t *inst, const char *name,
                   const uint8_t *kbuf, uint32_t len);

/* ramfs_mkdir — create a directory entry. Returns 0, -17 (EEXIST), -12 (ENOMEM). */
int ramfs_mkdir(ramfs_t *inst, const char *name);

/* ramfs_unlink — remove a name. Returns 0, or -2 (ENOENT). The inode (and its
 * data) is freed only when its last dentry AND last open fd are gone. */
int ramfs_unlink(ramfs_t *inst, const char *name);

/* ramfs_rename — re-link oldname → newname (replacing newname if present).
 * Data never moves (the inode is untouched). Returns 0, or -2 (ENOENT). */
int ramfs_rename(ramfs_t *inst, const char *oldname, const char *newname);

#endif /* AEGIS_RAMFS_H */
