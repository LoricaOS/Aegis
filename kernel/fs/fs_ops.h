#ifndef AEGIS_FS_OPS_H
#define AEGIS_FS_OPS_H

/* fs_ops — the pluggable disk-filesystem backend interface.
 *
 * The VFS routes every path that is NOT a special mount (/proc, initrd, /tmp,
 * /run) to a single "root/disk" backend. Historically that backend was ext2,
 * called directly. This vtable makes it pluggable: ext2 is one implementation
 * (`ext2_ops`), FAT will be another, and `nullfs_ops` (a build with no disk fs)
 * fails every op so an initrd-only kernel still links and boots.
 *
 * `g_rootfs` is ALWAYS a complete vtable (never NULL, no NULL members), so call
 * sites dispatch with a plain `g_rootfs->op(...)` and never null-check.
 *
 * NOTE (phase 1): the inode model is still ext2-shaped — operations key off a
 * uint32 inode number and hand back `ext2_inode_t`. A filesystem without native
 * inodes (FAT) synthesizes stable inode numbers for its directory entries and
 * fills an ext2_inode_t-compatible struct. `ext2_inode_t`/`ext2_fd_priv_t` are
 * the de-facto generic inode / fd-private types for now; generalizing their
 * names (fs_inode_t, ...) is a later cosmetic pass.
 */
#include <stdint.h>
#include "ext2.h"       /* ext2_inode_t — the shared inode type            */
#include "ext2_vfs.h"   /* ext2_fd_priv_t — the shared fd-private type      */

typedef struct fs_ops {
    const char *name;                 /* "ext2", "fat", "none"                    */

    /* superblock */
    int      (*mount)(const char *devname);
    int      (*sync)(void);
    int      (*statfs)(uint64_t *total_kb, uint64_t *free_kb);
    void     (*mark_clean)(void);
    const char *(*devname)(void);

    /* path -> inode */
    int      (*open)(const char *path, uint32_t *ino_out);
    int      (*open_ex)(const char *path, uint32_t *ino_out, int follow_final);
    int      (*open_protected)(const char *path, uint32_t *ino_out, int *is_protected);
    int      (*lookup_parent)(const char *path, uint32_t *parent_ino_out,
                              const char **basename_out);
    int      (*path_under_protected)(const char *path);

    /* namespace mutations (has_install = caller holds the INSTALL capability) */
    int      (*create)(const char *path, uint16_t mode, int has_install);
    int      (*mkdir)(const char *path, uint16_t mode, int has_install);
    int      (*rmdir)(const char *path, int has_install);
    int      (*unlink)(const char *path, int has_install);
    int      (*rename)(const char *old_path, const char *new_path, int has_install);
    int      (*link)(const char *oldpath, const char *newpath, int has_install);
    int      (*symlink)(const char *linkpath, const char *target, int has_install);
    int      (*readlink)(const char *path, char *buf, uint32_t bufsiz);
    int      (*chmod)(const char *path, uint16_t mode, int has_install);
    int      (*chown)(const char *path, uint16_t uid, uint16_t gid, int follow,
                      int has_install);
    int      (*utimes)(const char *path, uint32_t atime, uint32_t mtime, int follow,
                       int has_install);

    /* inode-level I/O + metadata */
    int      (*read_inode)(uint32_t ino, ext2_inode_t *out);
    int      (*write_inode)(uint32_t ino, const ext2_inode_t *inode);
    int      (*read)(uint32_t ino, void *buf, uint64_t off, uint32_t len);
    int      (*read_validated)(uint32_t ino, void *buf, uint64_t off, uint32_t len,
                               uint32_t expect_gen);
    int      (*write)(uint32_t ino, const void *buf, uint32_t off, uint32_t len);
    int      (*readdir)(uint32_t dir_ino, uint64_t index, char *name_out,
                        uint8_t *type_out);
    int      (*file_size)(uint32_t ino);
    int      (*truncate)(uint32_t ino);
    int      (*is_dir)(uint32_t ino);
    int      (*check_perm)(uint32_t ino, uint16_t uid, uint16_t gid, int want);
    uint32_t (*inode_gen)(uint32_t ino);
    int      (*read_symlink_target)(uint32_t ino, char *buf, uint32_t bufsiz);

    /* open-file private-data pool (backs vfs_file_t.priv) */
    ext2_fd_priv_t *(*pool_alloc)(uint32_t ino);
    void     (*pool_free)(ext2_fd_priv_t *p);

    /* protected system-file inodes (0 for a filesystem that has none, e.g. FAT) */
    uint32_t (*get_admin_ino)(void);
    uint32_t (*get_passwd_ino)(void);
    uint32_t (*get_shadow_ino)(void);
    uint32_t (*get_group_ino)(void);
    void     (*anchors_reload)(void);
} fs_ops_t;

/* The active root/disk backend. Always valid. */
extern const fs_ops_t *g_rootfs;

#endif /* AEGIS_FS_OPS_H */
