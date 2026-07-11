/* ext2.h — ext2 filesystem driver
 *
 * Read-write ext2 over blkdev. No journal (ext2, not ext3/4).
 * Block cache: 16-slot LRU. Single indirect blocks supported.
 */
#ifndef EXT2_H
#define EXT2_H

#include <stdint.h>

#define EXT2_MAGIC          0xEF53
/* s_state flags (superblock byte offset 58): VALID_FS set = volume was cleanly
 * unmounted; ERROR_FS set = errors were detected.  Used for unclean-shutdown
 * detection at mount — detection only, there is no journal or in-kernel fsck. */
#define EXT2_VALID_FS       0x0001
#define EXT2_ERROR_FS       0x0002
#define EXT2_ROOT_INODE     2
#define EXT2_DIRECT_BLOCKS  12
#define EXT2_NAME_LEN       255

/* Superblock — at byte offset 1024 from partition start */
typedef struct __attribute__((packed)) {
    uint32_t s_inodes_count;
    uint32_t s_blocks_count;
    uint32_t s_r_blocks_count;
    uint32_t s_free_blocks_count;
    uint32_t s_free_inodes_count;
    uint32_t s_first_data_block;
    uint32_t s_log_block_size;      /* block_size = 1024 << s_log_block_size */
    uint32_t s_log_frag_size;
    uint32_t s_blocks_per_group;
    uint32_t s_frags_per_group;
    uint32_t s_inodes_per_group;
    uint32_t s_mtime;
    uint32_t s_wtime;
    uint16_t s_mnt_count;
    uint16_t s_max_mnt_count;
    uint16_t s_magic;
    uint16_t s_state;
    uint16_t s_errors;
    uint16_t s_minor_rev_level;
    uint32_t s_lastcheck;
    uint32_t s_checkinterval;
    uint32_t s_creator_os;
    uint32_t s_rev_level;
    uint16_t s_def_resuid;
    uint16_t s_def_resgid;
    /* EXT2_DYNAMIC_REV fields */
    uint32_t s_first_ino;
    uint16_t s_inode_size;
    uint16_t s_block_group_nr;
    uint32_t s_feature_compat;
    uint32_t s_feature_incompat;
    uint32_t s_feature_ro_compat;
    uint8_t  s_uuid[16];
    char     s_volume_name[16];
    char     s_last_mounted[64];
    uint32_t s_algo_bitmap;
    /* Padding to 1024 bytes total — we only read what we need */
} ext2_superblock_t;

/* Block Group Descriptor — 32 bytes */
typedef struct __attribute__((packed)) {
    uint32_t bg_block_bitmap;
    uint32_t bg_inode_bitmap;
    uint32_t bg_inode_table;
    uint16_t bg_free_blocks_count;
    uint16_t bg_free_inodes_count;
    uint16_t bg_used_dirs_count;
    uint16_t bg_pad;
    uint8_t  bg_reserved[12];
} ext2_bgd_t;

/* Inode — 128 bytes (ext2 rev 0) */
typedef struct __attribute__((packed)) {
    uint16_t i_mode;
    uint16_t i_uid;
    uint32_t i_size;
    uint32_t i_atime;
    uint32_t i_ctime;
    uint32_t i_mtime;
    uint32_t i_dtime;
    uint16_t i_gid;
    uint16_t i_links_count;
    uint32_t i_blocks;          /* 512-byte sectors */
    uint32_t i_flags;
    uint32_t i_osd1;
    uint32_t i_block[15];       /* [0..11] direct, [12] indirect, [13] double, [14] triple */
    uint32_t i_generation;
    uint32_t i_file_acl;
    uint32_t i_dir_acl;
    uint32_t i_faddr;
    uint8_t  i_osd2[12];
} ext2_inode_t;

/* Directory entry */
typedef struct __attribute__((packed)) {
    uint32_t inode;
    uint16_t rec_len;
    uint8_t  name_len;
    uint8_t  file_type;
    char     name[EXT2_NAME_LEN];
} ext2_dirent_t;

/* File type values in directory entries */
#define EXT2_FT_UNKNOWN  0
#define EXT2_FT_REG_FILE 1
#define EXT2_FT_DIR      2

/* Inode mode bits */
#define EXT2_S_IFMT   0xF000
#define EXT2_S_IFREG  0x8000
#define EXT2_S_IFDIR  0x4000
#define EXT2_S_IFLNK  0xA000

/* Directory entry file type for symlinks */
#define EXT2_FT_SYMLINK  7

/* Maximum symlink depth before returning ELOOP */
#define SYMLINK_MAX_DEPTH 8

/* Mount an ext2 filesystem from the named block device.
 * Returns 0 on success, -1 on failure. */
int ext2_mount(const char *devname);

/* Re-read /etc/aegis/anchors and record each listed dir as a dynamic install
 * anchor (trusted-path + write-protected). Call at boot after mount and after a
 * package install (sys_install_commit). Idempotent; safe if the file is absent. */
void ext2_anchors_reload(void);

/* Low-level inode access */
int ext2_read_inode(uint32_t ino, ext2_inode_t *out);
int ext2_write_inode(uint32_t ino, const ext2_inode_t *inode);

/* File operations for VFS integration */
int ext2_open(const char *path, uint32_t *inode_out);
int ext2_read(uint32_t inode_num, void *buf, uint64_t offset, uint32_t len);

/* secfix M2 — lazy file mmap inode-recycle defense.
 * EXT2_EGEN: ext2_read_validated saw the backing inode's generation change
 * (number recycled for a different file) → caller must fault, not read. */
#define EXT2_EGEN (-2)
uint32_t ext2_inode_gen(uint32_t inode_num);
int ext2_read_validated(uint32_t inode_num, void *buf, uint64_t offset,
                        uint32_t len, uint32_t expect_gen);
int ext2_write(uint32_t inode_num, const void *buf, uint32_t offset, uint32_t len);
/* ext2_truncate — drop a regular file to length 0, freeing ALL its data blocks
 * (direct + indirect trees + pointer blocks).  Used by the O_TRUNC open path,
 * which previously zeroed only i_size and leaked every block. Returns 0 / -1. */
int ext2_truncate(uint32_t inode_num);
/* Path-mutating operations take has_install: 1 if the caller holds
 * CAP_KIND_INSTALL (or is trusted kernel/boot context), 0 otherwise. Each
 * checks — atomically, under the single ext2_lock it already holds across
 * resolve+mutate — whether the target resolves under an install-protected tree
 * and, if so, refuses with -EPERM unless has_install. Doing the check inside
 * the lock (not in the syscall layer, which released the lock between check and
 * mutate) closes the symlink-swap TOCTOU: a concurrent rename/symlink cannot
 * change what the path resolves to between the protection check and the
 * mutation. */
int ext2_create(const char *path, uint16_t mode, int has_install);
int ext2_unlink(const char *path, int has_install);
int ext2_mkdir(const char *path, uint16_t mode, int has_install);
int ext2_rmdir(const char *path, int has_install);
int ext2_rename(const char *old_path, const char *new_path, int has_install);
int ext2_file_size(uint32_t inode_num);

/* ext2_perfbench — block-cache throughput micro-benchmark.  Writes a large
 * file to the ext2 root then reads it back, printing MiB/ms/MB/s to serial.
 * Invoked from boot only when the `perfbench_fs` cmdline token is present
 * (so it never perturbs the boot oracle). */
void ext2_perfbench(void);

/* Filesystem totals from the in-memory superblock, in 1K units.
 * Returns 0 on success, -1 if no ext2 volume is mounted. */
int ext2_statfs(uint64_t *total_kb, uint64_t *free_kb);

/* Name of the block device the ext2 root was mounted from
 * (e.g. "ramdisk0", "nvme0p1").  NULL if not mounted. */
const char *ext2_devname(void);
int ext2_readdir(uint32_t dir_inode, uint64_t index,
                 char *name_out, uint8_t *type_out);
int ext2_is_dir(uint32_t ino);

/* Symlink operations */
int ext2_symlink(const char *linkpath, const char *target, int has_install);
int ext2_readlink(const char *path, char *buf, uint32_t bufsiz);
int ext2_read_symlink_target(uint32_t ino, char *buf, uint32_t bufsiz);

/* Permission check — POSIX DAC (no root bypass) */
int ext2_check_perm(uint32_t ino, uint16_t proc_uid, uint16_t proc_gid, int want);

/* Metadata modification (has_install: see the mutating-ops note above) */
int ext2_chmod(const char *path, uint16_t mode, int has_install);
int ext2_chown(const char *path, uint16_t uid, uint16_t gid, int follow, int has_install);

/* utimensat: leave a timestamp field unchanged (UTIME_OMIT) */
#define EXT2_UTIME_KEEP 0xFFFFFFFFu
int ext2_utimes(const char *path, uint32_t atime, uint32_t mtime, int follow, int has_install);

/* Hard link: newpath becomes another name for oldpath's inode. */
int ext2_link(const char *oldpath, const char *newpath, int has_install);

/* Path walk with symlink following control.
 * follow_final: 1 = follow symlinks on final component, 0 = no-follow (lstat). */
int ext2_open_ex(const char *path, uint32_t *inode_out, int follow_final);

/* Split path into parent directory inode and basename */
int ext2_lookup_parent(const char *path, uint32_t *parent_ino_out,
                       const char **basename_out);

/* Flush all dirty cache slots to disk */
void ext2_sync(void);

/* Restore the superblock's clean state (set EXT2_VALID_FS) — call on an orderly
 * shutdown, after ext2_sync(), so the next mount does not report an unclean
 * unmount.  No-op if no volume is mounted. */
void ext2_mark_clean(void);

/* Returns the inode of /etc/shadow on the mounted ext2 volume (0 if absent).
 * Used by vfs_open for post-symlink-resolution CAP_KIND_AUTH enforcement. */
uint32_t ext2_get_shadow_ino(void);

/* Returns the inode of /etc/aegis/admin (the admin-elevation credential hash)
 * on the mounted ext2 volume (0 if absent).  Used by vfs_open for the same
 * post-symlink-resolution CAP_KIND_AUTH read enforcement as /etc/shadow. */
uint32_t ext2_get_admin_ino(void);

/* Return the inodes of /etc/passwd and /etc/group on the mounted volume (0 if
 * absent).  Used by the sensitive-inode mutation gate (vfs_open write path +
 * the sys_dir/sys_meta mutators) to require an admin_session before the account
 * identity DB can be modified — these are world-readable but admin-managed. */
uint32_t ext2_get_passwd_ino(void);
uint32_t ext2_get_group_ino(void);

/* Returns 1 if mutating `path` would touch the install-protected trees
 * (/apps or /etc/aegis), resolved through symlinks and "." / ".." — set even
 * when the final component does not exist (so O_CREAT targets are caught).
 * Used by the CAP_KIND_INSTALL enforcement to defeat symlink/path bypasses. */
int ext2_path_under_protected(const char *path);

#endif /* EXT2_H */
