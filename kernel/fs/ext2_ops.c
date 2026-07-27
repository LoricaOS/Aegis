/* ext2_ops.c — ext2 as an fs_ops backend.
 *
 * A pure wrapper: the vtable points straight at the existing ext2_* functions,
 * so routing callers through g_rootfs->op() is behaviour-identical to calling
 * ext2_op() directly. This is the seam that later lets FAT (or nullfs) take the
 * root backend's place. When CONFIG_FS_EXT2 is off, ext2_ops.c is not built and
 * g_rootfs is provided by nullfs instead (a future step). */
#include "fs_ops.h"
#include "ext2.h"
#include "ext2_internal.h"   /* ext2_lock_acquire / ext2_lock_release */

const fs_ops_t ext2_ops = {
    .name                 = "ext2",

    .mount                = ext2_mount,
    .sync                 = ext2_sync,
    .statfs               = ext2_statfs,
    .mark_clean           = ext2_mark_clean,
    .devname              = ext2_devname,
    .lock                 = ext2_lock_acquire,
    .unlock               = ext2_lock_release,
    /* ext2_vfs_ino_of's first arg is const vfs_ops_t*; the vtable types it as
     * const void* to stay filesystem-agnostic. */
    .ino_of               = (uint32_t (*)(const void *, void *))ext2_vfs_ino_of,

    .open                 = ext2_open,
    .open_ex              = ext2_open_ex,
    .open_protected       = ext2_open_protected,
    .lookup_parent        = ext2_lookup_parent,
    .path_under_protected = ext2_path_under_protected,

    .create               = ext2_create,
    .mkdir                = ext2_mkdir,
    .rmdir                = ext2_rmdir,
    .unlink               = ext2_unlink,
    .rename               = ext2_rename,
    .link                 = ext2_link,
    .symlink              = ext2_symlink,
    .readlink             = ext2_readlink,
    .chmod                = ext2_chmod,
    .chown                = ext2_chown,
    .utimes               = ext2_utimes,

    .read_inode           = ext2_read_inode,
    .write_inode          = ext2_write_inode,
    .read                 = ext2_read,
    .read_validated       = ext2_read_validated,
    .write                = ext2_write,
    .readdir              = ext2_readdir,
    .file_size            = ext2_file_size,
    .truncate             = ext2_truncate,
    .is_dir               = ext2_is_dir,
    .check_perm           = ext2_check_perm,
    .inode_gen            = ext2_inode_gen,
    .read_symlink_target  = ext2_read_symlink_target,

    .pool_alloc           = ext2_pool_alloc,
    .pool_free            = ext2_pool_free,

    .get_admin_ino        = ext2_get_admin_ino,
    .get_passwd_ino       = ext2_get_passwd_ino,
    .get_shadow_ino       = ext2_get_shadow_ino,
    .get_group_ino        = ext2_get_group_ino,
    .anchors_reload       = ext2_anchors_reload,
};

const fs_ops_t *g_rootfs = &ext2_ops;
