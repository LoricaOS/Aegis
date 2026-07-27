/* nullfs.c — the "no disk filesystem" backend.
 *
 * Compiled when CONFIG_FS_EXT2 is off and no other disk fs is selected. Every
 * op fails or no-ops, so a kernel whose only filesystems are initrd (read-only)
 * and tmpfs still links and boots: the VFS routes non-special paths here, and
 * they simply don't resolve. This is what makes ext2 optional. A real embedded
 * config replaces nullfs with a FAT backend on the SD card.
 */
#include "fs_ops.h"
#include "vfs.h"
#include "../include/aegis_errno.h"

/* Never used for I/O: nullfs opens always fail before out->ops is set. It only
 * needs to be a stable address for the `f->ops != g_rootfs->file_ops` check. */
static const vfs_ops_t nf_file_ops = {0};

static int      nf_mount(const char *d)                    { (void)d; return -1; }
static int      nf_sync(void)                              { return 0; }
static int      nf_statfs(uint64_t *t, uint64_t *f)        { if (t) *t = 0; if (f) *f = 0; return 0; }
static void     nf_mark_clean(void)                        { }
static const char *nf_devname(void)                        { return "none"; }
static irqflags_t nf_lock(void)                            { return 0; }
static void     nf_unlock(irqflags_t fl)                   { (void)fl; }
static uint32_t nf_ino_of(const void *o, void *p)          { (void)o; (void)p; return 0; }

static int      nf_open(const char *p, uint32_t *i)        { (void)p; (void)i; return -ENOENT; }
static int      nf_open_ex(const char *p, uint32_t *i, int f){ (void)p; (void)i; (void)f; return -ENOENT; }
static int      nf_open_prot(const char *p, uint32_t *i, int *pr){ (void)p; (void)i; if (pr) *pr = 0; return -ENOENT; }
static int      nf_lookup_parent(const char *p, uint32_t *pi, const char **b){ (void)p; (void)pi; (void)b; return -ENOENT; }
static int      nf_under_prot(const char *p)               { (void)p; return 0; }

static int      nf_create(const char *p, uint16_t m, int h){ (void)p; (void)m; (void)h; return -EPERM; }
static int      nf_mkdir(const char *p, uint16_t m, int h) { (void)p; (void)m; (void)h; return -EPERM; }
static int      nf_rmdir(const char *p, int h)             { (void)p; (void)h; return -EPERM; }
static int      nf_unlink(const char *p, int h)            { (void)p; (void)h; return -EPERM; }
static int      nf_rename(const char *a, const char *b, int h){ (void)a; (void)b; (void)h; return -EPERM; }
static int      nf_link(const char *a, const char *b, int h){ (void)a; (void)b; (void)h; return -EPERM; }
static int      nf_symlink(const char *a, const char *b, int h){ (void)a; (void)b; (void)h; return -EPERM; }
static int      nf_readlink(const char *p, char *b, uint32_t n){ (void)p; (void)b; (void)n; return -ENOENT; }
static int      nf_chmod(const char *p, uint16_t m, int h) { (void)p; (void)m; (void)h; return -EPERM; }
static int      nf_chown(const char *p, uint16_t u, uint16_t g, int fl, int h){ (void)p; (void)u; (void)g; (void)fl; (void)h; return -EPERM; }
static int      nf_utimes(const char *p, uint32_t a, uint32_t m, int fl, int h){ (void)p; (void)a; (void)m; (void)fl; (void)h; return -EPERM; }

static int      nf_read_inode(uint32_t i, ext2_inode_t *o) { (void)i; (void)o; return -ENOENT; }
static int      nf_write_inode(uint32_t i, const ext2_inode_t *o){ (void)i; (void)o; return -EPERM; }
static int      nf_read(uint32_t i, void *b, uint64_t off, uint32_t n){ (void)i; (void)b; (void)off; (void)n; return -ENOENT; }
static int      nf_read_val(uint32_t i, void *b, uint64_t off, uint32_t n, uint32_t g){ (void)i; (void)b; (void)off; (void)n; (void)g; return -ENOENT; }
static int      nf_write(uint32_t i, const void *b, uint32_t off, uint32_t n){ (void)i; (void)b; (void)off; (void)n; return -EPERM; }
static int      nf_readdir(uint32_t d, uint64_t idx, char *nm, uint8_t *ty){ (void)d; (void)idx; (void)nm; (void)ty; return -ENOENT; }
static int      nf_file_size(uint32_t i)                   { (void)i; return -ENOENT; }
static int      nf_truncate(uint32_t i)                    { (void)i; return -EPERM; }
static int      nf_is_dir(uint32_t i)                      { (void)i; return 0; }
static int      nf_check_perm(uint32_t i, uint16_t u, uint16_t g, int w){ (void)i; (void)u; (void)g; (void)w; return -EACCES; }
static uint32_t nf_inode_gen(uint32_t i)                   { (void)i; return 0; }
static int      nf_read_symlink(uint32_t i, char *b, uint32_t n){ (void)i; (void)b; (void)n; return -ENOENT; }

static ext2_fd_priv_t *nf_pool_alloc(uint32_t i)           { (void)i; return 0; }
static void     nf_pool_free(ext2_fd_priv_t *p)            { (void)p; }

static uint32_t nf_zero_ino(void)                          { return 0; }
static void     nf_anchors_reload(void)                    { }

const fs_ops_t nullfs_ops = {
    .name = "none", .file_ops = &nf_file_ops,
    .mount = nf_mount, .sync = nf_sync, .statfs = nf_statfs,
    .mark_clean = nf_mark_clean, .devname = nf_devname,
    .lock = nf_lock, .unlock = nf_unlock, .ino_of = nf_ino_of,
    .open = nf_open, .open_ex = nf_open_ex, .open_protected = nf_open_prot,
    .lookup_parent = nf_lookup_parent, .path_under_protected = nf_under_prot,
    .create = nf_create, .mkdir = nf_mkdir, .rmdir = nf_rmdir, .unlink = nf_unlink,
    .rename = nf_rename, .link = nf_link, .symlink = nf_symlink, .readlink = nf_readlink,
    .chmod = nf_chmod, .chown = nf_chown, .utimes = nf_utimes,
    .read_inode = nf_read_inode, .write_inode = nf_write_inode,
    .read = nf_read, .read_validated = nf_read_val, .write = nf_write,
    .readdir = nf_readdir, .file_size = nf_file_size, .truncate = nf_truncate,
    .is_dir = nf_is_dir, .check_perm = nf_check_perm, .inode_gen = nf_inode_gen,
    .read_symlink_target = nf_read_symlink,
    .pool_alloc = nf_pool_alloc, .pool_free = nf_pool_free,
    .get_admin_ino = nf_zero_ino, .get_passwd_ino = nf_zero_ino,
    .get_shadow_ino = nf_zero_ino, .get_group_ino = nf_zero_ino,
    .anchors_reload = nf_anchors_reload,
};

const fs_ops_t *g_rootfs = &nullfs_ops;
