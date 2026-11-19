#!/usr/bin/env python3
"""Check ext2 sizes through real inode and VFS code on an in-memory device."""
import argparse
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]

STUBS = {
    'host_compat.h': r'''#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* Darwin's libc defines a macro with the same name as a k_stat_t member. */
#undef __unused
''',
    'spinlock.h': r'''#pragma once
#include <assert.h>
typedef unsigned long irqflags_t;
typedef struct { unsigned held; } spinlock_t;
#define SPINLOCK_INIT {0}
static inline void spin_lock(spinlock_t *s) { assert(!s->held); s->held = 1; }
static inline void spin_unlock(spinlock_t *s) { assert(s->held); s->held = 0; }
static inline irqflags_t arch_irq_save(void) { return 0; }
static inline void arch_irq_restore(irqflags_t f) { (void)f; }
''',
    'smp.h': r'''#pragma once
typedef struct { unsigned cpu_id; } host_cpu_t;
static inline host_cpu_t *percpu_self(void) { static host_cpu_t cpu; return &cpu; }
''',
    'sched.h': r'''#pragma once
typedef struct { int is_user; } aegis_task_t;
static inline aegis_task_t *sched_current(void) { static aegis_task_t task; return &task; }
''',
    'proc.h': r'''#pragma once
#include "cap.h"
typedef struct { unsigned uid, gid, admin_session; cap_slot_t caps[CAP_TABLE_SIZE]; } aegis_process_t;
static inline aegis_process_t *current_proc(void) { static aegis_process_t proc; return &proc; }
''',
    'arch.h': r'''#pragma once
#include <stdint.h>
static inline uint64_t arch_get_ticks(void) { return 0; }
static inline uint64_t arch_get_cycles(void) { return 0; }
static inline uint64_t arch_tsc_hz(void) { return 0; }
''',
    'printk.h': '#pragma once\n#define printk(...) ((void)0)\n',
    'kva.h': '#pragma once\n#include <stdint.h>\nvoid *kva_alloc_pages(uint64_t);\nvoid kva_free_pages(void *, uint64_t);\n',
    'uaccess.h': r'''#pragma once
#include <stdint.h>
#include <string.h>
static inline uint64_t copy_from_user(void *d, const void *s, uint64_t n) { memcpy(d, s, n); return 0; }
''',
}

HARNESS = r'''
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ext2_internal.h"
#include "fs_ops.h"
#include "mount.h"
#include "ramfs.h"

/* Other filesystems and devices are not part of this fixture. */
blkdev_t *blkdev_get(const char *name) { (void)name; return NULL; }
int ptmx_open(int f, vfs_file_t *o) { (void)f; (void)o; abort(); }
int pts_open(uint32_t i, int f, vfs_file_t *o) { (void)i; (void)f; (void)o; abort(); }
int procfs_open(const char *p, int f, vfs_file_t *o) { (void)p; (void)f; (void)o; abort(); }
int procfs_stat(const char *p, k_stat_t *o) { (void)p; (void)o; abort(); }
int initrd_open(const char *p, vfs_file_t *o) { (void)p; (void)o; return -ENOENT; }
int initrd_stat_entry(const char *p, k_stat_t *o) { (void)p; (void)o; return -ENOENT; }
int dev_table_stat(const char *p, k_stat_t *o) { (void)p; (void)o; return -ENOENT; }
int ramfs_opendir(ramfs_t *r, vfs_file_t *o) { (void)r; (void)o; abort(); }
int ramfs_open(ramfs_t *r, const char *p, int f, uint16_t m, vfs_file_t *o)
{ (void)r; (void)p; (void)f; (void)m; (void)o; abort(); }
int ramfs_stat(ramfs_t *r, const char *p, k_stat_t *o) { (void)r; (void)p; (void)o; abort(); }
int mount_acquire(const char *p, void **ctx, const char **rel)
{ (void)p; (void)ctx; (void)rel; return MOUNT_FS_NONE; }
void mount_release(void *ctx) { (void)ctx; abort(); }
void arch_clock_gettime(uint64_t *sec, uint64_t *nsec) { *sec = *nsec = 0; }

enum { BLOCK_SIZE = 4096, BLOCKS = 8, INODE_TABLE = 4, ROOT_DIR = 5,
       LARGE_INO = 12, SMALL_INO = 13 };
#define LARGE_SIZE UINT32_C(0x90000004)
static uint8_t disk[BLOCKS][BLOCK_SIZE];

static int disk_read(blkdev_t *dev, uint64_t lba, uint32_t count, void *buf)
{
    if (lba > dev->block_count || count > dev->block_count - lba)
        return -1;
    memcpy(buf, (const uint8_t *)&disk + lba * dev->block_size, count * dev->block_size);
    return 0;
}

static void setup(void)
{
    static blkdev_t dev = {
        .block_count = sizeof(disk) / 512, .block_size = 512, .read = disk_read,
    };
    s_dev = &dev;
    s_mounted = 1;
    s_block_size = BLOCK_SIZE;
    s_num_groups = 1;
    s_sb.s_inodes_count = s_sb.s_inodes_per_group = 32;
    s_sb.s_blocks_count = s_sb.s_blocks_per_group = BLOCKS;
    s_bgd[0].bg_inode_table = INODE_TABLE;

    const ext2_inode_t root = {
        .i_mode = EXT2_S_IFDIR | 0755, .i_size = BLOCK_SIZE, .i_links_count = 2,
        .i_block = { ROOT_DIR },
    };
    ext2_inode_t file = { .i_mode = EXT2_S_IFREG | 0644, .i_links_count = 1 };
    const ext2_dirent_t large = { LARGE_INO, 16, 5, EXT2_FT_REG_FILE, "large" };
    const ext2_dirent_t small = { SMALL_INO, BLOCK_SIZE - 16, 5, EXT2_FT_REG_FILE, "small" };
    memcpy(disk[ROOT_DIR], &large, 16);
    memcpy(disk[ROOT_DIR] + 16, &small, sizeof(small));
    memcpy(disk[INODE_TABLE] + (EXT2_ROOT_INODE - 1) * sizeof(root), &root, sizeof(root));
    file.i_size = LARGE_SIZE; /* sparse: no large allocation needed */
    memcpy(disk[INODE_TABLE] + (LARGE_INO - 1) * sizeof(file), &file, sizeof(file));
    file.i_size = 5;
    memcpy(disk[INODE_TABLE] + (SMALL_INO - 1) * sizeof(file), &file, sizeof(file));
}

static int64_t fail_file_size(uint32_t ino) { (void)ino; return -1; }

int main(void)
{
    setup();
    assert(ext2_file_size(LARGE_INO) == (int64_t)LARGE_SIZE);
    puts("large inode size: PASS");
    assert(ext2_file_size(SMALL_INO) == 5);
    puts("small inode size: PASS");
    assert(ext2_file_size(0) == -1);
    puts("invalid inode size: PASS");

    vfs_file_t f;
    assert(vfs_open("/large", VFS_O_WRONLY | VFS_O_APPEND, 0, &f) == 0);
    assert(f.size == LARGE_SIZE);
    assert(((ext2_fd_priv_t *)f.priv)->write_offset == LARGE_SIZE);
    puts("VFS open size and append offset: PASS");

    k_stat_t st;
    assert(f.ops->stat(f.priv, &st) == 0 && st.st_size == (int64_t)LARGE_SIZE);
    f.ops->close(f.priv);
    assert(vfs_stat_path("/large", &st) == 0 && st.st_size == (int64_t)LARGE_SIZE);
    assert(vfs_stat_path_ex("/large", &st, 0) == 0 && st.st_size == (int64_t)LARGE_SIZE);
    puts("VFS fd and path stat size: PASS");

    /* Resolve a real inode, then fail the size lookup. */
    fs_ops_t fault_ops = *g_rootfs;
    fault_ops.file_size = fail_file_size;
    g_rootfs = &fault_ops;
    assert(vfs_open("/large", VFS_O_RDONLY, 0, &f) == -EIO);
    assert(vfs_stat_path("/large", &st) == -EIO);
    assert(vfs_stat_path_ex("/large", &st, 0) == -EIO);
    puts("VFS size lookup errors: PASS");
}
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--no-sanitize', action='store_true', help='disable UBSan')
    args = parser.parse_args()

    with tempfile.TemporaryDirectory(prefix='aegis-ext2-filesize-') as temp:
        temp = Path(temp)
        for name, source in STUBS.items():
            (temp / name).write_text(source)
        harness = temp / 'filesize.c'
        harness.write_text(HARNESS)
        exe = temp / 'filesize'
        sources = [ROOT / 'kernel/fs' / f'{name}.c' for name in
                   ('ext2', 'ext2_cache', 'ext2_dir', 'ext2_vfs', 'ext2_ops', 'vfs')]
        includes = [ROOT / 'kernel' / name for name in ('fs', 'cap', 'tty')]
        sanitizers = [] if args.no_sanitize else [
            '-fsanitize=undefined', '-fno-sanitize-recover=undefined',
        ]
        gc_sections = '-Wl,-dead_strip' if sys.platform == 'darwin' else '-Wl,--gc-sections'
        subprocess.run(
            ['cc', '-O1', '-g', *sanitizers, '-Werror=incompatible-pointer-types',
             '-ffunction-sections', '-fdata-sections', gc_sections,
             '-include', str(temp / 'host_compat.h'),
             '-DCONFIG_FS_EXT2=1', f'-I{temp}', *(f'-I{path}' for path in includes),
             harness, *sources, ROOT / 'kernel/cap/cap.c', '-o', exe],
            check=True,
        )
        subprocess.run([exe], check=True, timeout=60)


if __name__ == '__main__':
    main()
