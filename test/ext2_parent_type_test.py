#!/usr/bin/env python3
"""Check ext2 parent types using the real driver and a bounded memory device."""
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]

# Like fs_security_test.py, build the real ext2 sources against host stubs.
# This single-threaded fixture does not need the rest of the VFS or fd pool.
STUBS = {
    "spinlock.h": r"""
#pragma once
#include <assert.h>
typedef unsigned long irqflags_t;
typedef struct { unsigned value; } spinlock_t;
#define SPINLOCK_INIT {0}
static inline void spin_lock(spinlock_t *s) { assert(!s->value); s->value = 1; }
static inline void spin_unlock(spinlock_t *s) { assert(s->value); s->value = 0; }
static inline irqflags_t arch_irq_save(void) { return 0; }
static inline void arch_irq_restore(irqflags_t f) { (void)f; }
""",
    "smp.h": r"""
#pragma once
typedef struct { unsigned cpu_id; } host_cpu_t;
static host_cpu_t host_cpu;
static inline host_cpu_t *percpu_self(void) { return &host_cpu; }
""",
    "sched.h": r"""
#pragma once
typedef struct { int is_user; } aegis_task_t;
static aegis_task_t host_task = {1};
static inline aegis_task_t *sched_current(void) { return &host_task; }
""",
    "proc.h": r"""
#pragma once
typedef struct { unsigned uid, gid; } aegis_process_t;
static aegis_process_t host_proc = {1000, 1000};
static inline aegis_process_t *current_proc(void) { return &host_proc; }
""",
    "printk.h": "#pragma once\n#define printk(...) ((void)0)\n",
    "kva.h": r"""
#pragma once
#include <stdint.h>
void *kva_alloc_pages(uint64_t n);
void kva_free_pages(void *p, uint64_t n);
""",
    "arch.h": r"""
#pragma once
#include <stdint.h>
static inline uint64_t arch_get_cycles(void) { return 1000; }
static inline uint64_t arch_tsc_hz(void) { return 1000; }
""",
}

EXT2 = r"""
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#undef __unused
#define CONFIG_FS_EXT2 1
#include "kernel/fs/ext2.c"
#include "kernel/fs/ext2_cache.c"
#include "kernel/fs/ext2_dir.c"

void arch_clock_gettime(uint64_t *s, uint64_t *ns) { *s = 1; *ns = 0; }
void *kva_alloc_pages(uint64_t n) { return calloc(n, 4096); }
void kva_free_pages(void *p, uint64_t n) { (void)n; free(p); }
blkdev_t *blkdev_get(const char *name) { (void)name; return NULL; }
int ext2_pool_has_inode(uint32_t ino) { (void)ino; return 0; }
int vfs_open(const char *path, int flags, uint16_t mode, vfs_file_t *out)
{
    (void)path; (void)flags; (void)mode; (void)out;
    return -ENOENT;
}

enum { SECTORS = 256, SECTOR_SIZE = 512, BLOCK_SIZE = 1024 };
static uint8_t disk[SECTORS][SECTOR_SIZE];

static int disk_read(blkdev_t *dev, uint64_t lba, uint32_t n, void *out)
{
    (void)dev;
    if (lba >= SECTORS || n > SECTORS - lba)
        return -1;
    memcpy(out, disk[lba], n * SECTOR_SIZE);
    return 0;
}

static int disk_write(blkdev_t *dev, uint64_t lba, uint32_t n, const void *in)
{
    (void)dev;
    if (lba >= SECTORS || n > SECTORS - lba)
        return -1;
    memcpy(disk[lba], in, n * SECTOR_SIZE);
    return 0;
}

static void init_image(void)
{
    static blkdev_t dev = {
        .block_count = SECTORS, .block_size = SECTOR_SIZE,
        .read = disk_read, .write = disk_write,
    };
    s_dev = &dev;
    s_mounted = 1;
    s_block_size = BLOCK_SIZE;
    s_num_groups = 1;
    s_sb = (ext2_superblock_t){
        .s_inodes_count = 32, .s_blocks_count = 128, .s_blocks_per_group = 128,
        .s_inodes_per_group = 32, .s_inode_size = 128, .s_first_data_block = 1,
    };
    s_bgd[0] = (ext2_bgd_t){
        .bg_block_bitmap = 2, .bg_inode_bitmap = 3, .bg_inode_table = 4,
        .bg_free_blocks_count = 110, .bg_free_inodes_count = 22,
    };
    memset(disk[4], 0xff, 2);   /* reserve the first 16 block bitmap bits */
    disk[6][0] = 0xff;
    disk[6][1] = 3;           /* reserve the first 10 inode bitmap bits */
    ext2_inode_t root = { .i_mode = EXT2_S_IFDIR | 0777, .i_links_count = 2 };
    assert(ext2_write_inode(EXT2_ROOT_INODE, &root) == 0);
    assert(ext2_dir_add_entry(EXT2_ROOT_INODE, EXT2_ROOT_INODE, ".", EXT2_FT_DIR) == 0);
    assert(ext2_dir_add_entry(EXT2_ROOT_INODE, EXT2_ROOT_INODE, "..", EXT2_FT_DIR) == 0);
}

/* The first 8 bytes resemble a free dirent to the old code. Seed these
 * bytes through a normal file write, not by modifying on-disk metadata. */
static const uint8_t plain_data[] = {
    0, 0, 0, 0, 16, 0, 0, 0, 'p', 'l', 'a', 'i', 'n', '!', '!', '!',
};

static uint32_t make_plain_file(void)
{
    uint32_t ino;
    assert(ext2_create("/plain", 0700, 1) == 0);
    assert(ext2_open("/plain", &ino) == 0);
    assert(ext2_write(ino, plain_data, 0, sizeof(plain_data)) == sizeof(plain_data));
    return ino;
}

static int expect_enotdir(int rc)
{
    if (rc == -ENOTDIR)
        return 0;
    fprintf(stderr, "expected -ENOTDIR (%d), got %d\n", -ENOTDIR, rc);
    return 1;
}

static int creation_under_file(int make_dir)
{
    uint32_t ino = make_plain_file();
    ext2_inode_t before, after;
    uint8_t bytes[sizeof(plain_data)];
    assert(ext2_read_inode(ino, &before) == 0);
    assert((before.i_mode & EXT2_S_IFMT) == EXT2_S_IFREG);
    assert(before.i_size == sizeof(plain_data));
    assert(before.i_links_count == 1);

    int rc = make_dir ? ext2_mkdir("/plain/sub", 0700, 1)
                      : ext2_create("/plain/sub", 0600, 1);
    /* The parent-not-a-directory error must reach the caller intact; a bare
     * -1 here would hide the reason from the syscall layer. */
    int failed = expect_enotdir(rc);
    assert(ext2_read_inode(ino, &after) == 0);
    assert(ext2_read(ino, bytes, 0, sizeof(bytes)) == sizeof(bytes));
    if (memcmp(bytes, plain_data, sizeof(bytes)) != 0) {
        fputs("/plain: first bytes changed\n", stderr);
        failed = 1;
    }
    if (after.i_size != before.i_size || after.i_links_count != before.i_links_count) {
        fputs("/plain: size or link count changed\n", stderr);
        failed = 1;
    }
    return failed;
}

static void check_dir_parent(const char *path, uint32_t expected, const char *name)
{
    uint32_t parent;
    const char *basename;
    assert(ext2_lookup_parent(path, &parent, &basename) == 0);
    assert(parent == expected);
    assert(strcmp(basename, name) == 0);
}

int main(int argc, char **argv)
{
    assert(argc == 2);
    init_image();
    uint32_t ino;
    if (strcmp(argv[1], "lookup_regular_parent") == 0) {
        const char *basename;
        make_plain_file();
        return expect_enotdir(ext2_lookup_parent("/plain/sub", &ino, &basename));
    }
    if (strcmp(argv[1], "mkdir_regular_parent") == 0)
        return creation_under_file(1);
    if (strcmp(argv[1], "creat_regular_parent") == 0)
        return creation_under_file(0);
    if (strcmp(argv[1], "nested_directory_parent") == 0) {
        assert(ext2_mkdir("/dir", 0700, 1) == 0);
        assert(ext2_mkdir("/dir/nested", 0700, 1) == 0);
        assert(ext2_open("/dir/nested", &ino) == 0);
        check_dir_parent("/dir/nested/file", ino, "file");
        assert(ext2_create("/dir/nested/file", 0600, 1) == 0);
        assert(ext2_open("/dir/nested/file", &ino) == 0);
        return 0;
    }
    if (strcmp(argv[1], "root_directory_parent") == 0) {
        check_dir_parent("/file", EXT2_ROOT_INODE, "file");
        assert(ext2_create("/file", 0600, 1) == 0);
        assert(ext2_open("/file", &ino) == 0);
        assert(ext2_mkdir("/dir", 0700, 1) == 0);
        assert(ext2_open("/dir", &ino) == 0);
        return 0;
    }
    return 2;
}
"""

if __name__ == "__main__":
    with tempfile.TemporaryDirectory(prefix="aegis-ext2-parent-") as temp_dir:
        temp = Path(temp_dir)
        for name, contents in STUBS.items():
            (temp / name).write_text(contents)
        source = temp / "ext2_parent_type.c"
        source.write_text(EXT2)
        exe = temp / "ext2_parent_type"
        subprocess.run(
            ["cc", "-O1", "-g", f"-I{temp}", f"-I{ROOT}",
             f"-I{ROOT / 'kernel/fs'}", str(source), "-o", str(exe)],
            check=True,
        )

        failed = False
        for name in (
            "lookup_regular_parent", "mkdir_regular_parent", "creat_regular_parent",
            "nested_directory_parent", "root_directory_parent",
        ):
            print(f"{name}:", flush=True)
            result = subprocess.run([str(exe), name], timeout=60)
            print("PASS" if result.returncode == 0 else "FAIL", flush=True)
            failed |= result.returncode != 0
        raise SystemExit(int(failed))
