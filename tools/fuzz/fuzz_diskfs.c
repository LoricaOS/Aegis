/* Fuzz a disk filesystem backend with a hostile on-disk image.
 *
 * Threat model: removable media. Plugging in a USB stick or attaching a disk
 * image hands the kernel a fully attacker-controlled byte array and asks it to
 * parse superblocks, allocation tables, directory entries and inodes. Unlike
 * eth_rx this needs physical/local access, but it needs no capability — the
 * mount happens before any of the attacker's code runs.
 *
 * The fuzz input IS the disk image. It is registered as a blkdev backed by an
 * exact-size heap allocation, so a read past the end of the medium is an ASan
 * report rather than silently reading adjacent memory.
 *
 * Build twice from this one source:
 *   -DFS_BACKEND=fat_ops   -> fuzz_fat
 *   -DFS_BACKEND=ext2_ops  -> fuzz_ext2
 *
 * After a successful mount the harness WALKS the filesystem — readdir the root,
 * then open / stat / read / readlink each entry — because a mount that merely
 * validates a superblock exercises almost none of the parsing code.
 *
 * Known limitation, stated because it can produce a false positive: the
 * backends keep static superblock state and this harness mounts a DIFFERENT
 * image every iteration without an unmount. Real systems do not do that, so
 * investigate any crash for cross-image state contamination before believing
 * it.
 */
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <asm/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "smp.h"
#include "blkdev.h"
#include "fs_ops.h"
#include "vfs.h"

#ifndef FS_BACKEND
#define FS_BACKEND fat_ops
#endif
extern const fs_ops_t FS_BACKEND;

uint64_t g_fake_ticks = 0;
volatile int g_in_isr_poll = 0;

/* ext2's lock is recursive and keys re-entry on percpu_self()->cpu_id, which
 * reads gs:0. Rather than fake smp.h, give the host a real GS base pointing at
 * a genuine percpu_t — the actual kernel header and the actual inline asm then
 * work unmodified. Linux userspace puts TLS in FS, so GS is free.
 * Returns 0 on success. */
static percpu_t s_percpu;

static int percpu_host_init(void)
{
    s_percpu.self   = &s_percpu;
    s_percpu.cpu_id = 0;
    if (syscall(SYS_arch_prctl, ARCH_SET_GS, &s_percpu) != 0) {
        perror("arch_prctl(ARCH_SET_GS)");
        return -1;
    }
    return 0;
}

/* ---- stubs for the kernel services the backends reference ------------- */

/* A fixed wall clock: mtime/atime updates must not make a crash depend on when
 * it was run. */
void arch_clock_gettime(uint64_t *sec, uint64_t *nsec)
{
    if (sec)  *sec  = 1754870400ull;
    if (nsec) *nsec = 0;
}

/* ext2_anchors_reload reads /etc/aegis anchors through the VFS; there is no VFS
 * here, so report "not found" and leave the anchor set empty. */
int vfs_open(const char *path, int flags, uint16_t mode, vfs_file_t *out)
{ (void)path; (void)flags; (void)mode; (void)out; return -2; }

void *kva_alloc_pages(uint64_t n)
{
    void *p = NULL;
    if (n == 0 || n > (1u << 18))
        return NULL;
    if (posix_memalign(&p, 4096, (size_t)n * 4096) != 0)
        return NULL;
    memset(p, 0, (size_t)n * 4096);
    return p;
}

void kva_free_pages(void *va, uint64_t n) { (void)n; free(va); }

/* ---- the fuzz input, as a block device ------------------------------- */

static const uint8_t *s_img;
static size_t         s_img_len;

static int img_read(blkdev_t *dev, uint64_t lba, uint32_t count, void *buf)
{
    uint64_t off = (lba + dev->lba_offset) * dev->block_size;
    uint64_t n   = (uint64_t)count * dev->block_size;

    /* A real device fails a read past the end of the medium rather than
     * returning adjacent memory. */
    if (off > s_img_len || n > s_img_len - off)
        return -1;
    memcpy(buf, s_img + off, (size_t)n);
    return 0;
}

static int img_write(blkdev_t *dev, uint64_t lba, uint32_t count, const void *buf)
{
    /* Read-only medium: the interesting bugs are in parsing, and letting the
     * fs mutate the image would make crashes irreproducible. */
    (void)dev; (void)lba; (void)count; (void)buf;
    return -1;
}

static blkdev_t s_dev;

/* Coverage receipt. A clean fuzz run proves nothing if no image ever mounted —
 * and with printk shimmed to nothing there is otherwise no way to tell.
 * Set FUZZ_DISKFS_STATS=1 to print it. */
static unsigned long s_mounts, s_entries;

__attribute__((destructor)) static void report(void)
{
    if (getenv("FUZZ_DISKFS_STATS"))
        fprintf(stderr, "[harness] mounts=%lu dir-entries-walked=%lu\n",
                s_mounts, s_entries);
}

/* ---- walk the mounted filesystem ------------------------------------- */

/* readdir's name_out carries NO size parameter — the contract is an implicit
 * 256-byte buffer (ext2 name_len is a uint8, so 255 + NUL). Both in-kernel
 * callers use `char name[256]`. Allocate exactly that on the heap so ASan traps
 * a 257th byte instead of it landing harmlessly in a stack slot. */
#define READDIR_NAME_SZ 256

/* Depth-bounded recursive walk. The shallow version only touched root's direct
 * entries; the rich ext2/FAT bugs live DEEPER — path resolution across nested
 * directories, symlink chains (open() follows the final link and re-walks the
 * whole path, so a crafted symlink target exercises the resolver's loop/length
 * handling — the C1 symlink-target-read bug lived exactly here), and indirect
 * block lookup on large files. Bounds: MAX_DEPTH nesting, a global entry budget,
 * and a visited-dir set so a symlink/hardlink cycle in the tree can't spin the
 * harness (a genuine open() loop that ignores ELOOP would instead show as a
 * libFuzzer -timeout, which is itself a finding). */
#define WALK_MAX_DEPTH   10
#define WALK_MAX_VISITED 512u
#define WALK_ENTRY_BUDGET 4096u

static uint32_t s_visited[WALK_MAX_VISITED];
static unsigned s_visited_n;
static unsigned s_walk_budget;

static int seen_dir(uint32_t ino)
{
    unsigned i;
    for (i = 0; i < s_visited_n; i++)
        if (s_visited[i] == ino)
            return 1;
    if (s_visited_n < WALK_MAX_VISITED)
        s_visited[s_visited_n++] = ino;
    return 0;
}

static void walk_dir(const fs_ops_t *fs, uint32_t dir_ino,
                     const char *prefix, int depth, char *name)
{
    uint32_t idx;

    if (depth > WALK_MAX_DEPTH || seen_dir(dir_ino))
        return;

    for (idx = 0; idx < 256 && s_walk_budget < WALK_ENTRY_BUDGET; idx++) {
        ext2_inode_t ino;
        char path[1024];
        uint8_t buf[512];
        char link[256];
        uint8_t dtype = 0;
        uint32_t child;

        memset(name, 0, READDIR_NAME_SZ);
        if (fs->readdir(dir_ino, idx, name, &dtype) != 0)
            break;

        /* readdir must NUL-terminate inside the caller's buffer. */
        if (memchr(name, 0, READDIR_NAME_SZ) == NULL) {
            fprintf(stderr, "readdir returned an unterminated name\n");
            abort();
        }
        if (name[0] == '\0')
            continue;
        /* Skip the self/parent links so recursion terminates on the tree. */
        if (!strcmp(name, ".") || !strcmp(name, ".."))
            continue;
        s_entries++;
        s_walk_budget++;

        snprintf(path, sizeof(path), "%s/%s", prefix, name);

        /* Resolve by FULL PATH — open() re-walks the attacker's directory
         * structure from root and follows the final symlink. */
        if (fs->open(path, &child) != 0)
            continue;

        if (fs->read_inode(child, &ino) == 0) {
            fs->file_size(child);
            /* File head + deep offsets so single/double-indirect lookup runs. */
            fs->read(child, buf, 0, sizeof(buf));
            fs->read(child, buf, 4096, sizeof(buf));
            fs->read(child, buf, 0x100000, sizeof(buf));
        }

        fs->read_symlink_target(child, link, sizeof(link));
        fs->readlink(path, link, sizeof(link));
        fs->path_under_protected(path);

        /* Recurse into real subdirectories (child ino from the parent's
         * readdir, so a symlink-to-dir is read as a file here, not descended —
         * its resolution was already exercised by the open() above). */
        if (fs->is_dir(child))
            walk_dir(fs, child, path, depth + 1, name);
    }
}

static void walk(const fs_ops_t *fs)
{
    uint32_t root_ino;
    char *name = malloc(READDIR_NAME_SZ);

    if (!name)
        return;

    s_visited_n   = 0;
    s_walk_budget = 0;

    if (fs->open("/", &root_ino) == 0)
        walk_dir(fs, root_ino, "", 0, name);

    free(name);
}

int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n)
{
    const fs_ops_t *fs = &FS_BACKEND;
    uint8_t *img;
    static int percpu_ready;

    if (!percpu_ready) {
        if (percpu_host_init() != 0)
            abort();
        percpu_ready = 1;
    }

    /* Below one sector there is nothing to parse; cap the image so the corpus
     * stays fast. */
    if (n < 512 || n > (4u << 20))
        return 0;

    img = malloc(n);
    if (!img)
        return 0;
    memcpy(img, d, n);

    s_img     = img;
    s_img_len = n;

    memset(&s_dev, 0, sizeof(s_dev));
    strcpy(s_dev.name, "fuzz0");
    s_dev.block_size  = 512;
    s_dev.block_count = n / 512;
    s_dev.lba_offset  = 0;
    s_dev.read        = img_read;
    s_dev.write       = img_write;
    blkdev_register(&s_dev);

    if (fs->mount("fuzz0") == 0) {
        s_mounts++;
        walk(fs);
    }

    s_img     = NULL;
    s_img_len = 0;
    free(img);
    return 0;
}
