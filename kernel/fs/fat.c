/* fat.c — a read-write FAT32 disk-filesystem backend.
 *
 * Implements the fs_ops vtable so a build with CONFIG_FS_FAT mounts a FAT32
 * volume as the VFS root/disk backend in place of ext2 — small (~third of
 * ext2's code), and the on-disk format every SD card and PC already speaks.
 * The tradeoff is no Unix ownership/permissions: FAT has none, so check_perm
 * allows and get_*_ino report absent. Authority still comes from the capability
 * layer at the syscall boundary, which is what actually gates access.
 *
 * FAT has no inodes; we synthesize a stable inode number from a directory
 * entry's on-disk location:  ino = (entry_lba << 5) | entry_index  (index 0..15
 * within a 512 B sector). The root directory, which has no parent entry, uses
 * the sentinel FAT_ROOT_INO. read_inode/read re-fetch the entry from its
 * encoded location — no in-memory inode table needed.
 *
 * Read + write: mount parses the BPB; path resolution walks directory cluster
 * chains; read/write follow (and extend) the chain, allocating clusters and
 * updating every FAT copy + the directory entry. create/mkdir/unlink/rmdir/
 * rename/truncate are supported; long filenames (VFAT LFN) are read (reassembled)
 * and generated on create; names are case-insensitive; FAT dates decode into the
 * inode times. No Unix permissions — FAT has none; chmod/chown are accepted
 * no-ops, authority is the capability layer. Known gaps: FSInfo free-count is not
 * updated (a hint only), and a moved directory's ".." still points at its old
 * parent.
 */
#include "fs_ops.h"
#include "vfs.h"
#include "blkdev.h"
#include "printk.h"
#include "../lib/string.h"
#include "../include/aegis_errno.h"

#define SECTOR       512u
#define DIRENT_SIZE  32u
#define FAT_ROOT_INO 1u
#define FAT_EOC      0x0FFFFFF8u    /* >= this = end-of-chain              */
#define ATTR_RO      0x01
#define ATTR_HIDDEN  0x02
#define ATTR_SYSTEM  0x04
#define ATTR_VOLUME  0x08
#define ATTR_DIR     0x10
#define ATTR_LFN     0x0F           /* long-name entry (skip in phase 4a)  */
#define S_IFDIR_M    0040000
#define S_IFREG_M    0100000

/* mounted-volume geometry (single mount) */
static blkdev_t *s_dev;
static uint16_t  s_bps;             /* bytes per sector (expect 512)       */
static uint8_t   s_spc;             /* sectors per cluster                 */
static uint32_t  s_fat_lba;         /* first FAT sector                    */
static uint32_t  s_data_lba;        /* first data sector (cluster 2)       */
static uint32_t  s_root_cluster;    /* FAT32 root dir start cluster        */
static uint32_t  s_total_clusters;
static uint8_t   s_nfats;           /* number of FAT copies (write to all) */
static uint32_t  s_fat_size;        /* sectors per FAT                     */
static uint32_t  s_next_free;       /* allocation search hint              */

static irqflags_t s_lock_flags;     /* trivial big lock (single-threaded mount) */

#ifdef CONFIG_KERNEL_TESTS
static void fat_selftest(void);     /* create+write+read roundtrip on mount */
#endif

/* case-insensitive name compare — FAT names are case-insensitive (the kernel's
 * shared string.h has no strcmp anyway, only kmem*). */
static int fat_streq(const char *a, const char *b) {
    for (;; a++, b++) {
        char ca = *a, cb = *b;
        if (ca >= 'A' && ca <= 'Z') ca += 32;
        if (cb >= 'A' && cb <= 'Z') cb += 32;
        if (ca != cb) return 0;
        if (!ca)      return 1;
    }
}

/* ---- low-level sector / FAT access ----------------------------------- */

/* Both accessors bound `lba` to the device. This is the last line of defence
 * behind fat_cluster_ok(): every LBA here is derived from on-disk geometry or
 * cluster numbers, and neither the block layer nor the drivers below (virtio-blk
 * and AHCI have no LBA range check at all) will catch an out-of-range sector. */
static int fat_read_lba(uint32_t lba, void *buf) {
    if (!s_dev) return -1;
    if (s_dev->block_count && lba >= s_dev->block_count) return -1;
    return s_dev->read(s_dev, s_dev->lba_offset + lba, 1, buf);
}

static uint32_t cluster_lba(uint32_t cl) {
    return s_data_lba + (cl - 2) * s_spc;
}

/* fat_cluster_ok — is `cl` a real data cluster on this volume?
 *
 * Clusters are numbered from 2, so the last valid one is s_total_clusters + 1.
 * EVERY cluster number the driver handles is attacker-controlled on a crafted
 * image: first_cluster comes straight out of a directory entry, and the chain
 * successor straight out of the FAT. Unchecked, a value like 0x0FFFFFF0 passes
 * the old `cl < FAT_EOC` gate but makes cluster_lba()'s `(cl - 2) * s_spc`
 * overflow uint32 (s_spc is up to 255) into an arbitrary LBA — and fat_read_lba
 * does no bounds check of its own, so that became attacker-chosen on-disk read
 * AND write. Gate every walk and every cluster_lba() caller on this. */
static int fat_cluster_ok(uint32_t cl) {
    return s_total_clusters != 0 && cl >= 2 && cl - 2 < s_total_clusters;
}

/* FAT chains are singly linked with no on-disk cycle detection, so a crafted
 * image can simply point two clusters at each other (FAT[100]=101,
 * FAT[101]=100) and every walker below spins forever holding the FS lock —
 * on SMP that hangs every other CPU touching the filesystem too. No chain can
 * legitimately be longer than the volume's cluster count, so each walk carries
 * a step budget and gives up past it. */
#define FAT_CHAIN_STEPS_OK(steps) ((steps) <= s_total_clusters)

/* next cluster in the chain (FAT32), or >= FAT_EOC at end */
static uint32_t fat_next(uint32_t cl) {
    uint8_t sec[SECTOR];
    uint32_t off = cl * 4;
    if (fat_read_lba(s_fat_lba + off / SECTOR, sec) != 0) return FAT_EOC;
    uint32_t v;
    kmemcpy(&v, sec + (off % SECTOR), 4);
    return v & 0x0FFFFFFFu;
}

/* ---- directory-entry decode + inode synthesis ------------------------ */

typedef struct {
    uint32_t first_cluster;
    uint32_t size;
    uint8_t  attr;
    uint16_t mtime, mdate;
} fat_dirent_t;

/* build "NAME.EXT" (lowercased) from an 8.3 raw entry; returns 0 if usable */
static int decode_83(const uint8_t *e, char *out) {
    if (e[0] == 0x00 || e[0] == 0xE5) return -1;      /* free / deleted     */
    if ((e[11] & ATTR_LFN) == ATTR_LFN) return -1;    /* long-name fragment */
    if (e[11] & ATTR_VOLUME) return -1;               /* volume label       */
    int n = 0;
    for (int i = 0; i < 8 && e[i] != ' '; i++) out[n++] = e[i];
    if (e[8] != ' ') {
        out[n++] = '.';
        for (int i = 8; i < 11 && e[i] != ' '; i++) out[n++] = e[i];
    }
    out[n] = 0;
    for (int i = 0; i < n; i++)
        if (out[i] >= 'A' && out[i] <= 'Z') out[i] += 32;   /* FAT is upcased */
    return 0;
}

static void fill_dirent(const uint8_t *e, fat_dirent_t *d) {
    uint16_t hi, lo;
    kmemcpy(&hi, e + 20, 2);
    kmemcpy(&lo, e + 26, 2);
    /* FAT32 cluster numbers are 28-bit; the top 4 bits of the on-disk field
     * are reserved and must be ignored, not carried into arithmetic. */
    d->first_cluster = (((uint32_t)hi << 16) | lo) & 0x0FFFFFFFu;
    kmemcpy(&d->size, e + 28, 4);
    d->attr = e[11];
    kmemcpy(&d->mtime, e + 22, 2);
    kmemcpy(&d->mdate, e + 24, 2);
}

/* fetch the directory entry a synthesized ino points at */
static int read_dirent(uint32_t ino, fat_dirent_t *d) {
    if (ino == FAT_ROOT_INO) {
        d->first_cluster = s_root_cluster;
        d->size = 0;
        d->attr = ATTR_DIR;
        d->mtime = d->mdate = 0;
        return 0;
    }
    uint32_t lba = ino >> 5, idx = ino & 31;
    uint8_t sec[SECTOR];
    if (fat_read_lba(lba, sec) != 0) return -ENOENT;
    fill_dirent(sec + idx * DIRENT_SIZE, d);
    return 0;
}

/* iterate a directory's entries. For each valid 8.3 entry, invoke cb; cb
 * returns non-zero to stop. `want_index`<0 => visit all; else stop at the Nth.
 * On a hit, *hit_ino / *hit_dirent are set. Returns 1 if cb stopped, else 0. */
typedef int (*dir_cb)(const char *name, uint32_t ino, const fat_dirent_t *d, void *ctx);

/* the 13 UCS-2 char slots within a 32-byte LFN entry */
static const int LFN_POS[13] = { 1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30 };

static int walk_dir(uint32_t dir_cluster, dir_cb cb, void *ctx) {
    uint8_t sec[SECTOR];
    char lfn[260];
    int have_lfn = 0;
    uint32_t cl = dir_cluster;
    uint32_t steps = 0;
    while (fat_cluster_ok(cl) && FAT_CHAIN_STEPS_OK(steps)) {
        for (uint32_t s = 0; s < s_spc; s++) {
            uint32_t lba = cluster_lba(cl) + s;
            if (fat_read_lba(lba, sec) != 0) return 0;
            for (uint32_t i = 0; i < SECTOR / DIRENT_SIZE; i++) {
                const uint8_t *e = sec + i * DIRENT_SIZE;
                if (e[0] == 0x00) return 0;              /* end of directory */
                if (e[0] == 0xE5) { have_lfn = 0; continue; }
                if ((e[11] & ATTR_LFN) == ATTR_LFN) {    /* long-name fragment */
                    if (e[0] & 0x40) { kmemset(lfn, 0, sizeof lfn); have_lfn = 1; }
                    int seq = e[0] & 0x1F;
                    /* seq is 1-based; seq==0 made base = -13 and the SIGNED
                     * `base + k < 259` test below happily passed, writing 13
                     * attacker-chosen bytes BELOW lfn[] into the adjacent
                     * stack locals (sec[512], have_lfn, cl — corrupting cl
                     * redirects the whole directory walk). 20 fragments × 13
                     * chars covers the 255-char max long name. */
                    if (seq < 1 || seq > 20) { have_lfn = 0; continue; }
                    int base = (seq - 1) * 13;
                    for (int k = 0; k < 13 && base + k < 259; k++) {
                        uint16_t ch; kmemcpy(&ch, e + LFN_POS[k], 2);
                        lfn[base + k] = (ch == 0 || ch == 0xFFFF) ? 0 : (char)(ch & 0xFF);
                    }
                    continue;
                }
                if (e[11] & ATTR_VOLUME) { have_lfn = 0; continue; }
                char sname[16];
                const char *use = sname;
                if (have_lfn && lfn[0]) use = lfn;
                else if (decode_83(e, sname) != 0) { have_lfn = 0; continue; }
                fat_dirent_t d;
                fill_dirent(e, &d);
                uint32_t ino = (lba << 5) | i;
                have_lfn = 0;
                if (cb(use, ino, &d, ctx)) return 1;
            }
        }
        cl = fat_next(cl); steps++;
    }
    return 0;
}

/* ---- path resolution ------------------------------------------------- */

struct match_ctx { const char *want; uint32_t ino; fat_dirent_t d; int found; };
static int match_cb(const char *name, uint32_t ino, const fat_dirent_t *d, void *c) {
    struct match_ctx *m = c;
    if (fat_streq(name, m->want)) { m->ino = ino; m->d = *d; m->found = 1; return 1; }
    return 0;
}

/* resolve `path` to (ino, dirent). If parent_out != NULL, stop at the parent
 * and return the final component's name in *base_out instead. */
static int resolve(const char *path, uint32_t *ino_out, fat_dirent_t *d_out,
                   uint32_t *parent_cluster_out, const char **base_out) {
    while (*path == '/') path++;
    uint32_t cur_cluster = s_root_cluster;
    uint32_t cur_ino = FAT_ROOT_INO;
    fat_dirent_t cur_d = { s_root_cluster, 0, ATTR_DIR, 0, 0 };

    while (*path) {
        char comp[256];
        int n = 0;
        while (*path && *path != '/' && n < 255) comp[n++] = *path++;
        comp[n] = 0;
        while (*path == '/') path++;
        int last = (*path == 0);

        if (parent_cluster_out && last) {         /* caller wants the parent */
            *parent_cluster_out = cur_cluster;
            *base_out = base_out ? *base_out : 0;  /* filled by caller copy */
            /* Sized to match comp[] — `n` runs up to 255, so the old
             * lastname[16] took a 256-byte copy into a 16-byte buffer: a
             * 240-byte overflow into file-scope BSS, where the FAT geometry
             * statics (s_dev, s_bps, s_spc, s_fat_lba, s_data_lba,
             * s_root_cluster, s_total_clusters) live. Reachable from
             * fat_lookup_parent on the O_CREAT path with any final component
             * longer than 15 chars. */
            static char lastname[256];
            uint32_t ln = (uint32_t)n;
            if (ln > sizeof(lastname) - 1) ln = sizeof(lastname) - 1;
            kmemcpy(lastname, comp, ln);
            lastname[ln] = '\0';
            *base_out = lastname;
            return 0;
        }

        struct match_ctx m = { comp, 0, {0}, 0 };
        if (!(cur_d.attr & ATTR_DIR)) return -ENOTDIR;
        walk_dir(cur_cluster, match_cb, &m);
        if (!m.found) return -ENOENT;
        cur_ino = m.ino; cur_d = m.d; cur_cluster = m.d.first_cluster;
    }
    if (ino_out) *ino_out = cur_ino;
    if (d_out)   *d_out = cur_d;
    return 0;
}

/* ---- fs_ops: superblock ---------------------------------------------- */

static int fat_mount(const char *devname) {
    s_dev = blkdev_get(devname);
    if (!s_dev) return -ENOENT;
    uint8_t bpb[SECTOR];
    if (fat_read_lba(0, bpb) != 0) { s_dev = 0; return -EIO; }
    kmemcpy(&s_bps, bpb + 11, 2);
    s_spc = bpb[13];
    uint16_t reserved; kmemcpy(&reserved, bpb + 14, 2);
    uint8_t nfats = bpb[16];
    uint32_t fat_size; kmemcpy(&fat_size, bpb + 36, 4);
    kmemcpy(&s_root_cluster, bpb + 44, 4);
    uint32_t total; kmemcpy(&total, bpb + 32, 4);
    /* BPB_TotSec32 is 0 on volumes small enough to use the 16-bit
     * BPB_TotSec16 field instead; fall back to it rather than treating 0 as
     * the sector count (which the validation below would reject). */
    if (total == 0) {
        uint16_t total16; kmemcpy(&total16, bpb + 19, 2);
        total = total16;
    }
    if (s_bps != SECTOR || s_spc == 0 || nfats == 0 || fat_size == 0) {
        s_dev = 0; return -EINVAL;                  /* not a FAT32 volume    */
    }
    /* Validate the BPB before deriving any geometry from it. These fields are
     * attacker-controlled on a crafted image and were taken on trust:
     *  - reserved == 0 puts the FAT on top of the BPB itself;
     *  - reserved + nfats*fat_size overflows uint32 → s_data_lba wraps;
     *  - total <= s_data_lba underflows s_total_clusters to ~4 billion, which
     *    then makes every cluster look in-range to fat_cluster_ok().
     * Compute the data start in 64-bit so the overflow is visible. */
    uint64_t data_lba64 = (uint64_t)reserved + (uint64_t)nfats * fat_size;
    if (reserved == 0 || data_lba64 >= (uint64_t)total ||
        (s_dev->block_count && (uint64_t)total > s_dev->block_count)) {
        s_dev = 0; return -EINVAL;
    }
    s_fat_lba  = reserved;
    s_data_lba = (uint32_t)data_lba64;
    s_total_clusters = (total - s_data_lba) / s_spc;
    /* The root cluster must itself be a real data cluster — it seeds every
     * path resolution, so a 0/1/out-of-range value walks off the volume. */
    if (s_total_clusters == 0 || !fat_cluster_ok(s_root_cluster)) {
        s_dev = 0; return -EINVAL;
    }
    s_nfats = nfats;
    s_fat_size = fat_size;
    s_next_free = 2;
    printk("[FAT] OK: mounted %s, %u clusters, root@%u\n",
           devname, s_total_clusters, s_root_cluster);
#ifdef CONFIG_KERNEL_TESTS
    fat_selftest();
#endif
    return 0;
}

static int  fat_sync(void)                          { return 0; }
static int  fat_statfs(uint64_t *t, uint64_t *f)    { if (t) *t = (uint64_t)s_total_clusters * s_spc / 2; if (f) *f = 0; return 0; }
static void fat_mark_clean(void)                    { }
static const char *fat_devname(void)                { return s_dev ? s_dev->name : "none"; }
static irqflags_t fat_lock(void)                    { return s_lock_flags; }
static void fat_unlock(irqflags_t fl)               { (void)fl; }
static uint32_t fat_ino_of(const void *o, void *p)  { (void)o; return p ? ((ext2_fd_priv_t *)p)->ino : 0; }

/* ---- fs_ops: path -> inode ------------------------------------------- */

static int fat_open(const char *path, uint32_t *ino) {
    fat_dirent_t d;
    return resolve(path, ino, &d, 0, 0);
}
static int fat_open_ex(const char *path, uint32_t *ino, int follow) { (void)follow; return fat_open(path, ino); }
static int fat_open_prot(const char *path, uint32_t *ino, int *prot) { if (prot) *prot = 0; return fat_open(path, ino); }
static int fat_lookup_parent(const char *path, uint32_t *pino, const char **base) {
    uint32_t pcl = 0;
    int r = resolve(path, 0, 0, &pcl, base);
    if (r) return r;
    /* the VFS uses parent_ino as a cluster handle here; encode the cluster */
    if (pino) *pino = pcl;
    return 0;
}
static int fat_under_prot(const char *path)         { (void)path; return 0; }

/* ---- fs_ops: inode-level -------------------------------------------- */

/* FAT date/time (DOS format) -> unix epoch seconds */
static uint32_t fat_time_unix(uint16_t date, uint16_t time) {
    if (date == 0) return 0;
    int y = 1980 + (date >> 9), mo = (date >> 5) & 15, d = date & 31;
    int h = time >> 11, mi = (time >> 5) & 63, s = (time & 31) * 2;
    if (mo < 1) mo = 1;
    if (d < 1)  d = 1;
    static const int cum[] = { 0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334 };
    long days = (long)(y - 1970) * 365 + (y - 1969) / 4 + cum[mo - 1] + (d - 1);
    if (mo > 2 && ((y % 4 == 0 && y % 100 != 0) || y % 400 == 0)) days++;
    return (uint32_t)(days * 86400L + h * 3600 + mi * 60 + s);
}

static void dirent_to_inode(const fat_dirent_t *d, ext2_inode_t *o) {
    kmemset(o, 0, sizeof *o);
    o->i_mode = (d->attr & ATTR_DIR) ? (S_IFDIR_M | 0755) : (S_IFREG_M | 0644);
    o->i_size = (d->attr & ATTR_DIR) ? 0 : d->size;
    o->i_links_count = 1;
    o->i_uid = 0; o->i_gid = 0;
    o->i_blocks = (d->size + 511) / 512;
    o->i_mtime = o->i_atime = o->i_ctime = fat_time_unix(d->mdate, d->mtime);
}

static int fat_read_inode(uint32_t ino, ext2_inode_t *o) {
    fat_dirent_t d;
    int r = read_dirent(ino, &d);
    if (r) return r;
    dirent_to_inode(&d, o);
    return 0;
}

/* inode-level read: follow the cluster chain to `off`, copy up to `len` */
static int fat_read(uint32_t ino, void *buf, uint64_t off, uint32_t len) {
    fat_dirent_t d;
    if (read_dirent(ino, &d) != 0) return -ENOENT;
    if (d.attr & ATTR_DIR) return -EISDIR;
    if (off >= d.size) return 0;
    if (off + len > d.size) len = (uint32_t)(d.size - off);

    uint32_t csize = (uint32_t)s_spc * SECTOR;
    uint32_t cl = d.first_cluster;
    uint64_t skip = off;
    uint32_t steps = 0;
    while (skip >= csize && fat_cluster_ok(cl) && FAT_CHAIN_STEPS_OK(steps)) {
        cl = fat_next(cl); steps++; skip -= csize;
    }

    uint8_t sec[SECTOR];
    uint32_t done = 0;
    while (done < len && fat_cluster_ok(cl) && FAT_CHAIN_STEPS_OK(steps)) {
        uint32_t in_cluster = (uint32_t)skip;           /* offset within cluster */
        for (uint32_t s = in_cluster / SECTOR; s < s_spc && done < len; s++) {
            if (fat_read_lba(cluster_lba(cl) + s, sec) != 0) return (int)done;
            uint32_t so = (s == in_cluster / SECTOR) ? in_cluster % SECTOR : 0;
            uint32_t n = SECTOR - so;
            if (n > len - done) n = len - done;
            kmemcpy((uint8_t *)buf + done, sec + so, n);
            done += n;
        }
        skip = 0;
        cl = fat_next(cl); steps++;
    }
    return (int)done;
}
static int fat_read_val(uint32_t ino, void *buf, uint64_t off, uint32_t len, uint32_t gen) { (void)gen; return fat_read(ino, buf, off, len); }

/* fs_ops.readdir walks the directory whose inode is `dir_ino`, returning the
 * index-th valid entry's name+type. */
struct rd_ctx { uint64_t want; uint64_t cur; char *name; uint8_t *type; int hit; };
static int rd_cb(const char *name, uint32_t ino, const fat_dirent_t *d, void *c) {
    (void)ino;
    struct rd_ctx *r = c;
    if (r->cur == r->want) {
        int n = 0; while (name[n] && n < 255) { r->name[n] = name[n]; n++; } r->name[n] = 0;
        *r->type = (d->attr & ATTR_DIR) ? 4 : 8;
        r->hit = 1; return 1;
    }
    r->cur++; return 0;
}
static int fat_readdir(uint32_t dir_ino, uint64_t index, char *name_out, uint8_t *type_out) {
    fat_dirent_t d;
    if (read_dirent(dir_ino, &d) != 0 || !(d.attr & ATTR_DIR)) return -ENOTDIR;
    struct rd_ctx r = { index, 0, name_out, type_out, 0 };
    walk_dir(d.first_cluster, rd_cb, &r);
    return r.hit ? 0 : -1;
}

static int fat_file_size(uint32_t ino) { fat_dirent_t d; if (read_dirent(ino, &d)) return -ENOENT; return (int)d.size; }
static int fat_is_dir(uint32_t ino)    { fat_dirent_t d; if (read_dirent(ino, &d)) return 0; return (d.attr & ATTR_DIR) ? 1 : 0; }
static int fat_check_perm(uint32_t i, uint16_t u, uint16_t g, int w) { (void)i; (void)u; (void)g; (void)w; return 0; }
static uint32_t fat_inode_gen(uint32_t i) { (void)i; return 0; }
static int fat_readlink_ino(uint32_t i, char *b, uint32_t n) { (void)i; (void)b; (void)n; return -EINVAL; }

/* ---- write helpers (phase 4b) ---------------------------------------- */

static int fat_write_lba(uint32_t lba, const void *buf) {
    if (!s_dev || !s_dev->write) return -1;
    if (s_dev->block_count && lba >= s_dev->block_count) return -1;
    return s_dev->write(s_dev, s_dev->lba_offset + lba, 1, buf);
}

/* FAT[cl] = val in every FAT copy (preserving the top 4 reserved bits) */
static int fat_set(uint32_t cl, uint32_t val) {
    uint32_t off = cl * 4, rel = off / SECTOR, eo = off % SECTOR;
    uint8_t sec[SECTOR];
    for (uint8_t f = 0; f < s_nfats; f++) {
        uint32_t lba = s_fat_lba + f * s_fat_size + rel;
        if (fat_read_lba(lba, sec) != 0) return -EIO;
        uint32_t cur; kmemcpy(&cur, sec + eo, 4);
        cur = (cur & 0xF0000000u) | (val & 0x0FFFFFFFu);
        kmemcpy(sec + eo, &cur, 4);
        if (fat_write_lba(lba, sec) != 0) return -EIO;
    }
    return 0;
}

/* allocate one free cluster, mark EOC, return it (0 = ENOSPC) */
static uint32_t fat_alloc(void) {
    uint8_t sec[SECTOR];
    uint32_t last = s_total_clusters + 2;
    for (uint32_t cl = s_next_free; cl < last; cl++) {
        uint32_t off = cl * 4;
        if (fat_read_lba(s_fat_lba + off / SECTOR, sec) != 0) return 0;
        uint32_t v; kmemcpy(&v, sec + (off % SECTOR), 4);
        if ((v & 0x0FFFFFFFu) == 0) {
            if (fat_set(cl, 0x0FFFFFFFu) != 0) return 0;
            s_next_free = cl + 1;
            return cl;
        }
    }
    return 0;
}

static void fat_zero_cluster(uint32_t cl) {
    uint8_t z[SECTOR]; kmemset(z, 0, SECTOR);
    for (uint32_t s = 0; s < s_spc; s++) fat_write_lba(cluster_lba(cl) + s, z);
}

static void fat_free_chain(uint32_t cl) {
    uint32_t steps = 0;
    while (fat_cluster_ok(cl) && FAT_CHAIN_STEPS_OK(steps)) {
        uint32_t nx = fat_next(cl);
        fat_set(cl, 0);
        if (cl < s_next_free) s_next_free = cl;
        cl = nx; steps++;
    }
}

/* basename -> 11-byte raw 8.3 (space-padded, upcased). -1 if it can't fit 8.3. */
static int to_83(const char *name, uint8_t raw[11]) {
    kmemset(raw, ' ', 11);
    int len = 0, dot = -1;
    for (const char *p = name; *p; p++) { if (*p == '.') dot = len; len++; }
    int stop = (dot < 0) ? len : dot, n = 0;
    for (int i = 0; i < stop; i++) {
        if (n >= 8) return -1;
        char c = name[i]; if (c >= 'a' && c <= 'z') c -= 32;
        raw[n++] = (uint8_t)c;
    }
    if (dot >= 0) {
        int e = 0;
        for (const char *p = name + dot + 1; *p; p++) {
            if (e >= 3) return -1;
            char c = *p; if (c >= 'a' && c <= 'z') c -= 32;
            raw[8 + e++] = (uint8_t)c;
        }
    }
    return 0;
}

/* find a free dir slot in dir_cluster (extending it if full) */
static int find_free_slot(uint32_t dir_cluster, uint32_t *o_lba, uint32_t *o_idx) {
    uint8_t sec[SECTOR];
    uint32_t cl = dir_cluster, prev = dir_cluster;
    uint32_t steps = 0;
    while (fat_cluster_ok(cl) && FAT_CHAIN_STEPS_OK(steps)) {
        for (uint32_t s = 0; s < s_spc; s++) {
            uint32_t lba = cluster_lba(cl) + s;
            if (fat_read_lba(lba, sec) != 0) return -EIO;
            for (uint32_t i = 0; i < SECTOR / DIRENT_SIZE; i++) {
                uint8_t b = sec[i * DIRENT_SIZE];
                if (b == 0x00 || b == 0xE5) { *o_lba = lba; *o_idx = i; return 0; }
            }
        }
        prev = cl; cl = fat_next(cl); steps++;
    }
    uint32_t nc = fat_alloc();
    if (!nc) return -ENOSPC;
    fat_zero_cluster(nc);
    fat_set(prev, nc);
    *o_lba = cluster_lba(nc); *o_idx = 0;
    return 0;
}

static int write_entry(uint32_t lba, uint32_t idx, const uint8_t raw[11],
                       uint8_t attr, uint32_t first, uint32_t size) {
    uint8_t sec[SECTOR];
    if (fat_read_lba(lba, sec) != 0) return -EIO;
    uint8_t *e = sec + idx * DIRENT_SIZE;
    kmemset(e, 0, DIRENT_SIZE);
    kmemcpy(e, raw, 11);
    e[11] = attr;
    uint16_t hi = (uint16_t)(first >> 16), lo = (uint16_t)(first & 0xFFFF);
    kmemcpy(e + 20, &hi, 2); kmemcpy(e + 26, &lo, 2); kmemcpy(e + 28, &size, 4);
    return fat_write_lba(lba, sec) == 0 ? 0 : -EIO;
}

static int patch_entry(uint32_t ino, uint32_t first, uint32_t size) {
    if (ino == FAT_ROOT_INO) return 0;
    uint32_t lba = ino >> 5, idx = ino & 31; uint8_t sec[SECTOR];
    if (fat_read_lba(lba, sec) != 0) return -EIO;
    uint8_t *e = sec + idx * DIRENT_SIZE;
    uint16_t hi = (uint16_t)(first >> 16), lo = (uint16_t)(first & 0xFFFF);
    kmemcpy(e + 20, &hi, 2); kmemcpy(e + 26, &lo, 2); kmemcpy(e + 28, &size, 4);
    return fat_write_lba(lba, sec) == 0 ? 0 : -EIO;
}

/* split path into parent-dir cluster + basename */
static int split_parent(const char *path, uint32_t *parent_cluster, char base[256]) {
    const char *slash = 0;
    for (const char *p = path; *p; p++) if (*p == '/') slash = p;
    if (!slash) return -EINVAL;
    int bn = 0; for (const char *p = slash + 1; *p && bn < 255; p++) base[bn++] = *p;
    base[bn] = 0;
    if (bn == 0) return -EINVAL;
    if (slash == path) { *parent_cluster = s_root_cluster; return 0; }
    char parent[256]; int pn = 0;
    for (const char *p = path; p != slash && pn < 255; p++) parent[pn++] = *p;
    parent[pn] = 0;
    uint32_t pino; fat_dirent_t pd;
    int r = resolve(parent, &pino, &pd, 0, 0);
    if (r) return r;
    if (!(pd.attr & ATTR_DIR)) return -ENOTDIR;
    *parent_cluster = pd.first_cluster;
    return 0;
}

/* ---- long-name (LFN) generation on create ---------------------------- */

static uint8_t lfn_checksum(const uint8_t raw[11]) {
    uint8_t s = 0;
    for (int i = 0; i < 11; i++) s = (uint8_t)(((s & 1) << 7) + (s >> 1) + raw[i]);
    return s;
}

/* linear directory slot -> (lba, idx), extending the dir chain if needed */
static int dir_slot(uint32_t dir_cluster, uint32_t slot, uint32_t *o_lba, uint32_t *o_idx) {
    uint32_t per = (uint32_t)s_spc * (SECTOR / DIRENT_SIZE);
    uint32_t ci = slot / per, within = slot % per, cl = dir_cluster;
    for (uint32_t k = 0; k < ci; k++) {
        uint32_t nx = fat_next(cl);
        if (nx >= FAT_EOC) { nx = fat_alloc(); if (!nx) return -ENOSPC; fat_zero_cluster(nx); fat_set(cl, nx); }
        cl = nx;
    }
    *o_lba = cluster_lba(cl) + within / (SECTOR / DIRENT_SIZE);
    *o_idx = within % (SECTOR / DIRENT_SIZE);
    return 0;
}

/* index of the first free (0x00-terminated) slot in the directory */
static uint32_t dir_end_slot(uint32_t dir_cluster) {
    uint8_t sec[SECTOR];
    uint32_t slot = 0, cl = dir_cluster;
    uint32_t steps = 0;
    while (fat_cluster_ok(cl) && FAT_CHAIN_STEPS_OK(steps)) {
        for (uint32_t s = 0; s < s_spc; s++) {
            if (fat_read_lba(cluster_lba(cl) + s, sec) != 0) return slot;
            for (uint32_t i = 0; i < SECTOR / DIRENT_SIZE; i++, slot++)
                if (sec[i * DIRENT_SIZE] == 0x00) return slot;
        }
        cl = fat_next(cl); steps++;
    }
    return slot;
}

/* generate an 8.3 short name (BASE~1.EXT) to back a long name */
static void gen_short(const char *name, uint8_t raw[11]) {
    kmemset(raw, ' ', 11);
    const char *dot = 0;
    for (const char *p = name; *p; p++) if (*p == '.') dot = p;
    int bn = 0;
    for (const char *p = name; *p && (!dot || p < dot) && bn < 6; p++) {
        char c = *p;
        if (c == ' ' || c == '.') continue;
        if (c >= 'a' && c <= 'z') c -= 32;
        raw[bn++] = (uint8_t)c;
    }
    raw[6] = '~'; raw[7] = '1';
    if (dot) {
        int e = 0;
        for (const char *p = dot + 1; *p && e < 3; p++) {
            char c = *p;
            if (c >= 'a' && c <= 'z') c -= 32;
            raw[8 + e++] = (uint8_t)c;
        }
    }
}

/* write the LFN entries (reverse order) + the backing 8.3 entry at the dir end */
static int write_lfn_name(uint32_t dir_cluster, const char *name, uint8_t attr,
                          uint32_t first, uint32_t size, const uint8_t raw[11]) {
    int len = 0;
    for (const char *p = name; *p && len < 255; p++) len++;
    int nent = (len + 12) / 13;
    uint8_t csum = lfn_checksum(raw);
    uint32_t end = dir_end_slot(dir_cluster);
    for (int seq = nent; seq >= 1; seq--) {
        uint8_t e[DIRENT_SIZE]; kmemset(e, 0, DIRENT_SIZE);
        e[0] = (uint8_t)(seq | (seq == nent ? 0x40 : 0));
        e[11] = ATTR_LFN; e[13] = csum;
        int cbase = (seq - 1) * 13;
        for (int k = 0; k < 13; k++) {
            uint16_t ch;
            int ci = cbase + k;
            if (ci < len)       ch = (uint8_t)name[ci];
            else if (ci == len) ch = 0;
            else                ch = 0xFFFF;
            kmemcpy(e + LFN_POS[k], &ch, 2);
        }
        uint32_t lba, idx;
        if (dir_slot(dir_cluster, end + (uint32_t)(nent - seq), &lba, &idx)) return -ENOSPC;
        uint8_t sec[SECTOR];
        if (fat_read_lba(lba, sec)) return -EIO;
        kmemcpy(sec + idx * DIRENT_SIZE, e, DIRENT_SIZE);
        if (fat_write_lba(lba, sec)) return -EIO;
    }
    uint32_t lba, idx;
    if (dir_slot(dir_cluster, end + (uint32_t)nent, &lba, &idx)) return -ENOSPC;
    return write_entry(lba, idx, raw, attr, first, size);
}

static int fat_make(const char *path, int dir) {
    uint32_t pcl; char base[256];
    int r = split_parent(path, &pcl, base);
    if (r) return r;
    uint8_t attr = dir ? ATTR_DIR : 0x20 /* archive */;
    uint32_t first = 0;
    if (dir) {
        first = fat_alloc();
        if (!first) return -ENOSPC;
        fat_zero_cluster(first);
        uint8_t dot[11]; kmemset(dot, ' ', 11); dot[0] = '.';
        write_entry(cluster_lba(first), 0, dot, ATTR_DIR, first, 0);
        uint8_t dd[11]; kmemset(dd, ' ', 11); dd[0] = '.'; dd[1] = '.';
        write_entry(cluster_lba(first), 1, dd, ATTR_DIR, pcl, 0);
    }
    uint8_t raw[11];
    if (to_83(base, raw) == 0) {                    /* fits 8.3 — no LFN needed */
        uint32_t lba, idx;
        if (find_free_slot(pcl, &lba, &idx) != 0) return -ENOSPC;
        return write_entry(lba, idx, raw, attr, first, 0);
    }
    gen_short(base, raw);                            /* long name — LFN + 8.3 */
    return write_lfn_name(pcl, base, attr, first, 0, raw);
}

/* ---- fs_ops: write half ---------------------------------------------- */

static int fat_create(const char *p, uint16_t m, int h) { (void)m; (void)h; return fat_make(p, 0); }
static int fat_mkdir(const char *p, uint16_t m, int h)  { (void)m; (void)h; return fat_make(p, 1); }

static int fat_unlink(const char *path, int h) {
    (void)h;
    uint32_t ino; fat_dirent_t d;
    int r = resolve(path, &ino, &d, 0, 0);
    if (r) return r;
    if (d.attr & ATTR_DIR) return -EISDIR;
    if (d.first_cluster >= 2) fat_free_chain(d.first_cluster);
    uint32_t lba = ino >> 5, idx = ino & 31; uint8_t sec[SECTOR];
    if (fat_read_lba(lba, sec) != 0) return -EIO;
    sec[idx * DIRENT_SIZE] = 0xE5;
    return fat_write_lba(lba, sec) == 0 ? 0 : -EIO;
}

/* inode-level write: extend the chain as needed, RMW partial sectors, grow size */
static int fat_write(uint32_t ino, const void *buf, uint32_t off, uint32_t len) {
    fat_dirent_t d;
    if (read_dirent(ino, &d) != 0) return -ENOENT;
    if (d.attr & ATTR_DIR) return -EISDIR;
    uint32_t csize = (uint32_t)s_spc * SECTOR;
    uint32_t first = d.first_cluster;
    if (first < 2) { first = fat_alloc(); if (!first) return -ENOSPC; }
    /* first_cluster came off a directory entry: reject it before it reaches
     * cluster_lba() below. */
    if (!fat_cluster_ok(first)) return -EIO;

    uint32_t cl = first;
    for (uint32_t k = 0; k < off / csize; k++) {
        uint32_t nx = fat_next(cl);
        if (nx >= FAT_EOC) { nx = fat_alloc(); if (!nx) return -ENOSPC; fat_set(cl, nx); }
        cl = nx;
        if (!fat_cluster_ok(cl)) return -EIO;    /* corrupt/cyclic chain */
    }
    uint8_t sec[SECTOR];
    uint32_t done = 0, pos = off % csize;
    while (done < len) {
        uint32_t s = pos / SECTOR, so = pos % SECTOR;
        uint32_t lba = cluster_lba(cl) + s, n = SECTOR - so;
        if (n > len - done) n = len - done;
        if (so != 0 || n < SECTOR) { if (fat_read_lba(lba, sec) != 0) kmemset(sec, 0, SECTOR); }
        kmemcpy(sec + so, (const uint8_t *)buf + done, n);
        if (fat_write_lba(lba, sec) != 0) break;
        done += n; pos += n;
        if (pos >= csize && done < len) {
            uint32_t nx = fat_next(cl);
            if (nx >= FAT_EOC) { nx = fat_alloc(); if (!nx) break; fat_set(cl, nx); }
            cl = nx; pos = 0;
            if (!fat_cluster_ok(cl)) break;      /* corrupt/cyclic chain */
        }
    }
    /* Compute the new size in 64-bit (audit M8): `off` is 64-bit, so the old
     * `uint32_t ns = off + done` truncated, and a large offset recorded a size
     * SMALLER than what was just written — leaving the size field inconsistent
     * with the cluster chain. FAT32 tops out at 4 GiB - 1, so anything beyond
     * that is refused rather than silently wrapped (no EFBIG in this errno
     * set; ENOSPC is the closest and is already this function's overflow
     * return). */
    uint64_t ns64 = off + done;
    if (ns64 > 0xFFFFFFFFULL) return -ENOSPC;
    uint32_t ns = (uint32_t)ns64;
    patch_entry(ino, first, ns > d.size ? ns : d.size);
    return (int)done;
}

static int fat_truncate(uint32_t ino) {
    fat_dirent_t d;
    if (read_dirent(ino, &d) != 0) return -ENOENT;
    if (d.first_cluster >= 2) fat_free_chain(d.first_cluster);
    return patch_entry(ino, 0, 0);
}

/* ---- ops FAT genuinely lacks (no perms / hard links / symlinks) ------ */
static int fat_chmod(const char *p, uint16_t m, int h)  { (void)p; (void)m; (void)h; return 0; }  /* no-op: FAT has no mode */
static int notempty_cb(const char *name, uint32_t ino, const fat_dirent_t *d, void *c) {
    (void)ino; (void)d;
    if (fat_streq(name, ".") || fat_streq(name, "..")) return 0;
    *(int *)c = 1;
    return 1;   /* found a real entry — stop */
}
static int fat_rmdir(const char *path, int h) {
    (void)h;
    uint32_t ino; fat_dirent_t d;
    int r = resolve(path, &ino, &d, 0, 0);
    if (r) return r;
    if (!(d.attr & ATTR_DIR)) return -ENOTDIR;
    int nonempty = 0;
    walk_dir(d.first_cluster, notempty_cb, &nonempty);
    if (nonempty) return -ENOTEMPTY;
    if (d.first_cluster >= 2) fat_free_chain(d.first_cluster);
    uint32_t lba = ino >> 5, idx = ino & 31; uint8_t sec[SECTOR];
    if (fat_read_lba(lba, sec) != 0) return -EIO;
    sec[idx * DIRENT_SIZE] = 0xE5;
    return fat_write_lba(lba, sec) == 0 ? 0 : -EIO;
}
/* rename/move: create a new dir entry pointing at the same cluster chain, then
 * delete the old one (the data is NOT freed — it moved). A moved directory's
 * ".." still points at its old parent — a known limitation for now. */
static int fat_rename(const char *old, const char *neu, int h) {
    (void)h;
    uint32_t oino; fat_dirent_t od;
    int r = resolve(old, &oino, &od, 0, 0);
    if (r) return r;
    uint32_t tmp; fat_dirent_t td;
    if (resolve(neu, &tmp, &td, 0, 0) == 0) return -EEXIST;
    uint32_t pcl; char base[256];
    if ((r = split_parent(neu, &pcl, base)) != 0) return r;
    uint8_t raw[11];
    if (to_83(base, raw) != 0) return -EINVAL;   /* long dest names: later */
    uint32_t lba, idx;
    if (find_free_slot(pcl, &lba, &idx) != 0) return -ENOSPC;
    if ((r = write_entry(lba, idx, raw, od.attr, od.first_cluster, od.size)) != 0) return r;
    uint32_t olba = oino >> 5, oidx = oino & 31; uint8_t sec[SECTOR];
    if (fat_read_lba(olba, sec) != 0) return -EIO;
    sec[oidx * DIRENT_SIZE] = 0xE5;
    return fat_write_lba(olba, sec) == 0 ? 0 : -EIO;
}
static int fat_link(const char *a, const char *b, int h)   { (void)a; (void)b; (void)h; return -EPERM; }
static int fat_symlink(const char *a, const char *b, int h){ (void)a; (void)b; (void)h; return -EPERM; }
static int fat_readlink(const char *p, char *b, uint32_t n){ (void)p; (void)b; (void)n; return -EINVAL; }
static int fat_chown(const char *p, uint16_t u, uint16_t g, int f, int h) { (void)p; (void)u; (void)g; (void)f; (void)h; return 0; }  /* no-op */
static int fat_utimes(const char *p, uint32_t a, uint32_t m, int f, int h){ (void)p; (void)a; (void)m; (void)f; (void)h; return 0; }  /* no-op */
static int fat_write_inode(uint32_t i, const ext2_inode_t *o) { (void)i; (void)o; return 0; }  /* metadata not persisted */
static uint32_t fat_zero(void) { return 0; }
static void fat_anchors_reload(void) { }

/* ---- fd-private pool + file (vfs_ops_t) layer ------------------------ */
#define FAT_FDS 64
static ext2_fd_priv_t s_fds[FAT_FDS];

static ext2_fd_priv_t *fat_pool_alloc(uint32_t ino) {
    for (int i = 0; i < FAT_FDS; i++)
        if (!__atomic_exchange_n(&s_fds[i].in_use, 1, __ATOMIC_ACQ_REL)) {
            s_fds[i].ino = ino; s_fds[i].write_offset = 0;
            return &s_fds[i];
        }
    return 0;
}
static void fat_pool_free(ext2_fd_priv_t *p) { if (p) __atomic_store_n(&p->in_use, 0, __ATOMIC_RELEASE); }

static int  fat_f_read(void *priv, void *buf, uint64_t off, uint64_t len) { return fat_read(((ext2_fd_priv_t *)priv)->ino, buf, off, (uint32_t)len); }
static int  fat_f_write(void *priv, const void *buf, uint64_t len) {
    ext2_fd_priv_t *p = priv;
    int r = fat_write(p->ino, buf, p->write_offset, (uint32_t)len);   /* seq cursor */
    if (r > 0) p->write_offset += (uint32_t)r;
    return r;
}
static void fat_f_seek(void *priv, uint64_t off)  { ((ext2_fd_priv_t *)priv)->write_offset = (uint32_t)off; }
static void fat_f_close(void *priv) { fat_pool_free((ext2_fd_priv_t *)priv); }
static void fat_f_dup(void *priv)   { (void)priv; }
static int  fat_f_readdir(void *priv, uint64_t index, char *name, uint8_t *type) { return fat_readdir(((ext2_fd_priv_t *)priv)->ino, index, name, type); }

static const vfs_ops_t fat_file_ops = {
    .read    = fat_f_read,
    .write   = fat_f_write,
    .seek    = fat_f_seek,
    .close   = fat_f_close,
    .readdir = fat_f_readdir,
    .dup     = fat_f_dup,
    .stat    = (void *)0,       /* VFS synthesizes from f->size */
    .poll    = (void *)0,
    .seekable = 1,
};

#ifdef CONFIG_KERNEL_TESTS
/* create /FATTEST.TXT, write a string, read it back, verify — run once on
 * mount. Also leaves the file on disk so the host can confirm persistence. */
static void fat_selftest(void) {
    static const char msg[] = "AEGIS FAT WRITE OK\n";
    uint32_t wl = (uint32_t)(sizeof(msg) - 1), ino;

    /* 1. 8.3 create + write + read-back */
    int ok = (fat_create("/FATTEST.TXT", 0644, 0) == 0)
          && (fat_open("/FATTEST.TXT", &ino) == 0)
          && (fat_write(ino, msg, 0, wl) == (int)wl);
    if (ok) {
        char rb[32]; kmemset(rb, 0, sizeof rb);
        ok = (fat_read(ino, rb, 0, wl) == (int)wl);
        for (uint32_t i = 0; i < wl && ok; i++) if (rb[i] != msg[i]) ok = 0;
    }
    printk("[FAT] TEST short-name write %s\n", ok ? "PASS" : "FAIL");

    /* 2. long (VFAT) name: create, then resolve it BY the long name */
    const char *lname = "/A Long Filename.txt";
    ok = (fat_create(lname, 0644, 0) == 0)
      && (fat_open(lname, &ino) == 0)
      && (fat_write(ino, msg, 0, wl) == (int)wl);
    printk("[FAT] TEST long-name (LFN) %s\n", ok ? "PASS" : "FAIL");

    /* 3. mkdir then rmdir the (empty) directory */
    ok = (fat_mkdir("/SUBDIR", 0755, 0) == 0) && (fat_rmdir("/SUBDIR", 0) == 0);
    printk("[FAT] TEST mkdir/rmdir %s\n", ok ? "PASS" : "FAIL");

    /* 4. rename: new name resolves, old name is gone */
    ok = (fat_rename("/FATTEST.TXT", "/RENAMED.TXT", 0) == 0)
      && (fat_open("/RENAMED.TXT", &ino) == 0)
      && (fat_open("/FATTEST.TXT", &ino) != 0);
    printk("[FAT] TEST rename %s\n", ok ? "PASS" : "FAIL");
}
#endif

const fs_ops_t fat_ops = {
    .name = "fat", .file_ops = &fat_file_ops,
    .mount = fat_mount, .sync = fat_sync, .statfs = fat_statfs,
    .mark_clean = fat_mark_clean, .devname = fat_devname,
    .lock = fat_lock, .unlock = fat_unlock, .ino_of = fat_ino_of,
    .open = fat_open, .open_ex = fat_open_ex, .open_protected = fat_open_prot,
    .lookup_parent = fat_lookup_parent, .path_under_protected = fat_under_prot,
    .create = fat_create, .mkdir = fat_mkdir, .rmdir = fat_rmdir, .unlink = fat_unlink,
    .rename = fat_rename, .link = fat_link, .symlink = fat_symlink, .readlink = fat_readlink,
    .chmod = fat_chmod, .chown = fat_chown, .utimes = fat_utimes,
    .read_inode = fat_read_inode, .write_inode = fat_write_inode,
    .read = fat_read, .read_validated = fat_read_val, .write = fat_write,
    .readdir = fat_readdir, .file_size = fat_file_size, .truncate = fat_truncate,
    .is_dir = fat_is_dir, .check_perm = fat_check_perm, .inode_gen = fat_inode_gen,
    .read_symlink_target = fat_readlink_ino,
    .pool_alloc = fat_pool_alloc, .pool_free = fat_pool_free,
    .get_admin_ino = fat_zero, .get_passwd_ino = fat_zero,
    .get_shadow_ino = fat_zero, .get_group_ino = fat_zero,
    .anchors_reload = fat_anchors_reload,
};

const fs_ops_t *g_rootfs = &fat_ops;
