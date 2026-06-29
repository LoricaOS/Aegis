#ifndef AEGIS_DEV_TABLE_H
#define AEGIS_DEV_TABLE_H
/*
 * dev_table.h — one declarative table of /dev character specials, replacing
 * three hand-kept-in-sync sites.
 *
 * /dev specials have NO registry. Each special is described THREE TIMES, by
 * hand, in three different code shapes that drift:
 *   1. OPEN   — vfs.c vfs_open() / initrd.c initrd_open(): per-char path
 *      compares that install an ops+priv into the fd (vfs_file_t).
 *   2. STAT   — vfs.c vfs_stat_path(): a PARALLEL set of streq() blocks that
 *      synthesise a k_stat_t (st_mode/st_ino/st_rdev) for the SAME paths.
 *   3. READDIR— initrd.c s_dev_entries[]: {name, dirent-type} for listing /dev.
 * /dev/mouse already proves the drift — it is open-bespoke, stat-bespoke, and a
 * readdir entry, with the major/minor (13,0) written twice and the mode (0444
 * vs the read in mouse_stat_fn) easy to mismatch. Adding a new /dev node means
 * editing three places and hoping you matched ino/rdev/mode across all of them.
 *
 * This table is the single source of truth for the SIMPLE specials — the ones
 * whose open returns a static singleton vfs_file_t and whose stat is a fixed
 * (mode, ino, rdev) triple. All three sites consume it:
 *   - initrd_open: walk the table, on a path match `*out = *e->file; return 0`.
 *   - vfs_stat_path: walk the table, on a match fill k_stat_t from e->mode/
 *     ino/rdev and return 0.
 *   - initrd readdir: the table doubles as the /dev directory listing
 *     (e->name + a fixed DT_CHR type) — s_dev_entries[] is derived from it (or
 *     deleted in favour of iterating the table).
 *
 * DELIBERATELY NOT in the table (they are NOT simple singletons — keep their
 * bespoke open logic, but the spec moves their STAT rows here so stat is still
 * unified):
 *   - /dev/ptmx   → ptmx_open() allocates a PTY master dynamically.
 *   - /dev/pts/N  → pts_open(idx) parses N and opens a slave.
 *   - /dev/tty    → kbd_vfs_open() returns a shared singleton POINTER (not a
 *     by-value file); table can carry it if its file pointer is filled at init,
 *     else it stays a one-line special before the table walk.
 *   - the /proc, /tmp, /run subtrees and ext2 — not /dev, untouched.
 *
 * The table ENTRIES reference static `vfs_ops_t`/`vfs_file_t` that live in
 * initrd.c (s_urandom_file, s_null_file, s_mouse_file, the console file). So the
 * table itself is DEFINED in initrd.c (it needs those static symbols); this
 * header only declares the row type and the lookup that vfs.c's stat path
 * calls. Keeping the definition in initrd.c also keeps the /dev backing devices
 * colocated with the table that names them.
 *
 * (blkdev_t / netdev_t already have clean registries — this is the same idea
 * for the last unregistered device class. Do NOT touch those.)
 */
#include "vfs.h"
#include <stdint.h>

/*
 * One /dev character-special row. `file` is the singleton returned by open
 * (by value: `*out = *file`). The stat triple is what vfs_stat_path
 * synthesises. `name` is the leaf for readdir (path without the "/dev/"
 * prefix). For aliases that share one backing file (/dev/random→urandom,
 * /dev/console/tty/stdin/stdout/stderr→console) add one row per path, all
 * pointing at the same `file` and stat triple — drift becomes impossible
 * because they are literally the same struct fields.
 */
typedef struct {
    const char       *path;   /* full path, e.g. "/dev/urandom"           */
    const char       *name;   /* leaf for readdir, e.g. "urandom"; NULL to
                                 omit from the /dev listing (aliases)      */
    const vfs_file_t *file;   /* singleton installed on open (NULL = stat-
                                 only row, e.g. /dev/ptmx)                 */
    uint16_t          mode;   /* st_mode (S_IFCHR | perms)                 */
    uint32_t          ino;    /* st_ino                                    */
    uint32_t          rdev;   /* st_rdev (makedev(maj,min))                */
} dev_special_t;

/*
 * dev_table_get — return the NULL-terminated array of /dev specials. Defined in
 * initrd.c (where the backing vfs_file_t singletons live). Walk until
 * entry->path == NULL. Used by initrd_open (open), vfs_stat_path (stat), and
 * the /dev readdir.
 */
const dev_special_t *dev_table_get(void);

/*
 * dev_table_stat — fill *out for `path` if it names a /dev special, return 0;
 * return -1 (not a /dev special — caller falls through to its other cases) if
 * not found. Convenience wrapper over dev_table_get for vfs_stat_path so the
 * stat site is one call, not an open-coded walk. Defined in initrd.c.
 */
int dev_table_stat(const char *path, k_stat_t *out);

#endif /* AEGIS_DEV_TABLE_H */
