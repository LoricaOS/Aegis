/* cap_policy.c — file-based capability policy engine.
 *
 * Loads policy files from /etc/aegis/caps.d/ at boot via VFS.
 * Each file is named after a binary basename (e.g. "httpd") and contains
 * lines of the form:
 *     service NET_SOCKET
 *     admin AUTH SETUID
 *
 * "service" caps are granted unconditionally at exec.
 * "admin" caps are granted only if proc->authenticated == 1.
 *
 * cap_policy_lookup(exe_path) extracts the basename from the path
 * and returns the matching entry, or NULL.
 */
#include "vfs.h"
#include "ext2.h"
#include "cap.h"
#include "printk.h"
#include <stdint.h>
#include <stddef.h>

/* Static policy table */
static cap_policy_entry_t s_entries[CAP_POLICY_MAX_ENTRIES];
static uint32_t s_entry_count;

/* Dynamic trusted-path anchors: extra directory prefixes (beyond the hardcoded
 * /bin /sbin /apps) under which an installed binary may derive policy caps. Read
 * from /etc/aegis/anchors in cap_policy_load() — the SAME file ext2.c reads for
 * its write-protection inodes, so the granting set and the protected set stay
 * identical (the "trusted-for-granting == write-protected" invariant). Each entry
 * is stored with a trailing '/' for unambiguous prefix matching. */
#define CAP_ANCHOR_MAX 16
static char s_anchor_paths[CAP_ANCHOR_MAX][64];
static int  s_anchor_path_count;

/* Map a capability name string to its CAP_KIND_* value.
 * Returns 0 (CAP_KIND_NULL) if not recognized. */
static uint32_t
cap_name_to_kind(const char *name)
{
    /* Compare with known cap kind names.
     * Using manual comparison to avoid libc dependency. */
    struct { const char *str; uint32_t kind; } map[] = {
        { "VFS_OPEN",       CAP_KIND_VFS_OPEN },
        { "VFS_WRITE",      CAP_KIND_VFS_WRITE },
        { "VFS_READ",       CAP_KIND_VFS_READ },
        { "AUTH",           CAP_KIND_AUTH },
        { "CAP_GRANT",      CAP_KIND_CAP_GRANT },
        { "SETUID",         CAP_KIND_SETUID },
        { "NET_SOCKET",     CAP_KIND_NET_SOCKET },
        { "NET_ADMIN",      CAP_KIND_NET_ADMIN },
        { "THREAD_CREATE",  CAP_KIND_THREAD_CREATE },
        { "PROC_READ",      CAP_KIND_PROC_READ },
        { "DISK_ADMIN",     CAP_KIND_DISK_ADMIN },
        { "FB",             CAP_KIND_FB },
        { "CAP_DELEGATE",   CAP_KIND_CAP_DELEGATE },
        { "CAP_QUERY",      CAP_KIND_CAP_QUERY },
        { "IPC",            CAP_KIND_IPC },
        { "POWER",          CAP_KIND_POWER },
        { "INSTALL",        CAP_KIND_INSTALL },
        { "NET_LISTEN",     CAP_KIND_NET_LISTEN },
        { "ADMIN_AUTH",     CAP_KIND_ADMIN_AUTH },
    };
    /* T4 cap-enum guard: the table must name every cap kind 1..CAP_KIND_MAX
     * (CAP_KIND_NULL=0 is excluded — it is the empty-slot sentinel, not a
     * grantable cap). Adding a CAP_KIND_* without a matching name string here,
     * or bumping CAP_KIND_MAX without adding the kind, breaks this and fails the
     * build — far better than a policy file silently failing to grant a cap that
     * has no name to match. */
    _Static_assert(sizeof(map) / sizeof(map[0]) == CAP_KIND_MAX,
                   "cap_name_to_kind must list every cap kind 1..CAP_KIND_MAX");
    uint32_t i;
    for (i = 0; i < sizeof(map) / sizeof(map[0]); i++) {
        const char *a = map[i].str;
        const char *b = name;
        while (*a && *b && *a == *b) { a++; b++; }
        if (*a == '\0' && *b == '\0')
            return map[i].kind;
    }
    return CAP_KIND_NULL;
}

/* String comparison without libc */
static int
streq(const char *a, const char *b)
{
    while (*a && *b && *a == *b) { a++; b++; }
    return (*a == '\0' && *b == '\0');
}

/* Prefix test without libc: returns 1 if `s` begins with `prefix`. */
static int
starts_with(const char *s, const char *prefix)
{
    while (*prefix) {
        if (*s != *prefix)
            return 0;
        s++;
        prefix++;
    }
    return 1;
}

/* 1 if exe_path falls under a dynamically-registered trusted anchor. */
static int
anchor_path_trusted(const char *exe_path)
{
    int i;
    for (i = 0; i < s_anchor_path_count; i++)
        if (s_anchor_paths[i][0] && starts_with(exe_path, s_anchor_paths[i]))
            return 1;
    return 0;
}

/* Returns 1 if mutating `path` touches the install-protected trees (/apps,
 * /etc/aegis). Delegates to the ext2 resolver so the check is on the RESOLVED
 * inode, not the raw string: symlinks ("ln -s /apps /tmp/x; >/tmp/x/foo"),
 * "..", "//", and the bare directory names are all handled. A pure string
 * prefix check here was bypassable and is intentionally not used. */
int
cap_path_is_protected(const char *path)
{
    return ext2_path_under_protected(path);
}

/* Substring test without libc: returns 1 if `needle` occurs anywhere in `s`. */
static int
contains(const char *s, const char *needle)
{
    const char *h;
    const char *n;
    for (; *s; s++) {
        h = s;
        n = needle;
        while (*n && *h == *n) { h++; n++; }
        if (*n == '\0')
            return 1;
    }
    return 0;
}

/* Parse one policy file's contents into an entry.
 * Format: one line per cap, each line is "service CAP_NAME" or "admin CAP_NAME".
 * Multiple cap names per line separated by spaces.
 * Returns 0 on success, -1 on error. */
static int
parse_policy(const char *data, uint64_t len, cap_policy_entry_t *entry)
{
    uint64_t pos = 0;
    entry->count = 0;

    while (pos < len && entry->count < CAP_POLICY_MAX_CAPS) {
        /* Skip whitespace and newlines */
        while (pos < len && (data[pos] == ' ' || data[pos] == '\t' ||
                             data[pos] == '\n' || data[pos] == '\r'))
            pos++;
        if (pos >= len) break;

        /* Skip comment lines */
        if (data[pos] == '#') {
            while (pos < len && data[pos] != '\n') pos++;
            continue;
        }

        /* Read tier word */
        char tier_buf[16];
        uint32_t ti = 0;
        while (pos < len && data[pos] != ' ' && data[pos] != '\t' &&
               data[pos] != '\n' && data[pos] != '\r' && ti < sizeof(tier_buf) - 1) {
            tier_buf[ti++] = data[pos++];
        }
        tier_buf[ti] = '\0';

        uint32_t tier;
        if (streq(tier_buf, "service"))
            tier = CAP_TIER_SERVICE;
        else if (streq(tier_buf, "admin"))
            tier = CAP_TIER_ADMIN;
        else
            continue;  /* unknown tier — skip line */

        /* Read cap names on the rest of this line */
        while (pos < len && data[pos] != '\n' && data[pos] != '\r') {
            /* Skip whitespace */
            while (pos < len && (data[pos] == ' ' || data[pos] == '\t'))
                pos++;
            if (pos >= len || data[pos] == '\n' || data[pos] == '\r')
                break;

            /* Read cap name */
            char cap_buf[32];
            uint32_t ci = 0;
            while (pos < len && data[pos] != ' ' && data[pos] != '\t' &&
                   data[pos] != '\n' && data[pos] != '\r' && ci < sizeof(cap_buf) - 1) {
                cap_buf[ci++] = data[pos++];
            }
            cap_buf[ci] = '\0';

            uint32_t kind = cap_name_to_kind(cap_buf);
            if (kind == CAP_KIND_NULL) {
                printk("[CAP_POLICY] WARN: unknown cap '%s'\n", cap_buf);
                continue;
            }

            if (entry->count < CAP_POLICY_MAX_CAPS) {
                entry->caps[entry->count].kind   = kind;
                entry->caps[entry->count].rights = CAP_RIGHTS_READ | CAP_RIGHTS_WRITE | CAP_RIGHTS_EXEC;
                entry->caps[entry->count].tier   = tier;
                entry->count++;
            }
        }
    }

    return 0;
}

void
cap_policy_load(void)
{
    s_entry_count = 0;

    /* Read the directory listing from /etc/aegis/caps.d/ */
    vfs_file_t dir;
    int r = vfs_open("/etc/aegis/caps.d", 0, 0, &dir);
    if (r != 0) {
        printk("[CAP_POLICY] OK: no /etc/aegis/caps.d — 0 policies loaded\n");
        return;
    }

    /* Iterate directory entries */
    char name[256];
    uint8_t dtype;
    uint64_t idx = 0;

    while (dir.ops->readdir &&
           dir.ops->readdir(dir.priv, idx, name, &dtype) == 0) {
        idx++;
        if (dtype != 8)  /* DT_REG = 8, skip non-regular files */
            continue;
        if (s_entry_count >= CAP_POLICY_MAX_ENTRIES) {
            printk("[CAP_POLICY] WARN: policy table full (%u) — remaining "
                   "caps.d files IGNORED (apps will lose their caps)\n",
                   (unsigned)CAP_POLICY_MAX_ENTRIES);
            break;
        }

        /* Build full path */
        char path[256];
        uint32_t pi = 0;
        const char *prefix = "/etc/aegis/caps.d/";
        while (*prefix && pi < sizeof(path) - 1)
            path[pi++] = *prefix++;
        const char *np = name;
        while (*np && pi < sizeof(path) - 1)
            path[pi++] = *np++;
        path[pi] = '\0';

        /* Open and read the policy file */
        vfs_file_t f;
        if (vfs_open(path, 0, 0, &f) != 0)
            continue;

        /* Read file contents into a stack buffer (policy files are small) */
        char buf[512];
        uint64_t fsize = f.size;
        if (fsize > sizeof(buf) - 1)
            fsize = sizeof(buf) - 1;
        if (f.ops->read) {
            int bytes = f.ops->read(f.priv, buf, 0, fsize);
            if (bytes > 0) {
                buf[bytes] = '\0';
                cap_policy_entry_t *entry = &s_entries[s_entry_count];
                /* Copy basename as the entry name */
                uint32_t ni = 0;
                const char *src = name;
                while (*src && ni < sizeof(entry->name) - 1)
                    entry->name[ni++] = *src++;
                entry->name[ni] = '\0';

                if (parse_policy(buf, (uint64_t)bytes, entry) == 0 &&
                    entry->count > 0) {
                    s_entry_count++;
                }
            }
        }
        if (f.ops->close)
            f.ops->close(f.priv);
    }
    if (dir.ops->close)
        dir.ops->close(dir.priv);
    printk("[CAP_POLICY] loaded %u policy file(s)\n", (unsigned)s_entry_count);

    /* Load the dynamic trusted-path anchors from /etc/aegis/anchors (one absolute
     * dir per line). ext2.c reads the same file for write-protection inodes;
     * sys_install_commit() refreshes both together. Stored with a trailing '/'. */
    s_anchor_path_count = 0;
    {
        vfs_file_t af;
        if (vfs_open("/etc/aegis/anchors", 0, 0, &af) == 0) {
            char abuf[1024];
            uint64_t asz = af.size;
            int an = 0;
            if (asz > sizeof(abuf) - 1)
                asz = sizeof(abuf) - 1;
            if (af.ops->read)
                an = af.ops->read(af.priv, abuf, 0, asz);
            if (af.ops->close)
                af.ops->close(af.priv);
            if (an > 0) {
                int ai = 0;
                abuf[an] = '\0';
                while (ai < an && s_anchor_path_count < CAP_ANCHOR_MAX) {
                    int start, end, len;
                    while (ai < an && (abuf[ai] == ' ' || abuf[ai] == '\t' ||
                                       abuf[ai] == '\r' || abuf[ai] == '\n'))
                        ai++;
                    start = ai;
                    while (ai < an && abuf[ai] != '\n' && abuf[ai] != '\r')
                        ai++;
                    end = ai;
                    while (end > start && (abuf[end - 1] == ' ' || abuf[end - 1] == '\t'))
                        end--;
                    len = end - start;
                    if (len > 0 && abuf[start] == '/' &&
                        len < (int)sizeof(s_anchor_paths[0]) - 1) {
                        char *dst = s_anchor_paths[s_anchor_path_count];
                        int k;
                        for (k = 0; k < len; k++)
                            dst[k] = abuf[start + k];
                        if (dst[len - 1] != '/' &&
                            len < (int)sizeof(s_anchor_paths[0]) - 1)
                            dst[len++] = '/';
                        dst[len] = '\0';
                        s_anchor_path_count++;
                    }
                }
            }
        }
    }

    printk("[CAP_POLICY] OK: %u policies, %u anchors loaded\n",
           s_entry_count, (unsigned)s_anchor_path_count);
}

/* cap_anchor_audit — verify the trusted-for-granting tree ⊆ the write-protected
 * tree (T5). cap_policy_lookup derives authority from a binary's PATH, so every
 * granting anchor MUST be install-protected at the ext2 layer — otherwise an
 * unprivileged user could drop a forged binary under a granting-but-writable
 * directory and inherit its caps by basename. This walks each granting anchor
 * (static /bin /sbin /apps + the dynamic /etc/aegis/anchors entries) and asks
 * ext2 whether it is install-protected; any miss is a WARN, never a panic, so a
 * surprising fs layout can never block boot (the gate's explicit requirement).
 *
 * Direction: only anchor ⊆ protected is checked. The reverse is intentionally
 * looser — /etc/aegis is install-protected but is NOT a granting anchor (nothing
 * is exec'd from it), so a full set-equality check would false-WARN on it.
 *
 * MUST run AFTER ext2_anchors_reload() so the dynamic protected inodes
 * (s_anchor_ino in ext2.c) are populated; main.c calls it there. */
void
cap_anchor_audit(void)
{
    static const char *const static_anchors[] = { "/bin", "/sbin", "/apps" };
    unsigned warned = 0;
    unsigned i;

    for (i = 0; i < sizeof(static_anchors) / sizeof(static_anchors[0]); i++) {
        if (!ext2_path_under_protected(static_anchors[i])) {
            printk("[CAP_POLICY] WARN: granting anchor %s is NOT "
                   "install-protected — path-based authority is forgeable\n",
                   static_anchors[i]);
            warned++;
        }
    }
    for (i = 0; i < (unsigned)s_anchor_path_count; i++) {
        if (!s_anchor_paths[i][0])
            continue;
        if (!ext2_path_under_protected(s_anchor_paths[i])) {
            printk("[CAP_POLICY] WARN: dynamic anchor %s is NOT "
                   "install-protected — path-based authority is forgeable\n",
                   s_anchor_paths[i]);
            warned++;
        }
    }
    if (warned == 0)
        printk("[CAP_POLICY] OK: anchor/protected-tree invariant holds "
               "(%u anchors)\n",
               3u + (unsigned)s_anchor_path_count);
}

const cap_policy_entry_t *
cap_policy_lookup(const char *exe_path)
{
    if (!exe_path || !exe_path[0])
        return (const cap_policy_entry_t *)0;

    /* === Trusted-path anchor (CRITICAL: privilege-escalation defense) ===
     *
     * Policy capabilities (e.g. POWER → reboot, AUTH → login, DISK_ADMIN →
     * raw disk) are powerful. The previous implementation derived a process's
     * caps purely from the BASENAME of its executable path. That is forgeable:
     * the root fs is writable ext2 and uid is cosmetic, so any unprivileged
     * user could copy an arbitrary ELF to /tmp/reboot (basename "reboot" →
     * CAP_KIND_POWER) or /tmp/login (basename "login" → service-tier AUTH →
     * sys_auth_session → authenticated=1 → exec an admin-tier binary →
     * DISK_ADMIN), forging authority by choosing a filename.
     *
     * Fix: anchor policy authority to a trusted location. Caps are only
     * derived from policy when the executable lives under a trusted system
     * directory (/bin, /sbin, or /apps — the system app-bundle tree, which
     * like /bin is root-owned and only writable through an admin-gated
     * install). All shipped policies are for such binaries. If any of the
     * following fails, return NULL so the caller falls back to baseline
     * caps only:
     *   1. absolute path (begins with '/'),
     *   2. begins with "/bin/", "/sbin/", or "/apps/",
     *   3. contains no ".." path component (defends against /bin/../tmp/x).
     *
     * NOTE: `exe_path` here is the RAW user-supplied path (see callers in
     * kernel/syscall/sys_exec.c) — it is NOT kernel-canonicalized. The ".."
     * rejection blocks the obvious traversal. A symlink inside /bin pointing
     * outside it would also forge authority, BUT /bin, /sbin and /apps are now
     * install-protected at the fs layer (ext2.c: s_bin_ino/s_sbin_ino/
     * s_apps_ino → cap_path_is_protected → CAP_KIND_INSTALL): an unprivileged
     * user cannot create such a symlink (or overwrite a trusted binary) in the
     * first place. The trusted-for-granting tree and the write-protected tree
     * are deliberately the same set, which closes the writable-/bin hole. */
    if (exe_path[0] != '/')
        return (const cap_policy_entry_t *)0;
    if (!starts_with(exe_path, "/bin/") && !starts_with(exe_path, "/sbin/") &&
        !starts_with(exe_path, "/apps/") && !anchor_path_trusted(exe_path))
        return (const cap_policy_entry_t *)0;
    if (contains(exe_path, ".."))
        return (const cap_policy_entry_t *)0;

    /* === Granting set == write-protected set (anchor drift / TOCTOU defense) ===
     *
     * The string-prefix anchors above (and the dynamic anchor strings) are
     * necessary but NOT sufficient. The load-bearing invariant is "the
     * trusted-for-granting tree == the install-write-protected tree": authority
     * is derived from a binary's PATH, so that path must be unforgeable. Those
     * two sets were computed independently — grants by STRING prefix here,
     * write-protection by recorded INODE in ext2.c — and could drift apart:
     *   - a missing /sbin at mount (s_sbin_ino == 0) leaves the "/sbin/" string
     *     prefix granting while nothing under it is write-protected;
     *   - a dynamic /etc/aegis/anchors line whose directory did not resolve
     *     records the string prefix (cap_policy_load) but no inode
     *     (ext2_anchors_reload), again granting-but-writable;
     *   - the RAM-only fallback boot (!s_mounted) protects nothing yet would
     *     still grant on the string prefixes.
     * In every case an unprivileged user could drop a forged, policy-named ELF
     * under a granting-but-writable path and inherit its caps by basename.
     * cap_anchor_audit() only WARNs about this; it does not refuse the grant.
     *
     * Fix: tie the grant to the SAME inode-based check the fs layer uses for
     * write-protection. Only derive policy caps from a path that is genuinely
     * install-protected RIGHT NOW. ext2_path_under_protected() resolves the path
     * on the inode (following symlinks / ".." / "//"), so the grant decision and
     * the write-protection decision can no longer disagree (security review 04
     * finding 2 / 05 finding ... drift; subsumes the RAM-fallback hole too).
     *
     * Residual (documented honestly): this gates the GRANT, not the file
     * PLANTING. The check-vs-use TOCTOU in sys_open (cap_path_is_protected and
     * the O_CREAT are separate ext2_lock acquisitions) could still let a
     * symlink-swap race plant a binary that ends up genuinely under /bin — which
     * would then pass this inode check and receive caps. Fully closing that
     * requires an atomic resolve-and-create under a single ext2_lock in the
     * mutators (sys_open/sys_mkdir/sys_symlink/sys_rename); that is a larger
     * refactor left as follow-up. */
    if (!ext2_path_under_protected(exe_path))
        return (const cap_policy_entry_t *)0;

    /* Extract basename: everything after the last '/' */
    const char *basename = exe_path;
    const char *p = exe_path;
    while (*p) {
        if (*p == '/')
            basename = p + 1;
        p++;
    }

    if (!basename[0])
        return (const cap_policy_entry_t *)0;

    /* Search the policy table */
    uint32_t i;
    for (i = 0; i < s_entry_count; i++) {
        if (streq(s_entries[i].name, basename))
            return &s_entries[i];
    }
    return (const cap_policy_entry_t *)0;
}

void
cap_apply_policy(cap_slot_t *caps, const char *path, int authenticated,
                 int admin_session)
{
    /* Reset the table, then grant baseline + policy caps. This is the single
     * source of truth for "what caps does a fresh image get", shared by
     * execve, sys_spawn, and proc_spawn (it was copy-pasted in all three —
     * drift here would be a privilege bug). */
    uint32_t ci;
    for (ci = 0; ci < CAP_TABLE_SIZE; ci++) {
        caps[ci].kind   = CAP_KIND_NULL;
        caps[ci].rights = 0;
    }

    /* Baseline: granted unconditionally to every exec'd/spawned process. */
    cap_grant(caps, CAP_TABLE_SIZE, CAP_KIND_VFS_OPEN,      CAP_RIGHTS_READ);
    cap_grant(caps, CAP_TABLE_SIZE, CAP_KIND_VFS_WRITE,     CAP_RIGHTS_WRITE);
    cap_grant(caps, CAP_TABLE_SIZE, CAP_KIND_VFS_READ,      CAP_RIGHTS_READ);
    cap_grant(caps, CAP_TABLE_SIZE, CAP_KIND_IPC,           CAP_RIGHTS_READ);
    cap_grant(caps, CAP_TABLE_SIZE, CAP_KIND_PROC_READ,     CAP_RIGHTS_READ);
    cap_grant(caps, CAP_TABLE_SIZE, CAP_KIND_THREAD_CREATE, CAP_RIGHTS_READ);

    /* Policy: SERVICE-tier caps unconditionally; ADMIN-tier only for an
     * authenticated session. Trusted-path-anchored (see cap_policy_lookup). */
    const cap_policy_entry_t *pol = cap_policy_lookup(path);
    if (pol) {
        for (ci = 0; ci < pol->count; ci++) {
            if (pol->caps[ci].tier == CAP_TIER_SERVICE) {
                /* Defense in depth: INSTALL and DISK_ADMIN are the two kinds the
                 * ADMIN-tier path gates behind a sudo-style admin_session (below).
                 * The SERVICE tier grants unconditionally, so a policy line like
                 * `service INSTALL` would launder that elevation away — the tier
                 * word alone would forge the authority the admin_session gate
                 * exists to require. Refuse them here so the tier field can never
                 * be the escape hatch, no matter what a future caps.d ships. (No
                 * shipped policy needs this: real INSTALL/DISK_ADMIN users declare
                 * `admin`; the sole service-tier INSTALL, caps.d/vigil, is inert —
                 * PID 1's caps come from proc.c, not policy.) Fail closed + WARN. */
                if (pol->caps[ci].kind == CAP_KIND_INSTALL ||
                    pol->caps[ci].kind == CAP_KIND_DISK_ADMIN) {
                    printk("[CAP_POLICY] WARN: refusing service-tier %s for %s "
                           "— admin-gated caps cannot be granted unconditionally\n",
                           pol->caps[ci].kind == CAP_KIND_INSTALL
                               ? "INSTALL" : "DISK_ADMIN", path);
                    continue;
                }
                cap_grant(caps, CAP_TABLE_SIZE,
                          pol->caps[ci].kind, pol->caps[ci].rights);
            } else if (pol->caps[ci].tier == CAP_TIER_ADMIN) {
                /* ADMIN-tier caps require an authenticated session. A stricter
                 * subset requires a sudo-style ADMIN SESSION (admin_session, set
                 * by the stsh `admin` flow / `login -elevate` after a SEPARATE
                 * admin-credential check) — so even root must elevate their shell
                 * before wielding it. This is the anti-ambient-authority gate.
                 *
                 * The admin_session-gated kinds:
                 *   - INSTALL    — mutate the install-protected trees (herald).
                 *   - DISK_ADMIN — raw whole-disk read/write (sys_blkdev_io,
                 *     syscall 511). DISK_ADMIN is strictly MORE powerful than
                 *     INSTALL: a raw-block write lands BENEATH the ext2/VFS layer,
                 *     so it bypasses ext2 DAC, the install-protected-inode set,
                 *     the trusted==protected anchor invariant AND the setuid
                 *     binding in one move (rewrite /etc/shadow, /bin/login,
                 *     /etc/aegis/admin on disk). Granting it on mere `authenticated`
                 *     meant every login shell (caps.d/stsh: `admin DISK_ADMIN`)
                 *     silently held raw-disk authority — a non-root→root privesc
                 *     the instant a second user exists. It now requires the same
                 *     admin elevation as INSTALL (security review 05 finding 1).
                 *
                 * NOTE: POWER (reboot) deliberately stays `authenticated`-tier so
                 * a normal user can still reboot their own machine; it is a noted
                 * follow-up, not part of this change. */
                int ok = (pol->caps[ci].kind == CAP_KIND_INSTALL ||
                          pol->caps[ci].kind == CAP_KIND_DISK_ADMIN)
                             ? admin_session
                             : authenticated;
                if (ok)
                    cap_grant(caps, CAP_TABLE_SIZE,
                              pol->caps[ci].kind, pol->caps[ci].rights);
            }
        }
    }
}
