#include "initrd.h"
#include "kbd_vfs.h"
#include "random.h"
#include "printk.h"
#include "dev_table.h"
#include "../include/aegis_errno.h"
#include <stdint.h>

/* Injected by the Makefile from git (exact tag → "1.5.0", else dev-<hash>). */
#ifndef AEGIS_VERSION
#define AEGIS_VERSION "untracked"
#endif

/* /etc/motd content — displayed by stsh on login.
 * The filter keeps only lines starting with '['; content not matching is
 * silently dropped from the serial diff. */
static const char s_banner[] =
    "\n"
    " _______ _______  ______ _____ _______\n"
    " |_____| |______ |  ____   |   |______\n"
    " |     | |______ |_____| __|__ ______|\n"
    "\n"
    " WARNING: This system is restricted to authorized users.\n"
    " All activity is monitored and logged. Unauthorized access\n"
    " will be investigated and may result in prosecution.\n"
    "\n";

static const char s_banner_net[] =
    "\n"
    " _______ _______  ______ _____ _______\n"
    " |_____| |______ |  ____   |   |______\n"
    " |     | |______ |_____| __|__ ______|\n"
    "\n"
    " WARNING: This system is restricted to authorized users.\n"
    " All connections are monitored and logged.\n"
    "\n";

static const char s_motd[] =
    "\n"
    " _______ _______  ______ _____ _______\n"
    " |_____| |______ |  ____   |   |______\n"
    " |     | |______ |_____| __|__ ______|\n"
    "\n"
    " Aegis " AEGIS_VERSION " \"Ambient Argus\"\n"
    "\n";
static const char s_passwd[] = "root:x:0:0:root:/root:/bin/stsh\n";
static const char s_shadow[] =
    "root:$6$5a3b9c1d2e4f6789$fvwyIjdmyvB59hifGMRFrcwhBb4cH0.3nRy2j2LpCk."
    "aNIFNyvYQJ36Bsl94miFbD/JHICz8O1dXoegZ0OmOg.:19000:0:99999:7:::\n";
static const char s_profile[] =
    "PS1='root@aegis:${PWD:-/}# '\n"
    "export PS1\n"
    "PATH=/bin\n"
    "export PATH\n";
static const char s_hosts[] =
    "127.0.0.1 localhost\n"
    "10.0.2.15 aegis\n"
    "104.18.27.120 example.com\n";

/* Default vigil service config — allows vigil to find its getty service even
 * on a disk that was built before vigil was added (or on no disk at all).
 * run: direct path so start_service execs login without a shell intermediary.
 * Caps now come from /etc/aegis/caps.d/login (Phase 46c policy files), not
 * from vigil's exec_caps mechanism (which was retired in 46c). The s_vigil_caps
 * blob below is kept only because the legacy `caps` file path is still listed
 * in the directory enumeration; nothing reads its contents anymore. */
static const char s_vigil_run[]    = "/bin/login\n";
static const char s_vigil_policy[] = "respawn\nmax_restarts=5\n";
static const char s_vigil_caps[]   = "AUTH\nCAP_GRANT\nCAP_DELEGATE\nCAP_QUERY\n";

/* httpd vigil service config — binds :80, serves HTTP for socket API tests. */
static const char s_httpd_run[]    = "/bin/httpd\n";
static const char s_httpd_policy[] = "respawn\nmax_restarts=5\n";
static const char s_httpd_caps[]   = "NET_SOCKET VFS_OPEN VFS_READ\n";

/* dhcp vigil service config */
static const char s_dhcp_run[]    = "/bin/dhcp\n";
static const char s_dhcp_policy[] = "oneshot\n";
static const char s_dhcp_caps[]   = "NET_ADMIN NET_SOCKET\n";

/* chronos vigil service config — NTP time sync daemon */
static const char s_chronos_run[]    = "/bin/chronos\n";
static const char s_chronos_policy[] = "oneshot\n";
static const char s_chronos_caps[]   = "NET_SOCKET\n";

/* Capability policy files — /etc/aegis/caps.d/<binary>
 * The kernel's cap policy table reads these at execve time to determine
 * which capabilities to grant. Format: "tier CAP1 CAP2 ...\n" per line.
 * "service" tier: granted unconditionally at execve.
 * "admin" tier: granted only if the session is authenticated. */
static const char s_cap_login[]     = "service AUTH SETUID\n";
static const char s_cap_bastion[]   = "service AUTH FB SETUID\n";
static const char s_cap_httpd[]     = "service NET_SOCKET\n";
static const char s_cap_dhcp[]      = "service NET_SOCKET NET_ADMIN\n";
static const char s_cap_stsh[]      = "admin DISK_ADMIN POWER CAP_DELEGATE CAP_QUERY\nadmin PROC_READ\n";
static const char s_cap_lumen[]     = "service FB THREAD_CREATE\n";
static const char s_cap_installer[] = "admin DISK_ADMIN AUTH\n";

/* Compile-time size constants for static string entries. */
static const unsigned int s_hosts_size         = sizeof(s_hosts)         - 1;
static const unsigned int s_passwd_size        = sizeof(s_passwd)        - 1;
static const unsigned int s_shadow_size        = sizeof(s_shadow)        - 1;
static const unsigned int s_profile_size       = sizeof(s_profile)       - 1;
static const unsigned int s_vigil_run_size     = sizeof(s_vigil_run)     - 1;
static const unsigned int s_vigil_policy_size  = sizeof(s_vigil_policy)  - 1;
static const unsigned int s_vigil_caps_size    = sizeof(s_vigil_caps)    - 1;
static const unsigned int s_httpd_run_size     = sizeof(s_httpd_run)     - 1;
static const unsigned int s_httpd_policy_size  = sizeof(s_httpd_policy)  - 1;
static const unsigned int s_httpd_caps_size    = sizeof(s_httpd_caps)    - 1;
static const unsigned int s_dhcp_run_size    = sizeof(s_dhcp_run)    - 1;
static const unsigned int s_dhcp_policy_size = sizeof(s_dhcp_policy) - 1;
static const unsigned int s_dhcp_caps_size   = sizeof(s_dhcp_caps)   - 1;
static const unsigned int s_chronos_run_size    = sizeof(s_chronos_run)    - 1;
static const unsigned int s_chronos_policy_size = sizeof(s_chronos_policy) - 1;
static const unsigned int s_chronos_caps_size   = sizeof(s_chronos_caps)   - 1;
static const unsigned int s_cap_login_size      = sizeof(s_cap_login)      - 1;
static const unsigned int s_cap_bastion_size    = sizeof(s_cap_bastion)    - 1;
static const unsigned int s_cap_httpd_size      = sizeof(s_cap_httpd)      - 1;
static const unsigned int s_cap_dhcp_size       = sizeof(s_cap_dhcp)       - 1;
static const unsigned int s_cap_stsh_size       = sizeof(s_cap_stsh)       - 1;
static const unsigned int s_cap_lumen_size      = sizeof(s_cap_lumen)      - 1;
static const unsigned int s_cap_installer_size  = sizeof(s_cap_installer)  - 1;

/* Binary blobs embedded into the kernel image.
 * Size = end - start (computed at open time).
 *
 * Boot-critical static binaries in initrd: login, vigil, shell, echo, cat, ls.
 * All other user binaries are dynamically linked and live on the ext2 disk.
 *
 * Both x86_64 and aarch64 use the same objcopy-based embedding:
 *     objcopy -I binary -O elf64-<target> -B <arch> <blob>.bin <blob>.o
 * produces the linker-visible symbols
 *     _binary_<name>_bin_{start,end}
 * for each blob. The x86 build drives this from the top-level Makefile
 * (BLOB_COPY_RULE); the ARM64 build drives it from
 * kernel/arch/arm64/Makefile, which in turn calls
 * tools/build-arm64-userland.sh to produce the aarch64-musl blobs.
 *
 * If the ARM64 build is run with ARM64_SKIP_USERLAND=1, the blob
 * sources are zero-byte stubs: start == end, so any read through
 * initrd_open returns 0 bytes and initrd_open itself returns ENOENT
 * for a zero-sized entry (see initrd_open below). */
/* No userland binaries are embedded in the kernel (Linux model): /bin/login,
 * /bin/vigil, /bin/sh, /bin/echo, /bin/cat, /bin/ls all live on the ext2 root
 * filesystem now. The initrd serves only the inline /etc config fallback below. */

/* initrd_entry_t — each entry holds a path, a pointer to file data, and a
 * pointer to the file's size variable (link-time value from objcopy/bin2c).
 * Using a pointer-to-size avoids the "initializer element is not constant"
 * error that arises when placing extern uint variables in static initializers. */
typedef struct {
    const char          *name;
    const unsigned char *start;  /* blob start (_binary_<prog>_start or inline string) */
    const unsigned char *end;    /* blob end (_binary_<prog>_end or start + strlen) */
} initrd_entry_t;

static const initrd_entry_t s_files[] = {
    { "/etc/motd",       (const unsigned char *)s_motd,       (const unsigned char *)s_motd + sizeof(s_motd) - 1 },
    { "/etc/banner",     (const unsigned char *)s_banner,     (const unsigned char *)s_banner + sizeof(s_banner) - 1 },
    { "/etc/banner.net", (const unsigned char *)s_banner_net, (const unsigned char *)s_banner_net + sizeof(s_banner_net) - 1 },
    /* No userland-binary entries: login, vigil, sh, echo, cat, ls, stsh and
     * every other program now load from the ext2 root filesystem. */
    { "/etc/vigil/services/dhcp/run", (const unsigned char *)s_dhcp_run, (const unsigned char *)s_dhcp_run + s_dhcp_run_size },
    { "/etc/vigil/services/dhcp/policy", (const unsigned char *)s_dhcp_policy, (const unsigned char *)s_dhcp_policy + s_dhcp_policy_size },
    { "/etc/vigil/services/dhcp/caps", (const unsigned char *)s_dhcp_caps, (const unsigned char *)s_dhcp_caps + s_dhcp_caps_size },
    { "/etc/hosts",  (const unsigned char *)s_hosts,  (const unsigned char *)s_hosts + s_hosts_size },
    { "/etc/passwd", (const unsigned char *)s_passwd, (const unsigned char *)s_passwd + s_passwd_size },
    { "/etc/shadow", (const unsigned char *)s_shadow, (const unsigned char *)s_shadow + s_shadow_size },
    { "/etc/profile", (const unsigned char *)s_profile, (const unsigned char *)s_profile + s_profile_size },
    { "/etc/vigil/services/getty/run", (const unsigned char *)s_vigil_run, (const unsigned char *)s_vigil_run + s_vigil_run_size },
    { "/etc/vigil/services/getty/policy", (const unsigned char *)s_vigil_policy, (const unsigned char *)s_vigil_policy + s_vigil_policy_size },
    { "/etc/vigil/services/getty/caps", (const unsigned char *)s_vigil_caps, (const unsigned char *)s_vigil_caps + s_vigil_caps_size },
    { "/etc/vigil/services/httpd/run", (const unsigned char *)s_httpd_run, (const unsigned char *)s_httpd_run + s_httpd_run_size },
    { "/etc/vigil/services/httpd/policy", (const unsigned char *)s_httpd_policy, (const unsigned char *)s_httpd_policy + s_httpd_policy_size },
    { "/etc/vigil/services/httpd/caps", (const unsigned char *)s_httpd_caps, (const unsigned char *)s_httpd_caps + s_httpd_caps_size },
    { "/etc/vigil/services/chronos/run", (const unsigned char *)s_chronos_run, (const unsigned char *)s_chronos_run + s_chronos_run_size },
    { "/etc/vigil/services/chronos/policy", (const unsigned char *)s_chronos_policy, (const unsigned char *)s_chronos_policy + s_chronos_policy_size },
    { "/etc/vigil/services/chronos/caps", (const unsigned char *)s_chronos_caps, (const unsigned char *)s_chronos_caps + s_chronos_caps_size },
    { "/etc/aegis/caps.d/login", (const unsigned char *)s_cap_login, (const unsigned char *)s_cap_login + s_cap_login_size },
    { "/etc/aegis/caps.d/bastion", (const unsigned char *)s_cap_bastion, (const unsigned char *)s_cap_bastion + s_cap_bastion_size },
    { "/etc/aegis/caps.d/httpd", (const unsigned char *)s_cap_httpd, (const unsigned char *)s_cap_httpd + s_cap_httpd_size },
    { "/etc/aegis/caps.d/dhcp", (const unsigned char *)s_cap_dhcp, (const unsigned char *)s_cap_dhcp + s_cap_dhcp_size },
    { "/etc/aegis/caps.d/stsh", (const unsigned char *)s_cap_stsh, (const unsigned char *)s_cap_stsh + s_cap_stsh_size },
    { "/etc/aegis/caps.d/lumen", (const unsigned char *)s_cap_lumen, (const unsigned char *)s_cap_lumen + s_cap_lumen_size },
    { "/etc/aegis/caps.d/installer", (const unsigned char *)s_cap_installer, (const unsigned char *)s_cap_installer + s_cap_installer_size },
    { (const char *)0, (const unsigned char *)0, (const unsigned char *)0 }  /* sentinel */
};


/* Helper: return file size for an entry. */
static uint32_t
entry_size(const initrd_entry_t *e)
{
    return (uint32_t)(e->end - e->start);
}





/* ── Regular file ops ──────────────────────────────────────────────────── */

static int
initrd_read_fn(void *priv, void *buf, uint64_t off, uint64_t len)
{
    const initrd_entry_t *e = (const initrd_entry_t *)priv;
    uint32_t sz = entry_size(e);
    if (off >= sz) return 0;
    uint64_t avail = sz - off;
    if (len > avail) len = avail;
    __builtin_memcpy(buf, e->start + off, len);
    return (int)len;
}

static void
initrd_close_fn(void *priv)
{
    (void)priv; /* static data, nothing to free */
}

static int
initrd_stat_fn(void *priv, k_stat_t *st)
{
    const initrd_entry_t *e = (const initrd_entry_t *)priv;
    uint32_t sz = entry_size(e);

    /* Compute index of this entry in s_files for a synthetic inode */
    uint64_t ino = 1;
    {
        uint32_t i;
        for (i = 0; s_files[i].name != (const char *)0; i++) {
            if (&s_files[i] == e) { ino = (uint64_t)(i + 2); break; }
        }
    }

    __builtin_memset(st, 0, sizeof(*st));
    st->st_dev     = 1;
    st->st_ino     = ino;
    st->st_nlink   = 1;
    /* /etc/shadow must be 0640 root:root — not world-readable.
     * All other initrd files are executables or config (0555). */
    if (e->name[0]=='/' && e->name[1]=='e' && e->name[2]=='t' &&
        e->name[3]=='c' && e->name[4]=='/' && e->name[5]=='s' &&
        e->name[6]=='h' && e->name[7]=='a' && e->name[8]=='d' &&
        e->name[9]=='o' && e->name[10]=='w' && e->name[11]=='\0')
        st->st_mode = S_IFREG | 0640;
    else
        st->st_mode = S_IFREG | 0555;
    st->st_size    = (int64_t)sz;
    st->st_blksize = 512;
    st->st_blocks  = (int64_t)(((uint64_t)sz + 511) / 512 * 8);
    return 0;
}

static int
dir_stat_fn(void *priv, k_stat_t *st)
{
    (void)priv;
    __builtin_memset(st, 0, sizeof(*st));
    st->st_dev   = 1;
    st->st_ino   = 1;  /* root dir inode */
    st->st_nlink = 2;
    st->st_mode  = S_IFDIR | 0555;
    return 0;
}

static const vfs_ops_t initrd_ops = {
    .seekable = 1,
    .read    = initrd_read_fn,
    .write   = (void *)0,
    .close   = initrd_close_fn,
    .readdir = (void *)0,
    .dup     = (void *)0,
    .stat    = initrd_stat_fn,
    .poll    = (void *)0,
};

/* ── Directory entry type and static directory listings ────────────────── */

typedef struct { const char *name; uint8_t type; } dir_entry_t;

/* s_dev_entries removed — /dev readdir now driven directly by s_dev_table
 * (rows with name != NULL).  See dev_dir_readdir_fn below. */
/* NOTE: /root is intentionally NOT an initrd directory — it lives on the ext2
 * root fs (it's root's home). An empty initrd /root here would shadow the ext2
 * one per-component (initrd-first resolution), hiding e.g. /root/.ssh. */
static const dir_entry_t s_root_entries[] = {
    { "etc", 4 }, { "bin", 4 }, { "dev", 4 }, { "lib", 4 }, { "root", 4 },
    { "tmp", 4 }, { "run", 4 }, { "proc", 4 },
    { (const char *)0, 0 }
};
static const dir_entry_t s_etc_entries[] = {
    { "motd", 8 }, { "banner", 8 }, { "banner.net", 8 }, { "passwd", 8 }, { "shadow", 8 }, { "profile", 8 },
    { "vigil", 4 }, { "aegis", 4 }, { (const char *)0, 0 }
};
static const dir_entry_t s_vigil_entries[] = {
    { "services", 4 }, { (const char *)0, 0 }
};
static const dir_entry_t s_vigil_services_entries[] = {
    { "getty", 4 }, { "httpd", 4 }, { "dhcp", 4 }, { (const char *)0, 0 }
};
static const dir_entry_t s_vigil_getty_entries[] = {
    { "run", 8 }, { "policy", 8 }, { "caps", 8 }, { (const char *)0, 0 }
};
static const dir_entry_t s_vigil_httpd_entries[] = {
    { "run", 8 }, { "policy", 8 }, { "caps", 8 }, { (const char *)0, 0 }
};
static const dir_entry_t s_vigil_dhcp_entries[] = {
    { "run", 8 }, { "policy", 8 }, { "caps", 8 }, { (const char *)0, 0 }
};
static const dir_entry_t s_aegis_entries[] = {
    { "caps.d", 4 }, { (const char *)0, 0 }
};
static const dir_entry_t s_aegis_capsd_entries[] = {
    { "login", 8 }, { "bastion", 8 }, { "httpd", 8 }, { "dhcp", 8 },
    { "stsh", 8 }, { "lumen", 8 }, { "installer", 8 }, { (const char *)0, 0 }
};
/* s_bin_entries removed — /bin directory listing now handled by ext2.
 * Individual files (/bin/login, /bin/vigil) are still found via initrd_open
 * by name, but `ls /bin` falls through to ext2_readdir which shows all
 * binaries on disk. */

static int
dir_readdir_fn(void *priv, uint64_t index, char *name_out, uint8_t *type_out)
{
    const dir_entry_t *entries = (const dir_entry_t *)priv;
    uint64_t i = 0;
    while (entries[i].name && i < index) i++;
    if (!entries[i].name) return -1;
    const char *n = entries[i].name;
    uint64_t j;
    for (j = 0; n[j]; j++) name_out[j] = n[j];
    name_out[j] = '\0';
    *type_out = entries[i].type;
    return 0;
}

static int
dir_read_fn(void *priv, void *buf, uint64_t off, uint64_t len)
{
    (void)priv; (void)buf; (void)off; (void)len;
    return -EISDIR;
}

static void
dir_close_fn(void *priv)
{
    (void)priv;
}

static const vfs_ops_t dir_ops = {
    .read    = dir_read_fn,
    .write   = (void *)0,
    .close   = dir_close_fn,
    .readdir = dir_readdir_fn,
    .dup     = (void *)0,
    .stat    = dir_stat_fn,
    .poll    = (void *)0,
};

/*
 * dev_dir_readdir_fn — /dev-specific readdir that walks s_dev_table directly.
 * Emits one entry for each row where name != NULL.  The priv pointer is
 * unused (NULL); the table is the canonical source.  DT_CHR = 8.
 */
static int
dev_dir_readdir_fn(void *priv, uint64_t index, char *name_out, uint8_t *type_out)
{
    (void)priv;
    const dev_special_t *e;
    uint64_t i = 0;
    for (e = dev_table_get(); e->path; e++) {
        if (!e->name) continue;
        if (i == index) {
            const char *n = e->name;
            uint64_t j;
            for (j = 0; n[j]; j++) name_out[j] = n[j];
            name_out[j] = '\0';
            *type_out = 8; /* DT_CHR */
            return 0;
        }
        i++;
    }
    return -1; /* end of entries */
}

static const vfs_ops_t dev_dir_ops = {
    .read    = dir_read_fn,
    .write   = (void *)0,
    .close   = dir_close_fn,
    .readdir = dev_dir_readdir_fn,
    .dup     = (void *)0,
    .stat    = dir_stat_fn,
    .poll    = (void *)0,
};

/* ── /dev/urandom VFS device ────────────────────────────────────────────── */

static int
urandom_read_fn(void *priv, void *buf, uint64_t off, uint64_t len)
{
    (void)priv; (void)off;
    if (len > 4096) len = 4096;
    random_get_bytes(buf, (size_t)len);
    return (int)len;
}

static int
urandom_write_fn(void *priv, const void *buf, uint64_t len)
{
    /* Writes to urandom are accepted but not mixed into the pool.
     * buf is a user-space pointer (SMAP-protected); a proper implementation
     * would copy_from_user first. For now, just acknowledge the write. */
    (void)priv; (void)buf;
    return (int)(len > 256 ? 256 : len);
}

static void
urandom_close_fn(void *priv)
{
    (void)priv;
}

static int
urandom_stat_fn(void *priv, k_stat_t *st)
{
    (void)priv;
    __builtin_memset(st, 0, sizeof(*st));
    st->st_mode  = S_IFCHR | 0666;
    st->st_ino   = 5;
    st->st_rdev  = makedev(1, 9);   /* Linux: /dev/urandom = 1:9 */
    st->st_dev   = 1;
    st->st_nlink = 1;
    return 0;
}

static const vfs_ops_t s_urandom_ops = {
    .read    = urandom_read_fn,
    .write   = urandom_write_fn,
    .close   = urandom_close_fn,
    .readdir = (void *)0,
    .dup     = (void *)0,
    .stat    = urandom_stat_fn,
    .poll    = (void *)0,
};

static vfs_file_t s_urandom_file = {
    .ops    = &s_urandom_ops,
    .priv   = (void *)0,
    .offset = 0,
    .size   = 0,
};

/* ── /dev/null VFS device ───────────────────────────────────────────────── */
/* Was missing entirely: open("/dev/null") returned ENOENT, so e.g.
 * `curl -o /dev/null` failed with "Failure writing output to destination". */

static int
null_read_fn(void *priv, void *buf, uint64_t off, uint64_t len)
{
    (void)priv; (void)buf; (void)off; (void)len;
    return 0;   /* always at EOF */
}

static int
null_write_fn(void *priv, const void *buf, uint64_t len)
{
    /* Discard everything, acknowledge the full length (cap to int range). */
    (void)priv; (void)buf;
    if (len > 0x7FFFFFFFu) len = 0x7FFFFFFFu;
    return (int)len;
}

static void
null_close_fn(void *priv)
{
    (void)priv;
}

static int
null_stat_fn(void *priv, k_stat_t *st)
{
    (void)priv;
    __builtin_memset(st, 0, sizeof(*st));
    st->st_mode  = S_IFCHR | 0666;
    st->st_ino   = 4;
    st->st_rdev  = makedev(1, 3);   /* Linux: /dev/null = 1:3 */
    st->st_dev   = 1;
    st->st_nlink = 1;
    return 0;
}

static const vfs_ops_t s_null_ops = {
    .read    = null_read_fn,
    .write   = null_write_fn,
    .close   = null_close_fn,
    .readdir = (void *)0,
    .dup     = (void *)0,
    .stat    = null_stat_fn,
    .poll    = (void *)0,
};

static vfs_file_t s_null_file = {
    .ops    = &s_null_ops,
    .priv   = (void *)0,
    .offset = 0,
    .size   = 0,
};

/* ── /dev/audio VFS device — PCM sink → HDA playback ────────────────────────
 * write() appends 48 kHz/16-bit/stereo PCM; close() plays the accumulated
 * sound once. On non-x86 (no HDA) writes are silently consumed. */
#ifdef __x86_64__
#include "hda.h"
#endif

static int
audio_write_fn(void *priv, const void *buf, uint64_t len)
{
    (void)priv;
    if (len > 0x7FFFFFFFu) len = 0x7FFFFFFFu;
#ifdef __x86_64__
    return hda_audio_write(buf, (uint32_t)len);
#else
    (void)buf;
    return (int)len;
#endif
}

static void
audio_close_fn(void *priv)
{
    (void)priv;
#ifdef __x86_64__
    hda_audio_close();
#endif
}

static int
audio_stat_fn(void *priv, k_stat_t *st)
{
    (void)priv;
    __builtin_memset(st, 0, sizeof(*st));
    st->st_mode  = S_IFCHR | 0666;
    st->st_ino   = 9;
    st->st_rdev  = makedev(14, 4);   /* Linux: /dev/audio = 14:4 */
    st->st_dev   = 1;
    st->st_nlink = 1;
    return 0;
}

static const vfs_ops_t s_audio_ops = {
    .read    = null_read_fn,          /* reads return EOF */
    .write   = audio_write_fn,
    .close   = audio_close_fn,
    .readdir = (void *)0,
    .dup     = (void *)0,
    .stat    = audio_stat_fn,
    .poll    = (void *)0,
};

static vfs_file_t s_audio_file = {
    .ops    = &s_audio_ops,
    .priv   = (void *)0,
    .offset = 0,
    .size   = 0,
};

/* ── /dev/mouse VFS device ──────────────────────────────────────────────── */

#include "usb_mouse.h"
#include "../sched/waitq.h"

extern waitq_t g_mouse_waiters;

static struct waitq *
mouse_get_waitq_fn(void *priv)
{
    (void)priv;
    return &g_mouse_waiters;
}

static int
mouse_read_fn(void *priv, void *buf, uint64_t off, uint64_t len)
{
    (void)priv; (void)off;
    uint32_t count = 0;
    uint32_t max_events = (uint32_t)(len / sizeof(mouse_event_t));

    if (max_events == 0) return 0;

    /* Non-blocking: drain available events only */
    mouse_event_t evt;
    while (count < max_events && mouse_poll(&evt)) {
        __builtin_memcpy((uint8_t *)buf + count * sizeof(mouse_event_t),
                         &evt, sizeof(mouse_event_t));
        count++;
    }

    if (count == 0) return -EAGAIN;
    return (int)(count * sizeof(mouse_event_t));
}

static void
mouse_close_fn(void *priv)
{
    (void)priv;
}

static int
mouse_stat_fn(void *priv, k_stat_t *st)
{
    (void)priv;
    __builtin_memset(st, 0, sizeof(*st));
    st->st_mode  = S_IFCHR | 0444;
    st->st_ino   = 8;
    st->st_rdev  = makedev(13, 0);
    st->st_dev   = 1;
    st->st_nlink = 1;
    return 0;
}

static const vfs_ops_t s_mouse_ops = {
    .read      = mouse_read_fn,
    .write     = (void *)0,
    .close     = mouse_close_fn,
    .readdir   = (void *)0,
    .dup       = (void *)0,
    .stat      = mouse_stat_fn,
    .poll      = (void *)0,
    .get_waitq = mouse_get_waitq_fn,
};

static vfs_file_t s_mouse_file = {
    .ops    = &s_mouse_ops,
    .priv   = (void *)0,
    .offset = 0,
    .size   = 0,
};

/* ── /dev device table (single source of truth for all three consumers) ─── */

/*
 * s_dev_table — one row per /dev character special.  All three consumers
 * (initrd_open, vfs_stat_path via dev_table_stat, and /dev readdir) derive
 * from this array; nothing is hand-mirrored.
 *
 * Rows where file==NULL are stat-only (open is bespoke: ptmx allocates a
 * PTY master dynamically, the console family is handled before the walk).
 * Rows where name==NULL are path aliases (e.g. /dev/random→urandom) or
 * paths omitted from the /dev directory listing.
 */
static const dev_special_t s_dev_table[] = {
    /* path,            name,      file,            mode,            ino, rdev */
    { "/dev/urandom",  "urandom", &s_urandom_file, S_IFCHR|0666, 5, makedev(1,9)  },
    { "/dev/random",   "random",  &s_urandom_file, S_IFCHR|0666, 5, makedev(1,9)  },
    { "/dev/null",     "null",    &s_null_file,    S_IFCHR|0666, 4, makedev(1,3)  },
    { "/dev/audio",    "audio",   &s_audio_file,   S_IFCHR|0666, 9, makedev(14,4) },
    { "/dev/mouse",    "mouse",   &s_mouse_file,   S_IFCHR|0444, 8, makedev(13,0) },
    /* console family: shared singleton via kbd_vfs_open — file=NULL because
     * the singleton is a dynamic pointer (returned by kbd_vfs_open at open
     * time, not a stable static address).  Open handled before the walk.
     * Only /dev/console appears in readdir (name="tty" matches legacy
     * listing); the other aliases have name=NULL to suppress them. */
    { "/dev/console",  "tty",     (const vfs_file_t *)0, S_IFCHR|0600, 2, makedev(5,1) },
    { "/dev/tty",      (const char *)0, (const vfs_file_t *)0, S_IFCHR|0600, 2, makedev(5,1) },
    { "/dev/stdin",    (const char *)0, (const vfs_file_t *)0, S_IFCHR|0600, 2, makedev(5,1) },
    { "/dev/stdout",   (const char *)0, (const vfs_file_t *)0, S_IFCHR|0600, 2, makedev(5,1) },
    { "/dev/stderr",   (const char *)0, (const vfs_file_t *)0, S_IFCHR|0600, 2, makedev(5,1) },
    /* stat-only row: ptmx_open() allocates a PTY master dynamically */
    { "/dev/ptmx",     (const char *)0, (const vfs_file_t *)0, S_IFCHR|0666, 6, makedev(5,2) },
    { (const char *)0, (const char *)0, (const vfs_file_t *)0, 0, 0, 0 } /* sentinel */
};

const dev_special_t *
dev_table_get(void)
{
    return s_dev_table;
}

/*
 * dev_table_stat — fill *out for `path` if it names a /dev special.
 * Returns 0 on match, -1 if not found (caller falls through to its other
 * cases).  st_dev and st_nlink are always 1 (synthesised chardev).
 */
int
dev_table_stat(const char *path, k_stat_t *out)
{
    const dev_special_t *e;
    for (e = s_dev_table; e->path; e++) {
        const char *a = path, *b = e->path;
        while (*a && *b && *a == *b) { a++; b++; }
        if (*a == *b) {
            __builtin_memset(out, 0, sizeof(*out));
            out->st_mode  = (uint32_t)e->mode;
            out->st_ino   = (uint64_t)e->ino;
            out->st_rdev  = (uint64_t)e->rdev;
            out->st_dev   = 1;
            out->st_nlink = 1;
            return 0;
        }
    }
    return -1;
}

/* ── Public API ─────────────────────────────────────────────────────────── */

void
initrd_register(void)
{
    /* Count up to the sentinel so the reported count tracks the actual
     * number of entries even when #ifdef slices drop the user-binary
     * section (on arm64 until phase A4). */
    uint32_t n = 0;
    while (s_files[n].name != (const char *)0)
        n++;
    printk("[INITRD] OK: %u files registered\n", n);
}

int
initrd_open(const char *path, vfs_file_t *out)
{
    /* /dev/tty: return the keyboard VFS singleton directly */
    {
        const char *a = path, *b = "/dev/tty";
        while (*a && *b && *a == *b) { a++; b++; }
        if (*a == *b) {
            vfs_file_t *tty = kbd_vfs_open();
            *out = *tty;
            return 0;
        }
    }

    /* /dev specials with static singleton files — one table walk replaces
     * the four hand-rolled char-compare blocks that were here.  Rows with
     * file==NULL (console aliases, ptmx) are skipped: console is handled
     * above; ptmx/pts stay bespoke in vfs_open. */
    {
        const dev_special_t *e;
        for (e = dev_table_get(); e->path; e++) {
            if (!e->file) continue;
            const char *a = path, *b = e->path;
            while (*a && *b && *a == *b) { a++; b++; }
            if (*a == *b) {
                *out = *e->file;
                return 0;
            }
        }
    }

    /* Check for directory paths first */

    /* /dev — use dev_dir_ops whose readdir walks s_dev_table directly */
    {
        const char *a = path, *b = "/dev";
        while (*a && *b && *a == *b) { a++; b++; }
        if (*a == *b) {
            out->ops    = &dev_dir_ops;
            out->priv   = (void *)0;  /* dev_dir_readdir_fn ignores priv */
            out->offset = 0;
            out->size   = 0;
            return 0;
        }
    }

    {
        const char *dirs[11] = {
            "/", "/etc",
            "/etc/vigil", "/etc/vigil/services", "/etc/vigil/services/getty",
            "/etc/vigil/services/httpd",
            "/etc/vigil/services/dhcp",
            "/etc/aegis",
            "/etc/aegis/caps.d",
            (const char *)0
        };
        const dir_entry_t *dir_tables[11] = {
            s_root_entries, s_etc_entries,
            s_vigil_entries, s_vigil_services_entries, s_vigil_getty_entries,
            s_vigil_httpd_entries,
            s_vigil_dhcp_entries,
            s_aegis_entries,
            s_aegis_capsd_entries,
            (const dir_entry_t *)0
        };
        uint32_t d;
        for (d = 0; d < 9; d++) {
            const char *a = path, *b = dirs[d];
            while (*a && *b && *a == *b) { a++; b++; }
            if (*a == *b) {
                out->ops    = &dir_ops;
                out->priv   = (void *)dir_tables[d];
                out->offset = 0;
                out->size   = 0;
                return 0;
            }
        }
    }

    /* Regular file lookup */
    uint32_t i;
    for (i = 0; s_files[i].name != (const char *)0; i++) {
        const char *a = path, *b = s_files[i].name;
        while (*a && *b && *a == *b) { a++; b++; }
        if (*a == *b) {
            out->ops    = &initrd_ops;
            out->priv   = (void *)&s_files[i];
            out->offset = 0;
            out->size   = entry_size(&s_files[i]);
            return 0;
        }
    }
    return -ENOENT;
}

const void *
initrd_get_data(const vfs_file_t *f)
{
    if (!f->priv) return (const void *)0;
    const initrd_entry_t *e = (const initrd_entry_t *)f->priv; return (const void *)e->start;
}

uint32_t
initrd_get_size(const vfs_file_t *f)
{
    if (!f->priv) return 0;
    return entry_size((const initrd_entry_t *)f->priv);
}

/*
 * initrd_stat_entry — fill *out with stat for the initrd file at path.
 * Returns 0 if found, -2 (ENOENT) if not found.
 * Used by vfs_stat_path to avoid re-opening the file.
 */
int
initrd_stat_entry(const char *path, k_stat_t *out)
{
    uint32_t i;
    for (i = 0; s_files[i].name != (const char *)0; i++) {
        const char *a = path, *b = s_files[i].name;
        while (*a && *b && *a == *b) { a++; b++; }
        if (*a == *b) {
            return initrd_stat_fn((void *)&s_files[i], out);
        }
    }
    return -ENOENT;
}
