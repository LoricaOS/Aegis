/* kernel/fs/procfs.c — /proc virtual filesystem
 *
 * Generate-on-open design: opening a /proc file allocates a kva buffer,
 * generates content into it, and stores the buffer in vfs_file_t.priv.
 * read() copies from the buffer at offset; close() frees it.
 *
 * Capability gating: /proc/self/ is always permitted. /proc/[pid]/ for
 * a different pid requires CAP_KIND_PROC_READ in the caller's cap table.
 */
#include "procfs.h"
#include "vfs.h"
#include "proc.h"
#include "sched.h"
#include "pmm.h"
#include "vma.h"
#include "kva.h"
#include "cap.h"
#include "printk.h"
#include "ext2.h"  /* ext2_statfs/ext2_devname — /proc/mounts */
#include "stackshot.h"  /* dump_all_tasks — /proc/stackshot */
#include "trace.h"      /* trace_dump — /proc/trace */
#include "fd_table.h"
#include "arch.h"
#include "../include/aegis_errno.h"
#ifdef __x86_64__
#include "kbd.h"   /* kbd_stats_get — /proc/kbdstat input diagnostics */
#include "xhci.h"  /* xhci_usbnet_diag — /proc/usbnet USB-ethernet diagnostics */
#include "nvme.h"  /* nvme_smart_info — /proc/smart NVMe SMART/health        */
#include "hda.h"   /* hda_dump — /proc/hda codec graph                       */
#endif

/* Build-time version from the Makefile (git describe); see gen_version. */
#ifndef AEGIS_VERSION
#define AEGIS_VERSION "untracked"
#endif
#include <stdint.h>
#include <stddef.h>

/* sched_lock protects the global circular task list — defined in sched.c.
 * The /proc readdir walk below must hold it: sched_add (fork/clone/spawn)
 * and the sys_waitpid zombie unlink mutate the chain concurrently on SMP. */
extern spinlock_t sched_lock;

/* ── string helpers (no libc) ──────────────────────────────────────────── */

static int
pfs_streq(const char *a, const char *b)
{
    while (*a && *b && *a == *b) { a++; b++; }
    return *a == *b;
}

static char *
pfs_strcpy(char *dst, const char *src)
{
    while (*src)
        *dst++ = *src++;
    return dst;
}

static char *
pfs_u64_dec(char *buf, uint64_t val)
{
    if (val == 0) {
        *buf++ = '0';
        return buf;
    }
    char tmp[20];
    int i = 0;
    while (val > 0) {
        tmp[i++] = '0' + (char)(val % 10);
        val /= 10;
    }
    while (i > 0)
        *buf++ = tmp[--i];
    return buf;
}

static char *
pfs_u64_hex(char *buf, uint64_t val, int min_digits)
{
    static const char hex[] = "0123456789abcdef";
    char tmp[16];
    int i = 0;
    if (val == 0) {
        tmp[i++] = '0';
    } else {
        while (val > 0) {
            tmp[i++] = hex[val & 0xF];
            val >>= 4;
        }
    }
    while (i < min_digits)
        tmp[i++] = '0';
    while (i > 0)
        *buf++ = tmp[--i];
    return buf;
}

/* ── priv structures ───────────────────────────────────────────────────── */

typedef struct {
    char    *buf;
    uint32_t len;
    uint32_t refs;    /* fd refcount: fork/dup share priv; free on last close */
} procfs_file_priv_t;

typedef struct {
    uint32_t pid;     /* 0 = root /proc/ dir */
    uint8_t  is_fd;   /* 1 = /proc/[pid]/fd/ */
    uint8_t  _pad[3];
    uint32_t refs;    /* fd refcount: fork/dup share priv; free on last close */
} procfs_dir_priv_t;

/* ── content generators ────────────────────────────────────────────────── */

static uint32_t
gen_maps(char *buf, uint32_t bufsz, aegis_process_t *proc)
{
    /*
     * Largest single record this function can emit, worst case:
     *   start hex (16) + '-' (1) + end hex (16) + ' ' (1)
     *   + perms "rwxp" (4) + ' ' (1) + "00000000 00:00 0" (16)
     *   + 9 padding spaces (9) + path == exe_path[256] minus NUL = 255
     *   + '\n' (1) + the trailing '\0' written after the loop (1)
     * = 321 bytes. Round up for slack so the guard is provably safe.
     */
    enum { MAPS_MAX_RECORD = 350 };
    char *p = buf;
    char *end = buf + bufsz - 1;
    uint32_t i;

    if (!proc->vma_table)
        return 0;

    for (i = 0; i < vma_count_get(proc) && (end - p) >= MAPS_MAX_RECORD; i++) {
        vma_entry_t *v = &proc->vma_table[i];
        uint64_t vstart = v->base;
        uint64_t vend = v->base + v->len;

        /* start-end */
        p = pfs_u64_hex(p, vstart, 8);
        *p++ = '-';
        p = pfs_u64_hex(p, vend, 8);
        *p++ = ' ';

        /* perms: rwxp */
        *p++ = (v->prot & 1) ? 'r' : '-'; /* PROT_READ  = 1 */
        *p++ = (v->prot & 2) ? 'w' : '-'; /* PROT_WRITE = 2 */
        *p++ = (v->prot & 4) ? 'x' : '-'; /* PROT_EXEC  = 4 */
        *p++ = 'p';
        *p++ = ' ';

        /* offset dev inode */
        p = pfs_strcpy(p, "00000000 00:00 0");

        /* padding + name */
        switch (v->type) {
        case VMA_ELF_TEXT:
        case VMA_ELF_DATA:
            *p++ = ' '; *p++ = ' '; *p++ = ' '; *p++ = ' ';
            *p++ = ' '; *p++ = ' '; *p++ = ' '; *p++ = ' '; *p++ = ' ';
            p = pfs_strcpy(p, proc->exe_path);
            break;
        case VMA_HEAP:
            *p++ = ' '; *p++ = ' '; *p++ = ' '; *p++ = ' ';
            *p++ = ' '; *p++ = ' '; *p++ = ' '; *p++ = ' '; *p++ = ' ';
            p = pfs_strcpy(p, "[heap]");
            break;
        case VMA_STACK:
            *p++ = ' '; *p++ = ' '; *p++ = ' '; *p++ = ' ';
            *p++ = ' '; *p++ = ' '; *p++ = ' '; *p++ = ' '; *p++ = ' ';
            p = pfs_strcpy(p, "[stack]");
            break;
        case VMA_GUARD:
            *p++ = ' '; *p++ = ' '; *p++ = ' '; *p++ = ' ';
            *p++ = ' '; *p++ = ' '; *p++ = ' '; *p++ = ' '; *p++ = ' ';
            p = pfs_strcpy(p, "[guard]");
            break;
        case VMA_THREAD_STACK:
            *p++ = ' '; *p++ = ' '; *p++ = ' '; *p++ = ' ';
            *p++ = ' '; *p++ = ' '; *p++ = ' '; *p++ = ' '; *p++ = ' ';
            p = pfs_strcpy(p, "[thread_stack]");
            break;
        default:
            break;
        }
        *p++ = '\n';
    }

    *p = '\0';
    return (uint32_t)(p - buf);
}

/* ── bounded append helpers ─────────────────────────────────────────────
 * gen_status emits a linear sequence of small fields, so unlike the
 * loop-based generators (gen_maps/gen_mounts) it cannot use a single
 * "(end - p) >= MAX_RECORD" guard before each iteration.  These helpers
 * make every append respect the buffer end: a write that would not fit
 * (including its NUL room) is dropped, truncating cleanly instead of
 * running past `end`.  `end` points at the last writable byte (reserved
 * for the terminating '\0'), matching the gen_maps/gen_mounts convention
 * (`end = buf + bufsz - 1`).  Each helper returns the advanced cursor. */

static char *
pfs_bput(char *p, char *end, char c)
{
    if (p < end)
        *p++ = c;
    return p;
}

static char *
pfs_bstr(char *p, char *end, const char *src)
{
    while (*src && p < end)
        *p++ = *src++;
    return p;
}

static char *
pfs_bdec(char *p, char *end, uint64_t val)
{
    /* Render into a local scratch then copy only what fits, so a partial
     * number is never emitted past `end`. Max 20 digits for uint64. */
    char tmp[20];
    int i = 0;
    if (val == 0) {
        tmp[i++] = '0';
    } else {
        while (val > 0) {
            tmp[i++] = '0' + (char)(val % 10);
            val /= 10;
        }
    }
    /* digits are in tmp[0..i) least-significant first; emit reversed */
    while (i > 0 && p < end)
        *p++ = tmp[--i];
    return p;
}

/* basename helper — return pointer to last component after '/' */
static const char *
pfs_basename(const char *path)
{
    const char *last = path;
    while (*path) {
        if (*path == '/')
            last = path + 1;
        path++;
    }
    return last;
}

static uint32_t
gen_status(char *buf, uint32_t bufsz, aegis_process_t *proc)
{
    /* Every append goes through the pfs_b* bounded helpers so no write can
     * pass `end` (the last byte, reserved for the terminating '\0').  The
     * worst-case content (Name field bounded by exe_path[256] plus the fixed
     * fields) fits a 4096-byte page with room to spare, so truncation should
     * never trigger in practice — the guard is defense-in-depth against a
     * future larger field or a smaller buffer, matching gen_maps/gen_mounts. */
    char *p = buf;
    char *end = buf + bufsz - 1;

    p = pfs_bstr(p, end, "Name:\t");
    p = pfs_bstr(p, end, pfs_basename(proc->exe_path));
    p = pfs_bput(p, end, '\n');

    p = pfs_bstr(p, end, "State:\t");
    switch (proc->task.state) {
    case TASK_RUNNING: p = pfs_bstr(p, end, "R (running)"); break;
    case TASK_BLOCKED: p = pfs_bstr(p, end, "S (sleeping)"); break;
    case TASK_ZOMBIE:  p = pfs_bstr(p, end, "Z (zombie)"); break;
    case TASK_STOPPED: p = pfs_bstr(p, end, "T (stopped)"); break;
    default:           p = pfs_bstr(p, end, "? (unknown)"); break;
    }
    p = pfs_bput(p, end, '\n');

    p = pfs_bstr(p, end, "Tgid:\t");
    p = pfs_bdec(p, end, proc->tgid);
    p = pfs_bput(p, end, '\n');

    p = pfs_bstr(p, end, "Pid:\t");
    p = pfs_bdec(p, end, proc->pid);
    p = pfs_bput(p, end, '\n');

    p = pfs_bstr(p, end, "PPid:\t");
    p = pfs_bdec(p, end, proc->ppid);
    p = pfs_bput(p, end, '\n');

    p = pfs_bstr(p, end, "Uid:\t");
    p = pfs_bdec(p, end, proc->uid);
    p = pfs_bput(p, end, '\n');

    p = pfs_bstr(p, end, "Gid:\t");
    p = pfs_bdec(p, end, proc->gid);
    p = pfs_bput(p, end, '\n');

    /* VmSize: sum of VMA lengths in kB */
    p = pfs_bstr(p, end, "VmSize:\t");
    {
        uint64_t total = 0;
        uint32_t i;
        if (proc->vma_table) {
            for (i = 0; i < vma_count_get(proc); i++)
                total += proc->vma_table[i].len;
        }
        p = pfs_bdec(p, end, total / 1024);
    }
    p = pfs_bstr(p, end, " kB\n");

    *p = '\0';
    return (uint32_t)(p - buf);
}

static uint32_t
gen_stat(char *buf, uint32_t bufsz, aegis_process_t *proc)
{
    char *p = buf;
    (void)bufsz;

    /* pid (comm) state ppid pgid sid tty_nr tpgid ... */
    p = pfs_u64_dec(p, proc->pid);
    *p++ = ' ';
    *p++ = '(';
    p = pfs_strcpy(p, pfs_basename(proc->exe_path));
    *p++ = ')';
    *p++ = ' ';

    switch (proc->task.state) {
    case TASK_RUNNING: *p++ = 'R'; break;
    case TASK_BLOCKED: *p++ = 'S'; break;
    case TASK_ZOMBIE:  *p++ = 'Z'; break;
    case TASK_STOPPED: *p++ = 'T'; break;
    default:           *p++ = '?'; break;
    }
    *p++ = ' ';

    p = pfs_u64_dec(p, proc->ppid);
    *p++ = ' ';
    p = pfs_u64_dec(p, proc->pgid);
    *p++ = ' ';
    /* sid=0 tty_nr=0 tpgid=0 flags=0 ... pad with zeros for remaining fields */
    p = pfs_strcpy(p, "0 0 ");
    p = pfs_u64_dec(p, proc->tgid);
    p = pfs_strcpy(p, " 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n");

    *p = '\0';
    return (uint32_t)(p - buf);
}

static uint32_t
gen_exe(char *buf, uint32_t bufsz, aegis_process_t *proc)
{
    char *p = buf;
    (void)bufsz;
    p = pfs_strcpy(p, proc->exe_path);
    *p++ = '\n';
    *p = '\0';
    return (uint32_t)(p - buf);
}

static uint32_t
gen_cmdline(char *buf, uint32_t bufsz, aegis_process_t *proc)
{
    char *p = buf;
    (void)bufsz;
    p = pfs_strcpy(p, proc->exe_path);
    *p++ = '\0'; /* NUL-terminated argv[0] */
    return (uint32_t)(p - buf);
}

static uint32_t
gen_meminfo(char *buf, uint32_t bufsz)
{
    char *p = buf;
    (void)bufsz;
    uint64_t total_kb = pmm_total_pages() * 4;
    uint64_t free_kb  = pmm_free_pages()  * 4;

    p = pfs_strcpy(p, "MemTotal:       ");
    p = pfs_u64_dec(p, total_kb);
    p = pfs_strcpy(p, " kB\n");

    p = pfs_strcpy(p, "MemFree:        ");
    p = pfs_u64_dec(p, free_kb);
    p = pfs_strcpy(p, " kB\n");

    p = pfs_strcpy(p, "MemAvailable:   ");
    p = pfs_u64_dec(p, free_kb);
    p = pfs_strcpy(p, " kB\n");

    *p = '\0';
    return (uint32_t)(p - buf);
}

/* /proc/uptime — seconds since boot, derived from the 100 Hz tick counter.
 * Linux format: "<seconds>.<centiseconds> <idle>\n".  We have no per-CPU idle
 * accounting, so the second field mirrors the first (good enough for an
 * uptime readout; nothing in userland parses the idle column). */
static uint32_t
gen_uptime(char *buf, uint32_t bufsz)
{
    char *p = buf;
    (void)bufsz;
    uint64_t ticks = arch_get_ticks();      /* 100 Hz */
    uint64_t sec   = ticks / 100;
    uint64_t cs    = ticks % 100;            /* centiseconds */

    p = pfs_u64_dec(p, sec);
    *p++ = '.';
    if (cs < 10) *p++ = '0';
    p = pfs_u64_dec(p, cs);
    *p++ = ' ';
    p = pfs_u64_dec(p, sec);
    *p++ = '.';
    if (cs < 10) *p++ = '0';
    p = pfs_u64_dec(p, cs);
    *p++ = '\n';
    *p = '\0';
    return (uint32_t)(p - buf);
}

/* /proc/cpuinfo — processor brand + logical CPU count.  Deliberately minimal:
 * the Settings app reads "model name" and "cpus" out of this.  On x86 the
 * brand string comes from CPUID leaves 0x80000002..4 (48 bytes); the vendor
 * from leaf 0.  Non-x86 emits a generic line. */
extern uint32_t g_cpu_count;   /* defined per-arch in smp.c / stubs.c */

static uint32_t
gen_cpuinfo(char *buf, uint32_t bufsz)
{
    char *p = buf;
    (void)bufsz;

    char vendor[13] = {0};
    char brand[49]  = {0};

#ifdef __x86_64__
    uint32_t a, b, c, d;

    /* Vendor string (leaf 0, in EBX/EDX/ECX order). */
    __asm__ volatile("cpuid" : "=a"(a), "=b"(b), "=c"(c), "=d"(d) : "a"(0));
    *(uint32_t *)&vendor[0] = b;
    *(uint32_t *)&vendor[4] = d;
    *(uint32_t *)&vendor[8] = c;
    vendor[12] = '\0';

    /* Brand string (leaves 0x80000002..0x80000004), if supported. */
    __asm__ volatile("cpuid" : "=a"(a), "=b"(b), "=c"(c), "=d"(d)
                             : "a"(0x80000000));
    if (a >= 0x80000004) {
        uint32_t *bp = (uint32_t *)brand;
        for (uint32_t leaf = 0x80000002; leaf <= 0x80000004; leaf++) {
            __asm__ volatile("cpuid" : "=a"(a), "=b"(b), "=c"(c), "=d"(d)
                                     : "a"(leaf));
            *bp++ = a; *bp++ = b; *bp++ = c; *bp++ = d;
        }
        brand[48] = '\0';
    }
#endif

    /* Trim leading spaces the brand string often carries. */
    const char *bs = brand;
    while (*bs == ' ') bs++;

    p = pfs_strcpy(p, "vendor_id\t: ");
    p = pfs_strcpy(p, vendor[0] ? vendor : "unknown");
    *p++ = '\n';

    p = pfs_strcpy(p, "model name\t: ");
    p = pfs_strcpy(p, bs[0] ? bs : "Unknown Processor");
    *p++ = '\n';

    p = pfs_strcpy(p, "cpus\t\t: ");
    p = pfs_u64_dec(p, g_cpu_count ? g_cpu_count : 1);
    *p++ = '\n';

    *p = '\0';
    return (uint32_t)(p - buf);
}

/* /proc/smart — NVMe SMART/health (key: value lines). "device: none" when no
 * NVMe controller is present (or on non-x86). Settings → Storage renders it. */
static uint32_t
gen_smart(char *buf, uint32_t bufsz)
{
    char *p = buf;
    (void)bufsz;
#ifdef __x86_64__
    nvme_smart_t s;
    if (nvme_smart_info(&s) == 0) {
        p = pfs_strcpy(p, "device: nvme0\n");
        p = pfs_strcpy(p, "health: ");
        p = pfs_strcpy(p, s.critical_warning ? "WARNING" : "OK");
        p = pfs_strcpy(p, "\ntemperature: ");
        if (s.temp_c < 0) {
            *p++ = '-';
            p = pfs_u64_dec(p, (uint64_t)(-s.temp_c));
        } else {
            p = pfs_u64_dec(p, (uint64_t)s.temp_c);
        }
        p = pfs_strcpy(p, "\nspare: ");
        p = pfs_u64_dec(p, s.avail_spare);
        p = pfs_strcpy(p, "\nused: ");
        p = pfs_u64_dec(p, s.pct_used);
        p = pfs_strcpy(p, "\npoweronhours: ");
        p = pfs_u64_dec(p, s.power_on_hours);
        p = pfs_strcpy(p, "\npowercycles: ");
        p = pfs_u64_dec(p, s.power_cycles);
        *p++ = '\n';
        *p = '\0';
        return (uint32_t)(p - buf);
    }
#endif
    p = pfs_strcpy(p, "device: none\n");
    *p = '\0';
    return (uint32_t)(p - buf);
}

/* /proc/hda — Intel HD Audio codec widget graph (pins + config-defaults +
 * connections). The map used to route real codecs; readable from a terminal
 * on machines with no serial console (e.g. laptops). */
static uint32_t
gen_hda(char *buf, uint32_t bufsz)
{
#ifdef __x86_64__
    int n = hda_dump(buf, (int)bufsz);
    if (n > 0)
        return (uint32_t)n;
#else
    (void)bufsz;   /* no HDA driver on this arch */
#endif
    char *p = pfs_strcpy(buf, "no HDA codec\n");
    *p = '\0';
    return (uint32_t)(p - buf);
}

/* /proc/kbdstat — input-source event counters.  The bastion greeter
 * renders this live so "keyboard dead at greeter" reports from machines
 * with no serial console can be triaged on screen: counters incrementing
 * while typing = kernel sees input (delivery problem); frozen at 0 =
 * hardware/IRQ level. */
static uint32_t
gen_kbdstat(char *buf, uint32_t bufsz)
{
    char *p = buf;
    (void)bufsz;
    uint32_t ps2 = 0, usb = 0, serial = 0;
    p = pfs_strcpy(p, "ps2=");
#ifdef __x86_64__
    kbd_stats_get(&ps2, &usb, &serial);
#endif
    p = pfs_u64_dec(p, ps2);
    p = pfs_strcpy(p, " usb=");
    p = pfs_u64_dec(p, usb);
    p = pfs_strcpy(p, " serial=");
    p = pfs_u64_dec(p, serial);
#ifdef __x86_64__
    {
        /* i8042 bring-up outcome: cfg byte + what the device said.
         * Rendered on the bastion greeter — this is the remote-debug
         * channel for serial-less laptops. */
        static const char *st_name[] = {
            "absent", "ok", "f4", "nodev", "cfgfail"
        };
        uint8_t cfg = 0, st = 0;
        kbd_i8042_get(&cfg, &st);
        p = pfs_strcpy(p, "  8042: cfg=0x");
        p = pfs_u64_hex(p, cfg, 2);
        p = pfs_strcpy(p, " ");
        p = pfs_strcpy(p, (st < 5) ? st_name[st] : "?");
    }
#endif
    *p++ = '\n';
    *p = '\0';
    return (uint32_t)(p - buf);
}

static uint32_t
gen_version(char *buf, uint32_t bufsz)
{
    char *p = buf;
    (void)bufsz;
    /* AEGIS_VERSION is injected by the Makefile from git (exact tag on
     * release builds, dev-<hash> otherwise); string-literal concat. */
    p = pfs_strcpy(p, "Aegis " AEGIS_VERSION "\n");
    *p = '\0';
    return (uint32_t)(p - buf);
}

static uint32_t
gen_kcmdline(char *buf, uint32_t bufsz)
{
    const char *cmdline = arch_get_cmdline();
    char *p = buf;
    (void)bufsz;
    p = pfs_strcpy(p, cmdline);
    *p++ = '\n';
    *p = '\0';
    return (uint32_t)(p - buf);
}

/* /proc/dmesg — kernel log ring buffer (printk history).
 * The klog ring is 64KB but the procfs generation buffer is one kva page
 * (4096 bytes), so this returns only the newest ~4KB: klog_read copies
 * the TAIL of the ring when the destination is smaller than the log.
 *
 * A tail that is smaller than the full log starts at an arbitrary byte, i.e.
 * in the MIDDLE of a log line — so the first "line" a reader sees (e.g.
 * `dmesg | head -n 1`) would be a partial fragment with no leading "[SUBSYS]"
 * prefix.  When the buffer came back full (truncation happened), drop the
 * leading partial line so the snapshot begins on a real line boundary. */
static uint32_t
gen_dmesg(char *buf, uint32_t bufsz)
{
    uint32_t cap = bufsz - 1;
    uint32_t len = klog_read(buf, cap);

    if (len == cap) {
        /* Truncated: find the first newline and start just after it.  If the
         * snapshot somehow holds no newline at all (one >4KB line — printk
         * never emits that), leave it untouched rather than empty it. */
        uint32_t i = 0;
        while (i < len && buf[i] != '\n')
            i++;
        if (i < len) {
            i++;                       /* consume the '\n' */
            uint32_t kept = len - i;
            for (uint32_t j = 0; j < kept; j++)
                buf[j] = buf[i + j];
            len = kept;
        }
    }

    buf[len] = '\0';
    return len;
}

/* /proc/mounts — "<device> <mountpoint> <fstype> <total_kb> <free_kb>".
 * The ext2 root line comes from the in-memory superblock via ext2_statfs.
 * The ramfs mounts (/tmp, /run) are static instances private to vfs.c
 * with no size accessor, so they get placeholder "0 0" totals — readers
 * (df) must treat total 0 as "unknown".  The initrd / underlay is
 * intentionally skipped (not a real mount, no meaningful totals). */
static uint32_t
gen_mounts(char *buf, uint32_t bufsz)
{
    /* Largest single line, worst case:
     *   device name (15, blkdev_t.name[16]) + ' ' (1)
     *   + mountpoint (4) + ' ' (1) + fstype (5) + ' ' (1)
     *   + 2 × u64 decimal (20 each) + ' ' (1) + '\n' (1)
     *   + the trailing '\0' written after the loop (1)
     * = 70 bytes.  Round up for slack so the guard is provably safe. */
    enum { MOUNTS_MAX_LINE = 96 };
    char *p = buf;
    char *end = buf + bufsz - 1;
    uint64_t total_kb = 0;
    uint64_t free_kb = 0;

    if (ext2_statfs(&total_kb, &free_kb) == 0 &&
        (end - p) >= MOUNTS_MAX_LINE) {
        const char *dev = ext2_devname();
        p = pfs_strcpy(p, dev ? dev : "ext2root");
        p = pfs_strcpy(p, " / ext2 ");
        p = pfs_u64_dec(p, total_kb);
        *p++ = ' ';
        p = pfs_u64_dec(p, free_kb);
        *p++ = '\n';
    }

    if ((end - p) >= MOUNTS_MAX_LINE)
        p = pfs_strcpy(p, "ramfs /tmp ramfs 0 0\n");
    if ((end - p) >= MOUNTS_MAX_LINE)
        p = pfs_strcpy(p, "ramfs /run ramfs 0 0\n");

    *p = '\0';
    return (uint32_t)(p - buf);
}

/* /proc/usbnet — live USB-ethernet (AX88179) bring-up diagnostics. The driver
 * detects the adapter and arms bulk RX but does not yet register a netdev, so
 * this is the only window into "was it found, is the link up, are frames
 * arriving" on a serial-less laptop. Boot printks ([XHCI] ax88179 ...) scroll
 * out of the 4KB /proc/dmesg tail; this is a live snapshot instead. */
static uint32_t
gen_usbnet(char *buf, uint32_t bufsz)
{
    char *p = buf;
    (void)bufsz;
#ifdef __x86_64__
    xhci_usbnet_diag_t d;
    xhci_host_diag_t   h;
    int i;
    xhci_usbnet_diag(&d);

    /* --- USB-ethernet (AX88179) section --- */
    if (!d.present) {
        p = pfs_strcpy(p, "device:     none (no ASIX AX88179 claimed)\n");
        if (d.saw_device) {
            /* A USB device enumerated but wasn't an AX88179 — show its VID/PID
             * so we know what chip it is (e.g. RTL8153 dongle = 0x0bda). */
            p = pfs_strcpy(p, "last usb:   vid=0x");
            p = pfs_u64_hex(p, d.last_vid, 4);
            p = pfs_strcpy(p, " pid=0x");
            p = pfs_u64_hex(p, d.last_pid, 4);
            p = pfs_strcpy(p, " (enumerated, not a supported ethernet chip)\n");
        } else {
            p = pfs_strcpy(p, "last usb:   no non-HID USB device enumerated\n");
        }
    } else {
        p = pfs_strcpy(p, "device:     ASIX AX88179 USB ethernet\n");
        p = pfs_strcpy(p, "configured: ");
        p = pfs_strcpy(p, d.configured ? "yes (bulk endpoints set, RX armed)\n"
                                       : "no (configure failed)\n");
        p = pfs_strcpy(p, "link:       ");
        p = pfs_strcpy(p, d.link_up ? "UP" : "DOWN");
        p = pfs_strcpy(p, " physr=0x");
        p = pfs_u64_hex(p, d.physr, 4);
        p = pfs_strcpy(p, " bmsr=0x");
        p = pfs_u64_hex(p, d.bmsr, 4);
        p = pfs_strcpy(p, " medium=0x");
        p = pfs_u64_hex(p, d.medium_rb, 4);
        p = pfs_strcpy(p, d.link_reset_done ? " link_reset=yes" : " link_reset=no");
        p = pfs_strcpy(p, " mdio_cc=");
        if (d.phy_cc == 0xFFu) p = pfs_strcpy(p, "timeout");
        else                   p = pfs_u64_dec(p, d.phy_cc);
        *p++ = '\n';
        p = pfs_strcpy(p, "mac regs:   rx_ctl=0x");
        p = pfs_u64_hex(p, d.rxctl_rb, 4);
        p = pfs_strcpy(p, " plink=0x");
        p = pfs_u64_hex(p, d.plink_rb, 2);
        p = pfs_strcpy(p, " genstat=0x");
        p = pfs_u64_hex(p, d.genstat_rb, 2);
        p = pfs_strcpy(p, (d.genstat_rb & 0x04u) ? " (UA2)" : " (UA1+GPIO)");
        p = pfs_strcpy(p, " bcd=0x");
        p = pfs_u64_hex(p, d.bcd_device, 4);
        p = pfs_strcpy(p, (d.bcd_device >= 0x0200u) ? " (179A:FW_MODE forced)\n"
                                                    : "\n");
        p = pfs_strcpy(p, "mac:        ");
        for (i = 0; i < 6; i++) {
            if (i) *p++ = ':';
            p = pfs_u64_hex(p, d.mac[i], 2);
        }
        *p++ = '\n';
        p = pfs_strcpy(p, "netdev:     ");
        if (d.registered) {
            p = pfs_strcpy(p, d.ifname);
            p = pfs_strcpy(p, " (registered)\n");
        } else {
            p = pfs_strcpy(p, "not registered\n");
        }
        p = pfs_strcpy(p, "rx:         urbs=");
        p = pfs_u64_dec(p, d.rx_count);
        p = pfs_strcpy(p, " frames=");
        p = pfs_u64_dec(p, d.rx_frames);
        p = pfs_strcpy(p, " bytes=");
        p = pfs_u64_dec(p, d.rx_bytes);
        *p++ = '\n';
        p = pfs_strcpy(p, "tx:         frames=");
        p = pfs_u64_dec(p, d.tx_count);
        *p++ = '\n';
        /* Interrupt endpoint = the authoritative link source on this UA2 chip
         * (MDIO is dead). link bit = intdata1 & (1<<16). */
        p = pfs_strcpy(p, "int ep:     dci=");
        p = pfs_u64_dec(p, d.int_dci);
        p = pfs_strcpy(p, d.int_armed ? " armed" : " NOT-armed");
        p = pfs_strcpy(p, " reports=");
        p = pfs_u64_dec(p, d.int_count);
        p = pfs_strcpy(p, " link=");
        p = pfs_strcpy(p, d.link_up_intr ? "UP" : "down");
        p = pfs_strcpy(p, " intdata1=0x");
        p = pfs_u64_hex(p, d.intdata1, 8);
        p = pfs_strcpy(p, " intdata2=0x");
        p = pfs_u64_hex(p, d.intdata2, 8);
        *p++ = '\n';
        /* MDIO-free speed detection (MEDIUM signature-bit stick test). */
        p = pfs_strcpy(p, "speed:      detected=");
        if (d.det_speed == 0u) {
            p = pfs_strcpy(p, "NONE(no lock)");
        } else {
            p = pfs_u64_dec(p, d.det_speed);
            *p++ = 'M';
        }
        p = pfs_strcpy(p, " gig_rb=0x");
        p = pfs_u64_hex(p, d.med_gig_rb, 4);
        p = pfs_strcpy(p, " 100_rb=0x");
        p = pfs_u64_hex(p, d.med_100_rb, 4);
        *p++ = '\n';
        /* Endpoint assignment — confirm bulk-IN is armed on the right DCI
         * (the int EP being at dci=3 means an interrupt-first descriptor). */
        p = pfs_strcpy(p, "endpoints:  bulk_in=0x");
        p = pfs_u64_hex(p, d.bulk_in_addr, 2);
        p = pfs_strcpy(p, "(dci");
        p = pfs_u64_dec(p, d.bulk_in_dci);
        p = pfs_strcpy(p, ") bulk_out=0x");
        p = pfs_u64_hex(p, d.bulk_out_addr, 2);
        p = pfs_strcpy(p, "(dci");
        p = pfs_u64_dec(p, d.bulk_out_dci);
        p = pfs_strcpy(p, ") int=0x");
        p = pfs_u64_hex(p, d.int_addr, 2);
        p = pfs_strcpy(p, "(dci");
        p = pfs_u64_dec(p, d.int_dci);
        p = pfs_strcpy(p, ") in_burst=");
        p = pfs_u64_dec(p, d.bulk_in_burst);
        *p++ = '\n';
    }

    /* --- xHCI host-controller section --- Aegis adopts ONE controller; a
     * USB-C port on a different one is never scanned. This shows the full
     * picture so we can tell which case we're in. */
    xhci_host_diag(&h);
    p = pfs_strcpy(p, "\nxhci ctrls: ");
    p = pfs_u64_dec(p, h.total_controllers);
    p = pfs_strcpy(p, " present, ");
    p = pfs_u64_dec(p, h.count);
    p = pfs_strcpy(p, " scanned, adopted=");
    if (h.adopted_index < 0)
        p = pfs_strcpy(p, "NONE");
    else
        p = pfs_u64_dec(p, (uint64_t)(h.adopted_index + 1));
    *p++ = '\n';
    for (i = 0; i < (int)h.count; i++) {
        p = pfs_strcpy(p, "  #");
        p = pfs_u64_dec(p, (uint64_t)(i + 1));
        p = pfs_strcpy(p, " ");
        p = pfs_u64_hex(p, h.ctrl[i].vendor, 4);
        *p++ = ':';
        p = pfs_u64_hex(p, h.ctrl[i].device, 4);
        p = pfs_strcpy(p, "  ");
        p = pfs_strcpy(p, h.ctrl[i].result == 1 ? "ADOPTED (had a connected port)"
                        : h.ctrl[i].result == 0 ? "empty (no device at boot)"
                        :                          "init failed");
        *p++ = '\n';
    }
    if (h.total_controllers > h.count)
        p = pfs_strcpy(p, "  (remaining controllers not scanned — adopt stops at first)\n");
    if (h.adopted_index >= 0 && h.adopted_max_ports > 0) {
        uint32_t conn = 0, pn;
        for (pn = 1; pn <= h.adopted_max_ports; pn++)
            if (h.port[pn] & 0x1u) conn++;
        p = pfs_strcpy(p, "adopted ports: ");
        p = pfs_u64_dec(p, conn);
        p = pfs_strcpy(p, " of ");
        p = pfs_u64_dec(p, h.adopted_max_ports);
        p = pfs_strcpy(p, " connected\n");
        for (pn = 1; pn <= h.adopted_max_ports; pn++) {
            static const char *stg[] = {
                "not-enumerated", "reset-timeout", "enable-slot-failed",
                "address-device-failed", "configure-ep-failed",
                "HID-ready", "handed-to-eth-probe"
            };
            uint8_t st;
            if (!(h.port[pn] & 0x1u)) continue;   /* only connected ports */
            p = pfs_strcpy(p, "  port ");
            p = pfs_u64_dec(p, pn);
            p = pfs_strcpy(p, ": speed=");
            p = pfs_u64_dec(p, (h.port[pn] >> 10) & 0xFu);
            p = pfs_strcpy(p, h.is_usb3[pn] ? " usb3" : " usb2");
            st = h.enum_stage[pn];
            p = pfs_strcpy(p, " enum=");
            p = pfs_strcpy(p, st < 7u ? stg[st] : "?");
            /* show the command completion code + controller status for a failed stage */
            if (st == 3u || st == 4u) {   /* address-device / configure-ep failed */
                uint32_t us = h.enum_usbsts[pn];
                p = pfs_strcpy(p, " cc=");
                if (h.enum_cc[pn] == 0xFFu)
                    p = pfs_strcpy(p, "timeout");
                else
                    p = pfs_u64_dec(p, h.enum_cc[pn]);
                p = pfs_strcpy(p, " usbsts=0x");
                p = pfs_u64_hex(p, us, 4);
                /* decode the fatal/halt bits: HCH(0) HSE(2) HCE(12) */
                if (us & (1u << 0)) p = pfs_strcpy(p, "[HALTED]");
                if (us & (1u << 2)) p = pfs_strcpy(p, "[HSE]");
                if (us & (1u << 12)) p = pfs_strcpy(p, "[HCE]");
            }
            p = pfs_strcpy(p, " portsc=0x");
            p = pfs_u64_hex(p, h.port[pn], 8);
            *p++ = '\n';
        }
    }
    p = pfs_strcpy(p, "note: USB-eth SS MaxBurst + RX_CTL AP, safe 4K rxbuf. diag-rev=25\n");
#else
    p = pfs_strcpy(p, "device:     n/a (no xHCI on this architecture)\n");
#endif
    *p = '\0';
    return (uint32_t)(p - buf);
}

/* ── capability check ──────────────────────────────────────────────────── */

static int
procfs_check_access(uint32_t target_pid)
{
    aegis_task_t *cur = sched_current();
    if (!cur || !cur->is_user)
        return -1;
    aegis_process_t *caller = (aegis_process_t *)cur;
    if (target_pid == caller->pid)
        return 0; /* self always OK */
    return cap_check(caller->caps, CAP_TABLE_SIZE,
                     CAP_KIND_PROC_READ, CAP_RIGHTS_READ);
}

/* ── VFS ops for generated-content files ───────────────────────────────── */

static int
procfs_file_read(void *priv, void *buf, uint64_t off, uint64_t len)
{
    procfs_file_priv_t *fp = (procfs_file_priv_t *)priv;
    if (off >= fp->len)
        return 0;
    uint64_t avail = fp->len - off;
    if (len > avail)
        len = avail;
    __builtin_memcpy(buf, fp->buf + off, (uint32_t)len);
    return (int)len;
}

/* fork()/dup() copy the fd slot verbatim, so two fds share one priv pointer.
 * Without a refcount the first close would free it under the surviving fd
 * (use-after-free + double-free on the second close). Bump on dup, free only
 * on last close. SEQ_CST atomics: fork/dup and close can run on different CPUs. */
static void
procfs_file_dup(void *priv)
{
    procfs_file_priv_t *fp = (procfs_file_priv_t *)priv;
    if (fp) __atomic_fetch_add(&fp->refs, 1, __ATOMIC_SEQ_CST);
}

static void
procfs_file_close(void *priv)
{
    procfs_file_priv_t *fp = (procfs_file_priv_t *)priv;
    if (!fp) return;
    if (__atomic_fetch_sub(&fp->refs, 1, __ATOMIC_SEQ_CST) > 1)
        return;  /* other fds still reference it */
    if (fp->buf)
        kva_free_pages(fp->buf, 1);
    kva_free_pages(fp, 1);
}

static int
procfs_file_stat(void *priv, k_stat_t *st)
{
    procfs_file_priv_t *fp = (procfs_file_priv_t *)priv;
    __builtin_memset(st, 0, sizeof(*st));
    st->st_dev   = 5;
    st->st_ino   = 1;
    st->st_nlink = 1;
    st->st_mode  = S_IFREG | 0444;
    st->st_size  = (int64_t)fp->len;
    return 0;
}

static const vfs_ops_t s_procfs_file_ops = {
    .read    = procfs_file_read,
    .write   = 0,
    .close   = procfs_file_close,
    .readdir = 0,
    .dup     = procfs_file_dup,
    .stat    = procfs_file_stat,
    .poll    = 0,
};

/* ── /proc root node registry ──────────────────────────────────────────────
 * The single source of truth for the entries directly under /proc/. readdir,
 * procfs_open and procfs_stat all iterate this table instead of three
 * hand-maintained, drift-prone lists (an `index == N` ladder + a `pfs_streq`
 * chain + a `pfs_streq` OR-wall, each with its own PID-base offset). Adding a
 * /proc/<x> node is now one row here plus the gen_<x>() generator.
 *
 * `gen == NULL` marks a directory entry ("self"); files carry their generator.
 * dtype: 4 = DT_DIR, 8 = DT_REG. */
/* /proc/tasks — DIAG: one line per user task: "<pid> <name> st=<state>
 * sc=<last_syscall> wait=<waiting_for>".  state: 0=RUNNING 1=BLOCKED 2=ZOMBIE.
 * Shows what a hung/blocked process is stuck in (the syscall number it last
 * entered).  Walks the circular task list under sched_lock. */
static uint32_t
gen_tasks(char *buf, uint32_t bufsz)
{
    char *p = buf;
    char *end = buf + bufsz - 400;   /* per-task margin (name <=255 + fields) */
    aegis_task_t *cur = sched_current();
    if (!cur) { *p = '\0'; return 0; }
    irqflags_t fl = spin_lock_irqsave(&sched_lock);
    aegis_task_t *t = cur;
    do {
        if (t->is_user && p < end) {
            aegis_process_t *proc = (aegis_process_t *)t;
            p = pfs_u64_dec(p, proc->pid);
            *p++ = ' ';
            p = pfs_strcpy(p, pfs_basename(proc->exe_path));
            p = pfs_strcpy(p, " st=");
            p = pfs_u64_dec(p, t->state);
            p = pfs_strcpy(p, " sc=");
            p = pfs_u64_dec(p, t->last_syscall);
            p = pfs_strcpy(p, " wait=");
            p = pfs_u64_dec(p, t->waiting_for);
            *p++ = '\n';
        }
        t = t->next;
    } while (t != cur);
    spin_unlock_irqrestore(&sched_lock, fl);
    *p = '\0';
    return (uint32_t)(p - buf);
}

typedef struct {
    const char *name;
    uint8_t     dtype;
    uint16_t    mode;
    uint32_t  (*gen)(char *buf, uint32_t bufsz);
} procfs_root_node_t;

/* /proc/stackshot — reading it triggers a full stackshot (all tasks +
 * backtraces) to the kernel log / serial.  The read returns a short ack; the
 * dump itself goes to serial (too big and multi-line for a procfs buffer, and
 * the point is to capture it on the console of a possibly-wedged system). */
static uint32_t
gen_stackshot(char *buf, uint32_t bufsz)
{
    (void)bufsz;
    dump_all_tasks("/proc/stackshot");
    char *p = pfs_strcpy(buf, "stackshot written to kernel log (see serial / dmesg)\n");
    return (uint32_t)(p - buf);
}

/* /proc/trace — reading it dumps the lockless trace ring (kbd inject/consume
 * tracepoints, by CPU) to the kernel log / serial. */
static uint32_t
gen_trace(char *buf, uint32_t bufsz)
{
    (void)bufsz;
    trace_dump("/proc/trace");
    char *p = pfs_strcpy(buf, "trace ring written to kernel log (see serial / dmesg)\n");
    return (uint32_t)(p - buf);
}

static const procfs_root_node_t s_proc_root[] = {
    { "self",    4, S_IFDIR | 0555, (void *)0 },
    { "meminfo", 8, S_IFREG | 0444, gen_meminfo  },
    { "version", 8, S_IFREG | 0444, gen_version  },
    { "cmdline", 8, S_IFREG | 0444, gen_kcmdline },
    { "kbdstat", 8, S_IFREG | 0444, gen_kbdstat  },
    { "dmesg",   8, S_IFREG | 0444, gen_dmesg    },
    { "mounts",  8, S_IFREG | 0444, gen_mounts   },
    { "usbnet",  8, S_IFREG | 0444, gen_usbnet   },
    { "uptime",  8, S_IFREG | 0444, gen_uptime   },
    { "cpuinfo", 8, S_IFREG | 0444, gen_cpuinfo  },
    { "smart",   8, S_IFREG | 0444, gen_smart    },
    { "hda",     8, S_IFREG | 0444, gen_hda      },
    { "tasks",   8, S_IFREG | 0444, gen_tasks    },
    { "stackshot", 8, S_IFREG | 0444, gen_stackshot },
    { "trace",   8, S_IFREG | 0444, gen_trace    },
};
#define PROCFS_NROOT (sizeof(s_proc_root) / sizeof(s_proc_root[0]))

/* ── VFS ops for directory listings ────────────────────────────────────── */

static int
procfs_dir_readdir(void *priv, uint64_t index, char *name_out, uint8_t *type_out)
{
    procfs_dir_priv_t *dp = (procfs_dir_priv_t *)priv;

    if (dp->is_fd) {
        /* /proc/[pid]/fd/ — enumerate open fds */
        aegis_process_t *proc = proc_find_by_pid(dp->pid);
        if (!proc || !proc->fd_table)
            return -1;
        uint64_t found = 0;
        uint32_t i;
        for (i = 0; i < PROC_MAX_FDS; i++) {
            if (!proc->fd_table->fds[i].ops)
                continue;
            if (found == index) {
                /* write decimal fd number into name_out */
                char *p = pfs_u64_dec(name_out, i);
                *p = '\0';
                *type_out = 8; /* DT_REG */
                return 0;
            }
            found++;
        }
        return -1;
    }

    if (dp->pid != 0) {
        /* /proc/[pid]/ — fixed entries */
        static const char *entries[] = {
            "maps", "status", "stat", "exe", "cmdline", "fd"
        };
        static const uint8_t types[] = {
            8, 8, 8, 8, 8, 4  /* DT_REG=8, DT_DIR=4 */
        };
        if (index < 6) {
            char *p = pfs_strcpy(name_out, entries[index]);
            *p = '\0';
            *type_out = types[index];
            return 0;
        }
        return -1;
    }

    /* /proc/ root — fixed nodes from the registry, then live PIDs. */
    if (index < PROCFS_NROOT) {
        char *p = pfs_strcpy(name_out, s_proc_root[index].name);
        *p = '\0';
        *type_out = s_proc_root[index].dtype;
        return 0;
    }

    /* Enumerate user processes from circular task list.
     * Walk under sched_lock — sched_add (fork/clone/spawn) and the
     * sys_waitpid zombie unlink mutate the chain concurrently on SMP. */
    uint64_t pidx = index - PROCFS_NROOT;
    aegis_task_t *cur = sched_current();
    if (!cur)
        return -1;
    irqflags_t fl = spin_lock_irqsave(&sched_lock);
    aegis_task_t *t = cur;
    uint64_t found = 0;
    do {
        if (t->is_user) {
            if (found == pidx) {
                aegis_process_t *proc = (aegis_process_t *)t;
                char *p = pfs_u64_dec(name_out, proc->pid);
                *p = '\0';
                *type_out = 4; /* DT_DIR */
                spin_unlock_irqrestore(&sched_lock, fl);
                return 0;
            }
            found++;
        }
        t = t->next;
    } while (t != cur);
    spin_unlock_irqrestore(&sched_lock, fl);

    return -1;
}

/* Same fork/dup-sharing hazard as procfs_file_dup/close above. */
static void
procfs_dir_dup(void *priv)
{
    procfs_dir_priv_t *dp = (procfs_dir_priv_t *)priv;
    if (dp) __atomic_fetch_add(&dp->refs, 1, __ATOMIC_SEQ_CST);
}

static void
procfs_dir_close(void *priv)
{
    procfs_dir_priv_t *dp = (procfs_dir_priv_t *)priv;
    if (!dp) return;
    if (__atomic_fetch_sub(&dp->refs, 1, __ATOMIC_SEQ_CST) > 1)
        return;  /* other fds still reference it */
    kva_free_pages(dp, 1);
}

static int
procfs_dir_stat(void *priv, k_stat_t *st)
{
    (void)priv;
    __builtin_memset(st, 0, sizeof(*st));
    st->st_dev   = 5;
    st->st_ino   = 1;
    st->st_nlink = 2;
    st->st_mode  = S_IFDIR | 0555;
    return 0;
}

static const vfs_ops_t s_procfs_dir_ops = {
    .read    = 0,
    .write   = 0,
    .close   = procfs_dir_close,
    .readdir = procfs_dir_readdir,
    .dup     = procfs_dir_dup,
    .stat    = procfs_dir_stat,
    .poll    = 0,
};

/* ── path helpers ──────────────────────────────────────────────────────── */

/* Parse a decimal PID from path; advance *pp past the digits.
 * Returns 0 if no digits found. */
static uint32_t
pfs_parse_pid(const char **pp)
{
    const char *s = *pp;
    uint32_t pid = 0;
    while (*s >= '0' && *s <= '9') {
        pid = pid * 10 + (uint32_t)(*s - '0');
        s++;
    }
    *pp = s;
    return pid;
}

/* Open a generated-content file into *out.
 * Allocates a kva page for the buffer, calls the generator, sets up the fd. */
static int
procfs_open_file(uint32_t (*gen)(char *, uint32_t, aegis_process_t *),
                 aegis_process_t *proc, vfs_file_t *out)
{
    procfs_file_priv_t *fp = (procfs_file_priv_t *)kva_alloc_pages(1);
    char *buf = (char *)kva_alloc_pages(1);
    if (!fp || !buf)
        return -ENOMEM;
    fp->buf = buf;
    fp->len = gen(buf, 4096, proc);
    fp->refs = 1;

    out->ops    = &s_procfs_file_ops;
    out->priv   = (void *)fp;
    out->offset = 0;
    out->size   = (uint64_t)fp->len;
    out->flags  = 0;
    out->kflags = 0;
    return 0;
}

/* Open a global file (meminfo, version) — generator takes no proc arg. */
static int
procfs_open_global(uint32_t (*gen)(char *, uint32_t), vfs_file_t *out)
{
    procfs_file_priv_t *fp = (procfs_file_priv_t *)kva_alloc_pages(1);
    char *buf = (char *)kva_alloc_pages(1);
    if (!fp || !buf)
        return -ENOMEM;
    fp->buf = buf;
    fp->len = gen(buf, 4096);
    fp->refs = 1;

    out->ops    = &s_procfs_file_ops;
    out->priv   = (void *)fp;
    out->offset = 0;
    out->size   = (uint64_t)fp->len;
    out->flags  = 0;
    out->kflags = 0;
    return 0;
}

/* Open a directory fd with a procfs_dir_priv_t. */
static int
procfs_open_dir(uint32_t pid, uint8_t is_fd, vfs_file_t *out)
{
    procfs_dir_priv_t *dp = (procfs_dir_priv_t *)kva_alloc_pages(1);
    if (!dp)
        return -ENOMEM;
    dp->pid   = pid;
    dp->is_fd = is_fd;
    dp->_pad[0] = 0;
    dp->_pad[1] = 0;
    dp->_pad[2] = 0;
    dp->refs  = 1;

    out->ops    = &s_procfs_dir_ops;
    out->priv   = (void *)dp;
    out->offset = 0;
    out->size   = 0;
    out->flags  = 0;
    out->kflags = 0;
    return 0;
}

/* Dispatch a per-pid subpath. path points AFTER the pid digits (e.g. "/maps" or ""). */
static int
procfs_open_pid(uint32_t pid, const char *path, vfs_file_t *out)
{
    int rc = procfs_check_access(pid);
    if (rc != 0)
        return -(int)ENOCAP;

    aegis_process_t *proc = proc_find_by_pid(pid);
    if (!proc)
        return -ENOENT;

    /* /proc/<pid> or /proc/<pid>/ → directory */
    if (path[0] == '\0' || (path[0] == '/' && path[1] == '\0'))
        return procfs_open_dir(pid, 0, out);

    /* Skip leading slash */
    if (path[0] == '/')
        path++;

    if (pfs_streq(path, "maps"))
        return procfs_open_file(gen_maps, proc, out);
    if (pfs_streq(path, "status"))
        return procfs_open_file(gen_status, proc, out);
    if (pfs_streq(path, "stat"))
        return procfs_open_file(gen_stat, proc, out);
    if (pfs_streq(path, "exe"))
        return procfs_open_file(gen_exe, proc, out);
    if (pfs_streq(path, "cmdline"))
        return procfs_open_file(gen_cmdline, proc, out);
    if (pfs_streq(path, "fd") || pfs_streq(path, "fd/"))
        return procfs_open_dir(pid, 1, out);

    return -ENOENT;
}

/* ── public API ────────────────────────────────────────────────────────── */

void
procfs_init(void)
{
    /* No-op — procfs is a VFS backend, not a hardware subsystem. */
}

/*
 * procfs_open — open a /proc path.
 * path is relative to /proc/ (prefix stripped by vfs_open).
 * e.g. "self/maps", "meminfo", "1/status", "" (root dir).
 */
int
procfs_open(const char *path, int flags, vfs_file_t *out)
{
    (void)flags;

    /* Root /proc/ directory */
    if (path[0] == '\0' || (path[0] == '/' && path[1] == '\0'))
        return procfs_open_dir(0, 0, out);

    /* Skip leading slash if present */
    if (path[0] == '/')
        path++;

    /* Global files (registry-driven; "self" has gen==NULL, handled below). */
    for (uint32_t i = 0; i < PROCFS_NROOT; i++) {
        if (s_proc_root[i].gen && pfs_streq(path, s_proc_root[i].name))
            return procfs_open_global(s_proc_root[i].gen, out);
    }

    /* /proc/self/... → resolve to current pid */
    if (path[0] == 's' && path[1] == 'e' && path[2] == 'l' && path[3] == 'f') {
        aegis_task_t *cur = sched_current();
        if (!cur || !cur->is_user)
            return -ENOENT;
        aegis_process_t *caller = (aegis_process_t *)cur;
        return procfs_open_pid(caller->pid, path + 4, out);
    }

    /* /proc/<pid>/... */
    if (path[0] >= '0' && path[0] <= '9') {
        const char *p = path;
        uint32_t pid = pfs_parse_pid(&p);
        if (pid == 0)
            return -ENOENT;
        return procfs_open_pid(pid, p, out);
    }

    return -ENOENT;
}

/*
 * procfs_stat — stat a /proc path.
 * path is the full path including "/proc" prefix.
 */
int
procfs_stat(const char *path, k_stat_t *out)
{
    if (!path || !out)
        return -ENOENT;

    __builtin_memset(out, 0, sizeof(*out));

    /* /proc itself */
    if (pfs_streq(path, "/proc") || pfs_streq(path, "/proc/")) {
        out->st_dev   = 5;
        out->st_ino   = 1;
        out->st_nlink = 2;
        out->st_mode  = S_IFDIR | 0555;
        return 0;
    }

    /* Strip /proc/ prefix */
    const char *rel = path + 5; /* past "/proc" */
    if (*rel == '/')
        rel++;

    /* Root nodes (registry-driven — files AND the "self" directory). Sharing
     * the one table with readdir/open means stat can never drift out of sync
     * again: "usbnet" was missing from this list (stat ENOENT'd while open
     * worked), and "cmdline" was too from Phase 31 until 1.2.0. */
    for (uint32_t i = 0; i < PROCFS_NROOT; i++) {
        if (pfs_streq(rel, s_proc_root[i].name)) {
            out->st_dev   = 5;
            out->st_ino   = 1;
            out->st_nlink = (s_proc_root[i].dtype == 4) ? 2 : 1;
            out->st_mode  = s_proc_root[i].mode;
            return 0;
        }
    }

    /* /proc/self/ (trailing slash) → directory */
    if (pfs_streq(rel, "self/")) {
        out->st_dev   = 5;
        out->st_ino   = 1;
        out->st_nlink = 2;
        out->st_mode  = S_IFDIR | 0555;
        return 0;
    }

    /* /proc/self/<file> */
    if (rel[0] == 's' && rel[1] == 'e' && rel[2] == 'l' && rel[3] == 'f' && rel[4] == '/') {
        const char *sub = rel + 5;
        if (pfs_streq(sub, "fd") || pfs_streq(sub, "fd/")) {
            out->st_dev   = 5;
            out->st_ino   = 1;
            out->st_nlink = 2;
            out->st_mode  = S_IFDIR | 0555;
            return 0;
        }
        if (pfs_streq(sub, "maps") || pfs_streq(sub, "status") ||
            pfs_streq(sub, "stat") || pfs_streq(sub, "exe") ||
            pfs_streq(sub, "cmdline")) {
            out->st_dev   = 5;
            out->st_ino   = 1;
            out->st_nlink = 1;
            out->st_mode  = S_IFREG | 0444;
            return 0;
        }
        return -ENOENT;
    }

    /* /proc/<pid> or /proc/<pid>/<file> */
    if (rel[0] >= '0' && rel[0] <= '9') {
        const char *p = rel;
        uint32_t pid = pfs_parse_pid(&p);
        if (pid == 0)
            return -ENOENT;

        /* Check process exists */
        aegis_process_t *proc = proc_find_by_pid(pid);
        if (!proc)
            return -ENOENT;

        /* /proc/<pid> → directory */
        if (*p == '\0' || (*p == '/' && *(p + 1) == '\0')) {
            out->st_dev   = 5;
            out->st_ino   = 1;
            out->st_nlink = 2;
            out->st_mode  = S_IFDIR | 0555;
            return 0;
        }

        if (*p == '/')
            p++;

        if (pfs_streq(p, "fd") || pfs_streq(p, "fd/")) {
            out->st_dev   = 5;
            out->st_ino   = 1;
            out->st_nlink = 2;
            out->st_mode  = S_IFDIR | 0555;
            return 0;
        }
        if (pfs_streq(p, "maps") || pfs_streq(p, "status") ||
            pfs_streq(p, "stat") || pfs_streq(p, "exe") ||
            pfs_streq(p, "cmdline")) {
            out->st_dev   = 5;
            out->st_ino   = 1;
            out->st_nlink = 1;
            out->st_mode  = S_IFREG | 0444;
            return 0;
        }
        return -ENOENT;
    }

    return -ENOENT;
}
