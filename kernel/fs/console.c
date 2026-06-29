#include "console.h"
#include "vfs.h"
#include "uaccess.h"
#include "arch.h"
#include "printk.h"
#include "fb.h"
#include "../sched/waitq.h"
#include "../include/aegis_errno.h"
#include <stdint.h>

#define CONSOLE_BUF 256

/* Shared input wait queue. Woken by the kbd ISR after each byte is
 * pushed into the input ring. The kbd VFS shares this same queue
 * (extern in kbd_vfs.c) — there's only one keyboard source on the
 * machine, so all readers wake together. */
waitq_t g_console_waiters = WAITQ_INIT;

static struct waitq *
console_get_waitq_fn(void *priv)
{
    (void)priv;
    return &g_console_waiters;
}

/*
 * console_write_fn — write user output to serial + VGA + FB directly.
 *
 * Bypasses printk so that printk_quiet (boot=quiet) does not suppress
 * user-visible output (login banners, shell prompts, command output).
 * Writes char-by-char to handle control characters (\b, \r, \n, etc.)
 * correctly through each output sink's character handler.
 */
static int
console_write_fn(void *priv, const void *buf, uint64_t len)
{
    (void)priv;
    char kbuf[CONSOLE_BUF];
    uint64_t n = (len > CONSOLE_BUF) ? CONSOLE_BUF : len;
    {
        uint64_t page_off = (uint64_t)(uintptr_t)buf & 0xFFFULL;
        uint64_t to_end   = 0x1000ULL - page_off;
        if (n > to_end)
            n = to_end;
    }
    copy_from_user(kbuf, buf, n);
    /* Route through printk_emit_bytes so this userspace output is serialized
     * against kernel printk under the shared printk_lock — otherwise a console
     * write on one CPU interleaves character-by-character with a kernel printk
     * on another CPU (the SMP serial-garble bug).  printk_emit_bytes honours
     * printk_quiet internally (quiet+graphical suppresses VGA/FB so the boot
     * log doesn't flash on the framebuffer before Bastion/Lumen take over). */
    printk_emit_bytes(kbuf, (uint32_t)n, 1);
    return (int)n;
}

static int
console_read_fn(void *priv, void *buf, uint64_t off, uint64_t len)
{
    (void)priv; (void)buf; (void)off; (void)len;
    return -ENOSYS; /* stdin not implemented */
}

static void
console_close_fn(void *priv)
{
    (void)priv; /* stateless singleton — nothing to free */
}

static int
console_stat_fn(void *priv, k_stat_t *st)
{
    (void)priv;
    __builtin_memset(st, 0, sizeof(*st));
    st->st_mode  = S_IFCHR | 0600;
    st->st_ino   = 2;
    st->st_rdev  = makedev(5, 1);  /* /dev/console: major=5 minor=1 */
    st->st_dev   = 1;
    st->st_nlink = 1;
    return 0;
}

static uint16_t
console_poll_fn(void *priv)
{
    (void)priv;
    return 0x0004; /* POLLOUT always — console is write-only */
}

static const vfs_ops_t s_console_ops = {
    .read      = console_read_fn,
    .write     = console_write_fn,
    .close     = console_close_fn,
    .readdir   = (void *)0,
    .dup       = (void *)0,
    .stat      = console_stat_fn,
    .poll      = console_poll_fn,
    .get_waitq = console_get_waitq_fn,
};

static vfs_file_t s_console_file = {
    .ops    = &s_console_ops,
    .priv   = (void *)0,
    .offset = 0,
    .size   = 0,
};

void
console_init(void)
{
    /* Stateless singleton — nothing to initialize. */
}

vfs_file_t *
console_open(void)
{
    return &s_console_file;
}
