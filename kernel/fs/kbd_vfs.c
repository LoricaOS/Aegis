#include "kbd_vfs.h"
#include "tty.h"
#include "vfs.h"
#include "kbd.h"
#include "printk.h"
#include "arch.h"
#include "fb.h"
#include "uaccess.h"
#include "syscall_util.h"
#include "../sched/waitq.h"
#include "../include/aegis_errno.h"
#include <stdint.h>

extern waitq_t g_console_waiters;

static struct waitq *
kbd_get_waitq_fn(void *priv)
{
	(void)priv;
	return &g_console_waiters;
}

/* ── Console tty singleton ──────────────────────────────────────── */

static tty_t s_console_tty;

/* console_tty_write_out — backend callback: emit characters directly.
 * Bypasses printk so that printk_quiet (boot=quiet) does not suppress
 * TTY echo (username display, line editing). Writes char-by-char to
 * serial + VGA + FB for correct control character handling. */
static int
console_tty_write_out(tty_t *tty, const char *buf, uint32_t len)
{
	(void)tty;
	for (uint32_t i = 0; i < len; i++) {
		char tmp[2];
		tmp[0] = buf[i];
		tmp[1] = '\0';
		serial_write_string(tmp);
		if (vga_available)
			vga_write_string(tmp);
		if (fb_available)
			fb_putchar(buf[i]);
	}
	return (int)len;
}

/* console_tty_read_raw — backend callback: read one raw character from the
 * PS/2 (or USB HID) keyboard ring buffer.  Blocks until a key is pressed
 * or a signal interrupts. */
static int
console_tty_read_raw(tty_t *tty, char *out, int *interrupted)
{
	(void)tty;
	*out = kbd_read_interruptible(interrupted);
	return (*interrupted) ? 0 : 1;
}

/* console_tty_poll_raw — non-blocking single-char poll from keyboard
 * ring buffer.  Returns 1 and stores the character in *out if available,
 * 0 if no data.  Used when VMIN=0 (non-blocking raw mode). */
static int
console_tty_poll_raw(tty_t *tty, char *out)
{
	(void)tty;
	return kbd_poll(out);
}

/* console_tty_init — set up the console tty with defaults + callbacks. */
static void
console_tty_init(void)
{
	tty_init_defaults(&s_console_tty);
	/* Console handles CRLF internally via printk/serial — disable OPOST
	 * to avoid double \r\n. */
	s_console_tty.termios.c_oflag = 0;
	s_console_tty.write_out = console_tty_write_out;
	s_console_tty.read_raw  = console_tty_read_raw;
	s_console_tty.poll_raw  = console_tty_poll_raw;
	/* Apply deferred fg_pgrp set before console was initialized */
	s_console_tty.fg_pgrp   = kbd_get_tty_pgrp();
	tty_set_console(&s_console_tty);
}

/* ── VFS callbacks ──────────────────────────────────────────────── */

static int
kbd_vfs_read_fn(void *priv, void *buf, uint64_t off, uint64_t len)
{
	(void)priv; (void)off;
	if (len == 0) return 0;
	return tty_read(&s_console_tty, (char *)buf, (uint32_t)len);
}

static int
kbd_vfs_write_fn(void *priv, const void *buf, uint64_t len)
{
	(void)priv; (void)buf; (void)len;
	return -ENOSYS; /* stdin is not writable */
}

static void
kbd_vfs_close_fn(void *priv)
{
	(void)priv; /* stateless singleton -- nothing to release */
}

static int
kbd_stat_fn(void *priv, k_stat_t *st)
{
	(void)priv;
	__builtin_memset(st, 0, sizeof(*st));
	st->st_mode  = S_IFCHR | 0400;
	st->st_ino   = 3;
	st->st_rdev  = makedev(4, 0);  /* /dev/tty: major=4 minor=0 */
	st->st_dev   = 1;
	st->st_nlink = 1;
	return 0;
}

static uint16_t
kbd_vfs_poll_fn(void *priv)
{
	(void)priv;
	uint16_t events = 0x0004; /* POLLOUT always */
	if (kbd_has_data())
		events |= 0x0001; /* POLLIN */
	return events;
}

static const vfs_ops_t s_kbd_ops = {
	.read      = kbd_vfs_read_fn,
	.write     = kbd_vfs_write_fn,
	.close     = kbd_vfs_close_fn,
	.readdir   = (void *)0,
	.dup       = (void *)0,
	.stat      = kbd_stat_fn,
	.poll      = kbd_vfs_poll_fn,
	.get_waitq = kbd_get_waitq_fn,
};

static vfs_file_t s_kbd_file = {
	.ops    = &s_kbd_ops,
	.priv   = (void *)0,
	.offset = 0,
	.size   = 0,
};

/* kbd_vfs_tcgets — delegate to tty_ioctl TCGETS. */
int
kbd_vfs_tcgets(void *dst_user)
{
	return tty_ioctl(&s_console_tty, TCGETS, (uint64_t)(uintptr_t)dst_user);
}

/* kbd_vfs_tcsets — delegate to tty_ioctl TCSETS. */
int
kbd_vfs_tcsets(const void *src_user)
{
	return tty_ioctl(&s_console_tty, TCSETS, (uint64_t)(uintptr_t)src_user);
}

/* kbd_vfs_is_tty — returns 1 if vfs_file uses the kbd_vfs ops (is a tty). */
int
kbd_vfs_is_tty(const vfs_file_t *f)
{
	return f->ops == &s_kbd_ops;
}

vfs_file_t *
kbd_vfs_open(void)
{
	static int s_inited = 0;
	if (!s_inited) {
		console_tty_init();
		s_inited = 1;
	}
	return &s_kbd_file;
}
