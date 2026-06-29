#include "pty.h"
#include "tty.h"
#include "vfs.h"
#include "uaccess.h"
#include "sched.h"
#include "proc.h"
#include "signal.h"
#include "arch.h"
#include "spinlock.h"
#include "../sched/waitq.h"
#include "../sched/wait_event.h"
#include "../lib/ringbuf.h"
#include <stdint.h>

/* ── Static pool ──────────────────────────────────────────────────── */

static pty_pair_t s_pty_pool[PTY_MAX_PAIRS];
static spinlock_t pty_pool_lock = SPINLOCK_INIT;

/* ── Ring buffer ──────────────────────────────────────────────────── */

/* The local ring_count/space/push/pull helpers were the prototype for the
 * shared pow2-mask inlines; they now live in ringbuf.h.  Call sites use
 * ringbuf_count/space/push/pull(.., PTY_BUF_SIZE) directly. */
RINGBUF_ASSERT_POW2(PTY_BUF_SIZE);

/* ── Forward declarations ─────────────────────────────────────────── */

static int      master_read_fn(void *priv, void *buf, uint64_t off, uint64_t len);
static int      master_write_fn(void *priv, const void *buf, uint64_t len);
static void     master_dup_fn(void *priv);
static void     master_close_fn(void *priv);
static int      master_stat_fn(void *priv, k_stat_t *st);

static int      slave_read_fn(void *priv, void *buf, uint64_t off, uint64_t len);
static int      slave_write_fn(void *priv, const void *buf, uint64_t len);
static void     slave_dup_fn(void *priv);
static void     slave_close_fn(void *priv);
static int      slave_stat_fn(void *priv, k_stat_t *st);

static struct waitq *
pty_master_get_waitq_fn(void *priv)
{
	return &((pty_pair_t *)priv)->master_waiters;
}

static struct waitq *
pty_slave_get_waitq_fn(void *priv)
{
	return &((pty_pair_t *)priv)->slave_waiters;
}

static uint16_t
master_poll_fn(void *priv)
{
	pty_pair_t *pair = (pty_pair_t *)priv;
	uint16_t events = 0x0004; /* POLLOUT always */
	if (ringbuf_count(pair->output_head, pair->output_tail, PTY_BUF_SIZE) > 0 || !pair->slave_open)
		events |= 0x0001; /* POLLIN */
	if (!pair->slave_open)
		events |= 0x0010; /* POLLHUP */
	return events;
}

static uint16_t
slave_poll_fn(void *priv)
{
	pty_pair_t *pair = (pty_pair_t *)priv;
	uint16_t events = 0x0004; /* POLLOUT always */
	if (ringbuf_count(pair->input_head, pair->input_tail, PTY_BUF_SIZE) > 0 || !pair->master_open)
		events |= 0x0001; /* POLLIN */
	if (!pair->master_open)
		events |= 0x0010; /* POLLHUP */
	return events;
}

static const vfs_ops_t s_master_ops = {
	.read      = master_read_fn,
	.write     = master_write_fn,
	.close     = master_close_fn,
	.readdir   = (void *)0,
	.dup       = master_dup_fn,
	.stat      = master_stat_fn,
	.poll      = master_poll_fn,
	.get_waitq = pty_master_get_waitq_fn,
};

static const vfs_ops_t s_slave_ops = {
	.read      = slave_read_fn,
	.write     = slave_write_fn,
	.close     = slave_close_fn,
	.readdir   = (void *)0,
	.dup       = slave_dup_fn,
	.stat      = slave_stat_fn,
	.poll      = slave_poll_fn,
	.get_waitq = pty_slave_get_waitq_fn,
};

/* ── TTY backend callbacks for the slave side ─────────────────────── */

/*
 * pty_slave_write_out -- called by tty_write/tty_echo to emit processed
 * output.  Pushes bytes into output_buf for the master to read.
 * Returns bytes written or -5 (EIO) if master closed.
 */
static int
pty_slave_write_out(tty_t *tty, const char *buf, uint32_t len)
{
	pty_pair_t *pair = (pty_pair_t *)tty->ctx;
	uint32_t i;

	if (!pair->master_open)
		return -5; /* EIO */

	/*
	 * Push bytes UNDER pair->lock so the ring indices are not raced against
	 * a concurrent master_read_fn.  The wake is deferred until AFTER the
	 * lock is dropped: waitq_wake_all takes sched_lock, and the canonical
	 * ordering is sched_lock > (all others), so we must not acquire it
	 * under pair->lock (deferred-wake pattern, per kernel/sched/waitq.c).
	 */
	irqflags_t fl = spin_lock_irqsave(&pair->lock);
	for (i = 0; i < len; i++) {
		if (ringbuf_space(pair->output_head, pair->output_tail, PTY_BUF_SIZE) == 0)
			break; /* output_buf full; partial write */
		ringbuf_push(pair->output_buf, &pair->output_head, (uint8_t)buf[i], PTY_BUF_SIZE);
	}
	spin_unlock_irqrestore(&pair->lock, fl);

	/* Deposited data — wake the master end (blocked master reader via
	 * wait_event AND sys_poll waiters; one unified waitq).  The woken
	 * reader re-validates the ring under pair->lock in its retry loop, so
	 * it observes the freshly written bytes — no lost wakeup. */
	if (i > 0)
		waitq_wake_all(&pair->master_waiters);
	return (int)i;
}

/*
 * pty_slave_read_raw -- called by tty_read to get one raw character
 * from the master's input.  Blocks via wait_event on slave_waiters until
 * data available, master closes (hangup), or a signal interrupts.
 * Woken by master_write_fn / master_close_fn (waitq_wake_all(slave_waiters)).
 *
 * Returns 1 on success (char in *out), 0 if interrupted, -5 on hangup.
 */
static int
pty_slave_read_raw(tty_t *tty, char *out, int *interrupted)
{
	pty_pair_t *pair = (pty_pair_t *)tty->ctx;
	*interrupted = 0;

	/*
	 * Blocking raw read.  The authoritative data/hangup/signal checks run
	 * under pair->lock at the top of the loop; the block itself goes through
	 * wait_event_interruptible on slave_waiters (the same queue sys_poll and
	 * master_write_fn / master_close_fn use), with the lock dropped first —
	 * wait_event's condition is a lockless hint, re-validated authoritatively
	 * under pair->lock here.  The lock is fully released before returning,
	 * because tty_read calls back into pty_slave_write_out (echo) after we
	 * return and that path also needs pair->lock — holding it across the
	 * return would self-deadlock the non-recursive ticket lock.
	 */
	for (;;) {
		irqflags_t fl = spin_lock_irqsave(&pair->lock);

		/* Data available? */
		if (ringbuf_count(pair->input_head, pair->input_tail, PTY_BUF_SIZE) > 0) {
			*out = (char)ringbuf_pull(pair->input_buf,
			    &pair->input_tail, PTY_BUF_SIZE);
			spin_unlock_irqrestore(&pair->lock, fl);
			return 1;
		}
		/* Master closed -- hangup */
		if (!pair->master_open) {
			spin_unlock_irqrestore(&pair->lock, fl);
			return -5; /* EIO */
		}
		/* Check for pending signals before blocking */
		if (signal_check_pending()) {
			spin_unlock_irqrestore(&pair->lock, fl);
			*interrupted = 1;
			return 0;
		}
		/* Block until the master writes data or closes.  Drop the lock
		 * first; wait_event re-validates the condition lockless and the
		 * loop re-checks authoritatively under pair->lock above.  A
		 * signal sets rc=-4: report it as an interrupt (matches the
		 * pre-block signal check). */
		spin_unlock_irqrestore(&pair->lock, fl);
		int rc;
		wait_event_interruptible(&pair->slave_waiters,
		    ringbuf_count(pair->input_head, pair->input_tail, PTY_BUF_SIZE) > 0
		    || !pair->master_open, rc);
		if (rc == -4) {
			*interrupted = 1;
			return 0;
		}
		/* Resumes here; loop re-checks authoritatively under lock. */
	}
}

/* pty_slave_poll_raw -- non-blocking single-char poll from the master's
 * input ring buffer.  Returns 1 if a character was available (stored in
 * *out), 0 if the buffer is empty.  Used when VMIN=0. */
static int
pty_slave_poll_raw(tty_t *tty, char *out)
{
	pty_pair_t *pair = (pty_pair_t *)tty->ctx;
	int got = 0;
	/* Hold pair->lock across the count check and the pull so the ring
	 * indices are not raced against a concurrent master_write_fn. */
	irqflags_t fl = spin_lock_irqsave(&pair->lock);
	if (ringbuf_count(pair->input_head, pair->input_tail, PTY_BUF_SIZE) > 0) {
		*out = (char)ringbuf_pull(pair->input_buf, &pair->input_tail, PTY_BUF_SIZE);
		got = 1;
	}
	spin_unlock_irqrestore(&pair->lock, fl);
	return got;
}

/* ── Controlling terminal helper ──────────────────────────────────── */

/*
 * try_acquire_ctty_locked -- if the current process is a session leader
 * with no controlling terminal (sid == pid && no tty has this session_id),
 * claim this PTY's tty as the controlling terminal.
 *
 * CALLER MUST HOLD pty_pool_lock.  This function scans the PTY pool
 * directly instead of calling tty_find_controlling (which would call
 * pty_find_by_session, which would attempt to re-acquire pty_pool_lock
 * and deadlock).  Bug discovered 2026-04-09: sys_spawn creates a new
 * session leader, which is precisely when this code path was exercised —
 * so the deadlock only manifested when callers switched from fork+execve
 * (session inherited, sid != pid, early return) to sys_spawn.
 */
static void
try_acquire_ctty_locked(pty_pair_t *pair)
{
	aegis_task_t *t = sched_current();
	aegis_process_t *proc;
	uint32_t j;

	if (!t || !t->is_user)
		return;
	proc = (aegis_process_t *)t;
	/* Only session leaders acquire a ctty */
	if (proc->sid != proc->pid)
		return;
	/* Check the console TTY (singleton, no separate lock).  If the
	 * caller's session already owns the console, don't take a PTY too. */
	{
		tty_t *console = tty_console();
		if (console && console->session_id == proc->sid)
			return;
	}
	/* Inline PTY pool scan — we already hold pty_pool_lock, so we
	 * must NOT call pty_find_by_session (which re-acquires it). */
	for (j = 0; j < PTY_MAX_PAIRS; j++) {
		if (s_pty_pool[j].in_use &&
		    s_pty_pool[j].tty.session_id == proc->sid)
			return;   /* session already has a PTY ctty */
	}
	pair->tty.session_id = proc->sid;
	pair->tty.fg_pgrp = proc->pgid;
}

/* ── Master VFS ops ───────────────────────────────────────────────── */

/*
 * master_read_fn -- read from the output_buf (what the slave wrote).
 * buf is a kernel buffer (kbuf from sys_read). Blocks via wait_event on
 * master_waiters until data available or slave closes.  Woken by
 * pty_slave_write_out / slave_close_fn (waitq_wake_all(master_waiters)).
 * Respects vfs_read_nonblock (O_NONBLOCK): returns -EAGAIN immediately.
 */
static int
master_read_fn(void *priv, void *buf, uint64_t off, uint64_t len)
{
	pty_pair_t *pair = (pty_pair_t *)priv;
	uint32_t n = 0;
	(void)off;

	if (len == 0)
		return 0;

	/*
	 * Blocking read.  The authoritative data/EOF/EAGAIN/signal checks and
	 * all copy-out run under pair->lock at the top of the loop (so the ring
	 * indices are never raced); the block itself goes through
	 * wait_event_interruptible on master_waiters — the same queue sys_poll
	 * and pty_slave_write_out / slave_close_fn use — with the lock dropped
	 * first.  wait_event's condition is a lockless hint, re-validated
	 * authoritatively under pair->lock here.
	 */
	for (;;) {
		irqflags_t fl = spin_lock_irqsave(&pair->lock);

		uint32_t avail = ringbuf_count(pair->output_head, pair->output_tail, PTY_BUF_SIZE);
		if (avail > 0) {
			/* Copy out as much as requested or available. */
			uint32_t want = (uint32_t)len;
			if (want > avail)
				want = avail;
			for (n = 0; n < want; n++)
				((char *)buf)[n] = (char)ringbuf_pull(
				    pair->output_buf, &pair->output_tail, PTY_BUF_SIZE);
			spin_unlock_irqrestore(&pair->lock, fl);
			return (int)n;
		}
		/* Slave closed and buffer empty -- EOF */
		if (!pair->slave_open) {
			spin_unlock_irqrestore(&pair->lock, fl);
			return 0;
		}
		/* O_NONBLOCK: return -EAGAIN instead of blocking.
		 * Use per-task flag (safe under preemption) rather than
		 * the global vfs_read_nonblock which can be clobbered. */
		if (sched_current()->read_nonblock) {
			spin_unlock_irqrestore(&pair->lock, fl);
			return -11; /* EAGAIN */
		}
		/* Check for pending signals */
		if (signal_check_pending()) {
			spin_unlock_irqrestore(&pair->lock, fl);
			return -4; /* EINTR */
		}
		/* Block until the slave writes data or closes.  Drop the lock
		 * first; wait_event re-validates lockless and the loop re-checks
		 * authoritatively under pair->lock above.  A signal sets rc=-4 →
		 * EINTR (matches the pre-block signal check). */
		spin_unlock_irqrestore(&pair->lock, fl);
		int rc;
		wait_event_interruptible(&pair->master_waiters,
		    ringbuf_count(pair->output_head, pair->output_tail, PTY_BUF_SIZE) > 0
		    || !pair->slave_open, rc);
		if (rc == -4)
			return -4; /* EINTR */
		/* Resumes here; loop re-checks authoritatively under lock. */
	}
}

/*
 * master_write_fn -- push bytes into input_buf for the slave to read.
 * buf is a USER pointer -- must use copy_from_user.
 * Page-boundary clamping like console_write_fn.
 */
static int
master_write_fn(void *priv, const void *buf, uint64_t len)
{
	pty_pair_t *pair = (pty_pair_t *)priv;
	char kbuf[256];
	uint64_t n;
	uint32_t i;

	if (!pair->slave_open)
		return -5; /* EIO */

	n = (len > 256) ? 256 : len;
	/* Page-boundary clamp */
	{
		uint64_t page_off = (uint64_t)(uintptr_t)buf & 0xFFFULL;
		uint64_t to_end   = 0x1000ULL - page_off;
		if (n > to_end)
			n = to_end;
	}
	copy_from_user(kbuf, buf, n);

	/*
	 * tty_receive_isig MUST be called WITHOUT pair->lock held: it calls
	 * signal_send_pgrp, which takes sched_lock, and the canonical ordering
	 * is sched_lock > (all others) (its own doc-comment also forbids
	 * callers holding ring locks).  So ISIG runs unlocked; only the ring
	 * push runs under pair->lock, and the wake is deferred until after the
	 * lock is dropped (see pty_slave_write_out for the same producer
	 * pattern / lost-wakeup rationale).
	 *
	 * Byte ordering is preserved: signal characters are consumed (never
	 * buffered), so pre-filtering them out before taking the lock does not
	 * reorder the bytes that actually reach the input ring.  Consumed
	 * signal chars still count as written (matches prior semantics), and a
	 * full ring still stops the count early.
	 */
	{
		irqflags_t fl;

		for (i = 0; i < (uint32_t)n; i++) {
			/* Receive-time ISIG: ^C from the terminal emulator
			 * signals the slave's foreground pgrp immediately, even
			 * if the foreground process never reads the tty.
			 * Consumed bytes are not buffered but still count as
			 * written. */
			if (tty_receive_isig(&pair->tty, kbuf[i]))
				continue;
			fl = spin_lock_irqsave(&pair->lock);
			if (ringbuf_space(pair->input_head, pair->input_tail, PTY_BUF_SIZE) == 0) {
				spin_unlock_irqrestore(&pair->lock, fl);
				break; /* input_buf full; partial write */
			}
			ringbuf_push(pair->input_buf, &pair->input_head,
			    (uint8_t)kbuf[i], PTY_BUF_SIZE);
			spin_unlock_irqrestore(&pair->lock, fl);
		}

		/* Deposited data — wake the slave end (blocked slave reader via
		 * wait_event AND sys_poll waiters; one unified waitq), AFTER the
		 * lock is dropped (sched_lock > pair->lock).  The woken reader
		 * re-validates the ring under pair->lock, so it observes the
		 * freshly written bytes — no lost wakeup. */
		if (i > 0)
			waitq_wake_all(&pair->slave_waiters);
	}
	return (int)i;
}

static void
master_dup_fn(void *priv)
{
	pty_pair_t *pair = (pty_pair_t *)priv;
	irqflags_t fl = spin_lock_irqsave(&pair->lock);
	refcount_inc(&pair->master_refs);
	spin_unlock_irqrestore(&pair->lock, fl);
}

static void
master_close_fn(void *priv)
{
	pty_pair_t *pair = (pty_pair_t *)priv;
	irqflags_t fl = spin_lock_irqsave(&pair->lock);
	if (!refcount_dec_and_test(&pair->master_refs)) {
		spin_unlock_irqrestore(&pair->lock, fl);
		return;
	}
	pair->master_open = 0;
	if (!pair->slave_open)
		pair->in_use = 0;
	spin_unlock_irqrestore(&pair->lock, fl);

	/* Wakes happen AFTER dropping pair->lock: waitq_wake_all takes
	 * sched_lock, and sched_lock > (all others).  Same deferred-wake
	 * discipline as the read/write paths.  Wake both ends (one unified
	 * waitq per end for blocking I/O + sys_poll): the blocked slave reader
	 * on slave_waiters sees master_open==0 and returns EIO; pollers on both
	 * ends see HUP / EOF. */
	waitq_wake_all(&pair->master_waiters);
	waitq_wake_all(&pair->slave_waiters);
}

static int
master_stat_fn(void *priv, k_stat_t *st)
{
	pty_pair_t *pair = (pty_pair_t *)priv;
	__builtin_memset(st, 0, sizeof(*st));
	st->st_mode  = S_IFCHR | 0600;
	st->st_ino   = 100 + pair->index * 2;
	st->st_rdev  = makedev(5, 2); /* /dev/ptmx: major=5 minor=2 */
	st->st_dev   = 1;
	st->st_nlink = 1;
	return 0;
}

/* ── Slave VFS ops ────────────────────────────────────────────────── */

/*
 * slave_read_fn -- delegates to tty_read which handles cooked/raw mode,
 * echo, signal generation, etc.  buf is a kernel buffer.
 */
static int
slave_read_fn(void *priv, void *buf, uint64_t off, uint64_t len)
{
	pty_pair_t *pair = (pty_pair_t *)priv;
	(void)off;
	if (len == 0)
		return 0;
	return tty_read(&pair->tty, (char *)buf, (uint32_t)len);
}

/*
 * slave_write_fn -- copies from user buffer, then delegates to tty_write
 * which handles OPOST/ONLCR output processing and calls pty_slave_write_out.
 * buf is a USER pointer.
 */
static int
slave_write_fn(void *priv, const void *buf, uint64_t len)
{
	pty_pair_t *pair = (pty_pair_t *)priv;
	char kbuf[256];
	uint64_t n;

	if (!pair->master_open)
		return -5; /* EIO */

	n = (len > 256) ? 256 : len;
	/* Page-boundary clamp */
	{
		uint64_t page_off = (uint64_t)(uintptr_t)buf & 0xFFFULL;
		uint64_t to_end   = 0x1000ULL - page_off;
		if (n > to_end)
			n = to_end;
	}
	copy_from_user(kbuf, buf, n);
	return tty_write(&pair->tty, kbuf, (uint32_t)n);
}

static void
slave_dup_fn(void *priv)
{
	pty_pair_t *pair = (pty_pair_t *)priv;
	irqflags_t fl = spin_lock_irqsave(&pair->lock);
	refcount_inc(&pair->slave_refs);
	spin_unlock_irqrestore(&pair->lock, fl);
}

static void
slave_close_fn(void *priv)
{
	pty_pair_t *pair = (pty_pair_t *)priv;
	irqflags_t fl = spin_lock_irqsave(&pair->lock);
	if (!refcount_dec_and_test(&pair->slave_refs)) {
		spin_unlock_irqrestore(&pair->lock, fl);
		return;
	}
	pair->slave_open = 0;
	if (!pair->master_open)
		pair->in_use = 0;
	spin_unlock_irqrestore(&pair->lock, fl);

	/* Wakes happen AFTER dropping pair->lock (sched_lock > all others);
	 * same deferred-wake discipline as the read/write paths.  Wake both
	 * ends (one unified waitq per end for blocking I/O + sys_poll): the
	 * blocked master reader on master_waiters sees slave_open==0 and returns
	 * EOF; pollers on both ends see HUP / EOF. */
	waitq_wake_all(&pair->master_waiters);
	waitq_wake_all(&pair->slave_waiters);
}

static int
slave_stat_fn(void *priv, k_stat_t *st)
{
	pty_pair_t *pair = (pty_pair_t *)priv;
	__builtin_memset(st, 0, sizeof(*st));
	st->st_mode  = S_IFCHR | 0620;
	st->st_ino   = 100 + pair->index * 2 + 1;
	st->st_rdev  = makedev(136, pair->index); /* /dev/pts/N: major=136 */
	st->st_dev   = 1;
	st->st_nlink = 1;
	return 0;
}

/* ── Public API ───────────────────────────────────────────────────── */

int
ptmx_open(int flags, vfs_file_t *out)
{
	uint32_t i;
	(void)flags;

	irqflags_t fl = spin_lock_irqsave(&pty_pool_lock);
	for (i = 0; i < PTY_MAX_PAIRS; i++) {
		if (!s_pty_pool[i].in_use)
			break;
	}
	if (i == PTY_MAX_PAIRS) {
		spin_unlock_irqrestore(&pty_pool_lock, fl);
		return -12; /* ENOMEM */
	}

	pty_pair_t *pair = &s_pty_pool[i];
	__builtin_memset(pair, 0, sizeof(*pair));
	pair->index = (uint8_t)i;
	pair->in_use = 1;
	pair->master_open = 1;
	refcount_init(&pair->master_refs, 1);
	pair->locked = 1; /* cleared by unlockpt (grantpt/unlockpt ioctl) */
	{
		spinlock_t init = SPINLOCK_INIT;
		pair->lock = init;
	}
	waitq_init(&pair->master_waiters);
	waitq_init(&pair->slave_waiters);

	tty_init_defaults(&pair->tty);
	pair->tty.write_out = pty_slave_write_out;
	pair->tty.read_raw  = pty_slave_read_raw;
	pair->tty.poll_raw  = pty_slave_poll_raw;
	pair->tty.ctx       = pair;

	/* POSIX: opening the PTY *master* never acquires a controlling
	 * terminal — only the slave does.  The previous master-side acquire
	 * was a latent bug, harmless only while the opener (Lumen) already
	 * owned a ctty (the console) and therefore early-returned.  When
	 * /bin/terminal — a fresh sys_spawn session leader with no ctty —
	 * began opening /dev/ptmx, the acquire fired and stole fg_pgrp from
	 * the shell it was about to spawn, so the shell's first read got
	 * SIGTTIN and stopped.  Master open must not touch the ctty. */
	spin_unlock_irqrestore(&pty_pool_lock, fl);

	out->ops    = &s_master_ops;
	out->priv   = pair;
	out->offset = 0;
	out->size   = 0;
	out->flags  = 2; /* O_RDWR */
	out->kflags = 0;
	return 0;
}

int
pts_open(uint32_t index, int flags, vfs_file_t *out)
{
	(void)flags;

	if (index >= PTY_MAX_PAIRS)
		return -2; /* ENOENT */

	irqflags_t fl = spin_lock_irqsave(&pty_pool_lock);
	pty_pair_t *pair = &s_pty_pool[index];
	if (!pair->in_use || !pair->master_open) {
		spin_unlock_irqrestore(&pty_pool_lock, fl);
		return -2; /* ENOENT */
	}
	if (pair->locked) {
		spin_unlock_irqrestore(&pty_pool_lock, fl);
		return -13; /* EACCES */
	}

	/* A fresh first open inits the refcount to 1; a SECOND open of an
	 * already-open slave (open("/dev/pts/N") twice — each path open re-enters
	 * pts_open, unlike dup which goes through slave_dup_fn) must BUMP the
	 * existing count, not reset it to 1. Resetting dropped the first opener's
	 * reference: closing one fd then tore the pair down under the surviving fd
	 * (refcount underflow → use-after-free + premature free). */
	if (pair->slave_open) {
		refcount_inc(&pair->slave_refs);
	} else {
		pair->slave_open = 1;
		refcount_init(&pair->slave_refs, 1);
	}
	/* O_NOCTTY (0400): caller does not want this slave to become its
	 * controlling terminal.  A terminal emulator opens the slave only to
	 * hand it to the child shell as stdio; the *shell*, not the emulator,
	 * should own the ctty and the foreground pgrp.  Without this, a
	 * session-leader emulator (e.g. /bin/terminal) grabs fg_pgrp and the
	 * shell's reads stop on SIGTTIN. */
	if (!(flags & 0400))
		try_acquire_ctty_locked(pair);
	spin_unlock_irqrestore(&pty_pool_lock, fl);

	out->ops    = &s_slave_ops;
	out->priv   = pair;
	out->offset = 0;
	out->size   = 0;
	out->flags  = 2; /* O_RDWR */
	out->kflags = 0;
	return 0;
}

tty_t *
pty_find_by_session(uint32_t session_id)
{
	irqflags_t fl = spin_lock_irqsave(&pty_pool_lock);
	uint32_t i;
	for (i = 0; i < PTY_MAX_PAIRS; i++) {
		if (s_pty_pool[i].in_use &&
		    s_pty_pool[i].tty.session_id == session_id) {
			tty_t *t = &s_pty_pool[i].tty;
			spin_unlock_irqrestore(&pty_pool_lock, fl);
			return t;
		}
	}
	spin_unlock_irqrestore(&pty_pool_lock, fl);
	return (tty_t *)0;
}

int
pty_is_master(const vfs_file_t *f)
{
	return f->ops == &s_master_ops;
}

int
pty_is_slave(const vfs_file_t *f)
{
	return f->ops == &s_slave_ops;
}

tty_t *
pty_get_tty(const vfs_file_t *f)
{
	if (f->ops == &s_slave_ops) {
		pty_pair_t *pair = (pty_pair_t *)f->priv;
		return &pair->tty;
	}
	return (tty_t *)0;
}
