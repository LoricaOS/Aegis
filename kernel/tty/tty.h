#ifndef AEGIS_TTY_H
#define AEGIS_TTY_H

#include <stdint.h>

/* ── termios flag constants ──────────────────────────────────────── */

/* c_iflag bits */
#define K_ICRNL   0000400   /* map CR to NL on input */

/* c_oflag bits */
#define K_OPOST   0000001   /* enable output processing */
#define K_ONLCR   0000004   /* map NL to CR-NL on output */

/* c_lflag bits */
#define K_ISIG    0000001   /* enable signals (INTR, QUIT, SUSP) */
#define K_ICANON  0000002   /* canonical (line-buffered) mode */
#define K_ECHO    0000010   /* echo input characters */
#define K_ECHOE   0000020   /* echo ERASE as BS-SP-BS */
#define K_TOSTOP  0000400   /* send SIGTTOU for background output */

/* c_cc indices */
#define K_VINTR    0
#define K_VQUIT    1
#define K_VERASE   2
#define K_VKILL    3
#define K_VEOF     4
#define K_VTIME    5
#define K_VMIN     6
#define K_VSUSP   10

#define K_NCCS    32

/* ── k_termios_t — matches musl struct termios layout ────────────── */

typedef struct {
    uint32_t c_iflag;
    uint32_t c_oflag;
    uint32_t c_cflag;
    uint32_t c_lflag;
    uint8_t  c_line;
    uint8_t  c_cc[K_NCCS];  /* 32 bytes */
    /* 3 bytes natural padding */
    uint32_t c_ispeed;
    uint32_t c_ospeed;
} k_termios_t;  /* 60 bytes */

_Static_assert(sizeof(k_termios_t) == 60,
    "k_termios_t must be 60 bytes (musl struct termios)");

/* ── ioctl command numbers ───────────────────────────────────────── */

#define TCGETS      0x5401
#define TCSETS      0x5402
#define TCSETSW     0x5403
#define TCSETSF     0x5404
#define TIOCSCTTY   0x540E
#define TIOCGPGRP   0x540F
#define TIOCSPGRP   0x5410
#define TIOCGWINSZ  0x5413
#define TIOCSWINSZ  0x5414

/* ── tty_t — shared TTY abstraction ──────────────────────────────── */

typedef struct tty {
    k_termios_t termios;
    uint32_t    fg_pgrp;
    uint32_t    session_id;
    uint16_t    rows, cols;
    char        linebuf[512];
    uint32_t    line_len;
    uint32_t    line_pos;
    uint8_t     line_ready;

    /* Backend callbacks — set by console or PTY driver */
    int  (*write_out)(struct tty *tty, const char *buf, uint32_t len);
    int  (*read_raw)(struct tty *tty, char *out, int *interrupted);
    /* poll_raw — non-blocking single-char read.  Returns 1 and stores
     * the character in *out if available, 0 if no data.  Used when
     * VMIN=0 (non-blocking raw mode).  NULL = not supported. */
    int  (*poll_raw)(struct tty *tty, char *out);
    void *ctx;   /* backend-private data */
} tty_t;

/* Initialize tty with default termios (cooked, echo, signals). */
void tty_init_defaults(tty_t *tty);

/* Register the console tty singleton. Called by console driver at init. */
void tty_set_console(tty_t *tty);

/* Line-discipline read: cooked buffering, signal generation. */
int tty_read(tty_t *tty, char *buf, uint32_t len);

/* Line-discipline write: OPOST/ONLCR output processing. */
int tty_write(tty_t *tty, const char *buf, uint32_t len);

/* Handle ioctl on this tty. arg is user pointer. */
int tty_ioctl(tty_t *tty, uint32_t cmd, uint64_t arg);

/* Return 1 if the current process is in the foreground group. */
int tty_is_fg(tty_t *tty);

/* Return the global console tty (set by console driver at init). */
tty_t *tty_console(void);

/* tty_receive_isig — receive-time VINTR/VQUIT/VSUSP processing.  Returns 1
 * if c was consumed (signal sent to fg pgrp), 0 to buffer it normally.
 * Call where bytes enter a tty's input path, without holding ring locks. */
int tty_receive_isig(tty_t *tty, char c);

/* Find the controlling tty for the current process's session. */
tty_t *tty_find_controlling(uint32_t session_id);

#endif /* AEGIS_TTY_H */
