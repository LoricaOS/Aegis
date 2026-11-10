/* Production-code regression. See fb_console_test.py for the executable runner.
 * Include fb.c, not a duplicate implementation: test private state invariants
 * and emergency rendering while the actual terminal lock is held. */
#include <assert.h>
#include <pthread.h>
#include <sched.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

/* Exercise x86 panic rendering even on arm64 hosts. All system headers above
 * have already selected the HOST ABI; only the kernel code sees this define. */
#ifndef __x86_64__
#define __x86_64__ 1
#endif
#include "../kernel/drivers/fb.c"

typedef struct {
    unsigned char *mapping, *data;
    size_t mapped, prefix, bytes;
} guarded_t;

static guarded_t hardware, shadow;
static arch_fb_info_t mock_info;
static int mock_shadow_failure, mock_map_calls, mock_alloc_calls;
static _Thread_local unsigned long irq_disabled;
static jmp_buf halt_target;
static int expect_halt, panic_signals;

static guarded_t
guarded_alloc(size_t bytes)
{
    size_t page = (size_t)sysconf(_SC_PAGESIZE);
    size_t usable = ((bytes + 64 + page - 1) / page) * page;
    size_t mapped = usable + 2 * page;
    unsigned char *p = mmap(NULL, mapped, PROT_NONE,
                           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    assert(p != MAP_FAILED);
    assert(!mprotect(p + page, usable, PROT_READ | PROT_WRITE));
    memset(p + page, 0xA5, usable);
    /* The exact end, not just the page-rounded KVA end, hits PROT_NONE.
     * Underflow is detected by the prefix canary (at least 64 bytes). */
    return (guarded_t){p, p + page + usable - bytes, mapped,
                       page + usable - bytes, bytes};
}

static void
guarded_check(guarded_t *g)
{
    if (!g->mapping) return;
    size_t page = (size_t)sysconf(_SC_PAGESIZE);
    for (size_t i = page; i < g->prefix; i++)
        assert(g->mapping[i] == 0xA5);
}

static void
teardown(void)
{
    guarded_check(&hardware);
    guarded_check(&shadow);
    if (hardware.mapping) assert(!munmap(hardware.mapping, hardware.mapped));
    if (shadow.mapping) assert(!munmap(shadow.mapping, shadow.mapped));
    hardware = shadow = (guarded_t){0};
}

int arch_get_fb_info(arch_fb_info_t *info) { *info = mock_info; return 1; }
unsigned long arch_irq_save(void)
{
    unsigned long old = irq_disabled;
    irq_disabled = 1;
    /* Widen scheduling opportunities immediately before taking the real
     * production ticket lock. This is not a mutex substituted for the lock. */
    sched_yield();
    return old;
}
void arch_irq_restore(unsigned long old) { irq_disabled = old; }
void arch_disable_irq(void) { irq_disabled = 1; }
void arch_pause(void) { sched_yield(); }
void arch_halt(void)
{
    assert(expect_halt && irq_disabled);
    longjmp(halt_target, 1);
}
void serial_write_string(const char *s) { (void)s; }
void printk(const char *fmt, ...) { (void)fmt; }
void pvpanic_signal_panic(void) { panic_signals++; }
const pcie_device_t *pcie_find_device(uint8_t c, uint8_t s, uint8_t p)
{
    (void)c; (void)s; (void)p;
    return NULL;
}
void *kva_map_mmio(uint64_t phys, uint32_t pages)
{
    assert(!irq_disabled); /* no allocator/hardware mapping under text lock */
    assert(phys == mock_info.addr);
    size_t bytes = (size_t)mock_info.pitch * mock_info.height;
    assert(pages == (bytes + 4095) / 4096);
    mock_map_calls++;
    hardware = guarded_alloc(bytes);
    return hardware.data;
}
void *kva_alloc_pages(uint64_t pages)
{
    assert(!irq_disabled);
    size_t bytes = (size_t)mock_info.pitch * mock_info.height;
    assert(pages == (bytes + 4095) / 4096);
    mock_alloc_calls++;
    if (mock_shadow_failure) return NULL;
    shadow = guarded_alloc(bytes);
    return shadow.data;
}

static void
setup(uint32_t width, uint32_t height, uint32_t pitch, int no_shadow)
{
    teardown();
    /* Production init is boot-only. Reset the TU explicitly between simulated
     * boots rather than adding a test-only reset API to the shipped driver. */
    fb_available = s_fb_locked = s_panic_active = s_cursor_drawn = 0;
    s_fb_va = NULL;
    s_shadow = NULL;
    s_cols = s_rows = s_col = s_row = s_pitch_px = 0;
    s_fb_pixels = s_fb_phys = 0;
    s_fb_width = s_fb_height = s_fb_pitch = 0;
    s_esc_state = s_esc_len = s_esc_overflow = 0;
    s_text_lock = (spinlock_t)SPINLOCK_INIT;
    irq_disabled = 0;
    mock_shadow_failure = no_shadow;
    mock_map_calls = mock_alloc_calls = 0;
    mock_info = (arch_fb_info_t){0xE0000000u, pitch, width, height, 32, 1};
    fb_init();
}

static void
invariant(void)
{
    assert(!irq_disabled);
    assert(s_text_lock.next == s_text_lock.owner);
    if (s_cols && s_rows) {
        uint64_t base;
        assert(s_row < s_rows && s_col < s_cols);
        assert(_fb_cell_base(s_row, s_col, &base));
    }
    assert(s_esc_len >= 0 && s_esc_len < (int)sizeof(s_esc_buf));
    guarded_check(&hardware);
    guarded_check(&shadow);
}

static void
write_checked(const char *s)
{
    while (*s) {
        fb_putchar(*s++);
        invariant();
    }
}

static void
text_margins(void)
{
    /* Sub-cell width/height remainders and pitch padding are not text cells. */
    for (uint32_t y = 0; y < s_fb_height; y++)
        for (uint32_t x = 0; x < s_pitch_px; x++)
            if (y >= s_rows * 16u || x >= s_cols * 8u) {
                assert(s_fb_va[y * s_pitch_px + x] == 0);
                if (s_shadow)
                    assert(s_shadow[y * s_pitch_px + x] == 0);
            }
}

static void
control_cases(void)
{
    setup(80, 48, 352, 0); /* 10x3 text cells; 8 padding pixels/scanline */
    assert(fb_available && s_cols == 10 && s_rows == 3 && s_shadow);
    write_checked("\033[3;10H");
    assert(s_row == 2 && s_col == 9);
    write_checked("X"); /* bottom-right wrap must scroll atomically */
    assert(s_row == 2 && s_col == 0);
    write_checked("\n\r\b");
    assert(s_row == 2 && s_col == 0);
    write_checked("\t");
    assert(s_row == 2 && s_col == 8);
    write_checked("\033[C\033[C");
    assert(s_col == 9);
    write_checked("\033[999999999999999C");
    assert(s_col == 9); /* saturate, not overflow */
    write_checked("\033[4294967296D");
    assert(s_col == 0); /* would wrap to zero, then default to one */
    write_checked("\033[999999;999999H");
    assert(s_col == 9 && s_row == 2);
    write_checked("\033[0;0f");
    assert(s_col == 0 && s_row == 0);
    write_checked("\033[2;3H\033[K\033[0K\033[2K");
    assert(s_row == 1 && s_col == 2);
    write_checked("\033[1;2;3H\033[1;2C\033[;D");
    assert(s_row == 1 && s_col == 2); /* malformed sequences do not move */
    write_checked("\033[000000000000000000009H");
    assert(s_row == 1 && s_col == 2); /* overlong sequence discarded */
    write_checked("\033[999\033[H");
    assert(s_row == 0 && s_col == 0); /* ESC restarts a partial sequence */
    write_checked("\033[999\030X\033[999\032Y");
    assert(s_row == 0 && s_col == 2);
    write_checked("\033[2J");
    assert(s_row == 0 && s_col == 0);
    static const char nonprinting[] = {0, 1, 7, 127};
    for (unsigned i = 0; i < sizeof(nonprinting); i++) {
        fb_putchar(nonprinting[i]);
        invariant();
    }
    assert(s_row == 0 && s_col == 0);
    for (unsigned i = 0; i < 2000; i++)
        fb_putchar((char)(i * 17)); /* arbitrary bytes, including C0/CSI */
    invariant();

    /* Directly probe defense-in-depth bounds, independent of cursor locking.
     * Before the fix, row==s_rows writes into the trailing guard page. */
    _fb_draw_char(s_rows, 0, 'X');
    _fb_draw_char(0, s_cols, 'X');
    _fb_draw_char(UINT32_MAX, UINT32_MAX, 'X');
    invariant();
    _fb_erase_cursor();
    uint32_t row = s_row, col = s_col;
    s_row = s_rows;
    _fb_draw_cursor();
    assert(!s_cursor_drawn);
    s_cursor_drawn = 1; /* stale cursor at an invalid cell is safe to erase */
    _fb_erase_cursor();
    assert(!s_cursor_drawn);
    s_row = row;
    s_col = col;
    _fb_draw_cursor();
    invariant();
    assert(!memcmp(hardware.data, shadow.data, hardware.bytes));

    /* No normal text/scroll operation may touch pitch padding. */
    for (uint32_t y = 0; y < s_fb_height; y++)
        for (uint32_t x = s_fb_width; x < s_pitch_px; x++)
            assert(s_shadow[y * s_pitch_px + x] == 0);
}

static void
geometry_cases(void)
{
    static const uint32_t cases[][3] = {
        {1, 1, 4}, {7, 15, 32}, {8, 15, 32}, {7, 16, 32},
        {8, 16, 32}, {9, 17, 48}, {81, 49, 352}, {1280, 800, 5120},
    };
    for (unsigned k = 0; k < sizeof(cases) / sizeof(cases[0]); k++)
        for (int fallback = 0; fallback < 2; fallback++) {
            setup(cases[k][0], cases[k][1], cases[k][2], fallback);
            assert(fb_available);
            assert(mock_map_calls == 1 && mock_alloc_calls == 1);
            write_checked("\033[999;999H\b\t\r\n\033[2J\033[H\033[K");
            for (unsigned i = 0; i < 4000; i++)
                fb_putchar((i % 17) ? 'A' : '\n');
            invariant();
            text_margins();
            if (!s_cols || !s_rows)
                assert(!s_col && !s_row && !s_cursor_drawn);
            if (s_rows == 1)
                assert(s_row == 0);
        }
    static const uint32_t invalid[][3] = {
        {0, 1, 4}, {1, 0, 4}, {9, 1, 32}, {1, 1, 5},
        {FB_MAX_WIDTH + 1, 16, FB_MAX_PITCH},
        {8, FB_MAX_HEIGHT + 1, 32}, {8, 16, FB_MAX_PITCH + 4},
    };
    for (unsigned k = 0; k < sizeof(invalid) / sizeof(invalid[0]); k++) {
        setup(invalid[k][0], invalid[k][1], invalid[k][2], 0);
        assert(!fb_available && !mock_map_calls && !mock_alloc_calls);
        write_checked("\033[H\nX\t");
        fb_heartbeat();
        invariant();
    }
}

static void *
one_echo(void *unused)
{
    (void)unused;
    fb_putchar('u');
    return NULL;
}

static void
bottom_row_interleaving(void)
{
    setup(1280, 800, 5120, 0);
    pthread_t echo;
    irqflags_t flags = spin_lock_irqsave(&s_text_lock);
    /* Pause the log writer precisely between bottom-row newline and scroll.
     * The real echo API must queue on the lock, not draw at row 50. */
    s_row = s_rows;
    s_col = 0;
    assert(!pthread_create(&echo, NULL, one_echo, NULL));
    unsigned spins = 0;
    while (__atomic_load_n(&s_text_lock.next, __ATOMIC_ACQUIRE) ==
           (uint16_t)(s_text_lock.owner + 1)) {
        assert(++spins < 1000000);
        sched_yield();
    }
    assert(s_row == s_rows && s_col == 0);
    _fb_scroll();
    spin_unlock_irqrestore(&s_text_lock, flags);
    assert(!pthread_join(echo, NULL));
    invariant();
    assert(s_row == s_rows - 1 && s_col == 1);
}

static void *
letters(void *unused)
{
    (void)unused;
    for (unsigned i = 0; i < 6000; i++)
        if (i & 1) fb_write_string("X");
        else fb_putchar('Y');
    assert(!irq_disabled);
    return NULL;
}

static void *
controls(void *id)
{
    static const char *streams[] = {
        "username\b \b\n", "[EXT2] sync: 42 blocks\n",
        "\033[999;999H\t\033[K\033[2J", "\033[4294967296D\r\n",
    };
    const char *s = streams[(uintptr_t)id];
    for (unsigned i = 0; i < 2000; i++)
        fb_write_string(s);
    return NULL;
}

static void
concurrency_cases(void)
{
    pthread_t threads[4];
    for (int fallback = 0; fallback < 2; fallback++) {
        setup(104, 48, 448, fallback);
        for (unsigned i = 0; i < 4; i++)
            assert(!pthread_create(&threads[i], NULL, letters, NULL));
        for (unsigned i = 0; i < 4; i++)
            assert(!pthread_join(threads[i], NULL));
        invariant();
        assert(s_col == 24000 % s_cols && s_row == s_rows - 1);
        for (uintptr_t i = 0; i < 4; i++)
            assert(!pthread_create(&threads[i], NULL, controls, (void *)i));
        for (unsigned i = 0; i < 4; i++)
            assert(!pthread_join(threads[i], NULL));
        invariant();
        if (s_shadow)
            assert(!memcmp(hardware.data, shadow.data, hardware.bytes));
    }
}

static void
takeover_and_panic_cases(void)
{
    /* Tiny displays must clip panic font/layout instead of writing off-screen.
     * Simulate faults from INSIDE the normal lock: emergency rendering must
     * complete without trying to acquire that same lock. */
    for (unsigned variant = 0; variant < 3; variant++) {
        setup(9, 17, 48, variant == 1);
        write_checked("A");
        fb_boot_splash();
        invariant();
        fb_lock_compositor();
        unsigned char saved[48 * 17];
        memcpy(saved, hardware.data, sizeof(saved));
        fb_write_string("X\n\033[2J");
        fb_heartbeat();
        fb_boot_splash();
        assert(!memcmp(saved, hardware.data, sizeof(saved)));
        irqflags_t flags = spin_lock_irqsave(&s_text_lock);
        expect_halt = 1;
        if (!setjmp(halt_target)) {
            if (variant == 0)
                panic_halt("long panic message\nsecond line\nthird line");
            else
                panic_bluescreen(14, 0, 2, UINT64_MAX, 0, 0, 0, 0);
            abort();
        }
        assert(s_panic_active && panic_signals == (int)variant + 1);
        assert(s_text_lock.owner != s_text_lock.next);
        expect_halt = 0;
        spin_unlock_irqrestore(&s_text_lock, flags);
        invariant();
        _panic_draw_char(UINT32_MAX, UINT32_MAX, 'X', FB_FG);
        _panic_draw_char(8, 16, 'X', FB_FG); /* bottom/right clipping */
        invariant();
    }
}

int
main(void)
{
    /* Before init must be a safe no-op. */
    fb_putchar('X');
    fb_write_string("before init");
    fb_heartbeat();
    control_cases();
    geometry_cases();
    bottom_row_interleaving();
    concurrency_cases();
    takeover_and_panic_cases();
    teardown();
    puts("fb-console: guarded geometry/control/concurrency/panic cases PASS");
    return 0;
}
