/* PoC — arithmetic extracted verbatim from the Aegis kernel sources.
 * Proves C1, H9, H1/H3 before the fix; re-run after to see them rejected.
 * cc -O0 -fno-strict-overflow -fwrapv -o poc poc.c && ./poc */
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define USER_ADDR_MAX       0x00007FFFFFFFFFFFUL
#define MM_MAX_RANGE_PAGES  (1UL << 20)

static int fails = 0;
#define CHECK(cond, msg) do { \
    if (cond) printf("  ok   %s\n", msg); \
    else { printf("  FAIL %s\n", msg); fails++; } } while (0)

/* ── C1: fs/ext2.c ext2_read_symlink_target_impl ────────────────────── */
/* Returns the loop-trip count the copy loop would perform. */
static uint64_t c1_tlen(uint32_t i_size, uint32_t bufsiz, int fixed)
{
    uint32_t tlen = i_size;
    if (tlen == 0) return 0;
    if (fixed && bufsiz == 0) return (uint64_t)-1;  /* -EINVAL */
    if (tlen >= bufsiz)
        tlen = bufsiz - 1;                          /* underflows at bufsiz==0 */
    return tlen;
}

/* ── H9: arch/x86_64/vga.c _vga_dispatch_csi ────────────────────────── */
#define VGA_ROWS 25
#define VGA_COLS 80
static int h9_srow(const char *esc, int fixed)
{
    int s_esc_len = (int)strlen(esc);
    if (s_esc_len > 15) s_esc_len = 15;             /* vga.c:128 cap */
    int i = 0;
    if (fixed) {
        /* shipped fix: accumulate UNSIGNED (as drivers/fb.c does) */
        uint32_t row = 0;
        while (i < s_esc_len && esc[i] >= '0' && esc[i] <= '9')
            row = row * 10u + (uint32_t)(esc[i++] - '0');
        if (row > 0) row--;
        return (row < VGA_ROWS) ? (int)row : VGA_ROWS - 1;
    }
    int row = 0;
    while (i < s_esc_len && esc[i] >= '0' && esc[i] <= '9')
        row = row * 10 + (esc[i++] - '0');
    if (row > 0) row--;
    return (row < VGA_ROWS) ? row : VGA_ROWS - 1;
}

/* ── C1 (syscall half): sys_meta.c sys_readlink bufsiz narrowing ────── */
/* Returns the bufsiz handed to the backend, or -1 for EINVAL. */
static long c1_sys_bufsiz(uint64_t arg3, int fixed)
{
    if (fixed) {
        if (arg3 == 0) return -1;                   /* EINVAL */
        return (long)((arg3 > 256UL) ? 256U : (uint32_t)arg3);
    }
    uint32_t bufsiz = (uint32_t)arg3;               /* narrowed BEFORE clamp */
    if (bufsiz > 256U) bufsiz = 256U;
    return (long)bufsiz;
}

/* ── H1/H3: syscall/sys_memory.c sys_mremap grow path ───────────────── */
/* out_trips = pages the unpreemptible scan would walk; ret 0 = accepted. */
static int h1_grow(uint64_t old_addr, uint64_t old_size, uint64_t new_size,
                   int fixed, uint64_t *out_trips)
{
    /* shipped fix: bound the raw args before any rounding */
    if (fixed && (old_addr >= USER_ADDR_MAX ||
                  old_size > USER_ADDR_MAX - old_addr ||
                  new_size > USER_ADDR_MAX - old_addr))
        return -1;                                          /* EINVAL */
    uint64_t osz = (old_size + 4095UL) & ~4095UL;
    uint64_t nsz = (new_size + 4095UL) & ~4095UL;
    if (nsz <= osz) return -1;
    uint64_t ext = old_addr + osz, glen = nsz - osz;
    if (fixed && glen / 4096UL > MM_MAX_RANGE_PAGES)
        return -1;                                          /* EINVAL */
    uint64_t trips = 0;
    for (uint64_t va = ext; va < ext + glen; va += 4096UL) {
        if (++trips > 4000000UL) break;   /* PoC: don't actually run 2^35 */
    }
    *out_trips = trips;
    return 0;
}

static void run(int fixed)
{
    printf("\n=== %s ===\n", fixed ? "AFTER FIX" : "BEFORE FIX (vulnerable)");
    uint64_t t;

    /* C1: stock fast symlink "/bin/sh -> busybox" (i_size=7), bufsiz=0 */
    t = c1_tlen(7, 0, fixed);
    printf("  C1  readlink(bufsiz=0) -> tlen=0x%llx\n", (unsigned long long)t);
    CHECK(t != 0xFFFFFFFFULL, "C1: no uint32 underflow to 0xFFFFFFFF");
    /* C1 regression: normal call must still work */
    CHECK(c1_tlen(7, 256, fixed) == 7, "C1: bufsiz=256 still copies 7 bytes");
    CHECK(c1_tlen(7, 4, fixed) == 3,   "C1: bufsiz=4 still truncates to 3");
    /* C1 syscall half: bufsiz = 2^32 narrows to 0 before the clamp */
    long b = c1_sys_bufsiz(0x100000000ULL, fixed);
    printf("  C1  sys_readlink(bufsiz=2^32) -> backend bufsiz=%ld\n", b);
    CHECK(b != 0, "C1: 2^32 bufsiz does not narrow to 0");
    CHECK(c1_sys_bufsiz(0, fixed) != 0,   "C1: bufsiz=0 rejected at syscall");
    CHECK(c1_sys_bufsiz(64, fixed) == 64, "C1: bufsiz=64 passes through");
    CHECK(c1_sys_bufsiz(9999, fixed) == 256, "C1: large bufsiz clamps to 256");

    /* H9: printf '\033[4294967295H' */
    int r = h9_srow("4294967295", fixed);
    printf("  H9  CSI 4294967295H -> s_row=%d (write at vga[%d])\n",
           r, r * VGA_COLS);
    CHECK(r >= 0, "H9: s_row never negative");
    CHECK(h9_srow("10", fixed) == 9,  "H9: CSI 10H still lands on row 9");
    CHECK(h9_srow("999", fixed) == 24, "H9: CSI 999H still clamps to last row");

    /* H1: mremap(0x10000, 0x1000, 0xFFFFFFFFFFFFE000, MAYMOVE) */
    t = 0;
    int rc = h1_grow(0x10000, 0x1000, 0xFFFFFFFFFFFFE000UL, fixed, &t);
    printf("  H1  mremap(nsz=~2^64) -> %s, scan trips=%llu\n",
           rc ? "EINVAL" : "ACCEPTED", (unsigned long long)t);
    CHECK(rc != 0, "H1: address-space-wrapping grow rejected");

    /* H3: mremap(.., new_size=0x7FFFFFFFFFFF0000) — no wrap, ~2^35 trips */
    t = 0;
    rc = h1_grow(0x10000, 0x1000, 0x7FFFFFFFFFFF0000UL, fixed, &t);
    printf("  H3  mremap(nsz=2^63) -> %s, scan trips=%llu%s\n",
           rc ? "EINVAL" : "ACCEPTED", (unsigned long long)t,
           t > 4000000UL - 1 ? " (capped by PoC)" : "");
    CHECK(rc != 0, "H3: unbounded grow scan rejected");

    /* H1/H3 regression: an ordinary 64 KiB -> 128 KiB grow must still work */
    t = 0;
    rc = h1_grow(0x10000000, 0x10000, 0x20000, fixed, &t);
    CHECK(rc == 0 && t == 16, "H1/H3: ordinary 64K->128K grow still accepted");
}

int main(void)
{
    run(0);
    run(1);
    printf("\n%d check(s) failed\n", fails);
    return 0;
}
