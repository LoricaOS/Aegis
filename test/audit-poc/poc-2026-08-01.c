/* PoC — 2026-08-01 audit. Arithmetic extracted verbatim from the sources.
 * Same convention as the sibling files: a BEFORE-FIX arm with failing checks,
 * an AFTER-FIX arm with none, and companion checks asserting that honest inputs
 * still behave identically in both arms (so a "fix" that simply rejected
 * everything would fail too).
 *
 * cc -O0 -fwrapv -o poc poc-2026-08-01.c && ./poc
 */
#include <stdio.h>
#include <stdint.h>

static int fails = 0;
#define CHECK(cond, msg) do { \
    if (cond) printf("  ok   %s\n", msg); \
    else { printf("  FAIL %s\n", msg); fails++; } } while (0)

/* ── C-4: drivers/virtio_gpu.c — GET_DISPLAY_INFO geometry ─────────────
 * The device answers with width/height. Pre-fix the whole computation was
 * uint32: a geometry whose w*h*4 wraps yields a SMALL page count, which passes
 * the GPU_MAX_FB_PAGES clamp — and because it passes, the clamp never rewrites
 * w/h. The declared geometry is then stored while the allocation is the wrapped
 * size, and the boot test-pattern loop walks h rows of (w*4) bytes over it.
 *
 * Returns bytes actually touched by that loop; *alloc_out = bytes allocated.
 * fb.c's pattern (bound each dimension first, compute the extent in 64-bit) is
 * what the fixed arm implements. */
#define GPU_MAX_FB_PAGES  2160u
#define FB_MAX_WIDTH      16384u
#define FB_MAX_HEIGHT     16384u

static uint64_t gpu_fb(uint32_t w, uint32_t h, int fixed, uint64_t *alloc_out)
{
    uint32_t pages;

    if (!fixed) {
        pages = (w * h * 4u + 4095u) / 4096u;          /* uint32 — wraps */
        if (pages > GPU_MAX_FB_PAGES) {
            w = 1024; h = 768;
            pages = (w * h * 4u + 4095u) / 4096u;
        }
    } else {
        uint64_t bytes   = (uint64_t)w * (uint64_t)h * 4ull;
        uint64_t pages64 = (bytes + 4095ull) / 4096ull;
        if (w == 0 || h == 0 || w > FB_MAX_WIDTH || h > FB_MAX_HEIGHT ||
            pages64 > (uint64_t)GPU_MAX_FB_PAGES) {
            w = 1024; h = 768;
            bytes   = (uint64_t)w * (uint64_t)h * 4ull;
            pages64 = (bytes + 4095ull) / 4096ull;
        }
        pages = (uint32_t)pages64;
    }

    *alloc_out = (uint64_t)pages * 4096ull;
    /* s_fb_pitch = w * 4; the loop runs y < h writing pitch bytes per row. */
    return (uint64_t)h * ((uint64_t)w * 4ull);
}

static void run(int fixed)
{
    printf("\n=== %s ===\n", fixed ? "AFTER FIX" : "BEFORE FIX (vulnerable)");
    uint64_t alloc, touched;

    /* The hostile case: 0x100000 x 1025. w*h*4 = 0x100_0400_0000, which
     * truncates to 0x0400_0000 in uint32 -> 16384 pages... still > the clamp.
     * Pick the geometry whose TRUNCATED product lands under it. */
    touched = gpu_fb(0x100000u, 1025u, fixed, &alloc);
    printf("  C-4  device says 1048576x1025 -> alloc %llu B, loop writes %llu B\n",
           (unsigned long long)alloc, (unsigned long long)touched);
    CHECK(touched <= alloc, "C-4: framebuffer loop stays inside the allocation");

    /* A second hostile geometry, chosen so the uint32 product wraps to a small
     * value that sails under GPU_MAX_FB_PAGES entirely. */
    touched = gpu_fb(0x40000000u, 5u, fixed, &alloc);
    printf("  C-4  device says 1073741824x5   -> alloc %llu B, loop writes %llu B\n",
           (unsigned long long)alloc, (unsigned long long)touched);
    CHECK(touched <= alloc, "C-4: wrapped-product geometry also contained");

    /* Honest modes must be untouched by the fix. */
    touched = gpu_fb(1280, 800, fixed, &alloc);
    CHECK(alloc == 1000ull * 4096 && touched == 1280ull * 800 * 4,
          "C-4: honest 1280x800 unchanged (1000 pages, exact fit)");
    touched = gpu_fb(1920, 1080, fixed, &alloc);
    CHECK(touched <= alloc && alloc <= (uint64_t)GPU_MAX_FB_PAGES * 4096,
          "C-4: honest 1920x1080 still accepted");
    touched = gpu_fb(3840, 2160, fixed, &alloc);
    CHECK(touched <= alloc,
          "C-4: oversize 4K still clamps to the safe default");
}

/* ── C-6: fs/fat.c — the install-protected-tree test ───────────────────
 * fat_under_prot was `return 0`, so on a FAT root nothing was ever protected
 * and four capability gates took the permitted branch unconditionally. It is a
 * path-PREFIX test (FAT has no inode identity to anchor to, and no symlinks),
 * so the boundary case that matters is a sibling name sharing a prefix with a
 * protected tree: "/binary" must NOT be treated as inside "/bin". */
static int fat_path_under(const char *path, const char *tree)
{
    uint32_t i = 0;
    while (tree[i] && path[i] == tree[i]) i++;
    if (tree[i] != '\0') return 0;
    return path[i] == '\0' || path[i] == '/';
}
static int fat_under_prot(const char *path, int fixed)
{
    if (!fixed) return 0;                 /* the pre-fix constant */
    if (!path || path[0] != '/') return 0;
    return fat_path_under(path, "/bin")  || fat_path_under(path, "/sbin") ||
           fat_path_under(path, "/apps") || fat_path_under(path, "/etc/aegis");
}

static void run_fat(int fixed)
{
    CHECK(fat_under_prot("/bin/sh", fixed),        "C-6: /bin/sh is protected");
    CHECK(fat_under_prot("/bin", fixed),           "C-6: /bin itself is protected");
    CHECK(fat_under_prot("/etc/aegis/caps.d/x", fixed),
                                                   "C-6: /etc/aegis subtree protected");
    /* These must be false in BOTH arms — a fix that over-matched would be worse
     * than the bug, locking users out of their own files. */
    CHECK(!fat_under_prot("/binary", fixed),       "C-6: /binary is NOT /bin");
    CHECK(!fat_under_prot("/home/u/bin/sh", fixed),"C-6: a nested bin/ is not /bin");
    CHECK(!fat_under_prot("/etc/passwd", fixed),   "C-6: /etc is not /etc/aegis");
}

int main(void)
{
    run(0);
    run(1);
    printf("\n=== C-6 fat_under_prot: BEFORE ===\n");  run_fat(0);
    printf("\n=== C-6 fat_under_prot: AFTER  ===\n");  run_fat(1);
    printf("\n%d check(s) failed\n", fails);
    return 0;
}
