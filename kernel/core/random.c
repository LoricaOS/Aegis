/*
 * random.c — Kernel CSPRNG (ChaCha20-based).
 *
 * Design:
 *   - Core PRNG is ChaCha20 (RFC 7539), the same algorithm used by
 *     Linux (/dev/urandom), OpenBSD (arc4random), and FreeBSD.
 *   - 256-bit key + 64-bit counter + 64-bit nonce = 384 bits of state.
 *   - Entropy pool accumulates hardware jitter via SipHash-style mixing.
 *   - Pool is folded into the ChaCha20 key periodically (every 64 output
 *     blocks) to provide forward secrecy and continuous re-seeding.
 *
 * Entropy sources:
 *   - RDTSC (x86) / CNTVCT_EL0 (ARM64) — CPU cycle counter with
 *     sub-nanosecond jitter between reads.
 *   - PIT/timer tick count — coarse 100Hz counter.
 *   - Interrupt timing — random_add_interrupt_entropy() called from ISR
 *     paths mixes cycle-counter value at each interrupt.
 *   - Keyboard events — timing and scancode data mixed in.
 *
 * No locks: single-core kernel, interrupts are disabled during syscall
 * dispatch. ISR entropy mixing writes to a separate accumulator that is
 * folded into the key on the next output request.
 */
#include "random.h"
#include "printk.h"
#include "arch.h"
#include "spinlock.h"
#include <stdint.h>

/* ── ChaCha20 quarter-round and block function ───────────────────────── */

#define ROTL32(v, n) (((v) << (n)) | ((v) >> (32 - (n))))

#define QR(a, b, c, d) do { \
    a += b; d ^= a; d = ROTL32(d, 16); \
    c += d; b ^= c; b = ROTL32(b, 12); \
    a += b; d ^= a; d = ROTL32(d, 8);  \
    c += d; b ^= c; b = ROTL32(b, 7);  \
} while (0)

/*
 * chacha20_block — generate one 64-byte keystream block.
 *
 * Input: 16 × uint32_t state (constant + key + counter + nonce).
 * Output: 16 × uint32_t (64 bytes) of keystream.
 * State is NOT modified — caller increments counter externally.
 */
static void
chacha20_block(const uint32_t input[16], uint32_t output[16])
{
    uint32_t x[16];
    int i;
    for (i = 0; i < 16; i++)
        x[i] = input[i];

    /* 20 rounds = 10 double-rounds */
    for (i = 0; i < 10; i++) {
        /* Column rounds */
        QR(x[0], x[4], x[ 8], x[12]);
        QR(x[1], x[5], x[ 9], x[13]);
        QR(x[2], x[6], x[10], x[14]);
        QR(x[3], x[7], x[11], x[15]);
        /* Diagonal rounds */
        QR(x[0], x[5], x[10], x[15]);
        QR(x[1], x[6], x[11], x[12]);
        QR(x[2], x[7], x[ 8], x[13]);
        QR(x[3], x[4], x[ 9], x[14]);
    }

    for (i = 0; i < 16; i++)
        output[i] = x[i] + input[i];
}

/* ── CSPRNG state ────────────────────────────────────────────────────── */

/* ChaCha20 state: "expand 32-byte k" constant + 256-bit key + counter + nonce */
static uint32_t s_state[16];

/* Entropy accumulator — ISR-safe. Mixed into key on next output. */
static uint64_t s_entropy_acc;
static uint32_t s_entropy_count;

/* Output buffer — one ChaCha20 block (64 bytes) */
static uint8_t  s_buf[64];
static uint32_t s_buf_pos;     /* next byte to consume from s_buf */

/* Blocks generated since last re-key */
static uint32_t s_blocks_since_rekey;

static spinlock_t rng_lock = SPINLOCK_INIT;

/* ── Entropy mixing ──────────────────────────────────────────────────── */

/*
 * mix64 — mix a 64-bit value into the entropy accumulator.
 * Uses a fast integer hash (splitmix64 finalizer) to distribute bits.
 */
static uint64_t
mix64(uint64_t x)
{
    x ^= x >> 30;
    x *= 0xBF58476D1CE4E5B9ULL;
    x ^= x >> 27;
    x *= 0x94D049BB133111EBULL;
    x ^= x >> 31;
    return x;
}

/* ── Hardware RNG (audit L15) ─────────────────────────────────────────────
 * s_entropy_count is a REKEY trigger and is reset every rekey, so it cannot
 * answer "has this pool ever been meaningfully seeded". s_seed_credits is the
 * cumulative counter that can, and s_rng_ready latches once the pool is
 * trustworthy — either because the CPU's hardware RNG seeded it at init, or
 * because enough interrupt/device entropy has since accumulated. */
static uint32_t s_seed_credits;
static int      s_rng_ready;
#define RNG_READY_CREDITS 64u

#if defined(__x86_64__)
/* CPUID.01H:ECX[30] = RDRAND. Present on essentially every x86-64 since Ivy
 * Bridge, and unlike virtio-rng it needs no device — which is exactly the
 * case this closes: a deterministic VM with no virtio-rng seeded the entire
 * 256-bit key and 64-bit nonce from four cycle-counter reads and one tick. */
static int hw_rng_supported(void)
{
    uint32_t a, b, c, d;
    __asm__ volatile("cpuid" : "=a"(a), "=b"(b), "=c"(c), "=d"(d)
                             : "a"(1u), "c"(0u));
    (void)a; (void)b; (void)d;
    return (c >> 30) & 1u;
}

static int hw_rng_read(uint64_t *out)
{
    unsigned char ok = 0;
    uint64_t v = 0;
    /* RDRAND may transiently fail; the ISA recommends ~10 retries. */
    for (int i = 0; i < 10; i++) {
        __asm__ volatile("rdrand %0; setc %1" : "=r"(v), "=qm"(ok) : : "cc");
        if (ok) { *out = v; return 1; }
    }
    return 0;
}
#elif defined(__aarch64__)
/* Armv8.5-A RNG extension: ID_AA64ISAR0_EL1.RNDR advertises RNDR. RNDR sets
 * Z on a transient failure, just like RDRAND clears CF. Use the architectural
 * encoding so older cross-assemblers do not need the RNDR register name. */
static int hw_rng_supported(void)
{
    uint64_t isar0;
    __asm__ volatile("mrs %0, ID_AA64ISAR0_EL1" : "=r"(isar0));
    return ((isar0 >> 60) & 0xfu) != 0;
}

static int hw_rng_read(uint64_t *out)
{
    for (int i = 0; i < 10; i++) {
        uint64_t v;
        uint32_t ok;
        __asm__ volatile("mrs %0, S3_3_C2_C4_0; cset %w1, ne"
                         : "=r"(v), "=r"(ok) : : "cc");
        if (ok) { *out = v; return 1; }
    }
    return 0;
}
#else
static int hw_rng_supported(void) { return 0; }
static int hw_rng_read(uint64_t *out) { (void)out; return 0; }
#endif

int
random_is_ready(void)
{
    if (!s_rng_ready &&
        __atomic_load_n(&s_seed_credits, __ATOMIC_RELAXED) >= RNG_READY_CREDITS)
        s_rng_ready = 1;
    return s_rng_ready;
}

void
random_add_entropy(const void *data, size_t len)
{
    __atomic_fetch_add(&s_seed_credits, (uint32_t)len, __ATOMIC_RELAXED);
    const uint8_t *p = (const uint8_t *)data;
    size_t i;
    uint64_t v = 0;
    for (i = 0; i < len; i++) {
        v = (v << 8) | p[i];
        if ((i & 7) == 7 || i == len - 1) {
            s_entropy_acc ^= mix64(v ^ arch_get_cycles());
            s_entropy_count++;
            v = 0;
        }
    }
}

void
random_add_interrupt_entropy(void)
{
    /* Called from ISR context on multiple CPUs — use atomics to prevent
     * lost updates when two CPUs XOR/increment simultaneously. */
    __atomic_fetch_xor(&s_entropy_acc, mix64(arch_get_cycles()), __ATOMIC_RELAXED);
    __atomic_fetch_add(&s_entropy_count, 1, __ATOMIC_RELAXED);
    __atomic_fetch_add(&s_seed_credits, 1, __ATOMIC_RELAXED);
}

/* ── Re-key: fold accumulated entropy into ChaCha20 key ──────────────── */

static void
rekey(void)
{
    /* XOR accumulated entropy into key words */
    uint32_t lo = (uint32_t)s_entropy_acc;
    uint32_t hi = (uint32_t)(s_entropy_acc >> 32);
    s_state[4] ^= lo;
    s_state[5] ^= hi;
    s_state[6] ^= lo ^ hi;
    s_state[7] ^= hi ^ (uint32_t)arch_get_cycles();

    /* Generate a block and use it as the new key (forward secrecy).
     * An attacker who compromises the state after this point cannot
     * recover previous outputs. */
    uint32_t tmp[16];
    chacha20_block(s_state, tmp);

    /* New key = first 8 words of output */
    s_state[4]  = tmp[0];
    s_state[5]  = tmp[1];
    s_state[6]  = tmp[2];
    s_state[7]  = tmp[3];
    s_state[8]  = tmp[4];
    s_state[9]  = tmp[5];
    s_state[10] = tmp[6];
    s_state[11] = tmp[7];

    /* Increment counter to avoid repeating keystream */
    s_state[12]++;
    if (s_state[12] == 0)
        s_state[13]++;

    /* Reset accumulator */
    s_entropy_acc = 0;
    s_entropy_count = 0;
    s_blocks_since_rekey = 0;
}

/* ── Generate random bytes ───────────────────────────────────────────── */

static void
refill_buf(void)
{
    /* Re-key every 64 blocks (4 KB of output) or when entropy is available */
    if (s_blocks_since_rekey >= 64 || s_entropy_count >= 8)
        rekey();

    uint32_t out[16];
    chacha20_block(s_state, out);

    /* Increment 64-bit counter */
    s_state[12]++;
    if (s_state[12] == 0)
        s_state[13]++;

    __builtin_memcpy(s_buf, out, 64);
    s_buf_pos = 0;
    s_blocks_since_rekey++;
}

int
random_get_bytes(void *buf, size_t len)
{
    /* Never label deterministic timing state as random. Callers that cannot
     * wait fail with EAGAIN; boot-critical callers check readiness before their
     * point of no return. */
    if (!random_is_ready()) {
        static int warned;
        if (!warned) {
            warned = 1;
            printk("[RNG] WARN: random bytes unavailable until pool is seeded\n");
        }
        return -11; /* -EAGAIN */
    }

    irqflags_t fl = spin_lock_irqsave(&rng_lock);
    uint8_t *dst = (uint8_t *)buf;
    while (len > 0) {
        if (s_buf_pos >= 64)
            refill_buf();
        size_t avail = 64 - s_buf_pos;
        size_t chunk = (len < avail) ? len : avail;
        __builtin_memcpy(dst, s_buf + s_buf_pos, chunk);
        s_buf_pos += (uint32_t)chunk;
        dst += chunk;
        len -= chunk;
    }
    spin_unlock_irqrestore(&rng_lock, fl);
    return 0;
}

/* ── Initialization ──────────────────────────────────────────────────── */

void
random_init(void)
{
    /* ChaCha20 constant: "expand 32-byte k" in little-endian */
    s_state[0] = 0x61707865;  /* "expa" */
    s_state[1] = 0x3320646E;  /* "nd 3" */
    s_state[2] = 0x79622D32;  /* "2-by" */
    s_state[3] = 0x6B206574;  /* "te k" */

    /* Seed key from multiple entropy sources.
     * Each read of the cycle counter has jitter relative to the previous
     * one, even in the same function — instruction scheduling, cache state,
     * and pipeline effects all contribute non-deterministic timing. */
    uint64_t t0 = arch_get_cycles();
    uint64_t t1 = arch_get_cycles();
    uint64_t t2 = arch_get_ticks();
    uint64_t t3 = arch_get_cycles();

    s_state[4]  = (uint32_t)mix64(t0);
    s_state[5]  = (uint32_t)(mix64(t0) >> 32);
    s_state[6]  = (uint32_t)mix64(t1);
    s_state[7]  = (uint32_t)(mix64(t1) >> 32);
    s_state[8]  = (uint32_t)mix64(t2);
    s_state[9]  = (uint32_t)(mix64(t2) >> 32);
    s_state[10] = (uint32_t)mix64(t3);
    s_state[11] = (uint32_t)(mix64(t3) >> 32);

    /* Counter starts at 0 */
    s_state[12] = 0;
    s_state[13] = 0;

    /* Nonce from more cycle-counter jitter */
    uint64_t t4 = arch_get_cycles();
    s_state[14] = (uint32_t)mix64(t4);
    s_state[15] = (uint32_t)(mix64(t4) >> 32);

    /* Fold the CPU's hardware RNG into the seed UNCONDITIONALLY when present,
     * before the priming rekey below spreads it over every key bit. On a VM
     * without virtio-rng this is the difference between a 256-bit key derived
     * from five timer reads and one derived from a real entropy source.
     * (audit L15) */
    if (hw_rng_supported()) {
        int got = 0;
        for (int i = 0; i < 4; i++) {
            uint64_t hw;
            if (!hw_rng_read(&hw))
                break;
            s_state[4 + i * 2] ^= (uint32_t)hw;
            s_state[5 + i * 2] ^= (uint32_t)(hw >> 32);
            got++;
        }
        uint64_t hwn;
        if (hw_rng_read(&hwn)) {
            s_state[14] ^= (uint32_t)hwn;
            s_state[15] ^= (uint32_t)(hwn >> 32);
        }
        if (got == 4)
            s_rng_ready = 1;   /* hardware-seeded — trustworthy from boot */
    }

    /* Prime the buffer */
    s_buf_pos = 64;  /* force refill on first request */
    s_blocks_since_rekey = 0;
    s_entropy_acc = 0;
    s_entropy_count = 0;

    /* Do an initial re-key to thoroughly mix the seed.
     * This runs ChaCha20 once and uses the output as the new key,
     * providing avalanche over all seed bits. */
    rekey();

    printk("[RNG] OK: ChaCha20 CSPRNG seeded (%s)\n",
           s_rng_ready ? "hardware RNG" : "timing only — awaiting entropy");
}
