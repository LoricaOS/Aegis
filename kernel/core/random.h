#ifndef RANDOM_H
#define RANDOM_H

#include <stdint.h>
#include <stddef.h>

/*
 * random.h — Kernel CSPRNG interface.
 *
 * ChaCha20-based cryptographically secure PRNG seeded from hardware
 * entropy sources (CPU cycle counter, timer jitter, interrupt timing).
 * Provides getrandom(2) and /dev/urandom backing.
 */

/* Initialize the CSPRNG. Seeds from RDTSC/CNTVCT + PIT ticks.
 * Must be called after pit_init() (timer running) and before any
 * user process is spawned. Prints [RNG] OK. */
void random_init(void);

/* Mix additional entropy into the pool. Called from interrupt handlers
 * (keyboard, timer, network) to continuously gather timing jitter.
 * Safe to call from ISR context — no locks, no allocation. */
void random_add_entropy(const void *data, size_t len);

/* Fill buf with len cryptographically random bytes.
 * Always succeeds (pool is seeded at boot). Returns 0. */
int random_get_bytes(void *buf, size_t len);

/* Called from interrupt handlers to mix in cycle-counter jitter.
 * Cheaper than random_add_entropy — just mixes one 64-bit timestamp. */
void random_add_interrupt_entropy(void);

#endif /* RANDOM_H */
