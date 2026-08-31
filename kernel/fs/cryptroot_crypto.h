#ifndef AEGIS_CRYPTROOT_CRYPTO_H
#define AEGIS_CRYPTROOT_CRYPTO_H
#include <stdint.h>
#define CRYPTROOT_KEY_BYTES 64
typedef struct { uint8_t data_rk[240], tweak_rk[240]; } cryptroot_xts_ctx_t;
void cryptroot_pbkdf2(const uint8_t *, uint32_t, const uint8_t[16], uint32_t, uint8_t[64]);
void cryptroot_verifier(const uint8_t[64], uint8_t[32]);
void cryptroot_xts_init(cryptroot_xts_ctx_t *, const uint8_t[64]);
void cryptroot_xts(cryptroot_xts_ctx_t *, uint8_t *, uint32_t, uint64_t, int);
#endif
