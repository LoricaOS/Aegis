#ifndef WPA2_CRYPTO_H
#define WPA2_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

void wpa2_pmk(const uint8_t *pass, size_t pass_len,
              const uint8_t *ssid, size_t ssid_len, uint8_t pmk[32]);
void wpa2_ptk(const uint8_t pmk[32], const uint8_t aa[6],
              const uint8_t spa[6], const uint8_t anonce[32],
              const uint8_t snonce[32], uint8_t ptk[64]);
void wpa2_mic(const uint8_t kck[16], const uint8_t *eapol, size_t len,
              uint8_t mic[16]);
int wpa2_aes_unwrap(const uint8_t kek[16], const uint8_t *wrapped,
                    size_t wrapped_len, uint8_t *plain);

#endif
