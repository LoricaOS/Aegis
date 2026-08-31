#include <assert.h>
#include <stdint.h>
#include <string.h>
#include "../kernel/drivers/wpa2_crypto.h"

static void hex(const char *s, uint8_t *out, size_t n)
{
    for (size_t i=0;i<n;i++) {
        unsigned a=(unsigned)(s[i*2]>'9'?s[i*2]-'a'+10:s[i*2]-'0');
        unsigned b=(unsigned)(s[i*2+1]>'9'?s[i*2+1]-'a'+10:s[i*2+1]-'0');
        out[i]=(uint8_t)((a<<4)|b);
    }
}

int main(void)
{
    uint8_t got[64], want[64], kek[16], wrapped[24];
    wpa2_pmk((const uint8_t *)"password",8,(const uint8_t *)"IEEE",4,got);
    hex("f42c6fc52df0ebef9ebb4b90b38a5f902e83fe1b135a70e23aed762e9710a12e",want,32);
    assert(memcmp(got,want,32)==0);
    hex("000102030405060708090a0b0c0d0e0f",kek,16);
    hex("1fa68b0a8112b447aef34bd8fb5a7b829d3e862371d2cfe5",wrapped,24);
    assert(wpa2_aes_unwrap(kek,wrapped,24,got)==16);
    hex("00112233445566778899aabbccddeeff",want,16);
    assert(memcmp(got,want,16)==0);
    return 0;
}
