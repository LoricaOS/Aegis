#ifndef AEGIS_CRYPTROOT_H
#define AEGIS_CRYPTROOT_H
/* Return the original device name for plaintext media, "cryptroot" after a
 * successful unlock, or NULL when an encrypted device cannot be unlocked. */
const char *cryptroot_open(const char *devname);
#endif
