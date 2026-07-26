/* hda_stub.c — compiled only when CONFIG_AUDIO_HDA is off (see Makefile).
 *
 * The /dev/audio path (sys_io.c), the /proc HDA dump (procfs.c), and initrd.c
 * reference the HDA public API. With no audio hardware driver there is no
 * device, so every op reports "not present" / does nothing — the callers stay
 * compiled and link unchanged. */
#include <stdint.h>
#include "hda.h"

int      hda_present(void)                              { return 0; }
int      hda_audio_write(const void *buf, uint32_t len) { (void)buf; (void)len; return -1; }
void     hda_audio_close(void)                          { }
void     hda_audio_stop(void)                           { }
uint64_t hda_play_position_ms(void)                     { return 0; }
void     hda_set_volume(int pct)                        { (void)pct; }
int      hda_dump(char *buf, int bufsz)                 { (void)buf; (void)bufsz; return 0; }
