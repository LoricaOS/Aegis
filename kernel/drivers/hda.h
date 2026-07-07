/* hda.h — Intel High Definition Audio (HDA) controller driver */
#ifndef HDA_H
#define HDA_H

#include <stdint.h>

/* Probe for an HDA controller (PCI class 04:03), bring up the first audio
 * codec's DAC→output-pin path, and play a test tone. Silent (no printk) if no
 * controller is present. Called from kernel_main after the storage/NIC probes.
 *
 * This is Aegis's first audio output path. The controller half (CORB/immediate
 * verbs, stream + BDL DMA) is HDA-spec-standard and portable to real hardware;
 * the codec half is written spec-correctly (widget-graph walk, amp unmute, pin
 * control, EAPD) to maximise that portability, but real codecs carry per-board
 * quirks (EAPD/GPIO, complex widget topologies) that only bare metal exercises.
 *
 * Playback model: hda_init configures the codec path and allocates DMA buffers
 * but stays silent. /dev/audio feeds PCM via hda_audio_write + hda_audio_close;
 * each open/write/close cycle plays one sound once (hda_poll stops it). */
void hda_init(void);

/* 1 if an HDA codec output path is configured and /dev/audio can play. */
int  hda_present(void);

/* Append PCM (48 kHz, signed 16-bit, stereo) to the playback buffer. One
 * open/write.../close cycle plays one sound. Returns len (always accepts). */
int  hda_audio_write(const void *buf, uint32_t len);

/* End of a write session → start playing the accumulated buffer (once). */
void hda_audio_close(void);

/* Stop playback immediately, discarding the buffered tail (Stop button). */
void hda_audio_stop(void);

/* Milliseconds actually played on the current /dev/audio stream (LPIB-derived
 * = what's being heard, the A/V master clock). 0 when idle or no HDA. */
uint64_t hda_play_position_ms(void);

/* Timer-tick hook: stops a one-shot playback after a single pass. */
void hda_poll(void);

/* Output volume, 0..100% (scales the codec output amp gain). */
void hda_set_volume(int pct);

/* Format the codec widget graph (pins, config-defaults, connections) into buf
 * for /proc/hda. Returns the length written. */
int  hda_dump(char *buf, int bufsz);

#endif /* HDA_H */
