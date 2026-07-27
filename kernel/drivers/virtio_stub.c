/* virtio_stub.c — always compiled.
 *
 * For each virtio device configured OUT, provide a no-op init (plus poll / API
 * where the core references it) so the unconditional call-sites in main.c,
 * poll_sources.c and sys_disk.c link against the real driver when the device is
 * IN and against this no-op when it is OUT. The device .c is excluded by the
 * Makefile; the #ifndef here selects the stub. This is the sys_ni_syscall
 * pattern applied to driver init hooks — it keeps the call-sites edit-free, so
 * every device is an independent knob without scattering #ifdefs through main.c.
 *
 * (virtio-net / virtio-vsock are the exception: their call-sites ARE guarded,
 * on CONFIG_VIRTIO_NET / CONFIG_VIRTIO_VSOCK, since they also gate on NET.)
 */
#include <stdint.h>

#ifndef CONFIG_VIRTIO_BLK
void virtio_blk_init(void) {}
#endif
#ifndef CONFIG_VIRTIO_SCSI
void virtio_scsi_init(void) {}
#endif
#ifndef CONFIG_VIRTIO_RNG
void virtio_rng_init(void) {}
#endif
#ifndef CONFIG_VIRTIO_PMEM
void virtio_pmem_init(void) {}
#endif
#ifndef CONFIG_VIRTIO_CONSOLE
void virtio_console_init(void) {}
#endif
#ifndef CONFIG_VIRTIO_9P
void virtio_9p_init(void) {}
#endif
#ifndef CONFIG_VIRTIO_BALLOON
void virtio_balloon_init(void) {}
void virtio_balloon_poll(void) {}
#endif
#ifndef CONFIG_VIRTIO_INPUT
void virtio_input_init(void) {}
void virtio_input_poll(void) {}
#endif
#ifndef CONFIG_VIRTIO_GPU
void     virtio_gpu_init(void) {}
int      virtio_gpu_active(void) { return 0; }
uint8_t *virtio_gpu_framebuffer(uint32_t *w, uint32_t *h, uint32_t *pitch)
             { (void)w; (void)h; (void)pitch; return 0; }
void     virtio_gpu_flush(void) {}
#endif
