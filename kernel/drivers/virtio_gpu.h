/* virtio_gpu.h — virtio 1.0 GPU (2D scanout) on the shared virtio core
 *
 * First step of the GPU/OpenCL program: a working virtio-gpu 2D pipeline
 * (GET_DISPLAY_INFO → RESOURCE_CREATE_2D → ATTACH_BACKING → SET_SCANOUT →
 * TRANSFER_TO_HOST_2D → RESOURCE_FLUSH). 3D/virgl and a compute path build on
 * this later.
 */
#ifndef VIRTIO_GPU_H
#define VIRTIO_GPU_H

#include <stdint.h>

/* Probe for a virtio-gpu, bring up scanout 0 with a guest-backed framebuffer,
 * and present a test pattern. Silent if no device. Called from kernel_main. */
void virtio_gpu_init(void);

/* 1 if a virtio-gpu was brought up and its backing framebuffer is live.
 * sys_fb_map uses this to publish the GPU backing to a compositor. */
int virtio_gpu_active(void);

/* Present the current backing framebuffer to the screen (TRANSFER_TO_HOST_2D +
 * RESOURCE_FLUSH of the full scanout). No-op if virtio-gpu is not active.
 * This is the hook a future compositor calls after drawing a frame. */
void virtio_gpu_flush(void);

/* Return the linear BGRX framebuffer backing + geometry, or NULL/0 if inactive.
 * The buffer is virtually contiguous in KVA (physically scattered pages bound to
 * the GPU resource via ATTACH_BACKING). */
uint8_t *virtio_gpu_framebuffer(uint32_t *w, uint32_t *h, uint32_t *pitch);

#endif /* VIRTIO_GPU_H */
