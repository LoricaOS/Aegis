/* virtio_gpu.c — virtio 1.0 GPU, 2D scanout, on the shared virtio core
 *
 * Brings up scanout 0 with a guest-backed BGRX framebuffer and runs the full 2D
 * pipeline. The framebuffer is virtually contiguous in KVA (easy to draw into)
 * and physically scattered <4GB pages bound to the host resource via
 * ATTACH_BACKING — virtio's native scatter-gather, so no contiguous allocator.
 *
 * Command model (§5.7): every command is a chain [request (OUT) | response (IN)]
 * on the control queue; the response is a virtio_gpu_ctrl_hdr whose type tells
 * success (VIRTIO_GPU_RESP_OK_*). Synchronous poll-in-call, like virtio-blk.
 *
 * This is the GPU/OpenCL program's foundation; 3D/virgl + compute build on it.
 *
 * References: VIRTIO v1.0 §5.7 GPU Device; Linux include/uapi/linux/virtio_gpu.h
 */
#include "virtio_gpu.h"
#include "virtio.h"
#include "arch.h"
#include "kva.h"
#include "printk.h"
#include "spinlock.h"
#include <stdint.h>
#include <stddef.h>

#define VIRTIO_GPU_MODERN  0x1050u

/* Control-queue command + response types (§5.7.6). */
#define VIRTIO_GPU_CMD_GET_DISPLAY_INFO       0x0100u
#define VIRTIO_GPU_CMD_RESOURCE_CREATE_2D     0x0101u
#define VIRTIO_GPU_CMD_SET_SCANOUT            0x0103u
#define VIRTIO_GPU_CMD_RESOURCE_FLUSH         0x0104u
#define VIRTIO_GPU_CMD_TRANSFER_TO_HOST_2D    0x0105u
#define VIRTIO_GPU_CMD_RESOURCE_ATTACH_BACKING 0x0106u
#define VIRTIO_GPU_RESP_OK_NODATA             0x1100u
#define VIRTIO_GPU_RESP_OK_DISPLAY_INFO       0x1101u

#define VIRTIO_GPU_FORMAT_B8G8R8X8_UNORM      2u
#define VIRTIO_GPU_MAX_SCANOUTS               16u
#define GPU_RESOURCE_ID                       1u

/* Cap the backing at 1920×1080×4 = 2025 pages; covers 1080p. */
#define GPU_MAX_FB_PAGES   2160u
#define GPU_POLL_BUDGET    50000000u

typedef struct __attribute__((packed)) {
    uint32_t type;
    uint32_t flags;
    uint64_t fence_id;
    uint32_t ctx_id;
    uint32_t padding;
} virtio_gpu_ctrl_hdr_t;

typedef struct __attribute__((packed)) {
    uint32_t x, y, width, height;
} virtio_gpu_rect_t;

typedef struct __attribute__((packed)) {
    virtio_gpu_ctrl_hdr_t hdr;
    struct {
        virtio_gpu_rect_t r;
        uint32_t enabled;
        uint32_t flags;
    } pmodes[VIRTIO_GPU_MAX_SCANOUTS];
} virtio_gpu_resp_display_info_t;

typedef struct __attribute__((packed)) {
    virtio_gpu_ctrl_hdr_t hdr;
    uint32_t resource_id;
    uint32_t format;
    uint32_t width;
    uint32_t height;
} virtio_gpu_resource_create_2d_t;

typedef struct __attribute__((packed)) {
    uint64_t addr;
    uint32_t length;
    uint32_t padding;
} virtio_gpu_mem_entry_t;

typedef struct __attribute__((packed)) {
    virtio_gpu_ctrl_hdr_t hdr;
    uint32_t resource_id;
    uint32_t nr_entries;
} virtio_gpu_attach_backing_t;   /* followed by nr_entries mem entries */

typedef struct __attribute__((packed)) {
    virtio_gpu_ctrl_hdr_t hdr;
    virtio_gpu_rect_t r;
    uint32_t scanout_id;
    uint32_t resource_id;
} virtio_gpu_set_scanout_t;

typedef struct __attribute__((packed)) {
    virtio_gpu_ctrl_hdr_t hdr;
    virtio_gpu_rect_t r;
    uint64_t offset;
    uint32_t resource_id;
    uint32_t padding;
} virtio_gpu_transfer_to_host_2d_t;

typedef struct __attribute__((packed)) {
    virtio_gpu_ctrl_hdr_t hdr;
    virtio_gpu_rect_t r;
    uint32_t resource_id;
    uint32_t padding;
} virtio_gpu_resource_flush_t;

static virtio_dev_t s_gpu;
static virtq_t      s_ctrlq;

static uintptr_t s_cmd_va;   /* request scratch (one page) */
static uint64_t  s_cmd_pa;
static uintptr_t s_resp_va;  /* response scratch (one page) */
static uint64_t  s_resp_pa;
static uintptr_t s_ent_va;   /* mem-entry array (multi-page) */
static uint64_t  s_ent_pa_base;
static uint32_t  s_ent_pages;

static uint8_t  *s_fb;       /* KVA-contiguous BGRX framebuffer */
static uint32_t  s_fb_w, s_fb_h, s_fb_pitch, s_fb_pages;
static int       s_active;

static void
_memset(void *d, int v, uint32_t n)
{
    uint8_t *p = d;
    while (n--)
        *p++ = (uint8_t)v;
}

/* Run one command chain (n OUT segments already built in segs[0..n-2], the IN
 * response segment in segs[n-1]); return the response hdr type, or 0 on failure. */
static uint32_t
gpu_exec(const virtq_buf_t *segs, int nseg)
{
    uint16_t head;
    irqflags_t fl = spin_lock_irqsave(&s_ctrlq.lock);
    if (virtq_publish_chain(&s_ctrlq, segs, nseg, &head) < 0) {
        spin_unlock_irqrestore(&s_ctrlq.lock, fl);
        return 0;
    }
    virtq_notify(&s_ctrlq);

    uint16_t cid;
    uint32_t len;
    int done = 0;
    uint32_t budget;
    for (budget = 0; budget < GPU_POLL_BUDGET; budget++) {
        if (virtq_poll_used(&s_ctrlq, &cid, &len)) {
            virtq_free_chain(&s_ctrlq, cid);
            done = 1;
            break;
        }
        arch_pause();
    }
    spin_unlock_irqrestore(&s_ctrlq.lock, fl);
    if (!done)
        return 0;
    return ((volatile virtio_gpu_ctrl_hdr_t *)s_resp_va)->type;
}

/* Simple [request | response] command: request already staged at s_cmd_va. */
static uint32_t
gpu_cmd(uint32_t req_len, uint32_t resp_len)
{
    virtq_buf_t segs[2];
    segs[0].phys = s_cmd_pa;  segs[0].len = req_len;  segs[0].write = 0;
    segs[1].phys = s_resp_pa; segs[1].len = resp_len; segs[1].write = 1;
    return gpu_exec(segs, 2);
}

void
virtio_gpu_init(void)
{
    if (virtio_pci_find(VIRTIO_GPU_MODERN, 0, &s_gpu) < 0)
        return;  /* silent: no virtio-gpu present */

    virtio_reset(&s_gpu);
    if (virtio_negotiate(&s_gpu, 0) < 0)   /* no optional features needed */
        return;
    if (virtio_setup_queue(&s_gpu, 0, &s_ctrlq) < 0) {  /* controlq */
        s_gpu.common->device_status = VIRTIO_STATUS_FAILED;
        return;
    }
    virtio_driver_ok(&s_gpu);

    if (virtio_alloc_dma_page(&s_cmd_pa, &s_cmd_va) < 0 ||
        virtio_alloc_dma_page(&s_resp_pa, &s_resp_va) < 0)
        return;

    /* 1. GET_DISPLAY_INFO → scanout 0 geometry. */
    virtio_gpu_ctrl_hdr_t *h = (virtio_gpu_ctrl_hdr_t *)s_cmd_va;
    _memset(h, 0, sizeof(*h));
    h->type = VIRTIO_GPU_CMD_GET_DISPLAY_INFO;
    if (gpu_cmd(sizeof(*h), sizeof(virtio_gpu_resp_display_info_t)) !=
        VIRTIO_GPU_RESP_OK_DISPLAY_INFO)
        return;
    volatile virtio_gpu_resp_display_info_t *di =
        (volatile virtio_gpu_resp_display_info_t *)s_resp_va;
    uint32_t w   = di->pmodes[0].r.width;
    uint32_t hgt = di->pmodes[0].r.height;
    if (w == 0 || hgt == 0) { w = 1024; hgt = 768; }   /* sane default */

    uint32_t pages = (w * hgt * 4u + 4095u) / 4096u;
    if (pages > GPU_MAX_FB_PAGES) {
        /* Clamp resolution to what we can back. */
        w = 1024; hgt = 768;
        pages = (w * hgt * 4u + 4095u) / 4096u;
    }

    /* 2. RESOURCE_CREATE_2D. */
    virtio_gpu_resource_create_2d_t *c2 =
        (virtio_gpu_resource_create_2d_t *)s_cmd_va;
    _memset(c2, 0, sizeof(*c2));
    c2->hdr.type    = VIRTIO_GPU_CMD_RESOURCE_CREATE_2D;
    c2->resource_id = GPU_RESOURCE_ID;
    c2->format      = VIRTIO_GPU_FORMAT_B8G8R8X8_UNORM;
    c2->width       = w;
    c2->height      = hgt;
    if (gpu_cmd(sizeof(*c2), sizeof(virtio_gpu_ctrl_hdr_t)) !=
        VIRTIO_GPU_RESP_OK_NODATA)
        return;

    /* 3. Allocate the backing framebuffer (KVA-contiguous, <4GB scattered). */
    s_fb = (uint8_t *)kva_alloc_pages_low(pages);
    if (!s_fb)
        return;
    s_fb_w = w; s_fb_h = hgt; s_fb_pitch = w * 4u; s_fb_pages = pages;

    /* Build the mem-entry array (one per backing page) in its own DMA buffer. */
    s_ent_pages = (pages * (uint32_t)sizeof(virtio_gpu_mem_entry_t) + 4095u) / 4096u;
    s_ent_va = (uintptr_t)kva_alloc_pages_low(s_ent_pages);
    if (!s_ent_va)
        return;
    s_ent_pa_base = kva_page_phys((void *)s_ent_va);
    virtio_gpu_mem_entry_t *ents = (virtio_gpu_mem_entry_t *)s_ent_va;
    uint32_t i;
    for (i = 0; i < pages; i++) {
        ents[i].addr    = kva_page_phys(s_fb + (uint64_t)i * 4096);
        ents[i].length  = 4096;
        ents[i].padding = 0;
    }

    /* 3b. RESOURCE_ATTACH_BACKING — fixed header (OUT) + entry pages (OUT) +
     * response (IN). The entry pages are KVA-contiguous but physically
     * scattered, so one segment per page. */
    virtio_gpu_attach_backing_t *ab =
        (virtio_gpu_attach_backing_t *)s_cmd_va;
    _memset(ab, 0, sizeof(*ab));
    ab->hdr.type     = VIRTIO_GPU_CMD_RESOURCE_ATTACH_BACKING;
    ab->resource_id  = GPU_RESOURCE_ID;
    ab->nr_entries   = pages;

    {
        virtq_buf_t segs[2 + (GPU_MAX_FB_PAGES * sizeof(virtio_gpu_mem_entry_t) / 4096u) + 2];
        int n = 0;
        segs[n].phys = s_cmd_pa; segs[n].len = sizeof(*ab); segs[n].write = 0; n++;
        uint32_t remaining = pages * (uint32_t)sizeof(virtio_gpu_mem_entry_t);
        uint32_t j;
        for (j = 0; j < s_ent_pages; j++) {
            uint32_t seg = remaining < 4096u ? remaining : 4096u;
            segs[n].phys  = kva_page_phys((void *)(s_ent_va + (uint64_t)j * 4096));
            segs[n].len   = seg;
            segs[n].write = 0;
            n++;
            remaining -= seg;
        }
        segs[n].phys = s_resp_pa; segs[n].len = sizeof(virtio_gpu_ctrl_hdr_t);
        segs[n].write = 1; n++;
        if (gpu_exec(segs, n) != VIRTIO_GPU_RESP_OK_NODATA)
            return;
    }

    /* 4. SET_SCANOUT — bind scanout 0 to the resource. */
    virtio_gpu_set_scanout_t *ss = (virtio_gpu_set_scanout_t *)s_cmd_va;
    _memset(ss, 0, sizeof(*ss));
    ss->hdr.type     = VIRTIO_GPU_CMD_SET_SCANOUT;
    ss->r.width      = w;
    ss->r.height     = hgt;
    ss->scanout_id   = 0;
    ss->resource_id  = GPU_RESOURCE_ID;
    if (gpu_cmd(sizeof(*ss), sizeof(virtio_gpu_ctrl_hdr_t)) !=
        VIRTIO_GPU_RESP_OK_NODATA)
        return;

    s_active = 1;

    /* 5. Test pattern: a diagonal RGB gradient (BGRX little-endian = 0xXXRRGGBB). */
    uint32_t x, y;
    for (y = 0; y < hgt; y++) {
        uint32_t *row = (uint32_t *)(s_fb + (uint64_t)y * s_fb_pitch);
        for (x = 0; x < w; x++) {
            uint8_t r = (uint8_t)(x * 255u / (w ? w : 1));
            uint8_t g = (uint8_t)(y * 255u / (hgt ? hgt : 1));
            uint8_t b = (uint8_t)((x + y) * 255u / ((w + hgt) ? (w + hgt) : 1));
            row[x] = ((uint32_t)r << 16) | ((uint32_t)g << 8) | b;
        }
    }
    virtio_gpu_flush();

    printk("[GPU] OK: virtio-gpu %ux%u scanout 0 (%u pages backing)\n",
           w, hgt, pages);
}

void
virtio_gpu_flush(void)
{
    if (!s_active)
        return;

    virtio_gpu_transfer_to_host_2d_t *t =
        (virtio_gpu_transfer_to_host_2d_t *)s_cmd_va;
    _memset(t, 0, sizeof(*t));
    t->hdr.type     = VIRTIO_GPU_CMD_TRANSFER_TO_HOST_2D;
    t->r.width      = s_fb_w;
    t->r.height     = s_fb_h;
    t->offset       = 0;
    t->resource_id  = GPU_RESOURCE_ID;
    (void)gpu_cmd(sizeof(*t), sizeof(virtio_gpu_ctrl_hdr_t));

    virtio_gpu_resource_flush_t *f = (virtio_gpu_resource_flush_t *)s_cmd_va;
    _memset(f, 0, sizeof(*f));
    f->hdr.type     = VIRTIO_GPU_CMD_RESOURCE_FLUSH;
    f->r.width      = s_fb_w;
    f->r.height     = s_fb_h;
    f->resource_id  = GPU_RESOURCE_ID;
    (void)gpu_cmd(sizeof(*f), sizeof(virtio_gpu_ctrl_hdr_t));
}

int
virtio_gpu_active(void)
{
    return s_active;
}

uint8_t *
virtio_gpu_framebuffer(uint32_t *w, uint32_t *h, uint32_t *pitch)
{
    if (!s_active)
        return NULL;
    if (w)     *w     = s_fb_w;
    if (h)     *h     = s_fb_h;
    if (pitch) *pitch = s_fb_pitch;
    return s_fb;
}
