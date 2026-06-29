#include "sys_impl.h"
#include "sched.h"
#include "proc.h"
#include "vfs.h"
#include "vmm.h"
#include "vma.h"
#include "printk.h"
#include "cap.h"
#include "blkdev.h"
#include "gpt.h"
#include "fb.h"
#include "virtio_gpu.h"
#include "kva.h"
#include "spinlock.h"
#include <stdint.h>

/* ── blkdev_info_t — sent to userspace by sys_blkdev_list ───────────── */
typedef struct {
    char     name[16];
    uint64_t block_count;
    uint32_t block_size;
    uint32_t _pad;
} blkdev_info_t;

/*
 * sys_blkdev_list — syscall 510
 * Enumerate registered block devices.
 * arg1 = user buffer pointer
 * arg2 = buffer size in bytes
 * Returns number of devices, or negative errno.
 */
uint64_t
sys_blkdev_list(uint64_t arg1, uint64_t arg2)
{
    aegis_process_t *proc = current_proc();
    if (cap_check(proc->caps, CAP_TABLE_SIZE,
                  CAP_KIND_DISK_ADMIN, CAP_RIGHTS_READ) != 0)
        return SYS_ERR(ENOCAP);

    int count = blkdev_count();
    uint64_t max_entries = arg2 / sizeof(blkdev_info_t);
    int i;
    for (i = 0; i < count && (uint64_t)i < max_entries; i++) {
        blkdev_t *d = blkdev_get_index(i);
        if (!d) break;
        blkdev_info_t info;
        __builtin_memset(&info, 0, sizeof(info));
        /* Copy name */
        int j;
        for (j = 0; j < 15 && d->name[j]; j++)
            info.name[j] = d->name[j];
        info.name[j] = '\0';
        info.block_count = d->block_count;
        info.block_size  = d->block_size;
        COPY_TO_USER(arg1 + (uint64_t)i * sizeof(blkdev_info_t), &info);
    }
    return (uint64_t)i;
}

/*
 * sys_blkdev_io — syscall 511
 * Raw block device read/write.
 * arg1 = user pointer to device name (NUL-terminated)
 * arg2 = LBA start
 * arg3 = block count
 * arg4 = user buffer
 * arg5 = 0=read, 1=write
 * Returns 0 on success, negative errno on failure.
 */
uint64_t
sys_blkdev_io(uint64_t arg1, uint64_t arg2, uint64_t arg3,
              uint64_t arg4, uint64_t arg5)
{
    aegis_process_t *proc = current_proc();
    uint32_t rights = (arg5 != 0) ? CAP_RIGHTS_WRITE : CAP_RIGHTS_READ;
    if (cap_check(proc->caps, CAP_TABLE_SIZE,
                  CAP_KIND_DISK_ADMIN, rights) != 0)
        return SYS_ERR(ENOCAP);

    /* Copy device name from user */
    char name[16];
    {
        uint64_t i;
        for (i = 0; i < 15; i++) {
            if (!user_ptr_valid(arg1 + i, 1))
                return SYS_ERR(EFAULT);
            char c;
            copy_from_user(&c, (const void *)(uintptr_t)(arg1 + i), 1);
            name[i] = c;
            if (c == '\0') break;
        }
        name[15] = '\0';
    }

    blkdev_t *dev = blkdev_get(name);
    if (!dev) return SYS_ERR(ENODEV);

    uint64_t lba   = arg2;
    uint64_t count = arg3;
    if (count == 0) return 0;
    /* Overflow-safe bounds check. `lba + count` can wrap a uint64_t when
     * lba is near 2^64, which would let an out-of-range LBA slip past a
     * naive `lba + count > block_count` test. The first clause guarantees
     * count <= block_count, so block_count - count cannot underflow. */
    if (count > dev->block_count || lba > dev->block_count - count)
        return SYS_ERR(EINVAL);

    /* Transfer one native LBA at a time using a kernel bounce buffer.
     * Chunk clamped so chunk * block_size <= sizeof(s_bounce). */
    static uint8_t s_bounce[4096];
    static spinlock_t blkdev_io_lock = SPINLOCK_INIT;
    irqflags_t io_fl = spin_lock_irqsave(&blkdev_io_lock);
    uint32_t bs = dev->block_size ? dev->block_size : 512u;
    uint32_t max_chunk = (uint32_t)(sizeof(s_bounce) / bs);
    if (max_chunk < 1u) max_chunk = 1u;
    uint64_t done = 0;
    uint64_t rc = 0;
    while (done < count) {
        uint32_t chunk = (uint32_t)(count - done);
        if (chunk > max_chunk) chunk = max_chunk;
        uint64_t user_off = done * (uint64_t)bs;
        uint64_t nbytes   = (uint64_t)chunk * bs;

        if (arg5 == 0) {
            /* Read: dev → bounce → user */
            if (dev->read(dev, lba + done, chunk, s_bounce) < 0)
                { rc = SYS_ERR(EIO); break; }  /* EIO */
            if (!user_ptr_valid(arg4 + user_off, nbytes))
                { rc = SYS_ERR(EFAULT); break; }
            copy_to_user((void *)(uintptr_t)(arg4 + user_off), s_bounce, nbytes);
        } else {
            /* Write: user → bounce → dev */
            if (!user_ptr_valid(arg4 + user_off, nbytes))
                { rc = SYS_ERR(EFAULT); break; }
            copy_from_user(s_bounce,
                           (const void *)(uintptr_t)(arg4 + user_off), nbytes);
            if (dev->write(dev, lba + done, chunk, s_bounce) < 0)
                { rc = SYS_ERR(EIO); break; }  /* EIO */
        }
        done += chunk;
    }
    spin_unlock_irqrestore(&blkdev_io_lock, io_fl);
    return rc;
}

/*
 * sys_gpt_rescan — syscall 512
 * Re-scan GPT on a named block device.
 * arg1 = user pointer to device name
 * Returns number of partitions, or negative errno.
 */
uint64_t
sys_gpt_rescan(uint64_t arg1)
{
    aegis_process_t *proc = current_proc();
    if (cap_check(proc->caps, CAP_TABLE_SIZE,
                  CAP_KIND_DISK_ADMIN, CAP_RIGHTS_WRITE) != 0)
        return SYS_ERR(ENOCAP);

    char name[16];
    {
        uint64_t i;
        for (i = 0; i < 15; i++) {
            if (!user_ptr_valid(arg1 + i, 1))
                return SYS_ERR(EFAULT);
            char c;
            copy_from_user(&c, (const void *)(uintptr_t)(arg1 + i), 1);
            name[i] = c;
            if (c == '\0') break;
        }
        name[15] = '\0';
    }

    int n = gpt_rescan(name);
    return (uint64_t)(int64_t)n;
}

/*
 * sys_fb_map — syscall 513
 * Map the linear framebuffer into the calling process's address space.
 * arg1 = user pointer to fb_info struct to fill:
 *   struct { uint64_t addr; uint32_t width, height, pitch, bpp; }
 * Returns the user virtual address of the mapped framebuffer, or negative errno.
 */
uint64_t
sys_fb_map(uint64_t arg1)
{
    aegis_process_t *proc = current_proc();
    if (cap_check(proc->caps, CAP_TABLE_SIZE,
                  CAP_KIND_FB, CAP_RIGHTS_READ) != 0)
        return SYS_ERR(EPERM);

    /* virtio-gpu path: when an accelerated GPU is live, publish its backing
     * framebuffer (WB-cached RAM the compositor draws into) instead of the
     * direct Limine scanout. The compositor calls sys_fb_flush() after each
     * frame to push the backing to the host (TRANSFER_TO_HOST_2D + FLUSH). The
     * backing is KVA-contiguous but physically scattered, so map per page. */
    if (virtio_gpu_active()) {
        uint32_t gw, gh, gpitch;
        uint8_t *kva = virtio_gpu_framebuffer(&gw, &gh, &gpitch);
        if (kva) {
            fb_lock_compositor();
            uint32_t bytes = gpitch * gh;
            uint32_t pages = (bytes + 0xFFF) / 0x1000;
            uint64_t len_b = (uint64_t)pages * 0x1000;
            uint64_t base_va = proc->mmap_base;
            /* Bound the bump allocator against the user canonical boundary
             * before advancing (same rationale as the direct-fb path). */
            if (base_va + len_b > USER_ADDR_MAX || base_va + len_b < base_va)
                return SYS_ERR(ENOMEM);
            proc->mmap_base += len_b;
            uint32_t k;
            for (k = 0; k < pages; k++) {
                uint64_t pa = kva_page_phys((void *)(kva + (uint64_t)k * 0x1000));
                vmm_map_user_page(proc->pml4_phys,
                                  base_va + (uint64_t)k * 0x1000, pa,
                                  VMM_FLAG_PRESENT | VMM_FLAG_WRITABLE |
                                  VMM_FLAG_USER | VMM_FLAG_SHARED);
                                  /* WB cached — not MMIO. VMM_FLAG_SHARED: this
                                   * is the GPU driver's RAM, not owned by this
                                   * process — fork must not COW it and exit must
                                   * not free it (see vmm.h). */
            }
            /* Record the mapping as a VMA (VMA_SHARED: backing is the GPU's
             * KVA RAM, not owned by this process). Unwind on table overflow. */
            if (vma_insert(proc, base_va, len_b,
                           VMM_FLAG_PRESENT | VMM_FLAG_WRITABLE | VMM_FLAG_USER,
                           VMA_SHARED) != 0) {
                for (k = 0; k < pages; k++)
                    vmm_unmap_user_page(proc->pml4_phys,
                                        base_va + (uint64_t)k * 0x1000);
                return SYS_ERR(ENOMEM);
            }
            if (user_ptr_valid(arg1, 24)) {
                uint64_t va = base_va;
                uint32_t bpp = 32;
                copy_to_user((void *)(uintptr_t)arg1, &va, 8);
                copy_to_user((void *)(uintptr_t)(arg1 + 8), &gw, 4);
                copy_to_user((void *)(uintptr_t)(arg1 + 12), &gh, 4);
                copy_to_user((void *)(uintptr_t)(arg1 + 16), &gpitch, 4);
                copy_to_user((void *)(uintptr_t)(arg1 + 20), &bpp, 4);
            }
            printk("[FB] OK: compositor mapped virtio-gpu backing %ux%u\n",
                   gw, gh);
            return base_va;
        }
    }

    uint64_t fb_phys;
    uint32_t width, height, pitch;
    if (!fb_get_phys_info(&fb_phys, &width, &height, &pitch))
        return SYS_ERR(ENODEV);  /* ENODEV — no framebuffer */

    fb_lock_compositor();

    uint32_t fb_bytes = pitch * height;
    uint32_t fb_pages = (fb_bytes + 0xFFF) / 0x1000;
    uint64_t fb_len_b = (uint64_t)fb_pages * 0x1000;

    /* Pick a user VA for the mapping.
     * Use the process mmap_base bump allocator (same as sys_mmap).
     * Bound the bump against the user canonical boundary first: repeated
     * fb_map calls or a large FB could otherwise push mmap_base into the
     * non-canonical hole / kernel half, and subsequent sys_mmap calls would
     * hand out unusable VAs. */
    uint64_t base_va = proc->mmap_base;
    if (base_va + fb_len_b > USER_ADDR_MAX || base_va + fb_len_b < base_va)
        return SYS_ERR(ENOMEM);
    proc->mmap_base += fb_len_b;

    /* Map each FB physical page into the user's address space */
    uint32_t i;
    for (i = 0; i < fb_pages; i++) {
        vmm_map_user_page(proc->pml4_phys,
                          base_va + (uint64_t)i * 0x1000,
                          fb_phys + (uint64_t)i * 0x1000,
                          VMM_FLAG_PRESENT | VMM_FLAG_WRITABLE |
                          VMM_FLAG_USER | VMM_FLAG_WC | VMM_FLAG_SHARED);
                          /* SHARED: hardware scanout frames, not owned here. */
    }

    /* Record the FB region as a VMA so sys_munmap/sys_mprotect can find it and
     * /proc/<pid>/maps is accurate. VMA_SHARED: the phys frames belong to the
     * hardware/Limine scanout, not this process, so teardown must not free
     * them. On table overflow, unwind the PTE installs and return -ENOMEM. */
    if (vma_insert(proc, base_va, fb_len_b,
                   VMM_FLAG_PRESENT | VMM_FLAG_WRITABLE | VMM_FLAG_USER,
                   VMA_SHARED) != 0) {
        for (i = 0; i < fb_pages; i++)
            vmm_unmap_user_page(proc->pml4_phys, base_va + (uint64_t)i * 0x1000);
        return SYS_ERR(ENOMEM);
    }

    /* Fill user info struct: { uint64_t addr; uint32_t w, h, pitch, bpp } */
    if (user_ptr_valid(arg1, 24)) {
        uint64_t va = base_va;
        uint32_t bpp = 32;
        copy_to_user((void *)(uintptr_t)arg1, &va, 8);
        copy_to_user((void *)(uintptr_t)(arg1 + 8), &width, 4);
        copy_to_user((void *)(uintptr_t)(arg1 + 12), &height, 4);
        copy_to_user((void *)(uintptr_t)(arg1 + 16), &pitch, 4);
        copy_to_user((void *)(uintptr_t)(arg1 + 20), &bpp, 4);
    }

    return base_va;
}

/*
 * sys_fb_flush — syscall 515
 * Present the compositor's framebuffer to the display. On virtio-gpu this
 * issues TRANSFER_TO_HOST_2D + RESOURCE_FLUSH for the full scanout; on a direct
 * Limine framebuffer it is a no-op (writes already hit the scanout). Always
 * returns 0 — a missing GPU is not an error, just nothing to flush. Runs in the
 * caller's context, so the synchronous GPU command spin is safe here.
 *
 * Requires CAP_KIND_FB — the same gate sys_fb_map uses. Presenting the
 * framebuffer is a display-owner operation; only the compositor (which already
 * holds FB to map the scanout) has any business pushing scanout to the host.
 * Gating it closes the inconsistency where map was capability-gated but the
 * paired present was not (T1 cap-completeness audit).
 */
uint64_t
sys_fb_flush(void)
{
    aegis_process_t *proc = current_proc();
    if (cap_check(proc->caps, CAP_TABLE_SIZE,
                  CAP_KIND_FB, CAP_RIGHTS_READ) != 0)
        return SYS_ERR(ENOCAP);
    virtio_gpu_flush();
    return 0;
}
