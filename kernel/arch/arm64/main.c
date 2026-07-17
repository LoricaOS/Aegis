/*
 * kernel/arch/arm64/main.c — arm64 kernel entry (Limine boot protocol).
 *
 * The arm64 twin of kernel/core/main.c (which is x86-only). Reached via
 * entry.S → start.c:arm64_early_entry → limine_boot_entry →
 * kernel_main_limine (here), on the kernel's own boot stack.
 *
 * Bring-up mirrors the x86 order where the subsystems exist; the missing
 * pieces (PCIe/NVMe/virtio/SMP APs) are v1 gaps, not design differences —
 * the rootfs comes from the Limine boot module (ramdisk0 → ext2), which
 * is all `make test-arm64` needs to exec a real /bin/vigil.
 */

#include "arch.h"
#include "printk.h"
#include "bootinfo.h"
#include "cap.h"
#include "pmm.h"
#include "vmm.h"
#include "kva.h"
#include "sched.h"
#include "proc.h"
#include "vfs.h"
#include "console.h"
#include "smp.h"
#include "ext2.h"
#include "gpt.h"
#include "pcie.h"
#include "fdt.h"
#include "virtio.h"   /* virtio_blk_init */
#include "virtio_gpu.h"
#include "fb.h"
#include "ramdisk.h"
#include "ip.h"
#include "blkdev.h"
#include "random.h"
#include "poll.h"
#include <stdint.h>

void poll_test(void);
void arm64_map_early_uart(void);
void uaccess_selftest(void);

/* (g_cow_fork / g_lazyfile / g_perfbench_mm are defined in
 * sys_process.c / sys_memory.c — shared, default-ON like x86.) */

static void
task_idle(void)
{
    arch_enable_irq();
    for (;;)
        arch_wait_for_irq();
}

/* kernel_main_arm64 — shared continuation for every arm64 boot path.
 * Reached two ways:
 *   - Limine: kernel_main_limine(bi) below does arch_mm_ingest(bi) +
 *     arm64_map_early_uart() + serial_init() first (Limine's HHDM doesn't
 *     map device MMIO, so a temporary TTBR0 idmap is needed), then calls
 *     here.
 *   - Native (non-Limine, non-UEFI; kernel/arch/arm64/native_entry.c):
 *     kernel_main_native(dtb_phys) does arch_mm_init_native(dtb_phys) +
 *     serial_init() (no separate idmap needed — boot_probe.S's own TTBR0
 *     already covers the real UART, see that file's page-table comment),
 *     then calls here. Mirrors the x86 kernel_main(mb_magic,mb_info) /
 *     kernel_main_limine(bi) split (kernel/core/main.c) — same pattern,
 *     "don't build a fake bootinfo_t for the non-Limine path" (see
 *     kernel/core/bootinfo.h). */
void
kernel_main_arm64(void)
{
    smp_percpu_init_bsp();    /* TPIDR_EL1 — before any sched_current() */
    idt_init();               /* VBAR_EL1 — catch faults from here on   */

    {
        const char *cmdline = arch_get_cmdline();
        if (cmdline[0])
            printk("[CMDLINE] OK: %s\n", cmdline);
        else
            printk("[CMDLINE] OK: (none)\n");
    }

    fdt_init();               /* capture DTB now — HHDM dies at vmm_init */
    arch_mm_populate_regions_from_dtb();  /* no-op if Limine gave us usable[] already */

#if defined(AEGIS_BOOT_NATIVE) && defined(AEGIS_NATIVE_TEST_STOP) && AEGIS_NATIVE_TEST_STOP <= 1
    /* TEMPORARY (native-boot bring-up, one-subsystem-per-flash discipline
     * -- see rpi5-port-research memory): park here so a hang further
     * down can't be confused with a bug in fdt_init/arch_mm_populate_
     * regions_from_dtb, both genuinely new-to-this-hardware code. Bump
     * AEGIS_NATIVE_TEST_STOP (Makefile.pi5native) and re-flash to advance
     * past the next subsystem; remove once the whole chain is proven. */
    printk("[NATIVE] test-stop 1: fdt_init + region parse done, region_count=%u\n",
           (unsigned)arch_mm_region_count());
    for (;;) { __asm__ volatile("wfi"); }
#endif

    pmm_init();

#if defined(AEGIS_BOOT_NATIVE) && defined(AEGIS_NATIVE_TEST_STOP) && AEGIS_NATIVE_TEST_STOP <= 2
    /* DIAGNOSTIC (temporary): vmm_init's first pmm_alloc_page() reported
     * OOM despite pmm_init's own "8188MB usable" line -- dump the raw
     * region list + bootstrap-bitmap free count to discriminate "nothing
     * freed in the <4GB bootstrap window" from "alloc/free/reserve logic
     * bug" before touching any pmm/vmm code (see rpi5-port-research memory). */
    {
        uint32_t                  nr = arch_mm_region_count();
        const aegis_mem_region_t *rg = arch_mm_get_regions();
        for (uint32_t i = 0; i < nr; i++)
            printk("[NATIVE]   region[%u] base=0x%lx len=0x%lx (end=0x%lx)\n",
                   (unsigned)i, rg[i].base, rg[i].len, rg[i].base + rg[i].len);
        printk("[NATIVE]   pmm_free_pages()=%lu\n", pmm_free_pages());
    }
    printk("[NATIVE] test-stop 2: pmm_init done\n");
    for (;;) { __asm__ volatile("wfi"); }
#endif

    vmm_init();               /* TTBR1 kernel tables + DMAP go live     */
    serial_set_base(arch_dmap(arch_mm_get_uart_phys()));  /* off the early idmap */

#if defined(AEGIS_BOOT_NATIVE) && defined(AEGIS_NATIVE_TEST_STOP) && AEGIS_NATIVE_TEST_STOP <= 3
    printk("[NATIVE] test-stop 3: vmm_init done, UART re-based, still alive\n");
    for (;;) { __asm__ volatile("wfi"); }
#endif
    kva_init();
    pmm_init_late();
    pmm_set_alloc_high_pref(1);
    arch_set_master_pml4(vmm_get_master_pml4());
    uaccess_selftest();       /* [UACCESS] OK: EL1 fault fixup             */

#if defined(AEGIS_BOOT_NATIVE) && defined(AEGIS_NATIVE_TEST_STOP) && AEGIS_NATIVE_TEST_STOP <= 4
    /* TEMPORARY (native-boot bring-up): a prior red-team investigation
     * (see the "dsb ishst" fix, kernel/arch/arm64/vmm.c ensure_table/
     * map_page_in) flagged kva_alloc_pages()-backed refcount-array
     * allocation right in this span as a still-open early-boot crash
     * risk on real Cortex-A cores -- stop here to isolate it from
     * anything gic/timer/pcie touch next. */
    printk("[NATIVE] test-stop 4: kva_init+pmm_init_late+uaccess_selftest done\n");
    for (;;) { __asm__ volatile("wfi"); }
#endif

    fb_init();                /* silent when Limine gave no framebuffer */
    cap_init();
    gic_init();
    timer_init();

#if defined(AEGIS_BOOT_NATIVE) && defined(AEGIS_NATIVE_TEST_STOP) && AEGIS_NATIVE_TEST_STOP <= 5
    /* TEMPORARY (native-boot bring-up): gic_init/timer_init are genuinely
     * new to this hardware (GICv2/GIC-400 dispatch, see gic.c) -- stop
     * here before pcie_init, which is a known landmine on real Pi 5 (its
     * DTB-lookup fallback assumes a QEMU-only ECAM address; see task list
     * "Guard pcie_init() against non-ECAM hardware"). */
    printk("[NATIVE] test-stop 5: gic_init+timer_init done\n");
    for (;;) { __asm__ volatile("wfi"); }
#endif

    poll_sources_init();
    kbd_init();               /* PL011 RX console input                 */
    gic_enable_spi(33);       /* UART0 interrupt                        */
    random_init();
    pcie_init();              /* ECAM enumerate — [PCIE] OK or skip     */
    virtio_blk_init();        /* virtio-blk disk → vblk0 (poll mode)    */
    virtio_input_init();      /* virtio keyboard + mouse (desktop input) */
    virtio_gpu_init();        /* virtio-gpu scanout → compositor fb      */

    /* Boot modules → RAM blkdevs (rootfs, optional ESP image). */
    {
        uint64_t mod_phys = 0,  mod_size = 0;
        uint64_t mod2_phys = 0, mod2_size = 0;
        arch_get_module(&mod_phys, &mod_size);
        ramdisk_init(mod_phys, mod_size);
        arch_get_module2(&mod2_phys, &mod2_size);
        ramdisk_init2(mod2_phys, mod2_size);
        if (mod_size > 0 || mod2_size > 0) {
            pmm_unreserve_region(mod_phys, mod_size);
            pmm_unreserve_region(mod2_phys, mod2_size);
            printk("[PMM] OK: module pages reclaimed\n");
        }
    }

    vfs_init();
    console_init();

    /* Root filesystem: a boot-module ramdisk wins (live/test media); else
     * try a virtio-blk disk (GPT partition, then whole-disk ext2). */
    gpt_scan("vblk0");
    if (blkdev_get("ramdisk0")) {
        ext2_mount("ramdisk0");
    } else if (ext2_mount("vblk0p1") == 0) {
        /* Aegis partition on a virtio-blk disk */
    } else if (ext2_mount("vblk0") == 0) {
        /* whole-disk ext2 on virtio-blk */
    } else {
        printk("[VFS] WARN: no ramdisk and no virtio-blk root — initrd only\n");
    }

    cap_policy_load();        /* /etc/aegis/caps.d/ — after ext2 mount  */
    ext2_anchors_reload();
    cap_anchor_audit();
    poll_test();

    virtio_net_init();        /* virtio-net NIC → eth0 (poll mode)      */
    net_init();               /* loopback + TCP + eth0 stack            */

    smp_start_aps();          /* PSCI CPU_ON secondary cores — [SMP] OK  */
    sched_init();
    sched_spawn_idle(task_idle);   /* BSP (cpu 0) idle                   */
    /* One idle task per online AP so each core has its own hlt fallback
     * (adopted by the AP in ap_c_entry once sched_start sets the ready
     * flag). Mirrors kernel/core/main.c on x86. */
    if (g_ap_sched_enabled)
        for (uint32_t c = 1; c < g_cpu_count; c++)
            sched_spawn_idle_for(c, task_idle);
    proc_spawn_init();        /* exec /bin/vigil from the rootfs        */

    vmm_teardown_identity();  /* oracle line; nothing to tear down      */

    sched_start();
    __builtin_unreachable();
}

#ifndef AEGIS_BOOT_NATIVE
/* Limine boot protocol continuation (kernel/core/limine.c). Not compiled
 * for the native build (Makefile.pi5native defines AEGIS_BOOT_NATIVE) --
 * arm64_map_early_uart() lives in start.c, which the native build doesn't
 * link (its own entry, kernel/arch/arm64/native/boot_probe.S, does the
 * EL2->EL1 drop + MMU enable + identity map itself; see
 * kernel/arch/arm64/native_entry.c for that path's own thin wrapper). */
void
kernel_main_limine(const aegis_bootinfo_t *bi)
{
    arch_mm_ingest(bi);
    arm64_map_early_uart();   /* TTBR0 device idmap → PL011 reachable */
    serial_init();
    printk("[SERIAL] OK: PL011 UART initialized\n");
    kernel_main_arm64();
}
#endif
