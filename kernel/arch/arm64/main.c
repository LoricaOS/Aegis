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
#include "virtio.h"   /* virtio_blk_init */
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

void
kernel_main_limine(const aegis_bootinfo_t *bi)
{
    arch_mm_ingest(bi);
    arm64_map_early_uart();   /* TTBR0 device idmap → PL011 reachable */
    serial_init();
    printk("[SERIAL] OK: PL011 UART initialized\n");

    smp_percpu_init_bsp();    /* TPIDR_EL1 — before any sched_current() */
    idt_init();               /* VBAR_EL1 — catch faults from here on   */

    {
        const char *cmdline = arch_get_cmdline();
        if (cmdline[0])
            printk("[CMDLINE] OK: %s\n", cmdline);
        else
            printk("[CMDLINE] OK: (none)\n");
    }

    pmm_init();
    vmm_init();               /* TTBR1 kernel tables + DMAP go live     */
    serial_set_base(arch_dmap(0x09000000UL));  /* off the early idmap   */
    kva_init();
    pmm_init_late();
    pmm_set_alloc_high_pref(1);
    arch_set_master_pml4(vmm_get_master_pml4());
    uaccess_selftest();       /* [UACCESS] OK: EL1 fault fixup             */

    fb_init();                /* silent when Limine gave no framebuffer */
    cap_init();
    gic_init();
    timer_init();
    poll_sources_init();
    kbd_init();               /* PL011 RX console input                 */
    gic_enable_spi(33);       /* UART0 interrupt                        */
    random_init();
    pcie_init();              /* ECAM enumerate — [PCIE] OK or skip     */
    virtio_blk_init();        /* virtio-blk disk → vblk0 (poll mode)    */
    virtio_input_init();      /* virtio keyboard + mouse (desktop input) */

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

    net_init();               /* loopback + TCP (no NIC driver yet)     */

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
