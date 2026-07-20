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
#include "kbd.h"     /* kbd_inject — auto-repro console feed (NATIVE_REPRO) */
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
void kva_test_run(void);
void pcie_brcmstb_init(void);
void nvme_init(void);
void pi5_fb_init(void);        /* native/vc_mailbox_fb.c — VideoCore framebuffer */
void pi5_thermal_report(void); /* native/pi5_thermal.c — SoC temp via AVS monitor */
int  rp1_init(void);           /* native/rp1.c — RP1 southbridge (USB/eth/fan) */
void nvme_set_dma_offset(uint64_t off);
void nvme_set_dma_noncoherent(int nc);

#if defined(AEGIS_BOOT_NATIVE) && \
    (defined(AEGIS_NATIVE_TEST_STOP) || defined(AEGIS_NATIVE_REPRO) || \
     defined(AEGIS_NATIVE_WATCHDOG))
/* TEMPORARY (native-boot bring-up autonomy): arm the BCM2712 PM watchdog so
 * ANY hang self-recovers into a fresh TFTP-netboot -- it fires independent of
 * the (possibly wedged) CPU, unlike a PSCI self-reset. This is what makes the
 * iteration loop hang-proof: run -> watchdog resets ~16s later -> netboot
 * whatever kernel is staged, no human touch even when a build hangs.
 *
 * Address: watchdog@7d200000 (child) under soc@107c000000, whose ranges map
 * child 0 -> CPU 0x10_00000000, so CPU-physical 0x10_7d200000 -- inside the
 * UART's device block already mapped by vmm_init, hence reachable via
 * arch_dmap with no extra mapping. Register layout is the classic bcm2835 PM
 * watchdog (Debian's own dmesg shows the Pi 5 driven by the "Broadcom BCM2835
 * Watchdog timer"): PM_WDOG=+0x24, PM_RSTC=+0x1c, password 0x5a000000,
 * ~65536 ticks/s (0xfffff ~= 15.9s max). Only compiled into TEST_STOP debug
 * builds -- a real full boot must not be watchdog-reset mid-run. */
static void
native_arm_watchdog(void)
{
    volatile uint8_t *pm = (volatile uint8_t *)arch_dmap(0x107d200000UL);
    *(volatile uint32_t *)(pm + 0x24) = 0x5a000000UL | 0x000fffffUL; /* PM_WDOG max */
    uint32_t rstc = *(volatile uint32_t *)(pm + 0x1c);
    *(volatile uint32_t *)(pm + 0x1c) =
        0x5a000000UL | (rstc & 0xffffffcfUL) | 0x00000020UL;         /* WRCFG_FULL_RESET */
}

/* Petted watchdog: the timer tick (native_watchdog_tick, from timer_irq) re-arms
 * the ~16s watchdog while s_wdog_pet_ticks remain, keeping a healthy board up for
 * ~5 min instead of ~16s. When the count runs out the pet stops and the watchdog
 * fires — so the board still auto-recovers on a hang AND still cycles to pick up
 * a freshly-staged kernel, just on a 5-min cadence (uptime for interactive
 * testing while giving up the fast dev-loop). */
static volatile int32_t s_wdog_pet_ticks = 0;

void
native_watchdog_tick(void)
{
    if (s_wdog_pet_ticks > 0) {
        s_wdog_pet_ticks--;
        native_arm_watchdog();
    }
}

/* Disable the watchdog (clear PM_RSTC WRCFG so a timeout takes no action).
 * Called once we reach userland: the watchdog protects the (still flaky --
 * intermittent nvme_init hang) boot by resetting+retrying, but must not fire
 * during an interactive login session. Only the TEST_STOP path disables it;
 * the REPRO path deliberately leaves it armed so the board self-resets after
 * the repro output, closing the build->log->build loop with no power cycle. */
#if defined(AEGIS_NATIVE_TEST_STOP)
static void
native_disable_watchdog(void)
{
    volatile uint8_t *pm = (volatile uint8_t *)arch_dmap(0x107d200000UL);
    uint32_t rstc = *(volatile uint32_t *)(pm + 0x1c);
    *(volatile uint32_t *)(pm + 0x1c) = 0x5a000000UL | (rstc & 0xffffffcfUL);
}
#endif
#endif

#if defined(AEGIS_BOOT_NATIVE) && !(defined(AEGIS_NATIVE_TEST_STOP) || \
    defined(AEGIS_NATIVE_REPRO) || defined(AEGIS_NATIVE_WATCHDOG))
/* No watchdog compiled into this build — the timer's pet call is a no-op. */
void native_watchdog_tick(void) { }
#endif

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
 *   - Native (non-Limine, non-UEFI; kernel/arch/arm64/native/native_entry.c):
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

#if defined(AEGIS_BOOT_NATIVE) && \
    (defined(AEGIS_NATIVE_TEST_STOP) || defined(AEGIS_NATIVE_REPRO) || \
     defined(AEGIS_NATIVE_WATCHDOG))
    /* Arm the hardware watchdog as early as the DMAP allows, so a hang
     * anywhere past here (driver bring-up especially) self-recovers into a
     * fresh netboot ~16s later without any human touch. */
    native_arm_watchdog();
    s_wdog_pet_ticks = 3 * 60 * 100;   /* pet for ~3 min (100 Hz tick) then let it fire */
    printk("[NATIVE] watchdog armed, petted ~3min — hangs auto-reset+netboot\n");
#endif

#if defined(AEGIS_BOOT_NATIVE) && defined(AEGIS_NATIVE_TEST_STOP) && AEGIS_NATIVE_TEST_STOP <= 3
    printk("[NATIVE] test-stop 3: vmm_init done, UART re-based, still alive\n");
    for (;;) { __asm__ volatile("wfi"); }
#endif
    kva_init();
    pmm_init_late();
    pmm_set_alloc_high_pref(1);
    arch_set_master_pml4(vmm_get_master_pml4());
    uaccess_selftest();       /* [UACCESS] OK: EL1 fault fixup             */

    /* `kvatest` on the cmdline: stress the kernel VA allocator and assert its
     * integrity invariants before anything else allocates. Chasing the arm64
     * multi-page corruption — see kernel/mm/kva_test.c. */
    {
        const char *cl = arch_get_cmdline();
        for (const char *p2 = cl; p2 && *p2; p2++)
            if (p2[0]=='k' && p2[1]=='v' && p2[2]=='a' && p2[3]=='t' &&
                p2[4]=='e' && p2[5]=='s' && p2[6]=='t') { kva_test_run(); break; }
    }

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

#ifdef AEGIS_BOOT_NATIVE
    pi5_fb_init();            /* ask the VideoCore for a linear FB (real Pi 5) */
    pi5_thermal_report();     /* SoC temperature (AVS monitor) */
    rp1_init();               /* RP1 southbridge: domain-2 enum + CHIP_ID probe */
#endif
    fb_init();                /* silent when no framebuffer provided */
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
#ifdef AEGIS_BOOT_NATIVE
    gic_enable_spi(153);      /* Pi5 debug PL011 RX: DTB SPI 0x79 (+32) */
#else
    gic_enable_spi(33);       /* QEMU virt PL011 UART0 interrupt        */
#endif
    random_init();
    pcie_init();              /* ECAM enumerate — [PCIE] OK or skip     */
#ifdef AEGIS_BOOT_NATIVE
    /* TEMP: the Pi 5 PCIe/NVMe bring-up still has an intermittent hang, and
     * the rootfs comes from the initramfs (not nvme), so the clean interactive
     * boot (no NATIVE_TEST_STOP) SKIPS storage to reach a reliable login.
     * Storage still runs in the NATIVE_TEST_STOP debug builds where the flaky
     * hang is being worked. Re-enable unconditionally once it's fixed. */
#if defined(AEGIS_NATIVE_TEST_STOP)
    pcie_brcmstb_init();      /* real Pi 5: Broadcom RC bring-up (pcie1) */
#if defined(AEGIS_NATIVE_TEST_STOP) && AEGIS_NATIVE_TEST_STOP == 6
    /* TEMPORARY (native-boot bring-up): isolate the brand-new Broadcom
     * PCIe root-complex driver (first real hardware use, first PCIe owner
     * on this board) from virtio/vfs/ext2/net init below -- one thing per
     * flash, same discipline as every prior milestone this session. */
    printk("[NATIVE] test-stop 6: pcie_brcmstb_init done\n");
    for (;;) { __asm__ volatile("wfi"); }   /* watchdog resets ~16s → netboot */
#endif
    /* The Broadcom RC's inbound DMA window maps PCIe bus 0x10_00000000 ->
     * CPU 0x0 (see set_inbound_window in pcie_brcmstb.c), so the NVMe
     * controller must add this offset to every host DMA target. */
    nvme_set_dma_offset(0x1000000000UL);
    /* The RC has no `dma-coherent` in its DTB -> the controller does not
     * snoop the CPU cache; NVMe DMA buffers must be non-cacheable (now truly
     * Normal-NC after the native MAIR fix). */
    nvme_set_dma_noncoherent(1);
    nvme_init();              /* bind NVMe on the Broadcom RC → blkdev */
#endif /* storage gated on AEGIS_NATIVE_TEST_STOP (TEMP: flaky hang) */
#if defined(AEGIS_NATIVE_TEST_STOP) && AEGIS_NATIVE_TEST_STOP <= 7
    /* DIAGNOSTIC (temporary): prove real block I/O + GPT parsing on nvme0.
     * Read LBA0 (protective MBR: 0x55AA at 0x1FE) and LBA1 (GPT header:
     * "EFI PART"), then gpt_scan() to register partitions and list them. */
    {
        blkdev_t *d = blkdev_get("nvme0");
        if (!d) {
            printk("[NATIVE] no nvme0 blkdev — skipping I/O test\n");
        } else {
            static uint8_t s0[512], s1[512];
            int r0 = d->read(d, 0, 1, s0);
            int r1 = d->read(d, 1, 1, s1);
            printk("[NATIVE] nvme0 LBA0 read=%d sig=%x%x (want 55aa) | "
                   "LBA1 read=%d hdr=%c%c%c%c%c%c%c%c (want EFI PART)\n",
                   r0, (unsigned)s0[0x1FE], (unsigned)s0[0x1FF], r1,
                   s1[0], s1[1], s1[2], s1[3], s1[4], s1[5], s1[6], s1[7]);
            /* Dump the 4 MBR partition entries (LBA0 +0x1BE, 16B each) —
             * confirms the read returns real data + shows this disk is MBR
             * (Debian/raspios), which is why gpt_scan finds nothing. */
            for (int e = 0; e < 4; e++) {
                uint8_t *pe = &s0[0x1BE + e * 16];
                uint32_t start = pe[8] | (pe[9]<<8) | (pe[10]<<16) | ((uint32_t)pe[11]<<24);
                uint32_t nsec  = pe[12] | (pe[13]<<8) | (pe[14]<<16) | ((uint32_t)pe[15]<<24);
                if (pe[4]) printk("[NATIVE]   MBR part%d type=%x start=%u sectors=%u\n",
                                  e, (unsigned)pe[4], start, nsec);
            }
            int np = gpt_scan("nvme0");
            printk("[NATIVE] gpt_scan(nvme0) registered %d partition(s):\n", np);
            for (int i = 0; i < blkdev_count(); i++) {
                blkdev_t *p = blkdev_get_index(i);
                if (p) printk("[NATIVE]   blkdev '%s' %lu blocks x %u (lba_off %lu)\n",
                              p->name, p->block_count, p->block_size, p->lba_offset);
            }
        }
    }

    printk("[NATIVE] test-stop 7: nvme_init done\n");
    for (;;) { __asm__ volatile("wfi"); }   /* watchdog resets ~16s → netboot */
#endif
#endif
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
#if defined(AEGIS_BOOT_NATIVE) && defined(AEGIS_NATIVE_TEST_STOP)
    /* Reached userland: disable the boot watchdog so it can't fire during an
     * interactive login (it did its job protecting the flaky nvme_init boot). */
    native_disable_watchdog();
#endif
    proc_spawn_init();        /* exec INIT_PATH (/bin/vigil, or /bin/sh on REPRO) */

#if defined(AEGIS_BOOT_NATIVE) && defined(AEGIS_NATIVE_REPRO)
    /* Auto-repro (NATIVE_REPRO=1): INIT_PATH is /bin/sh, spawned above with
     * fd 0 = console. Pre-load the reported crash sequence into the PL011 RX
     * ring so the shell forks+execve's uname/cat/ls exactly as a human at the
     * login shell would — no keyboard, no power cycle. The bytes wait in the
     * ring until sh drains stdin. Three unames back-to-back answer the open
     * question: identical ELR/FAR each time = a real syscall/process-setup
     * bug; addresses that move = residual rootfs cache corruption. cat/ls show
     * whether the fault is uname-specific or hits every fork+execve'd binary.
     * Watchdog stays armed (never disabled on this path) → self-reset ~16s
     * after the output, closing the build→log→build loop hands-free. Keep the
     * string < RX_RING (256B). */
    {
        static const char repro[] =
            "uname\nuname\nuname\ncat /etc/issue\nls /\necho AEGIS_REPRO_END\n";
        for (const char *c = repro; *c; c++)
            kbd_inject(*c);
    }
#endif

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
 * kernel/arch/arm64/native/native_entry.c for that path's own thin wrapper). */
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
