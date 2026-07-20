/*
 * kernel/core/main.c — x86-64 kernel entry point.
 *
 * Arch isolation note (2026-04-12): This file is the x86-64 kernel
 * main. It pulls in x86-only subsystems (ACPI, LAPIC, IOAPIC, PCIe,
 * NVMe, xHCI, i8042) and is NOT built by the ARM64 Makefile
 * (kernel/arch/arm64/Makefile). The ARM64 port has its own entry
 * point at kernel/arch/arm64/main.c. Do not add arch-agnostic
 * initialization here — put it in a shared helper that both entries
 * can call, or guard it with #ifdef __x86_64__.
 */
#ifndef __x86_64__
#error "kernel/core/main.c is x86-64 only; arm64 uses kernel/arch/arm64/main.c"
#endif

#include "arch.h"
#include "printk.h"
#include "trace.h"
#include "poll.h"
#include "cap.h"
#include "pmm.h"
#include "vmm.h"
#include "kva.h"
#include "kasan.h"
#include "sched.h"
#include "proc.h"
#include "vfs.h"
#include "console.h"
#include "acpi.h"
#include "smp.h"
#include "lapic.h"
#include "ioapic.h"
#include "pcie.h"
#include "nvme.h"
#include "ahci.h"
#include "pvscsi.h"
#include "hyperv.h"
#include "hv_kbd.h"
#include "hv_timesync.h"
#include "hv_mouse.h"
#include "hv_heartbeat.h"
#include "hv_shutdown.h"
#include "hv_kvp.h"
#include "vmbus.h"
#include "ext2.h"
#include "gpt.h"
#include "xhci.h"
#include "ps2_mouse.h"
#include "virtio_net.h"
#include "virtio_gpu.h"
#include "rtl8169.h"
#include "rtl8139.h"
#include "e1000.h"
#include "vmxnet3.h"
#include "iwl_ax200.h"
#include "hda.h"
#include "pvpanic.h"
#include "fb.h"
#include "ramdisk.h"
#include "ip.h"
#include "blkdev.h"
#include "random.h"
#include "bootinfo.h"
#include <stdint.h>

void poll_test(void);

/*
 * kernel_main — top-level kernel entry point.
 *
 * Called from boot.asm after long mode is established and the stack
 * is set up at boot_stack_top (higher-half virtual address).
 *
 * Arguments (System V AMD64 ABI, set in boot.asm):
 *   mb_magic — multiboot2 magic (0x36D76289)
 *   mb_info  — physical address of multiboot2 info struct
 */

/* Task 0: idle — enables interrupts and halts until next tick.
 * Never exits. Shutdown is triggered by sched_exit when the last user
 * process calls sys_exit.
 * Registered via sched_spawn_idle: NOT a run-queue member — the scheduler
 * selects it only when nothing else is runnable, so it no longer burns a
 * round-robin slice.  The BSP's LAPIC preemption timer is armed in
 * kernel_main before sched_start (not here), so preemption does not
 * depend on idle ever being scheduled. */
static void
task_idle(void)
{
    arch_enable_irq();
    /* Use sti;hlt;cli (arch_wait_for_irq) — NOT a bare hlt. The idle task can
     * be re-entered via ctx_switch with interrupts already disabled (e.g. it was
     * preempted mid-interrupt, saving IF=0; or a long IRQs-off kernel section
     * like a large COW fork hands off to it). A bare hlt with IF=0 halts the CPU
     * forever (no interrupt can wake it). sti;hlt;cli enables IRQs for each halt
     * so idle is always wakeable, matching the AP idle loop in smp.c. */
    for (;;)
        arch_wait_for_irq();
}

void kernel_main(uint32_t mb_magic, void *mb_info);

/* kernel_main_limine — Limine boot protocol continuation (see
 * kernel/core/limine.c). Runs on the kernel's own boot stack with the
 * bootloader's page tables still live. Adopt the ingested bootinfo into
 * arch_mm's statics, then run the ordinary kernel_main with no mb2 info —
 * arch_mm_init(NULL) knows the ingest already happened. */
void
kernel_main_limine(const aegis_bootinfo_t *bi)
{
    arch_mm_ingest(bi);
    kernel_main(0, NULL);
}

/* Boot phase profiler: record raw TSC at each milestone; converted to ms and
 * dumped once the TSC is calibrated (see the [BOOTPROF] table near the end). */
#define BOOT_NPHASE 24
static struct { const char *name; uint64_t tsc; } s_bph[BOOT_NPHASE];
static int s_bph_n;
static int g_bootprof;   /* `bootprof` cmdline → print the per-phase [BOOTPROF] table */
static void
bph(const char *name)
{
    if (s_bph_n < BOOT_NPHASE) {
        s_bph[s_bph_n].name = name;
        s_bph[s_bph_n].tsc  = arch_get_cycles();
        s_bph_n++;
    }
}

void
kernel_main(uint32_t mb_magic, void *mb_info)
{
    (void)mb_magic;

    /* Boot stopwatch: raw TSC at kernel entry, converted to ms once the TSC is
     * calibrated and reported just before init is spawned. A permanent baseline
     * for boot-speed work — see the [BOOT] line below. */
    uint64_t boot_tsc0 = arch_get_cycles();
    bph("(entry)");

    arch_init();            /* serial_init + vga_init                        */
    arch_pat_init();        /* PAT MSR: PA1=WC for framebuffer mapping       */
    arch_mm_init(mb_info);  /* parse multiboot2 memory map + cmdline         */
    /* Parse boot mode + quiet flag from kernel cmdline.
     * boot=text  → text console, no splash, printk writes to FB normally.
     * boot=graphical quiet → splash, printk suppressed on FB. */
    int text_mode = 0;
    {
        const char *cmdline = arch_get_cmdline();
        const char *p = cmdline;
        while (*p) {
            if (p[0]=='b' && p[1]=='o' && p[2]=='o' && p[3]=='t' &&
                p[4]=='=' && p[5]=='t' && p[6]=='e' && p[7]=='x' && p[8]=='t')
                { text_mode = 1; break; }
            p++;
        }
        if (!text_mode) {
            p = cmdline;
            while (*p) {
                if (p[0]=='q' && p[1]=='u' && p[2]=='i' && p[3]=='e' && p[4]=='t')
                    { printk_set_quiet(1); break; }
                p++;
            }
        }
        /* Multi-core scheduling is ON by default (APs run the scheduler).
         * `nosmp_sched` forces it off (APs halt, BSP-only) as a safety escape
         * hatch.  Matched as a distinct token so it does NOT collide with a
         * bare `smp_sched` substring. */
        {
            const char *q = cmdline;
            while (*q) {
                if (q[0]=='n'&&q[1]=='o'&&q[2]=='s'&&q[3]=='m'&&q[4]=='p'&&
                    q[5]=='_'&&q[6]=='s'&&q[7]=='c'&&q[8]=='h'&&q[9]=='e'&&q[10]=='d')
                    { g_ap_sched_enabled = 0; break; }
                q++;
            }
        }
        /* Opt-in process-lifecycle tracing: `proc_trace` emits a [PROC] line on
         * every fork/exec/exit.  Default off so boot output / the oracle are
         * unchanged.  Useful for watching a multi-process app's spawn sequence. */
        {
            const char *q = cmdline;
            while (*q) {
                if (q[0]=='p'&&q[1]=='r'&&q[2]=='o'&&q[3]=='c'&&q[4]=='_'&&
                    q[5]=='t'&&q[6]=='r'&&q[7]=='a'&&q[8]=='c'&&q[9]=='e')
                    { g_proc_trace = 1; break; }
                q++;
            }
        }
        /* Copy-on-write fork is DEFAULT-ON. The graphical+installed-NVMe
         * corruption that previously kept it off was root-caused (2026-06-28):
         * sys_fb_map published the GPU's WB system-RAM framebuffer backing into
         * every process WITHOUT marking it VMM_FLAG_SHARED, so COW fork copied
         * it and process teardown freed it — recycling the live scanout into a
         * kernel stack (the random #GP / reserved-bit faults). Fixed by exempting
         * VMM_FLAG_SHARED frames from COW and teardown (see research/cow-mm/03
         * deep-dive 7 + vmm.h). `nocow` forces the eager full-page-copy fork. */
        {
            const char *q = cmdline;
            while (*q) {
                if (q[0]=='n'&&q[1]=='o'&&q[2]=='c'&&q[3]=='o'&&q[4]=='w')
                    { g_cow_fork = 0; break; }
                q++;
            }
        }
        /* Perf instrumentation: `perfbench_mm` prints a [PERFMM] line per fork
         * with the address-space duplication cycle cost + page count. Default
         * off (oracle-safe). */
        {
            const char *q = cmdline;
            while (*q) {
                if (q[0]=='p'&&q[1]=='e'&&q[2]=='r'&&q[3]=='f'&&q[4]=='b'&&
                    q[5]=='e'&&q[6]=='n'&&q[7]=='c'&&q[8]=='h'&&q[9]=='_'&&
                    q[10]=='m'&&q[11]=='m')
                    { g_perfbench_mm = 1; break; }
                q++;
            }
        }
        /* `bootprof` — print the per-phase boot timing table ([BOOTPROF] lines).
         * Off by default (the one-line [BOOT] total is always printed). */
        {
            const char *q = cmdline;
            while (*q) {
                if (q[0]=='b'&&q[1]=='o'&&q[2]=='o'&&q[3]=='t'&&q[4]=='p'&&
                    q[5]=='r'&&q[6]=='o'&&q[7]=='f')
                    { g_bootprof = 1; break; }
                q++;
            }
        }
        /* Demand-paged file-backed mmap is the DEFAULT (g_lazyfile=1): a
         * MAP_PRIVATE ext2 file mapping records inode+offset and populates per
         * page on fault instead of eager-copying the whole file at mmap time.
         * `nolazyfile` forces the legacy eager path (A/B / safety escape).
         * Validated reading libs from a real NVMe device (installed boot). */
        {
            const char *q = cmdline;
            while (*q) {
                if (q[0]=='n'&&q[1]=='o'&&q[2]=='l'&&q[3]=='a'&&q[4]=='z'&&
                    q[5]=='y'&&q[6]=='f'&&q[7]=='i'&&q[8]=='l'&&q[9]=='e')
                    { g_lazyfile = 0; break; }
                q++;
            }
        }
        /* DIAG: `hwwatch` arms DR0-3 on every CPU to trap wild writes to
         * g_percpu[].self (SMP corruption hunt).  Default off. */
        {
            const char *q = cmdline;
            while (*q) {
                if (q[0]=='h'&&q[1]=='w'&&q[2]=='w'&&q[3]=='a'&&q[4]=='t'&&
                    q[5]=='c'&&q[6]=='h')
                    { g_hwwatch = 1; break; }
                q++;
            }
        }
        /* DIAG: `pmm_debug` turns on the PMM double-free sentinel — a symbolized
         * backtrace on any free of a managed-RAM page that is already free (a
         * double-free, a wrong-physical-frame producer). Default off so the
         * exact-match boot oracle is unaffected. Wire this into the SMP amplifier
         * runs (alongside smp_stress) to make the corruption class self-diagnosing.
         * Applied after pmm_init() below (the setter just flips a flag). */
        {
            const char *q = cmdline;
            while (*q) {
                if (q[0]=='p'&&q[1]=='m'&&q[2]=='m'&&q[3]=='_'&&q[4]=='d'&&
                    q[5]=='e'&&q[6]=='b'&&q[7]=='u'&&q[8]=='g')
                    { pmm_set_debug(1); break; }
                q++;
            }
        }
        /* DIAG: `pmm_acct` turns on the PMM ref/unref accounting ledger
         * (improve-mm T1) — a per-teardown scoreboard for the COW-fork
         * refcount-under-count hunt. Default off (oracle-safe). Applied after
         * pmm_init() (the setter just flips a flag). */
        {
            const char *q = cmdline;
            while (*q) {
                if (q[0]=='p'&&q[1]=='m'&&q[2]=='m'&&q[3]=='_'&&q[4]=='a'&&
                    q[5]=='c'&&q[6]=='c'&&q[7]=='t')
                    { pmm_set_acct(1); break; }
                q++;
            }
        }
        if (cmdline[0])
            printk("[CMDLINE] OK: %s\n", cmdline);
        else
            printk("[CMDLINE] OK: (none)\n");
    }
    pmm_init();             /* bitmap allocator — [PMM] OK                   */
    vmm_init();             /* page tables, higher-half map — [VMM] OK       */
    kva_init();             /* kernel virtual allocator — [KVA] OK           */
    kasan_init();           /* [KASAN] OK (KASAN=1 build only; else no-op)    */
#ifdef KASAN
    /* `kasantest` cmdline token: prove the instrumentation catches an OOB. */
    {
        extern void kasan_selftest(void);
        const char *q = arch_get_cmdline();
        for (; *q; q++)
            if (q[0]=='k'&&q[1]=='a'&&q[2]=='s'&&q[3]=='a'&&q[4]=='n'&&
                q[5]=='t'&&q[6]=='e'&&q[7]=='s'&&q[8]=='t') { kasan_selftest(); break; }
    }
#endif
    bph("mem");
    /* Swap the 4GB bootstrap bitmap for a full RAM-sized one now that KVA is
     * up (needs no identity map — it's higher-half). After this, all of RAM
     * is usable; before it, only the first 4GB. No-op on a <=4GB machine. */
    pmm_init_late();        /* full bitmap — [PMM] OK (only if >4GB)          */
    /* Bootstrap page tables are now placed (below 1GB via the identity map).
     * From here, prefer high (>=4GB) RAM for general allocations so the low
     * pool stays available for device DMA. No-op on a <=4GB machine. */
    pmm_set_alloc_high_pref(1);
    arch_set_master_pml4(vmm_get_master_pml4()); /* store master PML4 for ISR/SYSCALL */
    fb_init();              /* linear framebuffer — [FB] OK or silent        */
    bph("fb");
    if (!text_mode)
        fb_boot_splash();   /* draw logo immediately (graphical boot only)   */
    cap_init();             /* capability stub — [CAP] OK                    */
    smp_percpu_init_bsp();  /* per-CPU data — [SMP] OK                       */
    idt_init();             /* 48 interrupt gates — [IDT] OK                 */
    pic_init();             /* remap 8259A — [PIC] OK                        */
    pit_init();             /* 100 Hz timer — [PIT] OK                       */
    poll_sources_init();    /* register per-tick device pollers (silent)     */
    kbd_init();             /* PS/2 keyboard — [KBD] OK                      */
    ps2_mouse_init();       /* PS/2 mouse — [MOUSE] OK                       */
    arch_gdt_init();        /* ring-3 GDT + TSS descriptors — [GDT] OK       */
    arch_tss_init();        /* TSS RSP0 for ring-3 → ring-0 transitions      */
    arch_syscall_init();    /* enable SYSCALL/SYSRET MSRs — [SYSCALL] OK     */
    arch_smap_init();       /* SMAP detect + enable — [SMAP] OK/WARN         */
    arch_smep_init();       /* SMEP detect + enable — [SMEP] OK/WARN         */
    arch_sse_init();        /* enable SSE for user mode (CR0/CR4 bits)       */
    random_init();          /* ChaCha20 CSPRNG — [RNG] OK                    */
    bph("cpu+io");

    /* Map boot modules into KVA as RAM blkdevs */
    {
        uint64_t mod_phys = 0,  mod_size = 0;
        uint64_t mod2_phys = 0, mod2_size = 0;
        uint64_t mod3_phys = 0, mod3_size = 0;
        arch_get_module(&mod_phys, &mod_size);
        ramdisk_init(mod_phys, mod_size);    /* ramdisk0 = rootfs */
        arch_get_module2(&mod2_phys, &mod2_size);
        ramdisk_init2(mod2_phys, mod2_size); /* ramdisk1 = ESP image */
        arch_get_module3(&mod3_phys, &mod3_size);
        ramdisk_init_fw(mod3_phys, mod3_size); /* module2 = iwlwifi firmware blob */

        /* ramdisk_init/ramdisk_init2 COPY the module bytes into fresh KVA
         * pages (the originals may overlap future VMM page-table frames),
         * so the module physical ranges reserved by pmm_init are dead the
         * moment the copies complete. Release them — ~91 MB on a live
         * boot. The x86_reserved[] module entries in arch_mm.c are a
         * pmm_init-time input only and are never consulted again, so the
         * stale array entries are harmless. Installed-system boots have
         * no modules; this block is silent there. */
        if (mod_size > 0 || mod2_size > 0 || mod3_size > 0) {
            pmm_unreserve_region(mod_phys, mod_size);
            pmm_unreserve_region(mod2_phys, mod2_size);
            pmm_unreserve_region(mod3_phys, mod3_size);
            printk("[PMM] OK: module pages reclaimed\n");
        }
    }

    vfs_init();             /* [VFS] OK + [INITRD] OK                        */
    console_init();         /* register stdout device (silent)               */
    /* `mounttest` cmdline: exercise the mount table + VFS routing end to end. */
    {
        extern void mount_selftest(void);
        const char *q = arch_get_cmdline();
        for (; *q; q++)
            if (q[0]=='m'&&q[1]=='o'&&q[2]=='u'&&q[3]=='n'&&q[4]=='t'&&
                q[5]=='t'&&q[6]=='e'&&q[7]=='s'&&q[8]=='t') { mount_selftest(); break; }
    }
    bph("fs-base");
    acpi_init();            /* parse MCFG+MADT — [ACPI] OK                   */
    bph("acpi");
    fw_cfg_init();          /* QEMU/Proxmox fw_cfg host-injected config; silent */
    hyperv_init();          /* Hyper-V hypercall + SynIC foundation; silent off-HV */
    lapic_init();           /* Local APIC — [LAPIC] OK or silent skip        */
    ioapic_init();          /* I/O APIC — [IOAPIC] OK or silent skip         */
    bph("apic");
    /* Flush i8042 output buffer after PIC→IOAPIC transition.
     * Stale scancodes from BIOS/GRUB can hold IRQ1 asserted on the
     * i8042, preventing new keyboard interrupts until the buffer is
     * drained.  This fixes intermittent "no keyboard on boot" on bare
     * metal (2/3 boots affected on ThinkPad X13 Zen 2).
     * BOUND the drain: on platforms with no i8042 (Hyper-V Gen 2, which has
     * no legacy devices) port 0x64 reads 0xFF, so bit 0 is always set — an
     * unbounded loop here hangs the boot before PCIe. 64 reads is plenty to
     * drain a real controller's 16-byte buffer. */
    for (int i8042_drain = 0;
         (inb(0x64) & 0x01) && i8042_drain < 64;
         i8042_drain++)
        (void)inb(0x60);
    /* Calibrate the LAPIC-timer period + TSC ONCE, on the BSP, before any AP is
     * woken (smp_start_aps below). Each AP's lapic_timer_init then inherits this
     * value instead of re-running the ~10ms PIT-channel-2 spin — which, because
     * PIT ch2 is a single shared resource, serialized AP bring-up at ~10ms/core.
     * This is a no-op-cost move for single-CPU boots and saves ~10ms×(ncpu-1). */
    lapic_timer_calibrate();
    bph("intr+calib");
    pcie_init();            /* enumerate PCIe devices — [PCIE] OK            */
    bph("pcie");
    fb_check_amd();         /* warn if AMD GPU present but no UEFI fb tag    */
    virtio_gpu_init();      /* virtio-gpu 2D scanout — [GPU] OK or silent    */
    virtio_rng_init();      /* virtio-rng entropy — [RNG] mix or silent skip */
    nvme_init();            /* NVMe block device — [NVME] OK or silent skip  */
    ahci_init();            /* AHCI/SATA disk — [AHCI] OK or silent skip     */
    virtio_blk_init();      /* virtio-blk disk — [BLK] OK or silent skip     */
    virtio_scsi_init();     /* virtio-scsi disk — [SCSI] OK or silent skip   */
    pvscsi_init();          /* VMware PVSCSI disk — [PVSCSI] OK or silent skip */
    virtio_pmem_init();     /* virtio-pmem disk — [PMEM] OK or silent skip   */
    virtio_console_init();  /* virtio-console — [VCON] OK or silent skip     */
    virtio_9p_init();       /* virtio-9p host share — [9P] OK or silent skip */
    virtio_vsock_init();    /* virtio-vsock host↔guest socket — silent skip  */
    virtio_balloon_init();  /* virtio-balloon — [BALLOON] OK or silent skip  */
    virtio_input_init();    /* virtio-input kbd/tablet — [VINPUT] OK or skip  */
    vmbus_init();           /* Hyper-V VMBus connect + offer enumeration; silent off-HV */
    storvsc_init();         /* Hyper-V synthetic SCSI → hvdisk0; silent if absent */
    netvsc_init();          /* Hyper-V synthetic NIC → eth0; silent if absent */
    hv_kbd_init();          /* Hyper-V synthetic keyboard (Gen 2 has no i8042); silent if absent */
    hv_timesync_init();     /* Hyper-V time-sync IC → wall clock; silent if absent */
    hv_mouse_init();        /* Hyper-V synthetic mouse (Gen 2 has no PS/2 mouse); silent if absent */
    hv_heartbeat_init();    /* Hyper-V heartbeat IC → guest reports healthy; silent if absent */
    hv_shutdown_init();     /* Hyper-V shutdown IC → host-initiated graceful stop; silent if absent */
    hv_kvp_init();          /* Hyper-V KVP/data-exchange IC → guest OS info to host; silent if absent */
    bph("dev-probe");
    gpt_scan("nvme0");      /* GPT partitions — [GPT] OK or silent (no NVMe) */
    gpt_scan("sata0");      /* GPT on AHCI/SATA — silent if absent           */
    gpt_scan("vblk0");      /* GPT on virtio-blk — silent if absent          */
    gpt_scan("scsi0");      /* GPT on virtio-scsi — silent if absent         */
    gpt_scan("pvscsi0");    /* GPT on VMware PVSCSI — silent if absent        */
    gpt_scan("hvdisk0");    /* GPT on Hyper-V StorVSC — silent if absent      */
    gpt_scan("pmem0");      /* GPT on virtio-pmem — silent if absent         */
    /* Mount ext2 root filesystem.
     * If a ramdisk module is present (live USB/CDROM boot), ALWAYS use it —
     * never silently pick up an NVMe install which may be stale or broken.
     * Only mount NVMe when no ramdisk exists (installed system booting
     * from its own disk without GRUB modules). */
    if (blkdev_get("ramdisk0")) {
        ext2_mount("ramdisk0");
    } else if (ext2_mount("nvme0p1") == 0) {
        /* installed system on NVMe */
    } else if (ext2_mount("sata0p1") == 0) {
        /* Aegis partition on an AHCI/SATA disk */
    } else if (ext2_mount("sata0") == 0) {
        /* whole-disk ext2 on SATA */
    } else if (ext2_mount("vblk0p1") == 0) {
        /* Aegis partition on virtio-blk (cloud/QEMU disk) */
    } else if (ext2_mount("vblk0") == 0) {
        /* whole-disk ext2 on virtio-blk (unpartitioned cloud image) */
    } else if (ext2_mount("scsi0p1") == 0) {
        /* Aegis partition on a virtio-scsi disk */
    } else if (ext2_mount("scsi0") == 0) {
        /* whole-disk ext2 on virtio-scsi */
    } else if (ext2_mount("pvscsi0p1") == 0) {
        /* Aegis partition on a VMware PVSCSI disk */
    } else if (ext2_mount("pvscsi0") == 0) {
        /* whole-disk ext2 on VMware PVSCSI */
    } else if (ext2_mount("hvdisk0p1") == 0) {
        /* Aegis partition on a Hyper-V StorVSC disk (Gen 2 VM) */
    } else if (ext2_mount("hvdisk0") == 0) {
        /* whole-disk ext2 on Hyper-V StorVSC */
    } else {
        printk("[VFS] WARN: no ramdisk and no Aegis root on NVMe/virtio-blk — running from initrd only\n");
    }
    cap_policy_load();      /* load /etc/aegis/caps.d/ — must be after ext2  */
    ext2_anchors_reload();  /* register /etc/aegis/anchors install-anchors    */
    cap_anchor_audit();     /* WARN if a granting anchor isn't write-protected */
    poll_test();            /* VFS .poll self-test — [POLL] OK               */
    bph("mount+cap");
    xhci_init();            /* xHCI USB host — [XHCI] OK or silent skip     */
    gpt_scan("usb0");       /* GPT on a USB mass-storage device — silent if absent */
    virtio_net_init();      /* virtio-net NIC — [NET] OK or silent skip      */
    rtl8169_init();         /* RTL8168/8169 NIC — [NET] OK or silent skip   */
    rtl8139_init();         /* RTL8139 NIC — [NET] OK or silent skip        */
    e1000_init();           /* Intel e1000 NIC — [NET] OK or silent skip    */
    vmxnet3_init();         /* VMware vmxnet3 NIC — [NET] OK or silent skip  */
    iwl_ax200_init();       /* Intel Wi-Fi 6 AX200 — Phase 1 bring-up or skip */
    hda_init();             /* Intel HD Audio — [HDA] OK or silent skip      */
    pvpanic_init();         /* pvpanic guest→host notify — [PVPANIC] or skip */
    net_init();             /* Phase 25: protocol stack init + ICMP self-test ping */
    bph("usb+net");
    smp_start_aps();        /* wake APs via INIT-SIPI-SIPI — [SMP] OK       */
    bph("smp");
    hwwatch_arm_local();    /* DIAG: arm BSP watchpoints (no-op unless hwwatch);
                             * all g_percpu[].self are set by smp_start_aps now */
    sched_init();           /* init run queue (no tasks yet)                 */
    sched_spawn_idle(task_idle); /* BSP idle (cpu 0) — never enters run queue */
    /* One idle task per online AP (only when AP scheduling is enabled), so
     * every CPU has its own hlt fallback and two idle CPUs never adopt the
     * same task.  Pre-spawned here (BSP's sched_current() is valid) so the APs
     * can adopt theirs in ap_entry.  Skipped when APs halt (default) — no
     * point allocating idle TCBs/stacks the parked APs never use. */
    if (g_ap_sched_enabled)
        for (uint32_t c = 1; c < g_cpu_count; c++)
            sched_spawn_idle_for(c, task_idle);
    bph("sched");
    /* Boot stopwatch readout + per-phase breakdown (µs per phase, ms total).
     * kernel entry → here = all in-kernel init done, about to enter ring 3.
     * Guard on a calibrated TSC (0 without invariant). */
    if (arch_tsc_hz()) {
        uint64_t mhz = arch_tsc_hz() / 1000000;
        if (mhz) {
            if (g_bootprof)
                for (int i = 1; i < s_bph_n; i++)
                    printk("[BOOTPROF] %s %lu us\n", s_bph[i].name,
                           (s_bph[i].tsc - s_bph[i - 1].tsc) / mhz);
            printk("[BOOT] kernel init: %lu ms\n",
                   (arch_get_cycles() - boot_tsc0) / (mhz * 1000));
        }
    }
    proc_spawn_init();      /* spawn init user process in ring 3             */
    /* All TCBs and stacks are in kva range at this point —
     * safe to remove the identity map. */
    vmm_teardown_identity(); /* pml4[0] = 0, CR3 reload — [VMM] OK          */
    fb_boot_splash_end();   /* clear splash, unlock FB — all kernel init done */
    /* Arm the BSP's LAPIC preemption timer (vector 0x30, ~100 Hz) BEFORE
     * sched_start so a tick is guaranteed no matter which task runs first —
     * preemption must not depend on task_idle ever being scheduled (the PIT
     * no longer calls sched_tick; LAPIC = preemption, PIT = timekeeping +
     * polling).  Safe with IF=0 (set since boot): the PIT-channel-2
     * calibration inside lapic_timer_init is a polling spin on port 0x61
     * and needs no interrupts, and the armed vector 0x30 stays pending
     * until the first task enables interrupts — which happens only after
     * sched_start has set the s_sched_ready guard (sched_tick additionally
     * bails while no task is current).  APs finished their own channel-2
     * calibrations inside smp_start_aps (g_ap_online is set after
     * lapic_timer_init in ap_entry), so the shared PIT channel 2 is free.
     * lapic_timer_init prints nothing — boot oracle unaffected. */
    lapic_timer_init();
    /* `perfbench_fs` cmdline token: ext2 large-file write/read throughput on
     * the root.  Run HERE (after lapic_timer_init calibrates the TSC) so the
     * bench can time with arch_get_cycles()/arch_tsc_hz(); earlier in boot the
     * TSC frequency is still 0.  ext2 is mounted, BSP single-threaded, IF=0 —
     * safe.  Gated by the token so the boot oracle never sees it. */
    {
        const char *q = arch_get_cmdline();
        while (*q) {
            if (q[0]=='p'&&q[1]=='e'&&q[2]=='r'&&q[3]=='f'&&q[4]=='b'&&
                q[5]=='e'&&q[6]=='n'&&q[7]=='c'&&q[8]=='h'&&q[9]=='_'&&
                q[10]=='f'&&q[11]=='s')
                { ext2_perfbench(); break; }
            q++;
        }
    }
    sched_start();          /* prints [SCHED] OK, switches into first task   */
    /* UNREACHABLE — sched_start() never returns */
    __builtin_unreachable();
}
