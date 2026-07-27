# Aegis kernel — standalone build.
# Produces build/aegis.elf (a capability-based, POSIX-compatible x86-64
# microkernel-ish kernel). No userland: the kernel loads init from the root
# filesystem the bootloader/OS provides. See README.md.

CC      = x86_64-elf-gcc
AS      = nasm
LD      = x86_64-elf-ld
OBJCOPY = x86_64-elf-objcopy
NM      = x86_64-elf-nm
HOSTCC ?= cc

# Version: single source of truth is the VERSION file (NOT git) so builds are
# deterministic and reproducible anywhere. Stamped into the kernel (uname,
# /proc/version) via -DAEGIS_VERSION.
AEGIS_VERSION := $(shell cat VERSION 2>/dev/null || echo 0.0.0)

BUILD = build

# ── Configuration (kconf / Kconfig) ─────────────────────────────────────────
# `make <tier>_defconfig` (see configs/) writes .config; syncconfig turns it
# into the two artifacts the build consumes: build/generated/autoconf.h
# (#define CONFIG_* for source #ifdef guards) and build/auto.conf (Make vars,
# -include'd below so CONFIG_* gate the source lists). A bare `make` with no
# .config seeds configs/full_defconfig, preserving the historical build.
KCONF        ?= kconf
AUTOCONF_H   := $(BUILD)/generated/autoconf.h
AUTOCONF_MK  := $(BUILD)/auto.conf
export KCONFIG_CONFIG := .config
# Don't drag in config generation for clean/menuconfig/defconfig goals.
ifeq ($(filter clean distclean %config,$(MAKECMDGOALS)),)
-include $(AUTOCONF_MK)
endif

GCC_INCLUDE := $(shell $(CC) -print-file-name=include)
CFLAGS = \
    -ffreestanding -nostdlib -nostdinc \
    -isystem $(GCC_INCLUDE) \
    -mcmodel=kernel \
    -fno-pie -fno-pic \
    -mno-red-zone -mno-mmx -mno-sse -mno-sse2 \
    -fno-stack-protector \
    -fno-omit-frame-pointer \
    -O$(if $(CONFIG_CC_OPTIMIZE_FOR_SIZE),s,2) -fno-strict-aliasing \
    -ffunction-sections -fdata-sections \
    -g \
    -Wall -Wextra -Werror \
    -DAEGIS_VERSION=\"$(AEGIS_VERSION)\" \
    $(if $(wildcard $(AUTOCONF_H)),-include $(AUTOCONF_H)) \
    -Ikernel/arch/x86_64 -Ikernel/core -Ikernel/cap -Ikernel/mm \
    -Ikernel/sched -Ikernel/proc -Ikernel/syscall -Ikernel/fs \
    -Ikernel/tty -Ikernel/signal -Ikernel/drivers -Ikernel/net \
    $(EXTRA_CFLAGS)

ASFLAGS = -f elf64
# -z noseparate-code: emit ONE combined RWX PT_LOAD (text+rodata+data) instead
# of ld's default W^X-split segments. The kernel is designed to boot RWX (its
# early Limine-handoff path writes into the image before its own page tables are
# up; a non-writable text segment faults under Limine — 0 serial, triple fault).
# It also makes the segment layout DETERMINISTIC: without this, a tiny .text size
# change (e.g. one added symbol shifting the two-pass ksym blob) flips ld's
# auto-segment grouping and silently produces a non-booting image.
# --gc-sections drops every unreferenced function/data section (paired with
# -ffunction-sections/-fdata-sections above). The linker script KEEP()s all the
# boot roots (.multiboot, .limine_requests, __ex_table, .init_array), so only
# genuinely-dead code is removed — nano .text drops ~20% and still boots.
LDFLAGS = -T tools/linker.ld --gc-sections -nostdlib -z noseparate-code

# ── Kernel source lists ─────────────────────────────────��───────────────────
ARCH_SRCS = \
    kernel/arch/x86_64/arch.c \
    kernel/arch/x86_64/arch_exit.c \
    kernel/arch/x86_64/arch_mm.c \
    kernel/arch/x86_64/arch_vmm.c \
    kernel/arch/x86_64/serial.c \
    kernel/arch/x86_64/vga.c \
    kernel/arch/x86_64/idt.c \
    kernel/arch/x86_64/pic.c \
    kernel/arch/x86_64/pit.c \
    kernel/arch/x86_64/kbd.c \
    kernel/arch/x86_64/ps2_mouse.c \
    kernel/arch/x86_64/lapic.c \
    kernel/arch/x86_64/ioapic.c \
    kernel/arch/x86_64/smp.c \
    kernel/arch/x86_64/tlb.c \
    kernel/arch/x86_64/gdt.c \
    kernel/arch/x86_64/tss.c \
    kernel/arch/x86_64/arch_syscall.c \
    kernel/arch/x86_64/arch_smap.c \
    kernel/arch/x86_64/acpi.c \
    kernel/arch/x86_64/fw_cfg.c \
    kernel/arch/x86_64/hyperv.c \
    kernel/arch/x86_64/poll_sources.c \
    kernel/arch/x86_64/pcie.c \
    kernel/arch/x86_64/pvh.c \
    kernel/arch/x86_64/thermal.c

CORE_SRCS = \
    kernel/core/main.c \
    kernel/core/limine.c \
    kernel/core/printk.c \
    kernel/core/random.c \
    kernel/core/poll.c \
    kernel/core/ksym.c \
    kernel/core/trace.c \
    kernel/core/lockrank.c \
    kernel/cap/cap.c \
    kernel/cap/cap_policy.c

MM_SRCS = \
    kernel/mm/pmm.c \
    kernel/mm/vmm.c \
    kernel/mm/kva.c \
    kernel/mm/vma.c \
    kernel/lib/va_freelist.c \
    kernel/lib/string.c

# KASAN=1 — build the kernel with the Address Sanitizer (globals/BSS coverage).
# A debug-only build (slow: every memory access becomes an out-of-line call); it
# catches out-of-bounds reads/writes on static arrays. The runtime (kasan.c) is
# itself compiled WITHOUT the sanitizer via a dedicated rule below; kasan_test.c
# stays instrumented so `kasantest` on the cmdline can prove it fires.
ifeq ($(KASAN),1)
KASAN_CFLAGS = -fsanitize=kernel-address \
    --param asan-instrumentation-with-call-threshold=0 \
    --param asan-globals=1 --param asan-stack=0 \
    -fasan-shadow-offset=0xdffffc0000000000
CFLAGS  += $(KASAN_CFLAGS) -DKASAN=1
MM_SRCS += kernel/mm/kasan.c kernel/mm/kasan_test.c
endif

# UBSAN=1 — build the kernel with the Undefined Behavior Sanitizer. A debug-only
# build; the compiler emits an out-of-line __ubsan_handle_* call at every site it
# can't prove free of the checked classes. Disjoint from KASAN in what it catches,
# but the two don't co-fit: KASAN's redzones + UBSAN's checks together overrun the
# 8MB image window (tools/linker.ld), so run them as separate builds, not combined.
# -fsanitize-recover keeps the handlers non-abort so ubsan.c can report-and-continue.
#
# We enable a CURATED subset, not the full -fsanitize=undefined, matching how a
# real kernel (Linux CONFIG_UBSAN) configures it — for two reasons: (1) the full
# set's `alignment`/`object-size` checks fire constantly on a kernel's deliberate
# unaligned casts and pointer arithmetic, which is noise, not bugs; (2) that flood
# of extra checks bloats .text past the 8MB image window the linker enforces
# (tools/linker.ld). The subset below is the high-signal one: real arithmetic and
# indexing UB on (often untrusted) input at the trust boundary.
#
# The runtime (ubsan.c) is built WITHOUT the sanitizer via a dedicated rule below;
# ubsan_test.c stays instrumented so `ubsantest` on the cmdline can prove it fires.
ifeq ($(UBSAN),1)
UBSAN_CHECKS = shift,signed-integer-overflow,integer-divide-by-zero,bounds,unreachable,vla-bound,nonnull-attribute,returns-nonnull-attribute,pointer-overflow
UBSAN_CFLAGS = -fsanitize=$(UBSAN_CHECKS) -fsanitize-recover=undefined
CFLAGS  += $(UBSAN_CFLAGS) -DUBSAN=1
MM_SRCS += kernel/mm/ubsan.c kernel/mm/ubsan_test.c
endif

SCHED_SRCS  = kernel/sched/sched.c kernel/sched/waitq.c
SIGNAL_SRCS = kernel/signal/signal.c
TTY_SRCS    = kernel/tty/tty.c kernel/tty/pty.c

FS_SRCS = \
    kernel/fs/fd_table.c kernel/fs/vfs.c kernel/fs/initrd.c \
    kernel/fs/console.c kernel/fs/kbd_vfs.c kernel/fs/pipe.c \
    kernel/fs/blkdev.c kernel/fs/gpt.c \
    kernel/fs/ext2.c kernel/fs/ext2_cache.c kernel/fs/ext2_dir.c kernel/fs/ext2_vfs.c \
    kernel/fs/ext2_ops.c \
    kernel/fs/ramfs.c kernel/fs/procfs.c kernel/fs/memfd.c kernel/fs/eventfd.c \
    kernel/fs/mount.c \
    kernel/fs/poll_test.c

DRIVER_SRCS = \
    kernel/drivers/nvme.c kernel/drivers/ahci.c kernel/drivers/xhci.c \
    kernel/drivers/usb_hid.c kernel/drivers/usb_mouse.c \
    kernel/drivers/virtio_core.c kernel/drivers/virtio_mmio.c \
    kernel/drivers/virtio_pci.c kernel/drivers/virtqueue.c \
    kernel/drivers/virtio_net.c kernel/drivers/virtio_blk.c \
    kernel/drivers/virtio_scsi.c kernel/drivers/virtio_balloon.c \
    kernel/drivers/virtio_input.c kernel/drivers/virtio_pmem.c \
    kernel/drivers/virtio_console.c kernel/drivers/virtio_9p.c \
    kernel/drivers/virtio_rng.c kernel/drivers/virtio_gpu.c \
    kernel/drivers/virtio_vsock.c \
    kernel/drivers/rtl8169.c kernel/drivers/rtl8139.c \
    kernel/drivers/e1000.c kernel/drivers/vmxnet3.c \
    kernel/drivers/iwl_ax200.c \
    kernel/drivers/hda.c kernel/drivers/pvpanic.c \
    kernel/drivers/pvscsi.c \
    kernel/drivers/vmbus.c kernel/drivers/storvsc.c kernel/drivers/netvsc.c \
    kernel/drivers/hv_kbd.c kernel/drivers/hv_timesync.c kernel/drivers/hv_mouse.c \
    kernel/drivers/hv_ic.c kernel/drivers/hv_heartbeat.c kernel/drivers/hv_shutdown.c \
    kernel/drivers/hv_kvp.c \
    kernel/drivers/fb.c kernel/drivers/ramdisk.c

NET_SRCS = \
    kernel/net/netdev.c kernel/net/eth.c kernel/net/ip.c \
    kernel/net/udp.c kernel/net/tcp.c kernel/net/socket.c \
    kernel/net/unix_socket.c kernel/net/epoll.c

USERSPACE_SRCS = \
    kernel/syscall/syscall.c kernel/syscall/sys_io.c \
    kernel/syscall/sys_memory.c kernel/syscall/sys_process.c \
    kernel/syscall/sys_exec.c kernel/syscall/sys_identity.c \
    kernel/syscall/sys_hostname.c kernel/syscall/sys_adminconf.c \
    kernel/syscall/sys_cap.c kernel/syscall/sys_time.c \
    kernel/syscall/sys_file.c kernel/syscall/sys_dir.c \
    kernel/syscall/sys_mount.c \
    kernel/syscall/sys_meta.c kernel/syscall/sys_signal.c \
    kernel/syscall/sys_socket.c kernel/syscall/sys_poll.c kernel/syscall/sys_random.c \
    kernel/syscall/sys_disk.c kernel/syscall/futex.c \
    kernel/syscall/fd_waitq.c \
    kernel/syscall/uaccess_check.c \
    kernel/proc/proc.c kernel/proc/elf.c

BOOT_SRC  = kernel/arch/x86_64/boot.asm

ARCH_ASMS = \
    kernel/arch/x86_64/isr.asm \
    kernel/arch/x86_64/ctx_switch.asm \
    kernel/arch/x86_64/syscall_entry.asm \
    kernel/arch/x86_64/ap_trampoline.asm

# ── Config-gated subsystems ─────────────────────────────────────────────────
# Exclude optional sources when their CONFIG_ is off. Uses the same ifeq idiom
# as the KASAN/UBSAN knobs above. NET pulls in the whole protocol stack, the
# socket syscall, and every NIC driver (all useless without the stack).
ifneq ($(CONFIG_NET),y)
# Keep epoll.c — it provides the general poll/select/epoll syscalls (no net
# deps). net_stub.c satisfies the socket-syscall / fd-lookup / NIC symbols the
# core still references. Everything else net drops out.
NET_SRCS       := kernel/net/epoll.c kernel/net/net_stub.c
USERSPACE_SRCS := $(filter-out kernel/syscall/sys_socket.c,$(USERSPACE_SRCS))
DRIVER_SRCS    := $(filter-out \
    kernel/drivers/rtl8169.c kernel/drivers/rtl8139.c \
    kernel/drivers/e1000.c kernel/drivers/vmxnet3.c kernel/drivers/netvsc.c \
    kernel/drivers/iwl_ax200.c, $(DRIVER_SRCS))
endif

ifneq ($(CONFIG_AUDIO_HDA),y)
DRIVER_SRCS := $(filter-out kernel/drivers/hda.c, $(DRIVER_SRCS)) kernel/drivers/hda_stub.c
endif

# Hyper-V guest support: VMBus + all synthetic devices. netvsc also appears in
# the NET block — it needs both NET and HYPERV, so it drops if either is off.
ifneq ($(CONFIG_HYPERV),y)
ARCH_SRCS   := $(filter-out kernel/arch/x86_64/hyperv.c, $(ARCH_SRCS)) kernel/arch/x86_64/hyperv_stub.c
DRIVER_SRCS := $(filter-out \
    kernel/drivers/vmbus.c kernel/drivers/storvsc.c kernel/drivers/netvsc.c \
    kernel/drivers/hv_kbd.c kernel/drivers/hv_timesync.c kernel/drivers/hv_mouse.c \
    kernel/drivers/hv_heartbeat.c kernel/drivers/hv_ic.c kernel/drivers/hv_shutdown.c \
    kernel/drivers/hv_kvp.c, $(DRIVER_SRCS))
endif

# VirtIO: the transport (CONFIG_VIRTIO) plus an independent knob per device.
# virtio_stub.c (always built) supplies a no-op init/API for every device left
# out, so the call-sites stay edit-free. $(if $(CONFIG_X),,file) filters `file`
# out exactly when CONFIG_X is unset. virtio-net/vsock gate on their own knobs
# (which depend on NET && VIRTIO).
DRIVER_SRCS += kernel/drivers/virtio_stub.c
DRIVER_SRCS := $(filter-out \
    $(if $(CONFIG_VIRTIO),,kernel/drivers/virtio_core.c kernel/drivers/virtio_pci.c kernel/drivers/virtqueue.c) \
    $(if $(CONFIG_VIRTIO_MMIO),,kernel/drivers/virtio_mmio.c) \
    $(if $(CONFIG_VIRTIO_BLK),,kernel/drivers/virtio_blk.c) \
    $(if $(CONFIG_VIRTIO_SCSI),,kernel/drivers/virtio_scsi.c) \
    $(if $(CONFIG_VIRTIO_GPU),,kernel/drivers/virtio_gpu.c) \
    $(if $(CONFIG_VIRTIO_INPUT),,kernel/drivers/virtio_input.c) \
    $(if $(CONFIG_VIRTIO_RNG),,kernel/drivers/virtio_rng.c) \
    $(if $(CONFIG_VIRTIO_BALLOON),,kernel/drivers/virtio_balloon.c) \
    $(if $(CONFIG_VIRTIO_PMEM),,kernel/drivers/virtio_pmem.c) \
    $(if $(CONFIG_VIRTIO_CONSOLE),,kernel/drivers/virtio_console.c) \
    $(if $(CONFIG_VIRTIO_9P),,kernel/drivers/virtio_9p.c) \
    $(if $(CONFIG_VIRTIO_NET),,kernel/drivers/virtio_net.c) \
    $(if $(CONFIG_VIRTIO_VSOCK),,kernel/drivers/virtio_vsock.c) \
    , $(DRIVER_SRCS))

# Lean-build driver/test cuts. fb_stub / usb_stub satisfy the console, panic,
# poll and /proc symbols the core references when those drivers are gone.
ifneq ($(CONFIG_FB),y)
DRIVER_SRCS := $(filter-out kernel/drivers/fb.c, $(DRIVER_SRCS)) kernel/drivers/fb_stub.c
endif
ifneq ($(CONFIG_NVME),y)
DRIVER_SRCS := $(filter-out kernel/drivers/nvme.c, $(DRIVER_SRCS)) kernel/drivers/nvme_stub.c
endif
ifneq ($(CONFIG_AHCI),y)
DRIVER_SRCS := $(filter-out kernel/drivers/ahci.c, $(DRIVER_SRCS))
endif
ifneq ($(CONFIG_USB),y)
DRIVER_SRCS := $(filter-out kernel/drivers/xhci.c kernel/drivers/usb_hid.c kernel/drivers/usb_mouse.c, $(DRIVER_SRCS)) kernel/drivers/usb_stub.c
endif
ifneq ($(CONFIG_VMWARE),y)
DRIVER_SRCS := $(filter-out kernel/drivers/pvscsi.c, $(DRIVER_SRCS))
endif
ifneq ($(CONFIG_PVPANIC),y)
DRIVER_SRCS := $(filter-out kernel/drivers/pvpanic.c, $(DRIVER_SRCS))
endif
# CONFIG_PCI off (microVM, virtio-mmio only): swap pcie.c for a stub reporting an
# empty bus, and drop the virtio PCI transport. Any PCI driver left in still
# links against the stub and simply finds no devices.
ifneq ($(CONFIG_PCI),y)
ARCH_SRCS := $(filter-out kernel/arch/x86_64/pcie.c, $(ARCH_SRCS)) kernel/arch/x86_64/pcie_stub.c
DRIVER_SRCS := $(filter-out kernel/drivers/virtio_pci.c, $(DRIVER_SRCS))
endif
# CONFIG_ACPI off (Firecracker: no ACPI tables at all): swap acpi.c for a stub
# that reports no MADT/MCFG. smp.c / ioapic.c take their empty-table fallbacks
# (BSP-only, LAPIC timer, no I/O APIC). PCI depends on ACPI, so it is off too.
ifneq ($(CONFIG_ACPI),y)
ARCH_SRCS := $(filter-out kernel/arch/x86_64/acpi.c, $(ARCH_SRCS)) kernel/arch/x86_64/acpi_stub.c
endif
ifneq ($(CONFIG_KERNEL_TESTS),y)
FS_SRCS := $(filter-out kernel/fs/poll_test.c, $(FS_SRCS))
endif

# The disk backend behind the fs_ops vtable. Exactly one provides g_rootfs:
#   CONFIG_FS_EXT2 -> ext2_ops.c (already in FS_SRCS)
#   else FS_FAT    -> fat.c
#   else           -> nullfs.c (every disk op fails; initrd + tmpfs only)
ifneq ($(CONFIG_FS_EXT2),y)
FS_SRCS := $(filter-out kernel/fs/ext2.c kernel/fs/ext2_cache.c kernel/fs/ext2_dir.c \
    kernel/fs/ext2_vfs.c kernel/fs/ext2_ops.c, $(FS_SRCS))
ifeq ($(CONFIG_FS_FAT),y)
FS_SRCS += kernel/fs/fat.c
else
FS_SRCS += kernel/fs/nullfs.c
endif
endif

# ── Object file lists ───────────���────────────────────────────────��───────────
ARCH_OBJS      = $(patsubst kernel/%.c,$(BUILD)/%.o,$(ARCH_SRCS))
CORE_OBJS      = $(patsubst kernel/%.c,$(BUILD)/%.o,$(CORE_SRCS))
MM_OBJS        = $(patsubst kernel/%.c,$(BUILD)/%.o,$(MM_SRCS))
BOOT_OBJ       = $(BUILD)/arch/x86_64/boot.o
ARCH_ASM_OBJS  = $(patsubst kernel/%.asm,$(BUILD)/%.o,$(ARCH_ASMS))
SCHED_OBJS     = $(patsubst kernel/%.c,$(BUILD)/%.o,$(SCHED_SRCS))
SIGNAL_OBJS    = $(patsubst kernel/%.c,$(BUILD)/%.o,$(SIGNAL_SRCS))
TTY_OBJS       = $(patsubst kernel/%.c,$(BUILD)/%.o,$(TTY_SRCS))
FS_OBJS        = $(patsubst kernel/%.c,$(BUILD)/%.o,$(FS_SRCS))
DRIVER_OBJS    = $(patsubst kernel/%.c,$(BUILD)/%.o,$(DRIVER_SRCS))
NET_OBJS       = $(patsubst kernel/%.c,$(BUILD)/%.o,$(NET_SRCS))
USERSPACE_OBJS = $(patsubst kernel/%.c,$(BUILD)/%.o,$(USERSPACE_SRCS))

# ── Optional unity / jumbo build (UNITY=1) ──────────────────────────────────
# Compile each collision-free subsystem as ONE translation unit (a generated
# build/<grp>_unity.c that #includes its sources) instead of one cc1+as per
# file. Far fewer process spawns + headers parsed once → a faster clean build,
# byte-for-byte the same code. DRIVERS are excluded: several define a private
# `static _memcpy`/`_memset`, which redefine in a single TU. Off by default so
# incremental dev rebuilds don't recompile a whole subsystem for one file.
ifeq ($(UNITY),1)
# Unity/jumbo build: compile each clean subsystem as ONE TU (build/<grp>_unity.c
# that #includes its sources) — far fewer cc1+as spawns, the dominant self-build
# cost. The generating RULES live after `all:` (below) so their targets can't
# hijack the default goal; here we only redirect the *_OBJS the final link reads.
# A group must have no duplicate file-scope statics / clashing macros across files.
CORE_OBJS      = $(BUILD)/core_unity.o
MM_OBJS        = $(BUILD)/mm_unity.o
FS_OBJS        = $(BUILD)/fs_unity.o
NET_OBJS       = $(BUILD)/net_unity.o
SCHED_OBJS     = $(BUILD)/sched_unity.o
TTY_OBJS       = $(BUILD)/tty_unity.o
SIGNAL_OBJS    = $(BUILD)/signal_unity.o
USERSPACE_OBJS = $(BUILD)/syscall_unity.o
endif

# ── No embedded userland (Linux model) ──────────────────────────────────────
# The kernel embeds NO userland binaries. Init (/bin/vigil) and all other
# programs load from the ext2 root filesystem (rootfs module on live media,
# nvme on installed). proc_spawn_init() reads /bin/vigil via VFS at boot.

ALL_OBJS = $(BOOT_OBJ) $(ARCH_OBJS) $(ARCH_ASM_OBJS) $(CORE_OBJS) $(SIGNAL_OBJS) \
           $(MM_OBJS) $(SCHED_OBJS) $(TTY_OBJS) $(FS_OBJS) $(DRIVER_OBJS) \
           $(NET_OBJS) $(USERSPACE_OBJS)


.PHONY: all iso test clean version sym dist arm64 arm64-iso test-arm64
.PHONY: syncconfig allnoconfig allyesconfig oldconfig
all: $(BUILD)/aegis.elf

# ── Config generation ───────────────────────────────────────────────────────
# Every object depends on the generated header, so `make` with no .config first
# seeds configs/full_defconfig (historical everything-on build), then compiles.
$(ALL_OBJS): | $(AUTOCONF_H)

.config:
	@echo "  [config] no .config — seeding configs/full_defconfig"
	@$(KCONF) defconfig configs/full_defconfig Kconfig

$(AUTOCONF_MK): .config Kconfig
	@mkdir -p $(dir $(AUTOCONF_H))
	@KCONFIG_AUTOHEADER=$(AUTOCONF_H) KCONFIG_AUTOCONF=$(AUTOCONF_MK) $(KCONF) syncconfig Kconfig
$(AUTOCONF_H): $(AUTOCONF_MK) ;   # same syncconfig run emits both

# `make <tier>_defconfig` selects a tier; make allnoconfig/allyesconfig/oldconfig.
%_defconfig:
	$(KCONF) defconfig configs/$@ Kconfig
	@$(MAKE) --no-print-directory syncconfig
allnoconfig allyesconfig oldconfig:
	$(KCONF) $@ Kconfig
	@$(MAKE) --no-print-directory syncconfig
syncconfig: .config
	@mkdir -p $(dir $(AUTOCONF_H))
	@KCONFIG_AUTOHEADER=$(AUTOCONF_H) KCONFIG_AUTOCONF=$(AUTOCONF_MK) $(KCONF) syncconfig Kconfig

# ── Unity rule bodies (after all: so targets don't become the default goal) ──
ifeq ($(UNITY),1)
$(BUILD)/core_unity.c: $(CORE_SRCS)
	@mkdir -p $(@D) && echo "/* GENERATED unity (UNITY=1) */" > $@ && for s in $(CORE_SRCS); do echo "#include \"$$s\"" >> $@; done
$(BUILD)/mm_unity.c: $(MM_SRCS)
	@mkdir -p $(@D) && echo "/* GENERATED unity (UNITY=1) */" > $@ && for s in $(MM_SRCS); do echo "#include \"$$s\"" >> $@; done
$(BUILD)/fs_unity.c: $(FS_SRCS)
	@mkdir -p $(@D) && echo "/* GENERATED unity (UNITY=1) */" > $@ && for s in $(FS_SRCS); do echo "#include \"$$s\"" >> $@; done
$(BUILD)/net_unity.c: $(NET_SRCS)
	@mkdir -p $(@D) && echo "/* GENERATED unity (UNITY=1) */" > $@ && for s in $(NET_SRCS); do echo "#include \"$$s\"" >> $@; done
$(BUILD)/sched_unity.c: $(SCHED_SRCS)
	@mkdir -p $(@D) && echo "/* GENERATED unity (UNITY=1) */" > $@ && for s in $(SCHED_SRCS); do echo "#include \"$$s\"" >> $@; done
$(BUILD)/tty_unity.c: $(TTY_SRCS)
	@mkdir -p $(@D) && echo "/* GENERATED unity (UNITY=1) */" > $@ && for s in $(TTY_SRCS); do echo "#include \"$$s\"" >> $@; done
$(BUILD)/signal_unity.c: $(SIGNAL_SRCS)
	@mkdir -p $(@D) && echo "/* GENERATED unity (UNITY=1) */" > $@ && for s in $(SIGNAL_SRCS); do echo "#include \"$$s\"" >> $@; done
$(BUILD)/syscall_unity.c: $(USERSPACE_SRCS)
	@mkdir -p $(@D) && echo "/* GENERATED unity (UNITY=1) */" > $@ && for s in $(USERSPACE_SRCS); do echo "#include \"$$s\"" >> $@; done
$(BUILD)/%_unity.o: $(BUILD)/%_unity.c
	$(CC) $(CFLAGS) -I. -c $< -o $@
endif

# ── ARM64 build (aarch64-linux-gnu toolchain; see Makefile.arm64) ───────────
arm64:
	$(MAKE) -f Makefile.arm64
arm64-iso:
	$(MAKE) -f Makefile.arm64 iso
test-arm64:
	$(MAKE) -f Makefile.arm64 test

# asm/blob objects that have none. This is what makes header edits rebuild.
# MUST come AFTER `all:` — the .d files declare object targets, and if included
# first one of them would hijack the default goal away from `all`.
-include $(ALL_OBJS:.o=.d)

# ── Generic kernel compilation rules ──────���──────────────────────────────────
# -MMD -MP emits a per-object .d listing the headers it #included; the
# `-include` below feeds those back to make so editing a header rebuilds every
# object that uses it. Without this, incremental builds left stale objects when
# a struct layout changed in a header (e.g. a field removed from proc.h shifted
# pid/tgid offsets, so a stale procfs.o read pid as 0) — a silent wrong-binary
# class that an incremental `make` cannot otherwise catch. -MP adds phony header
# targets so deleting a header doesn't break the build with a missing-prereq error.
# The KASAN runtime must not instrument itself — strip the sanitizer flags for
# just this object (more specific than the generic rule below, so make prefers
# it). -DKASAN stays so the file's own #ifdef KASAN body compiles in.
$(BUILD)/mm/kasan.o: kernel/mm/kasan.c
	@mkdir -p $(dir $@)
	$(CC) $(filter-out $(KASAN_CFLAGS),$(CFLAGS)) -MMD -MP -c $< -o $@

# The UBSAN runtime must not instrument itself (a report is a memory-touching
# path; self-instrumentation risks recursion — the runtime has a guard, but not
# instrumenting it is cleaner and matches the KASAN rule above). -DUBSAN stays so
# the file's own #ifdef UBSAN body compiles in.
$(BUILD)/mm/ubsan.o: kernel/mm/ubsan.c
	@mkdir -p $(dir $@)
	$(CC) $(filter-out $(UBSAN_CFLAGS),$(CFLAGS)) -MMD -MP -c $< -o $@

$(BUILD)/%.o: kernel/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -MMD -MP -c $< -o $@

$(BOOT_OBJ): $(BOOT_SRC)
	@mkdir -p $(dir $@)
	$(AS) $(ASFLAGS) $< -o $@

$(BUILD)/arch/x86_64/%.o: kernel/arch/x86_64/%.asm
	@mkdir -p $(dir $@)
	$(AS) $(ASFLAGS) $< -o $@

# ── User program builds ─��──────────────────────────────────���────────────────
# ── Final link ────────────────────────────────────────────────────────────────
# Two-pass link to embed the in-kernel symbol table. No userland blobs are
# linked in — the kernel loads init from the root filesystem at boot.
NM = x86_64-elf-nm
$(BUILD)/aegis.elf: $(ALL_OBJS) tools/gen-ksyms.sh kernel/core/ksym.h
	@# Pass 1: link with the weak (empty) ksym fallbacks to fix function addrs.
	@# Response file: a ~150-object link line is several KB — past some shells'
	@# command-length limit (self-hosting on Aegis, where `make SHELL=/bin/stsh`
	@# truncated it and dropped the trailing driver objects). `ld @file` keeps
	@# the invocation short; make's $(file) writes the list with no shell line.
	$(file >$(BUILD)/objs.rsp,$(ALL_OBJS))
	$(LD) $(LDFLAGS) -o $@.tmp @$(BUILD)/objs.rsp
	@# Generate + compile the in-kernel symbol table from pass 1.  .text precedes
	@# .rodata in linker.ld, so embedding this const blob does not move any
	@# function address — the pass-1 addresses stay valid in the relink.
	@# gen-ksyms is best-effort: on failure fall back to an empty table (ksym.c's
	@# weak ksym_count=0 fallback → hex backtraces) so a self-host build still
	@# produces a complete kernel. Its stderr is surfaced for a real fix.
	NM=$(NM) $(SHELL) tools/gen-ksyms.sh $@.tmp > $(BUILD)/ksyms.c || echo "/* gen-ksyms unavailable — empty ksym table (weak fallback) */" > $(BUILD)/ksyms.c
	$(CC) $(CFLAGS) -c $(BUILD)/ksyms.c -o $(BUILD)/ksyms.o
	@# Pass 2: relink with the strong symbol table (overrides the weak arrays).
	$(file >$(BUILD)/objs2.rsp,$(ALL_OBJS) $(BUILD)/ksyms.o)
	$(LD) $(LDFLAGS) -o $@ @$(BUILD)/objs2.rsp
	@rm -f $@.tmp || true
KERNEL_STRIPPED = $(BUILD)/aegis-stripped.elf
$(KERNEL_STRIPPED): $(BUILD)/aegis.elf
	$(OBJCOPY) --strip-all $< $@

# ── Kernel-only smoke-test ISO (Limine; no rootfs module) ───────────────────
LIMINE_DIR = tools/limine
LIMINE_BIN = $(BUILD)/limine
ISO_DIR    = $(BUILD)/isodir

# Limine binaries are fetched (pinned in $(LIMINE_DIR)/VERSION), not vendored.
# The stamp runs the fetch once; every limine file depends on it so the ISO
# rules pull it in transitively via $(LIMINE_BIN).
LIMINE_STAMP = $(LIMINE_DIR)/.fetched
$(LIMINE_STAMP): tools/fetch-limine.sh $(LIMINE_DIR)/VERSION
	sh tools/fetch-limine.sh
	@touch $@
$(LIMINE_DIR)/limine.c $(LIMINE_DIR)/limine-bios-hdd.h $(LIMINE_DIR)/limine-bios.sys \
$(LIMINE_DIR)/limine-bios-cd.bin $(LIMINE_DIR)/limine-uefi-cd.bin \
$(LIMINE_DIR)/BOOTX64.EFI $(LIMINE_DIR)/BOOTIA32.EFI: $(LIMINE_STAMP)

$(LIMINE_BIN): $(LIMINE_DIR)/limine.c $(LIMINE_DIR)/limine-bios-hdd.h
	@mkdir -p $(BUILD)
	$(HOSTCC) -std=c99 -O2 -I$(LIMINE_DIR) -o $@ $(LIMINE_DIR)/limine.c

# Optional dev firmware blob: if the AX200 .ucode is staged in kernel/drivers,
# ship it as boot module0 so the iwl_ax200 driver can load it on the smoke ISO.
IWL_FW := $(wildcard kernel/drivers/iwlwifi-cc-a0-59.ucode)

iso: $(BUILD)/aegis.iso
$(BUILD)/aegis.iso: $(KERNEL_STRIPPED) $(LIMINE_BIN)
	@rm -rf $(ISO_DIR)
	@mkdir -p $(ISO_DIR)/boot/limine $(ISO_DIR)/EFI/BOOT
	cp $(KERNEL_STRIPPED) $(ISO_DIR)/boot/aegis.elf
	$(if $(IWL_FW),cp $(IWL_FW) $(ISO_DIR)/boot/iwlwifi.ucode,@true)
	printf 'timeout: 0\n\n/Aegis kernel\n    protocol: limine\n    path: boot():/boot/aegis.elf\n$(if $(IWL_FW),    module_path: boot():/boot/iwlwifi.ucode\n,)    cmdline: boot=text\n' > $(ISO_DIR)/boot/limine/limine.conf
	cp $(LIMINE_DIR)/limine-bios.sys $(LIMINE_DIR)/limine-bios-cd.bin $(LIMINE_DIR)/limine-uefi-cd.bin $(ISO_DIR)/boot/limine/
	cp $(LIMINE_DIR)/BOOTX64.EFI $(LIMINE_DIR)/BOOTIA32.EFI $(ISO_DIR)/EFI/BOOT/
	xorriso -as mkisofs -R -r -J \
	    -b boot/limine/limine-bios-cd.bin \
	    -no-emul-boot -boot-load-size 4 -boot-info-table \
	    --efi-boot boot/limine/limine-uefi-cd.bin \
	    -efi-boot-part --efi-boot-image \
	    --protective-msdos-label \
	    $(ISO_DIR) -o $@
	$(LIMINE_BIN) bios-install $@

# ── Capability test: a freestanding test-init booted from a minimal rootfs ──
# test/init.c is built with the kernel's own toolchain (no libc, raw syscalls),
# packed as /bin/vigil into a tiny ext2 image, and booted as a Limine module.
# It checks pid/write and — the point — that a POWER-gated syscall is DENIED to
# baseline-cap init (no ambient authority). See tools/captest.sh.
$(BUILD)/test-init: test/init.c
	@mkdir -p $(BUILD)
	$(CC) -ffreestanding -nostdlib -static -fno-pie -no-pie -fno-stack-protector \
	    -mno-red-zone -mno-mmx -mno-sse -mno-sse2 -O2 -e _start -o $@ $<

$(BUILD)/test-exectgt: test/exectgt.c
	@mkdir -p $(BUILD)
	$(CC) -ffreestanding -nostdlib -static -fno-pie -no-pie -fno-stack-protector \
	    -mno-red-zone -mno-mmx -mno-sse -mno-sse2 -O2 -e _start -o $@ $<

$(BUILD)/test-rootfs.img: $(BUILD)/test-init $(BUILD)/test-exectgt
	dd if=/dev/zero of=$@ bs=512 count=8192 2>/dev/null      # 4 MiB
	/sbin/mke2fs -t ext2 -F -b 4096 -L aegis-test $@ >/dev/null 2>&1
	printf 'mkdir /bin\nwrite $(BUILD)/test-init /bin/vigil\nwrite $(BUILD)/test-exectgt /bin/exectest\nmkdir /etc\nmkdir /etc/aegis\nmkdir /etc/aegis/caps.d\nwrite test/exectest.caps /etc/aegis/caps.d/exectest\n' | /sbin/debugfs -w $@ >/dev/null 2>&1

$(BUILD)/aegis-test.iso: $(KERNEL_STRIPPED) $(BUILD)/test-rootfs.img $(LIMINE_BIN)
	@rm -rf $(BUILD)/test-isodir
	@mkdir -p $(BUILD)/test-isodir/boot/limine $(BUILD)/test-isodir/EFI/BOOT
	cp $(KERNEL_STRIPPED) $(BUILD)/test-isodir/boot/aegis.elf
	cp $(BUILD)/test-rootfs.img $(BUILD)/test-isodir/boot/rootfs.img
	printf 'timeout: 0\n\n/Aegis kernel test\n    protocol: limine\n    path: boot():/boot/aegis.elf\n    module_path: boot():/boot/rootfs.img\n    cmdline: boot=text\n' > $(BUILD)/test-isodir/boot/limine/limine.conf
	cp $(LIMINE_DIR)/limine-bios.sys $(LIMINE_DIR)/limine-bios-cd.bin $(LIMINE_DIR)/limine-uefi-cd.bin $(BUILD)/test-isodir/boot/limine/
	cp $(LIMINE_DIR)/BOOTX64.EFI $(LIMINE_DIR)/BOOTIA32.EFI $(BUILD)/test-isodir/EFI/BOOT/
	xorriso -as mkisofs -R -r -J \
	    -b boot/limine/limine-bios-cd.bin \
	    -no-emul-boot -boot-load-size 4 -boot-info-table \
	    --efi-boot boot/limine/limine-uefi-cd.bin \
	    -efi-boot-part --efi-boot-image \
	    --protective-msdos-label \
	    $(BUILD)/test-isodir -o $@
	$(LIMINE_BIN) bios-install $@

# Multiboot2-protocol smoke ISO: same kernel, booted via the mb2 header +
# 32→64 entry in boot.asm. Keeps the microvm boot path (the code the Limine
# protocol obsoletes) verified on every `make test`.
$(BUILD)/aegis-mb2.iso: $(KERNEL_STRIPPED) $(LIMINE_BIN)
	@rm -rf $(BUILD)/mb2-isodir
	@mkdir -p $(BUILD)/mb2-isodir/boot/limine $(BUILD)/mb2-isodir/EFI/BOOT
	cp $(KERNEL_STRIPPED) $(BUILD)/mb2-isodir/boot/aegis.elf
	printf 'timeout: 0\n\n/Aegis kernel (multiboot2)\n    protocol: multiboot2\n    path: boot():/boot/aegis.elf\n    cmdline: boot=text\n' > $(BUILD)/mb2-isodir/boot/limine/limine.conf
	cp $(LIMINE_DIR)/limine-bios.sys $(LIMINE_DIR)/limine-bios-cd.bin $(LIMINE_DIR)/limine-uefi-cd.bin $(BUILD)/mb2-isodir/boot/limine/
	cp $(LIMINE_DIR)/BOOTX64.EFI $(LIMINE_DIR)/BOOTIA32.EFI $(BUILD)/mb2-isodir/EFI/BOOT/
	xorriso -as mkisofs -R -r -J \
	    -b boot/limine/limine-bios-cd.bin \
	    -no-emul-boot -boot-load-size 4 -boot-info-table \
	    --efi-boot boot/limine/limine-uefi-cd.bin \
	    -efi-boot-part --efi-boot-image \
	    --protective-msdos-label \
	    $(BUILD)/mb2-isodir -o $@
	$(LIMINE_BIN) bios-install $@

# Full test: (1) capability/syscall test via a booted test-init (Limine
# protocol), then (2) the kernel-only smoke test on BOTH boot protocols
# (no rootfs → "no init found" panic proves full bring-up).
test: $(BUILD)/aegis-test.iso iso $(BUILD)/aegis-mb2.iso
	bash tools/captest.sh $(BUILD)/aegis-test.iso
	bash tools/ktest.sh $(BUILD)/aegis.iso
	bash tools/ktest.sh $(BUILD)/aegis-mb2.iso

# Full userspace in a microVM: build the microvm tier (PVH, no PCI/ACPI,
# virtio-mmio) and a test rootfs, then boot it in QEMU's `microvm` machine with
# the rootfs as a virtio-blk-device and check the ring-3 test suite all-passes.
# Reconfigures to microvm_defconfig — run `make <tier>_defconfig` afterwards to
# switch back. Needs a local qemu-system-x86_64 with the `microvm` machine.
.PHONY: test-microvm
test-microvm:
	$(MAKE) microvm_defconfig
	$(MAKE) $(BUILD)/test-rootfs.img
	$(MAKE)
	bash tools/captest-microvm.sh $(BUILD)/aegis.elf $(BUILD)/test-rootfs.img

# Resolve a kernel address (e.g. from a [PANIC] backtrace) to source:line.
sym:
	@test -n "$(ADDR)" || { echo "usage: make sym ADDR=0x..."; exit 1; }
	x86_64-elf-addr2line -e $(BUILD)/aegis.elf -f $(ADDR)

# Produce the release artifact: a stripped, version-named kernel image to attach
# to the GitHub release an OS downloads (see LoricaOS tools/fetch-kernel.sh).
dist: $(KERNEL_STRIPPED)
	@mkdir -p $(BUILD)/dist
	cp $(KERNEL_STRIPPED) $(BUILD)/dist/aegis-$(AEGIS_VERSION).elf
	@echo "release artifact: $(BUILD)/dist/aegis-$(AEGIS_VERSION).elf"

version:
	@echo $(AEGIS_VERSION)

clean:
	rm -rf $(BUILD)
