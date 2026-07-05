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

GCC_INCLUDE := $(shell $(CC) -print-file-name=include)
CFLAGS = \
    -ffreestanding -nostdlib -nostdinc \
    -isystem $(GCC_INCLUDE) \
    -mcmodel=kernel \
    -fno-pie -fno-pic \
    -mno-red-zone -mno-mmx -mno-sse -mno-sse2 \
    -fno-stack-protector \
    -fno-omit-frame-pointer \
    -O2 -fno-strict-aliasing \
    -g \
    -Wall -Wextra -Werror \
    -DAEGIS_VERSION=\"$(AEGIS_VERSION)\" \
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
LDFLAGS = -T tools/linker.ld -nostdlib -z noseparate-code

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
    kernel/arch/x86_64/pcie.c

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

SCHED_SRCS  = kernel/sched/sched.c kernel/sched/waitq.c
SIGNAL_SRCS = kernel/signal/signal.c
TTY_SRCS    = kernel/tty/tty.c kernel/tty/pty.c

FS_SRCS = \
    kernel/fs/fd_table.c kernel/fs/vfs.c kernel/fs/initrd.c \
    kernel/fs/console.c kernel/fs/kbd_vfs.c kernel/fs/pipe.c \
    kernel/fs/blkdev.c kernel/fs/gpt.c \
    kernel/fs/ext2.c kernel/fs/ext2_cache.c kernel/fs/ext2_dir.c kernel/fs/ext2_vfs.c \
    kernel/fs/ramfs.c kernel/fs/procfs.c kernel/fs/memfd.c kernel/fs/eventfd.c \
    kernel/fs/poll_test.c

DRIVER_SRCS = \
    kernel/drivers/nvme.c kernel/drivers/ahci.c kernel/drivers/xhci.c \
    kernel/drivers/usb_hid.c kernel/drivers/usb_mouse.c \
    kernel/drivers/virtio_pci.c kernel/drivers/virtqueue.c \
    kernel/drivers/virtio_net.c kernel/drivers/virtio_blk.c \
    kernel/drivers/virtio_scsi.c kernel/drivers/virtio_balloon.c \
    kernel/drivers/virtio_input.c kernel/drivers/virtio_pmem.c \
    kernel/drivers/virtio_console.c kernel/drivers/virtio_9p.c \
    kernel/drivers/virtio_rng.c kernel/drivers/virtio_gpu.c \
    kernel/drivers/virtio_vsock.c \
    kernel/drivers/rtl8169.c kernel/drivers/rtl8139.c \
    kernel/drivers/e1000.c kernel/drivers/vmxnet3.c \
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
    kernel/syscall/sys_meta.c kernel/syscall/sys_signal.c \
    kernel/syscall/sys_socket.c kernel/syscall/sys_random.c \
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
fs_SRCS     := $(FS_SRCS)
net_SRCS    := $(NET_SRCS)
mm_SRCS     := $(MM_SRCS)
sched_SRCS  := $(SCHED_SRCS)
tty_SRCS    := $(TTY_SRCS)
signal_SRCS := $(SIGNAL_SRCS)
define UNITY_template
$(BUILD)/$(1)_unity.c: $$($(1)_SRCS)
	@mkdir -p $$(@D)
	@echo "/* GENERATED unity TU (UNITY=1) — do not edit */" > $$@
	@for s in $$($(1)_SRCS); do echo "#include \"$$$$s\"" >> $$@; done
$(BUILD)/$(1)_unity.o: $(BUILD)/$(1)_unity.c
	$$(CC) $$(CFLAGS) -I. -c $$< -o $$@
endef
$(foreach g,fs net mm sched tty signal,$(eval $(call UNITY_template,$(g))))
FS_OBJS     = $(BUILD)/fs_unity.o
NET_OBJS    = $(BUILD)/net_unity.o
MM_OBJS     = $(BUILD)/mm_unity.o
SCHED_OBJS  = $(BUILD)/sched_unity.o
TTY_OBJS    = $(BUILD)/tty_unity.o
SIGNAL_OBJS = $(BUILD)/signal_unity.o
endif

# ── No embedded userland (Linux model) ──────────────────────────────────────
# The kernel embeds NO userland binaries. Init (/bin/vigil) and all other
# programs load from the ext2 root filesystem (rootfs module on live media,
# nvme on installed). proc_spawn_init() reads /bin/vigil via VFS at boot.

ALL_OBJS = $(BOOT_OBJ) $(ARCH_OBJS) $(ARCH_ASM_OBJS) $(CORE_OBJS) $(SIGNAL_OBJS) \
           $(MM_OBJS) $(SCHED_OBJS) $(TTY_OBJS) $(FS_OBJS) $(DRIVER_OBJS) \
           $(NET_OBJS) $(USERSPACE_OBJS)


.PHONY: all iso test clean version sym dist arm64 arm64-iso test-arm64
all: $(BUILD)/aegis.elf

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

iso: $(BUILD)/aegis.iso
$(BUILD)/aegis.iso: $(KERNEL_STRIPPED) $(LIMINE_BIN)
	@rm -rf $(ISO_DIR)
	@mkdir -p $(ISO_DIR)/boot/limine $(ISO_DIR)/EFI/BOOT
	cp $(KERNEL_STRIPPED) $(ISO_DIR)/boot/aegis.elf
	printf 'timeout: 0\n\n/Aegis kernel\n    protocol: limine\n    path: boot():/boot/aegis.elf\n    cmdline: boot=text\n' > $(ISO_DIR)/boot/limine/limine.conf
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
	printf 'mkdir /bin\nwrite $(BUILD)/test-init /bin/vigil\nwrite $(BUILD)/test-exectgt /bin/exectest\n' | /sbin/debugfs -w $@ >/dev/null 2>&1

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
