/*
 * boot_probe.S — standalone native (non-Limine, non-UEFI) boot stub for
 * stock Raspberry Pi 5 firmware. NOT part of the Aegis kernel proper yet.
 *
 * Milestone 1 (DONE, verified on real hardware): image header, entry,
 * EL2->EL1 drop, UART access before and after the drop. Two [BOOT] messages.
 * Milestone 2 (this addition): enable the MMU and jump to the high half,
 * a third [BOOT] message from there. Deliberately isolated on top of
 * milestone 1's already-proven code — if this section hangs, the two
 * earlier messages still tell us how far it got, same bisection discipline
 * that found the bug below.
 *
 * Adapted from the pre-Limine port's kernel/arch/arm64/boot.S (aegis-old,
 * commit e1d7abe) — the EL2 sanitization sequence and the page-table/MMU-
 * enable sequence are both lifted close to verbatim from there; the VA
 * offset was changed from that file's 0xFFFF000000000000 to this repo's
 * own ARCH_KERNEL_VIRT_BASE convention (0xFFFFFFFF80000000) so addresses
 * already match the real kernel's linker script — see linker-pi5-probe.ld.
 *
 * UART is hardcoded to the real Pi 5 address (0x107D001000), no runtime
 * probing -- an earlier version tried to detect QEMU-vs-real-hardware by
 * reading the PL011 PeriphID0 register at offset 0xFE0 (the standard AMBA
 * PrimeCell convention, assuming a full 4KB peripheral window). That
 * silently hung on real hardware: this SoC's actual decoded MMIO window
 * for this UART is only 0x200 bytes (confirmed via the real DTB's `reg`
 * property), so offset 0xFE0 lands in unclaimed address space, and an
 * access there can stall the bus indefinitely with no catchable abort --
 * invisible on QEMU's idealized PL011 model, which always answers. Found
 * by bisection against a working dead-minimal build that skipped the
 * PeriphID0 read entirely. Lesson: never touch anything past the DTB's
 * declared `reg` size on real hardware, even a "standard" ID register.
 *
 * Contract: firmware loads this as kernel_2712.img (config.txt
 * kernel_address=0x80000; stock firmware then relocates it to a fixed
 * 0x200000 before starting the OS -- see linker-pi5-probe.ld, which now
 * has to match that real runtime address for the page tables to be
 * correct) with x0 = DTB physical address, MMU/caches off, EL2 (Pi 5
 * default) or EL1.
 */

    .section .text.boot
    .globl _start
_start:
    /* Linux arm64 Image header (64 bytes) — see
     * https://www.kernel.org/doc/html/latest/arch/arm64/booting.html */
    .word   0x14000010          /* 0x00  code0: b .+64 (b _kernel_entry) */
    .word   0x00000000          /* 0x04  code1 (reserved) */
    .quad   0                   /* 0x08  text_offset */
    .quad   0                   /* 0x10  image_size (stamped by gen-pi5-image.py) */
    .quad   0x0000000000000002  /* 0x18  flags: 4K pages, little-endian */
    .quad   0                   /* 0x20  res2 */
    .quad   0                   /* 0x28  res3 */
    .quad   0                   /* 0x30  res4 */
    .word   0x644D5241          /* 0x38  magic: "ARM\x64" */
    .word   0                   /* 0x3c  res5 */

    .globl _kernel_entry
_kernel_entry:
    /* Mask everything (D|A|I|F) FIRST, before installing any vector table
     * or touching any MMIO -- same reasoning as entry.S's Limine path
     * (see its header comment): if TF-A hands off with the physical timer
     * or GIC still armed and we install our crude skip-and-return vector
     * before masking, a stray IRQ/FIQ can be "handled" by that vector
     * (which blindly bumps ELR and erets, wrong for anything but the
     * synchronous abort it was designed for) and refire immediately --
     * an infinite, totally silent loop. Real firmware handoff state is
     * not something QEMU's virt machine reproduces, so this class of bug
     * only shows up on real hardware. */
    msr     daifset, #0xf
    mov     x19, x0              /* preserve DTB phys addr -- callee-saved,
                                    survives to .Lhigh's kernel_main_native() call */

    /* ── Probe 1: pre-EL-drop liveness message ──────────────────────────
     * Proves entry + header + UART access before touching EL2 state. */
    adr     x0, .Lvectors
    bl      .Linstall_vectors
    bl      .Lprobe_and_emit_pre

    /* ── EL2 -> EL1 drop (full sanitization, verbatim from the old port's
     * boot.S) ── QEMU virt/cortex-a72 already enters at EL1 and falls
     * through; stock Pi 5 firmware (TF-A BL31) hands off at EL2. */
    mrs     x0, CurrentEL
    lsr     x0, x0, #2
    cmp     x0, #2
    b.ne    .Lat_el1

    ldr     x0, =0x30C50830      /* INIT_SCTLR_EL2_MMU_OFF */
    msr     sctlr_el2, x0
    isb

    mov     x0, #(1 << 31)       /* HCR_EL2.RW = 1 (EL1 is AArch64) */
    msr     hcr_el2, x0

    msr     vttbr_el2, xzr       /* no stage-2 translation */

    mrs     x0, cnthctl_el2
    orr     x0, x0, #3           /* EL1PCEN | EL1PCTEN */
    msr     cnthctl_el2, x0
    msr     cntvoff_el2, xzr

    mov     x0, #0x33FF          /* CPTR_EL2_DEFAULT: no FP/SIMD trap to EL2 */
    msr     cptr_el2, x0

    msr     hstr_el2, xzr        /* no CP15 traps */

    mrs     x0, midr_el1
    msr     vpidr_el2, x0
    mrs     x0, mpidr_el1
    msr     vmpidr_el2, x0

    /* NO ICC_SRE_EL2 access here (deliberately -- this is the real-hardware
     * bug the fault-dump vector handler (.Lvec_sync_spx) found): ICC_SRE_EL2
     * is a GICv3/v4 system-register-CPU-interface control. Confirmed via a
     * real synchronous-exception capture that stock Pi 5 (BCM2712) traps
     * this as an undefined instruction -- ESR_EL1 EC=0 ("Unknown reason"),
     * ELR_EL1 pointing exactly at this `mrs` -- meaning this SoC's GIC is
     * v2 (memory-mapped CPU interface only, no ICC_* system registers at
     * all), matching the existing GICv2 driver work for this same port.
     * The old pre-Limine boot.S this was lifted from apparently only ever
     * ran on a GICv3 target (QEMU virt); never run on this hardware before.
     * Every previous "successful" boot to EL1 on real hardware was this
     * trap being silently caught and skipped by the old generic catch-all
     * vector stub (ELR+=4, eret) -- not a clean EL2->EL1 drop. */

    ldr     x0, =0x30D00800      /* INIT_SCTLR_EL1_MMU_OFF */
    msr     sctlr_el1, x0

    mov     x0, #0x3C5           /* EL1h, D|A|I|F masked */
    msr     spsr_el2, x0
    adr     x0, .Lat_el1
    msr     elr_el2, x0
    isb
    eret

.Lat_el1:
    msr     daifset, #0xf
    msr     spsel, #1

    mov     x0, #(3 << 20)       /* CPACR_EL1.FPEN = 0b11 */
    msr     cpacr_el1, x0
    isb

    /* Re-install the probe vectors at EL1 (VBAR_EL2 doesn't apply anymore)
     * and emit the post-drop confirmation — proves EL1 is really live and
     * the UART survived the transition, not just that we didn't fault. */
    adr     x0, .Lvectors
    msr     vbar_el1, x0
    isb
    bl      .Lprobe_and_emit_post

    /* DIAGNOSTIC (temporary): print the actual runtime PC. Milestone 1 only
     * ever used PC-relative (adr) addressing, so its success doesn't prove
     * firmware really relocates us to physical 0x200000 as its log message
     * claims -- milestone 2's page tables use absolute (ldr =symbol)
     * addresses, which DO need that assumption to hold. If this doesn't
     * print 0x00000000002000xx, that mismatch is the bug. */
    adr     x6, .
    ldr     x0, =0x107D001000
    adr     x1, .Lmsg_pc
    bl      .Lemit
    bl      .Lemit_hex
    adr     x1, .Lmsg_crlf
    bl      .Lemit

    /* ── Milestone 2: enable the MMU, jump to the high half ──────────────
     * Isolated addition on top of the now-proven milestone 1 above (its two
     * messages are unchanged and still print first — if this section hangs,
     * we still know exactly how far we got before it did). Page tables +
     * MAIR/TCR + the pre-MMU cache/TLB invalidate sequence are lifted close
     * to verbatim from the old pre-Limine port's boot.S (see this file's
     * header comment) — that invalidate step is the "#1 works-on-QEMU-
     * hangs-on-hardware" bare-metal arm64 bug per that file's own comment,
     * and exactly the kind of thing QEMU cannot verify either way.
     *
     * TTBR0 (identity, low VA == PA): boot_l1[0] covers PA[0,1GB) Normal-WB
     * (our own code lives at PA 0x200000, inside this block, so execution
     * doesn't fault the instant the MMU turns on) and boot_l1[65] covers PA
     * [0x1040000000, 0x1080000000) Device -- the UART at 0x107D001000 sits
     * in the 65th 1GB block (0x107D001000 >> 30 == 65), NOT the 4th as an
     * earlier version of this code assumed (that used PA base 0x100000000,
     * i.e. block index 4 -- off by a factor of ~16, presumably from reading
     * "0x1_07D0_0100_0" as if the UART were near the 4GB mark instead of
     * actually computing PA>>30). Kept live after the jump so .Lemit can go
     * on writing to that same low, identity-mapped UART address — no need
     * to also map the UART into the high half.
     *
     * TTBR1 (kernel, high VA): kern_l0[511] -> kern_l1, kern_l1[510] covers
     * PA[0,1GB) Normal-WB at VA_OFF+PA — i.e. exactly where the linker
     * placed .text.high. Only one block needed for this milestone. */
    movz    x3, #0x8000, lsl #32
    movk    x3, #0xFFFF, lsl #48       /* x3 = VA_OFF = 0xFFFFFFFF80000000 */

    ldr     x10, =boot_l0
    ldr     x11, =boot_l1
    ldr     x12, =kern_l0
    ldr     x13, =kern_l1

    mov     x14, #512
    mov     x15, x10
1:  str     xzr, [x15], #8
    subs    x14, x14, #1
    b.ne    1b
    mov     x14, #512
    mov     x15, x11
2:  str     xzr, [x15], #8
    subs    x14, x14, #1
    b.ne    2b
    mov     x14, #512
    mov     x15, x12
3:  str     xzr, [x15], #8
    subs    x14, x14, #1
    b.ne    3b
    mov     x14, #512
    mov     x15, x13
4:  str     xzr, [x15], #8
    subs    x14, x14, #1
    b.ne    4b

    .set PTE_V,   (1 << 0)     /* Valid */
    .set PTE_T,   (1 << 1)     /* Table descriptor */
    .set PTE_AF,  (1 << 10)    /* Access Flag */
    .set PTE_SH,  (3 << 8)     /* Inner Shareable */
    .set PTE_DEV, (1 << 2)     /* AttrIdx = 1 (Device) */

    /* TTBR0: boot_l0[0] -> boot_l1 (table) */
    mov     x14, #(PTE_V | PTE_T)
    orr     x14, x14, x11
    str     x14, [x10]

    /* boot_l1[0] = Normal-WB 1GB block @ PA 0 */
    mov     x14, #(PTE_V | PTE_AF | PTE_SH)
    str     x14, [x11]

    /* boot_l1[65] = Device 1GB block @ PA 0x1040000000 (real block
     * containing the UART at 0x107D001000 -- see comment above). */
    mov     x14, #(PTE_V | PTE_AF | PTE_DEV)
    ldr     x15, =0x1040000000
    orr     x14, x14, x15
    str     x14, [x11, #(65 * 8)]

    /* TTBR1: kern_l0[511] -> kern_l1 (table) */
    mov     x14, #(PTE_V | PTE_T)
    orr     x14, x14, x13
    str     x14, [x12, #(511 * 8)]

    /* kern_l1[510] = Normal-WB 1GB block @ PA 0 (covers .text.high at
     * VA_OFF + 0x200000, which falls in this same 1GB physical block). */
    mov     x14, #(PTE_V | PTE_AF | PTE_SH)
    str     x14, [x13, #(510 * 8)]

    /* MAIR: Attr0 = Normal WB, Attr1 = Device-nGnRnE */
    ldr     x1, =0x00000000000000FF
    msr     mair_el1, x1

    /* TCR: T0SZ=16, T1SZ=16, 4K granule both, inner shareable, WB alloc,
     * IPS=2 (40-bit PA — required for the UART at 0x107D001000). */
    ldr     x1, =(16 | (0b11 << 12) | (0b01 << 10) | (0b01 << 8) | \
                  (16 << 16) | (0b10 << 30) | (0b11 << 28) | (0b01 << 26) | (0b01 << 24) | \
                  (0b010UL << 32))
    msr     tcr_el1, x1

    msr     ttbr0_el1, x10
    msr     ttbr1_el1, x12
    dsb     sy
    isb

    /* Invalidate I-cache + TLB before flipping the MMU on. QEMU doesn't
     * model cache state so a missing invalidate here is invisible in
     * emulation — the old boot.S's own comment calls this out as the #1
     * cause of "works on QEMU, hangs on real hardware" in bare-metal
     * arm64 bring-up. */
    ic      iallu
    tlbi    vmalle1
    dsb     ish
    isb

    /* DIAGNOSTIC (temporary): confirms page tables + MAIR/TCR + cache/TLB
     * invalidate all completed without hanging -- still using pre-MMU
     * addressing, so this only tells us if we got THIS far, not whether
     * the MMU-enable/branch afterward succeeds. */
    ldr     x0, =0x107D001000
    adr     x1, .Lmsg_checkpoint
    bl      .Lemit

    /* Enable translation (M) ALONE first, with its own dsb+isb, before
     * touching the caches (C, I) in a second write -- bisection nailed the
     * hang down to `isb` itself (the first point ARM guarantees a fetch
     * actually goes through the new regime; everything printed earlier may
     * still have been fetched via the pre-enable path, implementation-
     * defined). Splitting M from C|I isolates whether translation itself
     * is the problem or whether it's specifically the cache-enable
     * happening in the same transition as the first post-enable fetch. */
    mrs     x1, sctlr_el1
    orr     x1, x1, #(1 << 0)      /* M only */
    msr     sctlr_el1, x1
    dsb     sy
    isb

    /* DIAGNOSTIC (temporary): if this prints, translation-only (M, no C/I)
     * survives the isb that hung with M|C|I together -- the problem is
     * specifically cache-enable at this transition. If it DOESN'T print,
     * the hang is translation itself (instruction-side fetch through the
     * new tables), unrelated to caches. */
    ldr     x0, =0x107D001000
    adr     x1, .Lmsg_m_only_done
    bl      .Lemit

    mrs     x1, sctlr_el1
    orr     x1, x1, #(1 << 2)      /* C   */
    orr     x1, x1, #(1 << 12)     /* I   */
    msr     sctlr_el1, x1
    dsb     sy
    isb

    /* DIAGNOSTIC (temporary): MMU is now ON. Still uses the identity-mapped
     * low VA for the UART (same address, still valid post-enable via TTBR0)
     * -- if this prints, the MMU-enable instruction itself is fine and the
     * hang is in the branch to high VA or in .Lhigh's own code. If it
     * DOESN'T print, the hang is the sctlr_el1 write / immediately after. */
    ldr     x0, =0x107D001000
    adr     x1, .Lmsg_mmu_on
    bl      .Lemit

    ldr     x2, =.Lhigh
    br      x2

    /* Page tables — 4 x 4KB, deliberately NOT in .bss: the raw Image
     * loader (gen-pi5-image.py's `objcopy -O binary`) has no NOBITS
     * concept, so this just reserves the address range in ordinary RAM
     * right after our code; explicitly zeroed above before use, same as
     * the old boot.S. */
    .balign 4096
boot_l0:
    .space 4096
boot_l1:
    .space 4096
kern_l0:
    .space 4096
kern_l1:
    .space 4096

    /* ── Shared emit helpers — write directly to the real Pi 5 UART, no
     * liveness probe (see header comment for why that was removed). */
.Lprobe_and_emit_pre:
    adr     x1, .Lmsg_pre
    b       .Lprobe_and_emit

.Lprobe_and_emit_post:
    adr     x1, .Lmsg_post
    /* fall through */

.Lprobe_and_emit:
    /* x1 = message ptr (arg to .Lemit). No stack exists yet at this point
     * in the boot path, so the nested `bl .Lemit` below would otherwise
     * clobber our own incoming x30 with no way to recover it -- save it
     * in x5 (caller-saved scratch, unused by .Lemit). */
    mov     x5, x30
    ldr     x0, =0x107D001000
    bl      .Lemit
    mov     x30, x5
    ret

    /* .Lemit: write asciz string at x1 to PL011 base x0. Clobbers w2/w3. */
.Lemit:
.Le_loop:
    ldrb    w2, [x1], #1
    cbz     w2, .Le_done
.Le_wait:
    ldr     w3, [x0, #0x18]      /* FR */
    tbnz    w3, #5, .Le_wait     /* TXFF set -> busy */
    str     w2, [x0]             /* DR */
    b       .Le_loop
.Le_done:
    ret

    /* .Lemit_hex: print x6 as 16 hex digits to PL011 base x0 (temporary
     * diagnostic, see the DIAGNOSTIC comment above). Clobbers w2/w3/x7. */
.Lemit_hex:
    mov     x7, #60
.Lh_loop:
    lsr     x2, x6, x7
    and     x2, x2, #0xF
    cmp     x2, #10
    b.lt    1f
    add     x2, x2, #('a' - 10)
    b       2f
1:  add     x2, x2, #'0'
2:
.Lh_wait:
    ldr     w3, [x0, #0x18]
    tbnz    w3, #5, .Lh_wait
    str     w2, [x0]
    subs    x7, x7, #4
    b.ge    .Lh_loop
    ret

.Linstall_vectors:
    mrs     x1, CurrentEL
    lsr     x1, x1, #2
    cmp     x1, #2
    b.ne    1f
    msr     vbar_el2, x0
    b       2f
1:  msr     vbar_el1, x0
2:  isb
    ret

.Lmsg_pc:
    .asciz "[BOOT] diagnostic runtime PC=0x"
.Lmsg_checkpoint:
    .asciz "[BOOT] diagnostic: tables+MAIR/TCR+cache/TLB-invalidate done, enabling MMU now\r\n"
.Lmsg_mmu_on:
    .asciz "[BOOT] diagnostic: MMU enabled (SCTLR_EL1 M|C|I set), branching to high VA now\r\n"
.Lmsg_m_only_done:
    .asciz "[BOOT] diagnostic: translation-only (M, no C/I) survived dsb+isb\r\n"
.Lmsg_fault_esr:
    .asciz "[FAULT] sync exception! ESR_EL1=0x"
.Lmsg_fault_elr:
    .asciz " ELR_EL1=0x"
.Lmsg_fault_far:
    .asciz " FAR_EL1=0x"
.Lmsg_crlf:
    .asciz "\r\n"
.Lmsg_pre:
    .asciz "[BOOT] aegis arm64 native probe: entry ok (pre-EL-drop)\r\n"
.Lmsg_post:
    .asciz "[BOOT] aegis arm64 native probe: EL1 reached, mmu off\r\n"

    /* Vector table. 16 entries x 128 bytes = 2KB, must be 2KB-aligned.
     * Slot 4 (offset 0x200 -- sync exception, current EL, SP_ELx) is a real
     * fault-dump handler (see .Lvec_sync_spx below): once `msr spsel,#1`
     * selects SP_ELx (done before EL1 setup, well before MMU-enable), any
     * synchronous fault taken at EL1 lands there, not in the generic stub --
     * this is the slot that actually matters for the real-hardware hang
     * we're bisecting. Every other slot keeps the old milestone-1
     * "skip faulting instruction and eret" stub, which is harmless/unused
     * now that UART access is hardcoded (no more dual-address probing) but
     * still a reasonable default for anything unexpected elsewhere. */
    .macro skip_stub
    mrs     x16, CurrentEL
    lsr     x16, x16, #2
    cmp     x16, #2
    b.ne    11f
    mrs     x17, elr_el2
    add     x17, x17, #4
    msr     elr_el2, x17
    eret
11: mrs     x17, elr_el1
    add     x17, x17, #4
    msr     elr_el1, x17
    eret
    .endm

    .balign 2048
.Lvectors:
    skip_stub                  /* 0x000 sync,  EL1t (SP_EL0) */
    .balign 128
    skip_stub                  /* 0x080 irq,   EL1t */
    .balign 128
    skip_stub                  /* 0x100 fiq,   EL1t */
    .balign 128
    skip_stub                  /* 0x180 serror,EL1t */
    .balign 128
.Lvec_sync_spx:                /* 0x200 sync,  current EL (SP_ELx) -- real handler */
    /* Not just a milestone-2 diagnostic -- keep this past cleanup. Dumps
     * ESR/ELR/FAR over UART and hangs, turning a silent real-hardware stall
     * into readable data, same information QEMU's `-d int` gives for the
     * emulated side. TF-A hands off at EL2 with SP_ELx already selected
     * (SPSR MODE_SP_ELX), so this slot can fire during EL2 setup too, not
     * just at EL1 -- read the EL2-banked regs in that case, or esr_el1 et
     * al reads back all-zero garbage (bit us once already, see
     * rpi5-port-research memory).
     *
     * BLIND SPOT, confirmed the hard way: this handler reports over the
     * SAME UART it's diagnosing. If the actual fault is a bad/missing UART
     * mapping (e.g. wrong page-table block index), .Lemit below faults
     * again trying to report it, re-entering this vector in a silent loop
     * -- "no output" then means "fault taken but unreportable," NOT "no
     * fault taken." Don't conclude the latter without ruling this out
     * first (e.g. does whatever eventually fixes it touch the UART
     * mapping/access path itself?). */
    mrs     x20, CurrentEL
    lsr     x20, x20, #2
    cmp     x20, #2
    b.eq    1f
    mrs     x21, esr_el1
    mrs     x22, elr_el1
    mrs     x23, far_el1
    b       2f
1:  mrs     x21, esr_el2
    mrs     x22, elr_el2
    mrs     x23, far_el2
2:
    ldr     x0, =0x107D001000
    adr     x1, .Lmsg_fault_esr
    bl      .Lemit
    mov     x6, x21
    bl      .Lemit_hex
    adr     x1, .Lmsg_fault_elr
    bl      .Lemit
    mov     x6, x22
    bl      .Lemit_hex
    adr     x1, .Lmsg_fault_far
    bl      .Lemit
    mov     x6, x23
    bl      .Lemit_hex
    adr     x1, .Lmsg_crlf
    bl      .Lemit
.Lvec_sync_spx_hang:
    wfi
    b       .Lvec_sync_spx_hang
    .balign 128
    skip_stub                  /* 0x280 irq,   EL1h */
    .balign 128
    skip_stub                  /* 0x300 fiq,   EL1h */
    .balign 128
    skip_stub                  /* 0x380 serror,EL1h */
    .balign 128
    skip_stub                  /* 0x400 sync,  lower EL (aarch64) */
    .balign 128
    skip_stub                  /* 0x480 irq,   lower EL (aarch64) */
    .balign 128
    skip_stub                  /* 0x500 fiq,   lower EL (aarch64) */
    .balign 128
    skip_stub                  /* 0x580 serror,lower EL (aarch64) */
    .balign 128
    skip_stub                  /* 0x600 sync,  lower EL (aarch32) */
    .balign 128
    skip_stub                  /* 0x680 irq,   lower EL (aarch32) */
    .balign 128
    skip_stub                  /* 0x700 fiq,   lower EL (aarch32) */
    .balign 128
    skip_stub                  /* 0x780 serror,lower EL (aarch32) */
    .balign 128

    /* ── High-half code (post-MMU only) ───────────────────────────────────
     * Placed by the linker at VA_OFF + PA (see linker-pi5-probe.ld), only
     * ever reached via the `br x2` absolute jump above — nothing falls off
     * the end of .text.boot into here. .Lemit/.Linstall_vectors above live
     * in .text.boot (low VMA); a plain `bl` can't reach them from here (the
     * VA gap is ~0xFFFFFFFF80000000, way past `bl`'s +-128MB range), so
     * calls from this section load the absolute address into a register
     * and use `blr` instead — works regardless of the distance between
     * sections, since `ldr x,=sym` always resolves to sym's real VMA. */
    .section .text.high
.Lhigh:
    mov     x5, x30
    adr     x1, .Lmsg_high
    ldr     x0, =0x107D001000
    ldr     x2, =.Lemit
    blr     x2
    mov     x30, x5

    /* ── Bridge into the real kernel (kernel/arch/arm64/native_entry.c) ──
     * Milestones 3a (C + stack) and 3b (.bss zeroing) proved the calling
     * convention and memory model this depends on, both on real hardware
     * -- see rpi5-port-research memory for that history. This call is
     * permanent: the real kernel's kernel_main_native() never returns
     * (falls into the shared kernel_main_arm64(), which ends in
     * sched_start()/__builtin_unreachable(), same as the Limine path). */
    ldr     x9, =.Lboot_stack_top
    mov     sp, x9

    /* Zero .bss before any C code (pmm/vmm/fdt/gic/sched/... -- most of
     * the kernel) can touch a static. The flat `objcopy -O binary` image
     * has no NOBITS concept (same reason the page tables/stack above are
     * `.space`, not `.bss`) -- firmware only copies the file's actual
     * byte length to the load address, so [_bss_start, _bss_end) is
     * neither loaded nor zeroed by anything. Unlike the x86 multiboot2
     * path (GRUB zeroes .bss per the ELF loader contract) or the Limine
     * arm64 path (same), there's no loader here to rely on -- genuinely
     * new code, not mirrored from anywhere else in this repo. _bss_start/
     * _bss_end are both 8-aligned by the linker script. */
    ldr     x9, =_bss_start
    ldr     x10, =_bss_end
1:  cmp     x9, x10
    b.ge    2f
    str     xzr, [x9], #8
    b       1b
2:

    mov     x0, x19                /* DTB phys addr, preserved from entry */
    ldr     x2, =kernel_main_native
    blr     x2
    /* kernel_main_native never returns */

.Lhang:
    wfi
    b       .Lhang

.Lmsg_high:
    .asciz "[BOOT] aegis arm64 native probe: MMU on, running from high VA\r\n"

    /* Stack for the kernel -- `.space`, not `.bss`, same reason as above:
     * must be real reserved bytes in the loaded file. Lives in .text.high
     * so its VMA is already the high half the kernel runs at (SP doesn't
     * need a separate VA_OFF add). 64KB: generous vs. Limine's 16KB
     * boot_stack (entry.S) since real driver/fs code paths on this path
     * haven't been stack-profiled yet on this port. */
    .balign 16
.Lboot_stack_bottom:
    .space 65536
.Lboot_stack_top:
