/*
 * RAM-only diagnostic, NOT the Aegis kernel entry.
 * Linux ARM64 Image transport: x0 = FDT, EL1/EL2, MMU and data cache off.
 * PC-relative code/data and a 2 MiB-aligned load base; no fixed RAM address.
 */
.section .text.boot, "ax"
.global apple_probe_start
apple_probe_start:
    b .Lentry
    .word 0
    .quad 0                         /* text_offset */
    .quad apple_probe_end - apple_probe_start /* includes BSS and stack */
#ifdef APPLE_PROBE_TRANSLATION
    .quad 2                         /* LE, 4 KiB translation test */
#else
    .quad 0                         /* LE, unspecified translation granule */
#endif
    .quad 0
    .quad 0
    .quad 0
    .word 0x644d5241
    .word 0
.Lentry:
    msr daifset, #15
    mov x19, x0
    mrs x20, CurrentEL
    cmp x20, #4
    b.eq .Lel1
    cmp x20, #8
    b.ne .Lhalt
    mrs x21, sctlr_el2
    b .Lcheck
.Lel1:
    mrs x21, sctlr_el1
.Lcheck:
    tbnz x21, #0, .Lhalt          /* never change a live MMU underneath us */
    tbnz x21, #2, .Lhalt          /* no unmaintained cacheable framebuffer */
    adrp x1, apple_probe_start
    add x1, x1, :lo12:apple_probe_start
    tst x1, #0x1fffff
    b.ne .Lhalt                  /* ADRP relocation requires aligned load */
    adrp x1, __bss_start
    add x1, x1, :lo12:__bss_start
    adrp x2, apple_probe_end
    add x2, x2, :lo12:apple_probe_end
.Lzero:
    cmp x1, x2
    b.hs .Lstack
    str xzr, [x1], #8
    b .Lzero
.Lstack:
    msr spsel, #1
    adrp x1, apple_probe_end
    add x1, x1, :lo12:apple_probe_end
    mov sp, x1
    mov x29, xzr
    mov x30, xzr
    adrp x3, apple_probe_vectors
    add x3, x3, :lo12:apple_probe_vectors
    cmp x20, #4
    b.ne .Lvbar_el2
    msr vbar_el1, x3
    b .Lvbar_done
.Lvbar_el2:
    msr vbar_el2, x3
.Lvbar_done:
    isb
    mov x0, x19
    mov x1, x20
    mov x2, x21
    bl apple_probe_main
.Lhalt:
    wfe
    b .Lhalt

/* All 16 slots are fatal. IRQ/FIQ remain masked; there is no interrupt
 * controller or exception-return path in this diagnostic. */
.section .text.vectors, "ax"
.balign 2048
.global apple_probe_vectors
apple_probe_vectors:
.macro slot number
    mov x0, #\number
    b .Lexception
    .balign 128
.endm
    slot 0
    slot 1
    slot 2
    slot 3
    slot 4
    slot 5
    slot 6
    slot 7
    slot 8
    slot 9
    slot 10
    slot 11
    slot 12
    slot 13
    slot 14
    slot 15
.global apple_probe_vectors_end
apple_probe_vectors_end:

.section .text.fault, "ax"
.Lexception:
    msr daifset, #15
    /* Do not trust the interrupted SP, and do not recursively try to draw
     * another fatal report if framebuffer access itself faults. */
    adrp x9, apple_probe_fault_active
    add x9, x9, :lo12:apple_probe_fault_active
    ldr x10, [x9]
    cbnz x10, .Lhalt
    mov x10, #1
    str x10, [x9]
    mov x5, sp
    adrp x9, apple_probe_fault_stack_top
    add x9, x9, :lo12:apple_probe_fault_stack_top
    mov sp, x9
    mrs x6, CurrentEL
    cmp x6, #4
    b.ne .Lfault_el2
    mrs x1, esr_el1
    mrs x2, elr_el1
    mrs x3, far_el1
    mrs x4, spsr_el1
    b .Lfault_c
.Lfault_el2:
    mrs x1, esr_el2
    mrs x2, elr_el2
    mrs x3, far_el2
    mrs x4, spsr_el2
.Lfault_c:
    lsr x6, x6, #2
    mov x29, xzr
    mov x30, xzr
    bl apple_probe_exception
    b .Lhalt

#ifdef APPLE_PROBE_TRANSLATION
.section .text.el1, "ax"
.global apple_probe_enter_el1
apple_probe_enter_el1:
    /* Only called from the observed EL2, MMU/cache-off environment.
     * Profile 7 additionally enables the Apple guest physical-timer gate;
     * no profile accesses an interrupt controller here. */
    msr daifset, #15
    mov x0, #(1 << 31)              /* HCR.RW, no VHE or stage-2 translation */
    msr hcr_el2, x0
    isb
    msr vttbr_el2, xzr
#ifdef APPLE_TIMER_CHECKPOINT
    /* HCR.E2H can be forced on Apple. Match the actual timer-access layout,
     * not merely the HCR value we attempted to write (Arm EL2 timer setup).
     * The only Apple-specific write enables this CPU's guest physical timer. */
    adrp x9, apple_timer_el2_state
    add x9, x9, :lo12:apple_timer_el2_state
    mrs x0, hcr_el2
    str x0, [x9]
    mov x1, #3
    tbz x0, #34, .Ltimer_nonvhe
    lsl x1, x1, #10
.Ltimer_nonvhe:
    msr cnthctl_el2, x1
    mrs x1, cnthctl_el2
    str x1, [x9, #24]
    mrs x2, midr_el1
    lsr x2, x2, #24
    cmp x2, #0x61
    b.ne .Ltimer_gate_done        /* QEMU/Arm has no Apple gate register */
    mrs x2, s3_5_c15_c1_3
    str x2, [x9, #8]
    orr x2, x2, #2
    msr s3_5_c15_c1_3, x2
    isb
    mrs x2, s3_5_c15_c1_3
    str x2, [x9, #16]
.Ltimer_gate_done:
#else
    mov x0, #3
    msr cnthctl_el2, x0
#endif
    msr cntvoff_el2, xzr
    mov x0, #0x33ff
#ifdef APPLE_SCHED_CHECKPOINT
    /* CPTR uses CPACR-style FPEN when effective E2H=1. The real context
     * switch saves all V registers, so EL2 must permit EL1 FP/SIMD first. */
    mrs x1, hcr_el2
    tbz x1, #34, .Lsched_cptr_ready
    mov x0, #(3 << 20)
.Lsched_cptr_ready:
#endif
    msr cptr_el2, x0
    msr hstr_el2, xzr
    mrs x0, midr_el1
    msr vpidr_el2, x0
    mrs x0, mpidr_el1
    msr vmpidr_el2, x0
    ldr x0, =0x30d00800             /* baseline RES1, M/C/I all clear */
    msr sctlr_el1, x0
    msr ttbr0_el1, xzr
    msr ttbr1_el1, xzr
    adrp x0, apple_probe_vectors
    add x0, x0, :lo12:apple_probe_vectors
    msr vbar_el1, x0
    adrp x0, apple_probe_end
    add x0, x0, :lo12:apple_probe_end
    msr sp_el1, x0
    adrp x0, apple_probe_el1_continue
    add x0, x0, :lo12:apple_probe_el1_continue
    msr elr_el2, x0
    mov x0, #0x3c5                 /* EL1h, D/A/I/F masked */
    msr spsr_el2, x0
    mov x29, xzr
    mov x30, xzr
    isb
    eret
#endif

#ifdef APPLE_TIMER_CHECKPOINT
.section .bss
.balign 8
.global apple_timer_el2_state
.hidden apple_timer_el2_state
apple_timer_el2_state:
    .zero 32
#endif
