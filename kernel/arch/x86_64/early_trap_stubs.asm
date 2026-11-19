; early_trap_stubs.asm — exception stubs for the pre-IDT window (x86-64).
;
; Paired with early_trap.c. (Distinct basenames on purpose: the Makefile maps
; both kernel/%.c and kernel/%.asm to build/%.o, so a .c and a .asm sharing a
; basename collide on one object and one of them silently disappears from the
; link.)
; Before idt_init() runs there is no usable IDT, so
; the first fault is a triple fault and the guest dies silently. These stubs
; give that window a voice.
;
; Every stub runs on its own static stack (early_trap_stack), NOT on the
; faulting stack. The likeliest reason to arrive here is that the boot stack
; overflowed — in which case pushing onto it would fault again and turn the
; report into the triple fault we are trying to explain. The CPU's frame is
; therefore copied off the faulting stack rather than pushed onto it.
;
; Normalised frame handed to early_trap_report(const uint64_t *f):
;   f[0] = vector      f[1] = error code   f[2] = rip
;   f[3] = cs          f[4] = rflags       f[5] = rsp at the fault
; Push order is the reverse of that, because push grows downwards.

bits 64

; 8 KiB trap stack, 16-byte aligned so the reported frame is aligned.
section .bss
align 16
early_trap_stack:     resb 8192
early_trap_stack_top:

extern early_trap_report

section .text

; %1 = vector number, %2 = 1 when the CPU pushes an error code for it.
%macro EARLY_STUB 2
global early_trap_stub_%1
early_trap_stub_%1:
    cld
    mov  rax, rsp                    ; rax -> CPU frame on the faulting stack
    mov  rsp, early_trap_stack_top   ; ... switch to a known-good stack
    push rax                         ; f[5] rsp at the fault
%if %2
    ; [rax+0]=err [rax+8]=rip [rax+16]=cs [rax+24]=rflags
    push qword [rax+24]              ; f[4] rflags
    push qword [rax+16]              ; f[3] cs
    push qword [rax+8]               ; f[2] rip
    push qword [rax]                 ; f[1] error code
%else
    ; [rax+0]=rip [rax+8]=cs [rax+16]=rflags
    push qword [rax+16]              ; f[4] rflags
    push qword [rax+8]               ; f[3] cs
    push qword [rax]                 ; f[2] rip
    push qword 0                     ; f[1] synthetic error code
%endif
    push qword %1                    ; f[0] vector
    mov  rdi, rsp
    call early_trap_report           ; never returns
%%hang_%1:
    cli
    hlt
    jmp %%hang_%1
%endmacro

; Vectors that push an error code (Intel SDM Vol 3A): 8, 10, 11, 12, 13, 14,
; 17, 21, and the newer 29 (#VC) / 30 (#SX). The rest push none.
%assign v 0
%rep 32
  %if v == 8 || v == 10 || v == 11 || v == 12 || v == 13 || v == 14 || v == 17 || v == 21 || v == 29 || v == 30
    EARLY_STUB v, 1
  %else
    EARLY_STUB v, 0
  %endif
  %assign v v+1
%endrep

; Stub table, indexed by vector, for early_trap_init() to load gates from.
section .data
global early_trap_stubs
align 8
early_trap_stubs:
%assign v 0
%rep 32
    dq early_trap_stub_%+v
  %assign v v+1
%endrep
