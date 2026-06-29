; ctx_switch.asm — preemptive context switch for Aegis scheduler
;
; Saves callee-saved registers (rbx, rbp, r12-r15) for the outgoing task
; and restores them for the incoming task. Swaps RSP via the TCB's rsp field.
; Also swaps the user FPU/SSE state (x87 ST0-7, FCW/FSW/FTW, XMM0-15, MXCSR)
; via FXSAVE/FXRSTOR on the TCB's fpu_state area — the kernel itself is
; compiled -mno-sse and never touches these registers, so the live FPU state
; at any switch point belongs to the outgoing task's user code.
;
; The compiler already saves caller-saved registers (rax, rcx, rdx, rsi,
; rdi, r8-r11) at any call site, so we only need callee-saved here.
;
; Calling convention: System V AMD64 ABI
;   rdi = pointer to current task's aegis_task_t  (outgoing)
;   rsi = pointer to next task's aegis_task_t     (incoming)
;
; Clobbers: RSP (switches to new task's stack). All callee-saved registers
;   and the full FPU/SSE register file are preserved across the call from
;   each task's perspective.
;
; New task entry: sched_spawn sets up the stack so the first ctx_switch
;   into a new task "returns" into the task's entry function. Stack layout
;   (low to high, RSP points at r15 slot):
;     [r15=0][r14=0][r13=0][r12=0][rbp=0][rbx=0][fn]
;   After pops: r15-rbx restored to 0, ret pops fn into RIP.
;   The incoming fxrstor below also covers first entry: every creation path
;   (sched_spawn / proc_spawn / fork / clone / sys_spawn) initializes the
;   task's fpu_state area before the task is added to the run queue.

bits 64
section .text

; Byte offset of aegis_task_t.fpu_state (kernel/sched/sched.h).
; MUST equal offsetof(aegis_task_t, fpu_state) — enforced by a
; _Static_assert in kernel/sched/sched.c.  The area is 64-byte aligned
; (XSAVE/XRSTOR #GP on operands not 64-aligned; FXSAVE only needed 16).
FPU_STATE_OFF equ 64

; g_use_xsave (uint8_t, kernel/arch/x86_64/arch_smap.c): 1 once AVX/XSAVE was
; enabled by arch_sse_init().  Selects XSAVE/XRSTOR (saves YMM) vs FXSAVE/FXRSTOR
; (SSE only) below.  RIP-relative reach: g_use_xsave is in the same higher-half
; kernel image as this code.
extern g_use_xsave

; Byte offset of aegis_task_t.on_cpu (kernel/sched/sched.h).  MUST equal
; offsetof(aegis_task_t, on_cpu) — enforced by a _Static_assert in sched.c.
ON_CPU_OFF equ 8

global ctx_switch
ctx_switch:
    ; Save outgoing task's callee-saved registers
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15

    ; Swap user FPU/SSE(/AVX) state. Done before the stack swap while rdi/rsi
    ; are live. XSAVE/XRSTOR (eax:edx = RFBM = 7 = x87|SSE|AVX) when AVX is
    ; enabled, else legacy FXSAVE/FXRSTOR (XMM0-15+MXCSR+x87, no YMM). rax/rdx
    ; are caller-saved so free to clobber here; rdi/rsi are untouched.
    ; CR4.OSFXSR (+OSXSAVE/XCR0 when g_use_xsave) set by arch_sse_init().
    cmp     byte [rel g_use_xsave], 0
    je      .fpu_fxsave
    mov     eax, 7
    xor     edx, edx
    xsave   [rdi + FPU_STATE_OFF]
    xrstor  [rsi + FPU_STATE_OFF]
    jmp     .fpu_done
.fpu_fxsave:
    fxsave  [rdi + FPU_STATE_OFF]
    fxrstor [rsi + FPU_STATE_OFF]
.fpu_done:

    ; current->rsp = rsp  (rsp field is at offset 0 — verified by _Static_assert)
    mov [rdi], rsp

    ; rsp = next->rsp  (switch to the incoming task's stack)
    mov rsp, [rsi]

    ; Release the outgoing task: on_cpu = -1.  Done HERE, AFTER the rsp swap —
    ; rsp now points at the INCOMING stack, so the outgoing task's kernel stack
    ; is fully vacated and may be freed by a reaper on another CPU.  rdi still
    ; holds the OUTGOING task pointer (only rsp changed).  A single aligned
    ; 32-bit store is atomic on x86.
    ;
    ; CRITICAL (SMP): this store MUST follow `mov rsp, [rsi]`, not precede it.
    ; A user task becomes TASK_ZOMBIE and wakes its parent (sched_exit) while
    ; still running ctx_switch on its own kernel stack.  The reaper (sys_waitpid)
    ; spins until on_cpu == -1 before kva_free_pages(stack).  If on_cpu were
    ; cleared at the old site (right after `mov [rdi], rsp`, BEFORE the rsp
    ; swap), the reaper could free the stack while this CPU is still executing
    ; on it (the `mov rsp,[rsi]` instruction) → the freed frame is recycled and
    ; this CPU's continued use sprays kernel memory.  Clearing it after the swap
    ; closes that window.  Picking the task on another CPU stays safe: that CPU
    ; only acts under sched_lock after observing on_cpu == -1, and [rdi] already
    ; holds the correct saved rsp (set above).  (Harmless for the
    ; sched_start/AP-entry dummy task.)
    mov dword [rdi + ON_CPU_OFF], -1

    ; Restore incoming task's callee-saved registers
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx

    ; Return into the incoming task (pops its saved RIP from the stack)
    ret
