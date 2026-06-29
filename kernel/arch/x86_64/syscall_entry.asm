; syscall_entry.asm — SYSCALL landing pad and ring-3 entry helper
;
; syscall_entry: called by CPU on SYSCALL instruction.
;   CPU state on entry:
;     RAX = syscall number
;     RCX = return RIP (user), R11 = saved RFLAGS, RSP = user RSP
;     RDI = arg1, RSI = arg2, RDX = arg3
;     IF=0, DF=0 (set by IA32_SFMASK=0x700)
;
; CR3 / PML4 policy on the syscall path (Phase 5):
;   syscall_entry does NOT switch CR3.  The user PML4 remains loaded
;   throughout syscall_dispatch so that sys_write (and any future
;   syscall) can dereference user virtual addresses directly.  This is
;   safe because:
;     (a) The user PML4 shares the full kernel higher-half (PML4[511])
;         so all kernel code and higher-half stacks are accessible.
;         Kernel task stacks use kva-allocated per-process VAs (higher-half
;         pages present in both master and user PML4 via the shared pdpt_hi).
;     (b) When sched_exit() transitions from a user task to a kernel task
;         it calls vmm_switch_to(master_pml4) before ctx_switch, ensuring
;         ctx_switch always runs with the correct PML4.
;     (c) Timer interrupts (sched_tick) arrive via isr_common_stub which
;         switches to the master PML4 before isr_dispatch, so scheduler
;         bookkeeping always runs under the master PML4.
;
; proc_enter_user: bare iretq label used by proc_spawn to enter ring 3
;   for the first time. ctx_switch's ret lands here; RSP points at an
;   iretq frame built by proc_spawn. Must NOT have a C prologue.

bits 64
section .text

extern syscall_dispatch
; Per-CPU data accessed via GS segment (set up by SWAPGS):
;   gs:24 = percpu.kernel_stack     (kernel RSP for this CPU)
;   gs:32 = percpu.user_rsp_scratch (scratch slot to save user RSP)
extern signal_deliver_sysret
extern signal_check_pending

global syscall_entry
global proc_enter_user

syscall_entry:
    ; ── Step 1: switch to kernel stack ──────────────────────────────────────
    ; GS.base is user value (TLS). SWAPGS loads percpu_t pointer into GS.base.
    swapgs
    mov  [gs:32], rsp               ; save user RSP to percpu.user_rsp_scratch
    mov  rsp, [gs:24]               ; load kernel stack from percpu.kernel_stack

    ; ── Step 2: save restore frame on kernel stack ───────────────────────────
    ; Pushed deepest-first so the pop order on return is r11, rcx, rsp.
    push qword [gs:32]             ; push saved user RSP onto kernel stack
    push rcx                       ; return RIP
    push r11                       ; RFLAGS

    ; ── Step 2b: save callee-saved registers (part of syscall_frame_t) ────────
    ; signal_deliver_sysret reads these to build a complete signal frame.
    ; sys_rt_sigreturn writes them back.  Without this, sigreturn after a
    ; SYSRET-path signal delivery zeroes rbx/rbp/r12-r15 (C5 audit fix).
    push r15
    push r14
    push r13
    push r12
    push rbp
    push rbx

    ; ── Step 3: save r8/r9/r10; build 8-arg SysV call ────────────────────────
    ; Linux: rax=num, rdi=arg1, rsi=arg2, rdx=arg3, r10=arg4, r8=arg5, r9=arg6
    ; New SysV 8-arg: rdi=frame, rsi=num, rdx=arg1, rcx=arg2, r8=arg3,
    ;                 r9=arg4, [rsp+8]=arg5(r8), [rsp+16]=arg6(r9) after call.
    ;
    ; Push r8/r9/r10 for restore-on-return AND as the syscall_frame_t body
    ; (frame->r10 is at the lowest address = struct base).
    push r8          ; save user r8  (also frame->r8 at +16)
    push r9          ; save user r9  (also frame->r9 at +8)
    push r10         ; save user r10 (also frame->r10 at +0 = struct base)
    ; rsp → frame base (&frame->r10)

    ; Save user rdi/rsi/rdx BEFORE the SysV shuffle destroys them.
    ; Linux ABI guarantees all registers except rax/rcx/r11 are preserved
    ; across syscall.  musl relies on this — readdir sets rsi=dir->buf before
    ; getdents64 and uses rsi AFTER the syscall returns.  Without this save,
    ; rsi contains post-call garbage and readdir computes a null pointer.
    push rdx         ; save user rdx (user arg3) — preserved per Linux ABI
    push rsi         ; save user rsi (user arg2) — preserved per Linux ABI
    push rdi         ; save user rdi (user arg1) — preserved per Linux ABI
    ; rsp → saved user rdi; frame base at [rsp+24]

    ; Push two stack args for 8-arg call (deepest = arg6 first):
    push r9          ; → [rsp+16] after call = arg6 (user r9)
    push r8          ; → [rsp+8]  after call = arg5 (user r8)
    ; rsp → top of stack arg slots; frame is at [rsp+40]

    ; Shuffle registers (dependency-safe order):
    mov  r9,  r10    ; SysV arg6 = arg4 = user r10
    mov  r8,  rdx    ; SysV arg5 = arg3 = user rdx
    mov  rcx, rsi    ; SysV arg4 = arg2 = user rsi
    mov  rdx, rdi    ; SysV arg3 = arg1 = user rdi
    mov  rsi, rax    ; SysV arg2 = num  = syscall number
    lea  rdi, [rsp+40] ; SysV arg1 = frame ptr (past 2 stack-arg + 3 user-reg-save slots)

    call syscall_dispatch
    add  rsp, 16     ; discard two stack-arg slots; rsp → saved user rdi

    ; Restore user rdi/rsi/rdx — these must have their original user-space
    ; values when we push them into the signal slots below.
    pop  rdi         ; restore user rdi
    pop  rsi         ; restore user rsi (critical: musl readdir uses rsi after getdents64)
    pop  rdx         ; restore user rdx
    ; rsp → frame base (&frame->r10) — same as old code after add rsp,16

    ; ── Allocate saved rdi/rsi/rdx slots for signal delivery ─────────────────
    ; Push in reverse pop order: rdi deepest, rdx shallowest.
    ; rdi slot will be overwritten by signal_deliver_sysret if a handler
    ; is installed, so pop rdi delivers signum as arg1 to the handler.
    push rdi         ; [rsp+16] = saved rdi slot  (deepest of the three)
    push rsi         ; [rsp+8]  = saved rsi slot
    push rdx         ; [rsp+0]  = saved rdx slot   (top, popped first)
    ;
    ; Stack layout now (rsp → saved rdx):
    ;   [rsp+0]  saved rdx  [rsp+8]  saved rsi  [rsp+16] saved rdi
    ;   [rsp+24] frame.r10  [rsp+32] frame.r9   [rsp+40] frame.r8
    ;   [rsp+48] frame.rflags  [rsp+56] frame.rip  [rsp+64] frame.user_rsp

    ; ── Signal delivery on syscall return path ─────────────────────────────
    ;
    ; Case 1: SIGRETURN_MAGIC — sys_rt_sigreturn patched frame already.
    ;         Skip signal delivery; sysret restores interrupted context.
    ; Case 2: No pending signals — skip. Normal sysret.
    ; Case 3: User handler — signal_deliver_sysret patches frame->rip/user_rsp,
    ;         writes signum to [rsp+16]. Set rax=0, sysret enters handler.
    ; Case 4: SIG_DFL — signal_deliver_sysret calls sched_exit (no return).

    ; Case 1: SIGRETURN_MAGIC check
    mov  r11, 0xdeadbeefcafebabe
    cmp  rax, r11
    je   .sig_sysret_done

    ; Case 2: fast no-signal check (preserves rax across call)
    push rax
    call signal_check_pending   ; returns 1 if signals pending, 0 otherwise
    test rax, rax
    pop  rax
    jz   .sig_sysret_done

    ; Case 3/4: deliver signal
    ; After push rax: [rsp+0]=saved rax, [rsp+24]=saved rdi, [rsp+32]=frame*
    push rax
    lea  rdi, [rsp + 32]    ; frame* = rsp+8(push)+24(frame_offset) = rsp+32
    lea  rsi, [rsp + 24]    ; &saved_rdi = rsp+8(push)+16(rdi_offset) = rsp+24
    call signal_deliver_sysret  ; returns 0=no handler, 1=handler installed
    test rax, rax
    pop  rax                    ; restore original syscall return value
    jz   .sig_sysret_done

    ; Case 3: user handler installed — rax=0 on entry to handler
    xor  eax, eax

.sig_sysret_done:
    ; ── End signal delivery ─────────────────────────────────────────────────

    ; Restore the three scratch slots (rdi gets signum if handler installed)
    pop  rdx
    pop  rsi
    pop  rdi

    ; Restore user r10/r9/r8
    pop  r10
    pop  r9
    pop  r8
    ; rax = return value from syscall_dispatch

    ; Restore callee-saved registers (pushed in Step 2b)
    pop  rbx
    pop  rbp
    pop  r12
    pop  r13
    pop  r14
    pop  r15

    ; ── Step 4: restore RFLAGS, RIP, RSP; return to ring 3 ──────────────────
    pop  r11          ; RFLAGS
    pop  rcx          ; return RIP
    pop  rsp          ; user RSP  (pop rsp sets RSP=[RSP], not RSP+8)

    swapgs            ; restore user GS.base before returning to ring 3
    o64 sysret       ; sysretq: restore RIP from RCX, RFLAGS from R11, RSP, enter ring 3

; proc_enter_user — switch to user PML4 and iretq into ring 3.
;
; Called via ret from ctx_switch on a new user task's first entry.
; On entry RSP points at the initial kernel stack frame built by proc_spawn:
;
;   [rsp+0]  user PML4 physical address  ← popped into CR3 first
;   [rsp+8]  RIP  (user entry point)
;   [rsp+16] CS   (0x23 = user code | RPL=3)
;   [rsp+24] RFLAGS (0x202 = IF=1 | reserved bit 1)
;   [rsp+32] RSP  (user stack top, 16-byte aligned)
;   [rsp+40] SS   (0x1B = user data | RPL=3)
;
; We are executing on the user task's kva-allocated kernel stack, which is
; mapped in BOTH the master and user PML4 via the shared pdpt_hi PDPT page.
; Switching CR3 here (on the kva stack) is safe: after the CR3 switch the
; stack is still accessible in the user PML4, and iretq consumes the
; remaining 5 qwords from the same stack.
;
; This is the ONLY correct place to switch CR3 to the user PML4 on first
; entry.  sched_tick must NOT switch CR3 before ctx_switch because switching
; mid-context-switch would leave the outgoing task's stack live on the CPU
; under the wrong CR3, causing a triple fault on the very next stack access.
proc_enter_user:
    pop  rax          ; user PML4 physical address
    mov  cr3, rax     ; switch to user PML4 — flushes TLB
    ; SWAPGS: swap the active GS.base with IA32_KERNEL_GS_BASE.
    ;
    ; Standard x86-64 convention: GS.base holds the kernel percpu pointer
    ; in kernel mode, and holds the user TLS pointer (typically 0 for new
    ; processes) in user mode. SWAPGS on trap/syscall entry promotes
    ; IA32_KERNEL_GS_BASE→GS.base (kernel takeover), and on exit demotes
    ; it back for user mode.
    ;
    ; History note: this instruction was removed twice during chaotic
    ; bare-metal debugging sessions (2026-03-28) — both times as a "test"
    ; to isolate phantom panics that turned out to be stale git-tracked
    ; user binaries and unrelated IOAPIC/LAPIC issues. See c6b0deb for
    ; the first revert ("the RIP=0 was caused by a stale vigil binary,
    ; not SWAPGS"). The second removal (20d2e56) was never reverted and
    ; left a "Root cause TBD" comment that survived until 2026-04-09.
    ;
    ; Root cause analysis (2026-04-09): in Aegis's current setup,
    ; smp_percpu_init_bsp writes BOTH IA32_GS_BASE and IA32_KERNEL_GS_BASE
    ; to the same percpu pointer, and nothing else touches them before
    ; the first proc_enter_user. So SWAPGS here swaps two equal values —
    ; a pure no-op at the architectural level — and cannot cause any
    ; fault on any CPU. Adding it back restores standard semantics and
    ; future-proofs against changes to smp_percpu_init_bsp that would
    ; store the user GS base in IA32_KERNEL_GS_BASE.
    swapgs
    iretq

; fork_child_return was removed in Phase 15 fix.
; The child now enters user space via isr_post_dispatch (iretq path)
; using a complete fake isr_common_stub frame built by sys_fork.
; See kernel/arch/x86_64/isr.asm:isr_post_dispatch.
