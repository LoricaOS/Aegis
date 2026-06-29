; ap_trampoline.asm — AP bootstrap: real mode → protected mode → long mode
;
; The BSP copies this entire block to physical address 0x8000 before sending
; SIPIs. Each AP wakes in 16-bit real mode at CS=0x0800, IP=0x0000
; (linear 0x8000). The code transitions through 32-bit protected mode to
; 64-bit long mode, picks up a per-CPU stack from the data area, and jumps
; to the higher-half C entry point (ap_entry).
;
; Register clobbers: all — this is an entry point, not a callable function.
; Calling convention: none — ends with a jmp to the C ap_entry() function.

TRAMPOLINE_PHYS equ 0x8000

section .text.ap_trampoline

; ─── Exported symbols (referenced by smp.c) ──────────────────────────────────
global ap_trampoline_start
global ap_trampoline_end
global ap_pml4
global ap_entry_addr
global ap_stacks

; ─── 16-bit real-mode entry ──────────────────────────────────────────────────
[BITS 16]
ap_trampoline_start:
    cli

    ; Enable A20 line (fast A20 via port 0x92)
    in   al, 0x92
    or   al, 2
    and  al, 0xFE           ; don't accidentally trigger reset (bit 0)
    out  0x92, al

    ; Point DS at the trampoline segment so LGDT can find the GDTR
    mov ax, 0x0800              ; segment = TRAMPOLINE_PHYS >> 4
    mov ds, ax

    ; Load the temporary GDT (GDTR address is a 32-bit linear address)
    lgdt [ap_gdtr - ap_trampoline_start]

    ; Enable protected mode (CR0.PE = bit 0)
    mov eax, cr0
    or  eax, 1
    mov cr0, eax

    ; Far-jump to 32-bit protected mode code, selector 0x08 (32-bit code)
    jmp dword 0x08:(pm32 - ap_trampoline_start + TRAMPOLINE_PHYS)

; ─── 32-bit protected mode ───────────────────────────────────────────────────
[BITS 32]
pm32:
    ; Set data segments to selector 0x10 (32-bit data)
    mov ax, 0x10
    mov ds, ax
    mov es, ax
    mov ss, ax

    ; Enable PAE (CR4 bit 5)
    mov eax, cr4
    or  eax, (1 << 5)
    mov cr4, eax

    ; Load PML4 from the data area (BSP writes this before SIPI)
    mov eax, [ap_pml4 - ap_trampoline_start + TRAMPOLINE_PHYS]
    mov cr3, eax

    ; Enable long mode (IA32_EFER: LME = bit 8, NXE = bit 11)
    mov ecx, 0xC0000080         ; IA32_EFER MSR
    rdmsr
    or  eax, (1 << 8) | (1 << 11)
    wrmsr

    ; Enable paging (CR0.PG = bit 31) + write-protect (CR0.WP = bit 16)
    mov eax, cr0
    or  eax, (1 << 31) | (1 << 16)
    mov cr0, eax

    ; Far-jump to 64-bit long mode, selector 0x18 (64-bit code)
    jmp 0x18:(lm64 - ap_trampoline_start + TRAMPOLINE_PHYS)

; ─── 64-bit long mode (still at physical address) ───────────────────────────
[BITS 64]
DEFAULT ABS     ; all addresses are absolute (not RIP-relative) — trampoline
                ; runs at physical 0x8000, not at its linked higher-half VMA
lm64:
    ; Set data segments to selector 0x20 (64-bit data)
    mov ax, 0x20
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax
    mov ss, ax

    ; Get LAPIC ID via CPUID leaf 1 (initial APIC ID is in EBX[31:24])
    mov eax, 1
    cpuid
    shr ebx, 24                 ; EBX = LAPIC ID (0-based on most hardware)

    ; Index into per-CPU stack table and set RSP
    mov rsp, [rbx * 8 + ap_stacks - ap_trampoline_start + TRAMPOLINE_PHYS]

    ; Load the higher-half C entry point address
    mov rax, [ap_entry_addr - ap_trampoline_start + TRAMPOLINE_PHYS]

    ; Jump to higher-half kernel code (ap_entry in smp.c)
    jmp rax

; ─── Temporary GDT (embedded in trampoline) ──────────────────────────────────
align 16
ap_gdt:
    dq 0                        ; [0x00] null descriptor
    dq 0x00CF9A000000FFFF       ; [0x08] 32-bit code: base=0, limit=4GB, DPL=0
    dq 0x00CF92000000FFFF       ; [0x10] 32-bit data: base=0, limit=4GB, DPL=0
    dq 0x00AF9A000000FFFF       ; [0x18] 64-bit code: L=1, D=0, DPL=0
    dq 0x00AF92000000FFFF       ; [0x20] 64-bit data: L=1, DPL=0
ap_gdt_end:

ap_gdtr:
    dw ap_gdt_end - ap_gdt - 1                         ; limit
    dd ap_gdt - ap_trampoline_start + TRAMPOLINE_PHYS   ; 32-bit linear base

; ─── Data area (filled by BSP before sending SIPIs) ──────────────────────────
align 4
ap_pml4:        dd 0            ; physical address of kernel PML4 (32-bit)

align 8
ap_entry_addr:  dq 0            ; 64-bit VA of ap_entry() C function

ap_stacks:      times 256 dq 0  ; per-CPU kernel stack tops (indexed by LAPIC ID, max 255)

; ─── End marker ──────────────────────────────────────────────────────────────
ap_trampoline_end:
