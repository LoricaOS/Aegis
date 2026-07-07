; boot.asm — Aegis x86-64 boot entries.
;
; TWO entry points share this file:
;
;   limine_start (ELF entry) — the Limine boot protocol path. The bootloader
;   hands off in 64-bit long mode with the kernel mapped higher-half and an
;   HHDM active, so no mode switching or bootstrap page tables are needed:
;   load our own GDT, switch to the .bss boot stack, call limine_boot_entry.
;
;   _start (multiboot2 header entry-address tag) — the legacy/microvm path
;   (GRUB, QEMU direct mb2 loaders). Everything the Limine protocol
;   obsoletes lives here and is PRESERVED for that path: the 32-bit entry,
;   the 5 bootstrap page tables in .bss, the PAE/EFER long-mode enable, and
;   the 32→64 far-jump trampoline.
;
; multiboot2 sequence:
;   1. GRUB loads us at physical 0x100000 (ELF LMA) in 32-bit protected mode.
;   2. We build 5 page tables in .bss (physical addresses via (label-KERN_VMA)).
;   3. Enable PAE + long mode (EFER), load CR3, enable paging.
;   4. Far-jump to long_mode_phys (executing at its physical address).
;   5. long_mode_phys sets segments, then jmp rax → long_mode_high.
;   6. long_mode_high (higher-half VMA, in .text) sets stack, calls kernel_main.
;
; All sections now carry higher-half VMAs (LMA = VMA - KERN_VMA via the
; linker AT() directive) so the Limine protocol accepts the ELF; the 32-bit
; code references every absolute symbol as (label - KERN_VMA) = physical.
;
; Register clobbers: all (these are entry points, not callable functions).
; Calling convention: none — we eventually call C via the SysV AMD64 ABI.

MULTIBOOT2_MAGIC  equ 0xE85250D6   ; identifies this as a multiboot2 header
MULTIBOOT2_ARCH   equ 0             ; 0 = i386 (32-bit protected mode entry)

KERN_VMA     equ 0xFFFFFFFF80000000
PDPT_HI_IDX  equ ((KERN_VMA >> 30) & 0x1FF)   ; = 510

; ────────────────────────────────────────────────
; .multiboot — must be within first 8KB for GRUB
; VMA = LMA = physical (linker places it first)
; ────────────────────────────────────────────────
section .multiboot
align 8
multiboot_header_start:
    dd MULTIBOOT2_MAGIC
    dd MULTIBOOT2_ARCH
    dd (multiboot_header_end - multiboot_header_start)
    ; Checksum: magic + arch + length + checksum must sum to 0 (mod 2^32)
    dd -(MULTIBOOT2_MAGIC + MULTIBOOT2_ARCH + \
         (multiboot_header_end - multiboot_header_start))
    ; Framebuffer request tag (type=5) — ask GRUB for a linear framebuffer.
    ; GRUB will honour this together with grub.cfg's gfxpayload=keep.
    ; Size is 20: 8 bytes header (type+flags+size) + 12 bytes payload.
    align 8
    dw 5        ; type = MULTIBOOT_HEADER_TAG_FRAMEBUFFER
    dw 0        ; flags = 0 (required, not optional)
    dd 20       ; tag size in bytes
    dd 0        ; preferred width  (0 = any — use native resolution)
    dd 0        ; preferred height (0 = any)
    dd 32       ; preferred depth  (32bpp required)

    ; Entry-address tag (type=3): GRUB must enter at _start's PHYSICAL
    ; address. Required now that every section (including .text.boot) has a
    ; higher-half VMA — the ELF e_entry points at limine_start (the Limine
    ; protocol entry) and is useless to a 32-bit multiboot2 loader.
    align 8
    dw 3        ; type = MULTIBOOT_HEADER_TAG_ENTRY_ADDRESS
    dw 0        ; flags = 0 (required)
    dd 12       ; tag size
    dd (_start - KERN_VMA)

    align 8
    ; End tag (type=0, flags=0, size=8)
    dw 0
    dw 0
    dd 8
multiboot_header_end:


; ────────────────────────────────────────────────
; .text.boot — the multiboot2 (microvm) path: 32-bit entry + trampoline.
; Contains: GDT, _start (32-bit), long_mode_phys (64-bit trampoline).
;
; VMA is higher-half (like every section now); LMA = VMA - KERN_VMA =
; physical. The 32-bit code below therefore references every absolute
; symbol as (label - KERN_VMA), which IS its physical address. Relative
; jumps within the section need no adjustment.
; ────────────────────────────────────────────────
section .text.boot
bits 32

; GDT for 64-bit mode — must be at physical address for lgdt in 32-bit mode.
; Descriptor format: see Intel SDM Vol 3A, Section 3.4.5
gdt64:
    ; Entry 0: null descriptor (required)
    dq 0x0000000000000000
    ; Entry 1 (selector 0x08): 64-bit code segment
    ;   Limit: 0xFFFFF (ignored in 64-bit mode), Base: 0
    ;   Access: P=1, DPL=0, S=1, Type=1011 (code/execute/read, Accessed=1)
    ;   Flags: G=1, L=1 (64-bit), D=0
    ;   The Accessed bit (0x9A -> 0x9B) is pre-set so a segment-selector load
    ;   never makes the CPU WRITE it back into the descriptor. gdt64 can land in
    ;   a page the bootloader maps read-only (it shares the first image page with
    ;   code/rodata); without A=1 the write faults -> #PF -> #DF -> triple fault,
    ;   a latent layout-dependent boot crash (exposed when unrelated size changes
    ;   shifted this page across a PT_LOAD read-only boundary).
    dq 0x00AF9B000000FFFF
    ; Entry 2 (selector 0x10): 64-bit data segment
    ;   Access: P=1, DPL=0, S=1, Type=0011 (data/read/write, Accessed=1)
    ;   Flags: G=1, L=0 (data segments ignore L bit)
    dq 0x00AF93000000FFFF
gdt64_end:

; LGDT descriptor for the 32-bit mb2 path: 2-byte limit + 4-byte base.
; The base must be PHYSICAL (paging is off) — gdt64 now has a higher-half
; VMA, so subtract KERN_VMA to get its load (physical) address.
gdt64_ptr:
    dw (gdt64_end - gdt64 - 1)
    dd (gdt64 - KERN_VMA)            ; 32-bit physical address


; _start — first instruction executed after the bootloader hands off control.
;
; Purpose: build page tables, enable PAE + long mode, jump to 64-bit code.
; Entry state per multiboot2 spec:
;   EAX = multiboot2 magic (0x36D76289)
;   EBX = physical address of multiboot2 info structure
;   CPU: 32-bit protected mode, interrupts disabled, paging off
; Clobbers: all registers
; Calling convention: none (we are the entry point)
global _start
_start:
    ; Disable interrupts; we have no IDT yet.
    cli

    ; Preserve multiboot2 args before we clobber EAX/EBX.
    ; kernel_main(uint32_t mb_magic, void *mb_info) per SysV AMD64 ABI:
    ;   RDI = first arg  = mb_magic (EAX from bootloader)
    ;   RSI = second arg = mb_info  (EBX from bootloader, physical addr)
    ; Both values are < 4GB so zero-extension into 64-bit registers is safe.
    ; EDI/ESI survive the mode transition — we don't clobber them below.
    mov edi, eax                ; mb_magic → RDI (first arg)
    mov esi, ebx                ; mb_info  → RSI (second arg)

    ; ── Set up page tables ──────────────────────────────────────────────
    ; All .bss labels have higher-half VMAs after the linker split.
    ; Use (label - KERN_VMA) to compute their physical addresses at
    ; assemble/link time. NASM evaluates these as 32-bit constants.
    ;
    ; We map 8MB total (four 2MB huge pages) for both identity and higher-half:
    ;   Identity:     VA [0x000000..0x7FFFFF] → PA [0x000000..0x7FFFFF]
    ;   Higher-half:  VA [KERN_VMA..KERN_VMA+0x7FFFFF] → PA [0x000000..0x7FFFFF]
    ;
    ; 8MB covers the kernel binary + BSS + any GRUB-placed multiboot2 info
    ; structure that GRUB may place above 4MB when the kernel grows large.
    ;
    ; Table layout:
    ;   PML4[0]   → pdpt_lo   (identity window)
    ;   PML4[511] → pdpt_hi   (higher-half kernel)
    ;   pdpt_lo[0]            → pd_lo
    ;   pdpt_hi[PDPT_HI_IDX]  → pd_hi
    ;   pd_lo[0..3]           → 2MB huge pages at PA 0x000000..0x600000
    ;   pd_hi[0..3]           → 2MB huge pages at PA 0x000000..0x600000

    ; PML4[0] → pdpt_lo  (identity: VA 0x000000 → PA 0x000000)
    mov eax, dword (pdpt_lo - KERN_VMA)
    or  eax, 0x03                    ; PRESENT | WRITABLE
    mov ebx, dword (pml4_table - KERN_VMA)
    mov [ebx], eax

    ; PML4[511] → pdpt_hi  (kernel: VA KERN_VMA → PA 0x000000)
    mov eax, dword (pdpt_hi - KERN_VMA)
    or  eax, 0x03
    mov [ebx + 511*8], eax

    ; pdpt_lo[0] → pd_lo
    mov eax, dword (pd_lo - KERN_VMA)
    or  eax, 0x03
    mov ebx, dword (pdpt_lo - KERN_VMA)
    mov [ebx], eax

    ; pdpt_hi[PDPT_HI_IDX] → pd_hi
    mov eax, dword (pd_hi - KERN_VMA)
    or  eax, 0x03
    mov ebx, dword (pdpt_hi - KERN_VMA)
    mov [ebx + PDPT_HI_IDX*8], eax

    ; pd_lo[0..511]: 2MB huge pages PA 0x000000..0x3FE00000 (identity, first 1GB)
    ; Covers all physical RAM that GRUB modules or PMM pages may occupy.
    ; Flags: PRESENT(0x01) | WRITABLE(0x02) | HUGE(0x80) = 0x83
    mov ebx, dword (pd_lo - KERN_VMA)
    xor ecx, ecx                       ; ecx = page index (0..511)
.fill_pd_lo:
    mov eax, ecx
    shl eax, 21                        ; eax = index * 2MB
    or  eax, 0x83                      ; PRESENT | WRITABLE | HUGE
    mov [ebx + ecx*8],     eax         ; low 32 bits
    mov dword [ebx + ecx*8 + 4], 0    ; high 32 bits = 0 (below 4GB)
    inc ecx
    cmp ecx, 512
    jb .fill_pd_lo

    ; pd_hi[0..3]: 2MB huge pages PA 0x000000..0x600000 (kernel higher-half)
    mov ebx, dword (pd_hi - KERN_VMA)
    mov dword [ebx],       0x00000083
    mov dword [ebx + 4],   0x00000000
    mov dword [ebx + 8],   0x00200083
    mov dword [ebx + 12],  0x00000000
    mov dword [ebx + 16],  0x00400083
    mov dword [ebx + 20],  0x00000000
    mov dword [ebx + 24],  0x00600083
    mov dword [ebx + 28],  0x00000000

    ; ── Enable Physical Address Extension (required for long mode) ───────
    ; CR4.PAE = bit 5
    mov eax, cr4
    or  eax, (1 << 5)                ; PAE bit
    mov cr4, eax

    ; ── Load CR3 with physical address of PML4 ──────────────────────────
    mov eax, dword (pml4_table - KERN_VMA)
    mov cr3, eax

    ; ── Enable long mode + NX via EFER MSR ──────────────────────────────
    ; MSR 0xC0000080 = EFER; bit 8 = LME (Long Mode Enable)
    ;                        bit 11 = NXE (No-Execute Enable)
    ; NXE is required for VMM_FLAG_NX (PTE bit 63) used by mmap/mprotect.
    mov ecx, 0xC0000080
    rdmsr
    or  eax, (1 << 8) | (1 << 11)   ; EFER.LME + EFER.NXE
    wrmsr

    ; ── Load GDT ────────────────────────────────────────────────────────
    ; gdt64_ptr has a higher-half VMA; its physical address is -KERN_VMA.
    lgdt [dword (gdt64_ptr - KERN_VMA)]

    ; ── Enable paging (also activates long mode) ────────────────────────
    ; Also set CR0.WP (write protect) so ring-0 respects read-only pages.
    ; Setting PG with LME set transitions CPU to IA-32e (long) mode.
    mov eax, cr0
    or  eax, (1 << 31) | (1 << 16)  ; CR0.PG | CR0.WP
    mov cr0, eax

    ; ── Far jump: reload CS with 64-bit code descriptor ─────────────────
    ; Selector 0x08 = GDT entry 1 (64-bit code), RPL=0.
    ; Jump target must be the PHYSICAL address of long_mode_phys (we are
    ; still executing at physical addresses; the higher-half mapping is
    ; active but this jump's immediate is what the CPU fetches next).
    ; CPU enters 64-bit long mode after this jump.
    jmp 0x08:(long_mode_phys - KERN_VMA)


; long_mode_phys — executes in 64-bit mode at a physical address (still .text.boot).
;
; Purpose: set segment registers, then jump to the higher-half entry point.
; We cannot use RIP-relative addressing to reach .text symbols yet —
; we are executing at a physical address, not a higher-half address.
; Instead we load the full 64-bit VMA into RAX and jump through it.
;
; Clobbers: AX, RAX
; Calling convention: none
bits 64
global long_mode_phys
long_mode_phys:
    ; Set data segments. CS was already loaded by the far jump.
    ; Selector 0x10 = GDT entry 2 (64-bit data), RPL=0.
    mov ax, 0x10
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax
    mov ss, ax

    ; Load the full 64-bit higher-half virtual address of long_mode_high.
    ; long_mode_high is in section .text (VMA = KERN_VMA + offset).
    ; The higher-half mapping is already active (loaded via CR3 above),
    ; so jumping to this VMA is valid.
    mov rax, long_mode_high
    jmp rax                          ; cross the VMA gap!


; ────────────────────────────────────────────────
; .text — runs at higher-half VMA (0xFFFFFFFF80xxxxxx)
; Contains: limine_start (Limine protocol entry), long_mode_high
; (multiboot2 path's permanent entry)
; ────────────────────────────────────────────────
section .text
bits 64

extern kernel_main
extern limine_boot_entry

; LGDT descriptor for the Limine path: 2-byte limit + 8-byte base (64-bit
; lgdt form). Base is gdt64's higher-half VMA — mapped by the bootloader
; (it's in a loaded section) AND by the kernel's own tables after vmm_init,
; so the GDT stays reachable across the page-table switch. This is why we
; don't keep running on Limine's GDT: it lives in bootloader-reclaimable
; memory that the kernel's tables never map, and the CPU re-reads GDT
; entries on every exception's CS load.
gdt64_ptr_high:
    dw (gdt64_end - gdt64 - 1)
    dq gdt64

; limine_start — ELF entry point: the Limine boot protocol handoff.
;
; Entry state per the Limine spec (base revision 3): 64-bit long mode,
; kernel mapped higher-half per the ELF plus an HHDM, bootloader GDT
; (CS=0x28, DS/ES/SS=0x30), IF=0, bootloader-provided stack, all GPRs 0.
;
; Everything the multiboot2 path builds by hand (page tables, the 32→64
; switch) is already done for us — we only: load our own GDT, move onto
; the kernel's .bss boot stack (the bootloader stack is in reclaimable
; memory that dies with Limine's page tables at vmm_init), and enter C.
;
; Clobbers: all. Calling convention: none (entry point).
global limine_start
limine_start:
    cli
    lgdt [rel gdt64_ptr_high]

    ; Reload CS with our 64-bit code selector via a far return.
    push 0x08
    lea  rax, [rel .reload_cs]
    push rax
    retfq
.reload_cs:
    mov ax, 0x10
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax
    mov ss, ax

    ; Kernel boot stack (16-byte aligned, .bss — mapped by the bootloader
    ; now and by the kernel's own tables later).
    mov rsp, boot_stack_top
    xor rbp, rbp

    call limine_boot_entry
.halt:
    hlt
    jmp .halt

; long_mode_high — first code executing at the higher-half virtual address.
;
; Purpose: set up the boot stack and call kernel_main.
; Entry state: all segment registers set, paging active, higher-half mapped.
; Clobbers: RSP, RBP, and anything kernel_main touches.
; Calling convention: sets up SysV AMD64 ABI for kernel_main call.
global long_mode_high
long_mode_high:
    ; Set up the higher-half stack.
    ; boot_stack_top is in .bss (higher-half VMA after linker split) — use as-is.
    ; Stack must be 16-byte aligned before the call instruction (ABI requirement).
    mov rsp, boot_stack_top

    ; Clear the frame pointer to terminate stack unwinding at kernel entry.
    xor rbp, rbp

    ; RDI = mb_magic and RSI = mb_info were set in _start and survive the mode
    ; transition. kernel_main(uint32_t mb_magic, void *mb_info) per SysV AMD64 ABI.
    call kernel_main

.halt:
    hlt
    jmp .halt


; ────────────────────────────────────────────────
; .bss — zeroed at load time by GRUB.
; Labels here have higher-half VMAs after the linker split.
; Physical addresses: use (label - KERN_VMA) in .text.boot code only.
; ────────────────────────────────────────────────
section .bss
align 4096

global pml4_table
pml4_table:  resb 4096

global pdpt_lo
pdpt_lo:     resb 4096

global pdpt_hi
pdpt_hi:     resb 4096

global pd_lo
pd_lo:       resb 4096

global pd_hi
pd_hi:       resb 4096

; 16KB boot stack — 16-byte aligned as required by the SysV AMD64 ABI.
boot_stack:  resb 16384

global boot_stack_top
boot_stack_top:
