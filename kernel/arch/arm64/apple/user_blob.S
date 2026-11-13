.section .rodata
.balign 8
.global apple_user_elf
.global apple_user_elf_end
apple_user_elf:
.incbin "build/appleuser/user.elf"
apple_user_elf_end:
