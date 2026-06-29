#include "arch.h"

/*
 * arch_debug_exit — signal QEMU's isa-debug-exit device.
 *
 * Writes `value` to I/O port 0xf4. QEMU translates this to process
 * exit code (value << 1) | 1. Writing 0x01 → exit code 3.
 * Only valid when QEMU is launched with:
 *   -device isa-debug-exit,iobase=0xf4,iosize=0x04
 * On real hardware this port is unassigned; the outb is a no-op.
 *
 * Clobbers: none.
 */
void arch_debug_exit(unsigned char value)
{
    __asm__ volatile ("outb %0, %1" : : "a"(value), "Nd"((unsigned short)0xf4));
}
