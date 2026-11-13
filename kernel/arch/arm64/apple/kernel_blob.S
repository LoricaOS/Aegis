#include "kernel_layout.h"
.section .rodata.kernel_blob, "a"
.balign 4096
.global apple_kernel_blob
.hidden apple_kernel_blob
apple_kernel_blob:
    .incbin KERNEL_BINARY_PATH
.global apple_kernel_blob_end
.hidden apple_kernel_blob_end
apple_kernel_blob_end:
