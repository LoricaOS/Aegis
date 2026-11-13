#include "qr_report.h"
#include "probe_console.h"
#include "qrcodegen.h"
#include <stddef.h>

#ifdef APPLE_TIMER_CHECKPOINT
#ifdef APPLE_SCHED_CHECKPOINT
#ifdef APPLE_USER_CHECKPOINT
#define QR_VERSION 28
char apple_qr_text[1280];
volatile uint64_t apple_qr_user[12];
#define QR_BUILD "user-qr1"
#elif defined(APPLE_PREEMPT_CHECKPOINT)
#define QR_VERSION 28
char apple_qr_text[1280];
volatile uint64_t apple_qr_preempt[6];
#define QR_BUILD "preempt-qr1"
#else
#define QR_VERSION 24
char apple_qr_text[896];
#define QR_BUILD "sched-qr1"
#endif
volatile uint64_t apple_qr_sched[8];
#else
#define QR_VERSION 22
char apple_qr_text[768];
#define QR_BUILD "timer-qr1"
#endif
volatile uint64_t apple_qr_timer[8];
volatile uint64_t apple_qr_memory[4];
#else
#define QR_VERSION 20
#ifdef APPLE_MEMORY_CHECKPOINT
char apple_qr_text[640];
volatile uint64_t apple_qr_memory[4];
#define QR_BUILD "mem-qr1"
#else
char apple_qr_text[512];
#define QR_BUILD "wb-qr2"
#endif
#endif
uint8_t apple_qr_matrix[qrcodegen_BUFFER_LEN_FOR_VERSION(QR_VERSION)];
static uint8_t scratch[qrcodegen_BUFFER_LEN_FOR_VERSION(QR_VERSION)];
static unsigned length;
static int busy;

__attribute__((noreturn))
void apple_qr_assert_fail(void)
{
    probe_puts("HALTED - QR ENCODER ASSERTION\n");
    for (;;) __asm__ volatile("wfe");
}

static int append(const char *s, unsigned bound)
{
    for (unsigned i = 0; i < bound; i++) {
        if (!s[i]) return 1;
        if (length == sizeof(apple_qr_text) - 1) return 0;
        apple_qr_text[length++] = s[i];
    }
    return 0;
}

static int field(const char *key, uint64_t value)
{
    static const char hex[] = "0123456789abcdef";
    if (!append("\",\"", 4) || !append(key, 32) || !append("\":\"0x", 7) ||
        length + 16 >= sizeof(apple_qr_text)) return 0;
    for (int shift = 60; shift >= 0; shift -= 4)
        apple_qr_text[length++] = hex[(value >> shift) & 15];
    return 1;
}

void apple_qr_progress(const char *phase, const volatile uint64_t *atomic)
{
    if (busy) return; /* a fatal fault while encoding must not recurse */
    busy = 1;
    uint64_t el, sctlr, pc, sp, esr, far, elr;
    __asm__ volatile("mrs %0, CurrentEL" : "=r"(el));
    __asm__ volatile("adr %0, ." : "=r"(pc));
    __asm__ volatile("mov %0, sp" : "=r"(sp));
    if (el == 8) {
        __asm__ volatile("mrs %0, sctlr_el2" : "=r"(sctlr));
        __asm__ volatile("mrs %0, esr_el2" : "=r"(esr));
        __asm__ volatile("mrs %0, far_el2" : "=r"(far));
        __asm__ volatile("mrs %0, elr_el2" : "=r"(elr));
    } else {
        __asm__ volatile("mrs %0, sctlr_el1" : "=r"(sctlr));
        __asm__ volatile("mrs %0, esr_el1" : "=r"(esr));
        __asm__ volatile("mrs %0, far_el1" : "=r"(far));
        __asm__ volatile("mrs %0, elr_el1" : "=r"(elr));
    }
    length = 0;
    int good = append("{\"schema\":\"aegis.apple.qr1\",\"build\":\"" QR_BUILD "\",\"phase\":\"", 80) &&
        append(phase, 40) && field("el", el >> 2) && field("sctlr", sctlr) &&
        field("pc", pc) && field("sp", sp) && field("esr", esr) &&
        field("far", far) && field("elr", elr);
    if (good && atomic)
        good = field("attempts", atomic[0]) && field("status", atomic[1]) &&
               field("value", atomic[2]) && field("lock", atomic[3]);
#ifdef APPLE_MEMORY_CHECKPOINT
    if (good)
        good = field("arena", apple_qr_memory[0]) && field("arena_bytes", apple_qr_memory[1]) &&
               field("free", apple_qr_memory[2]) && field("root", apple_qr_memory[3]);
#endif
#ifdef APPLE_USER_CHECKPOINT
    if (good)
        good = field("pid", apple_qr_user[0]) && field("uid", apple_qr_user[1]) &&
               field("svcs", apple_qr_user[2]) && field("kernel_deny", apple_qr_user[3]) &&
               field("text_deny", apple_qr_user[4]) && field("nx_deny", apple_qr_user[5]) &&
               field("capdeny", apple_qr_user[6]) && field("badptr", apple_qr_user[7]) &&
               field("reason", apple_qr_user[8]) && field("ttbr0", apple_qr_user[9]) &&
               field("usp", apple_qr_user[10]) && field("entered", apple_qr_user[11]);
#elif defined(APPLE_SCHED_CHECKPOINT)
    if (good)
        good = field("a", apple_qr_sched[0]) && field("b", apple_qr_sched[1]) &&
               field("rounds", apple_qr_sched[2]) && field("reason", apple_qr_sched[3]) &&
               field("cpacr", apple_qr_sched[4]) && field("daif", apple_qr_sched[5]) &&
               field("tasks", apple_qr_sched[6]) && field("free_now", apple_qr_sched[7]);
#ifdef APPLE_PREEMPT_CHECKPOINT
    if (good)
        good = field("ticks", apple_qr_preempt[0]) && field("fiq_a", apple_qr_preempt[1]) &&
               field("fiq_b", apple_qr_preempt[2]) && field("ret_a", apple_qr_preempt[3]) &&
               field("ret_b", apple_qr_preempt[4]) && field("freq", apple_qr_preempt[5]);
#endif
#elif defined(APPLE_TIMER_CHECKPOINT)
    if (good)
        good = field("freq", apple_qr_timer[0]) && field("fiq", apple_qr_timer[1]) &&
               field("returned", apple_qr_timer[2]) && field("reason", apple_qr_timer[3]) &&
               field("hcr", apple_qr_timer[4]) && field("gate_before", apple_qr_timer[5]) &&
               field("gate_after", apple_qr_timer[6]) && field("cnthctl", apple_qr_timer[7]);
#endif
    good = good && append("\"}", 3);
    apple_qr_text[length] = 0;
    if (good && qrcodegen_encodeText(apple_qr_text, scratch, apple_qr_matrix,
            qrcodegen_Ecc_MEDIUM, QR_VERSION, QR_VERSION, qrcodegen_Mask_0, false))
        probe_console_draw_qr(apple_qr_matrix, qrcodegen_getSize(apple_qr_matrix));
    else
        probe_puts("QR REPORT UNAVAILABLE - USE TEXT\n");
    __asm__ volatile("dsb sy" ::: "memory");
    busy = 0;
}
