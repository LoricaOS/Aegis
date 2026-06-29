/* hyperv.c — Microsoft Hyper-V foundation: detection, hypercalls, SynIC.
 * See hyperv.h. Researched against the Hyper-V TLFS + Linux drivers/hv.
 *
 * Blind bring-up: every step logs over serial so a first Hyper-V boot shows
 * exactly how far it got. All of this is gated on hyperv_present(), so QEMU /
 * bare-metal boots skip it entirely (the boot oracle is unaffected).
 */
#include "hyperv.h"
#include "kva.h"
#include "vmm.h"
#include "printk.h"
#include <stdint.h>
#include <stddef.h>

/* ── low-level CPU helpers ────────────────────────────────────────────────── */
static inline void
hv_cpuid(uint32_t leaf, uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d)
{
    __asm__ volatile("cpuid"
                     : "=a"(*a), "=b"(*b), "=c"(*c), "=d"(*d)
                     : "a"(leaf), "c"(0));
}

static inline uint64_t
hv_rdmsr(uint32_t msr)
{
    uint32_t lo, hi;
    __asm__ volatile("rdmsr" : "=a"(lo), "=d"(hi) : "c"(msr));
    return ((uint64_t)hi << 32) | lo;
}

static inline void
hv_wrmsr(uint32_t msr, uint64_t val)
{
    __asm__ volatile("wrmsr"
                     :
                     : "c"(msr), "a"((uint32_t)val), "d"((uint32_t)(val >> 32)));
}

static void
hv_memset(void *d, int v, uint32_t n)
{
    uint8_t *p = d;
    while (n--) *p++ = (uint8_t)v;
}
static void
hv_memcpy(void *d, const void *s, uint32_t n)
{
    uint8_t *dd = d; const uint8_t *ss = s;
    while (n--) *dd++ = *ss++;
}

/* ── state ────────────────────────────────────────────────────────────────── */
static void     *s_hc_page;        /* hypercall page (executable) */
static uint8_t  *s_simp;           /* SynIC message page  */
static uint8_t  *s_siefp;          /* SynIC event-flags page */
static void     *s_post_va;        /* HvPostMessage input page */
static uint64_t  s_post_pa;
static int       s_ready;

/* ── the hypercall instruction (call into the hypervisor-populated page) ───── */
static inline uint64_t
hv_hypercall(uint64_t control, uint64_t in_pa, uint64_t out_pa)
{
    uint64_t status;
    register uint64_t r8 asm("r8") = out_pa;
    __asm__ volatile("callq *%[hc]"
                     : "=a"(status), "+c"(control), "+d"(in_pa), "+r"(r8)
                     : [hc] "r"(s_hc_page)
                     : "memory", "cc", "r9", "r10", "r11");
    return status;
}

int
hyperv_present(void)
{
    static int cached = -1;
    if (cached >= 0)
        return cached;
    uint32_t a, b, c, d;
    hv_cpuid(HV_CPUID_VENDOR, &a, &b, &c, &d);
    /* "Microsoft Hv": EBX="Micr", ECX="osof", EDX="t Hv" (little-endian). */
    cached = (b == 0x7263694Du && c == 0x666F736Fu && d == 0x76482074u) ? 1 : 0;
    return cached;
}

/* hyperv_ref_time — partition reference counter, 100ns units (TLFS §Timers).
 * Monotonic, rate-constant, available without the SynIC handshake. The LAPIC
 * timer calibration uses this on Gen 2 VMs, which lack the 8254 PIT. */
uint64_t
hyperv_ref_time(void)
{
    if (!hyperv_present())
        return 0;
    return hv_rdmsr(HV_MSR_TIME_REF_COUNT);
}

/* Allocate one zeroed <4GB page; return VA, set *pa. */
static void *
hv_alloc_page(uint64_t *pa)
{
    void *va = kva_alloc_pages_low(1);
    if (!va)
        return NULL;
    hv_memset(va, 0, 4096);
    *pa = kva_page_phys(va);
    return va;
}

void
hyperv_init(void)
{
    if (!hyperv_present())
        return;                          /* not Hyper-V → silent skip */

    uint32_t a, b, c, d;
    hv_cpuid(HV_CPUID_INTERFACE, &a, &b, &c, &d);
    printk("[HV] detected: Microsoft Hv, interface=0x%x\n", (unsigned)a);
    hv_cpuid(HV_CPUID_FEATURES, &a, &b, &c, &d);
    printk("[HV] features eax=0x%x (hypercall=%u synic=%u)\n",
           (unsigned)a, (unsigned)((a & HV_FEATURE_HYPERCALL) != 0),
           (unsigned)((a & HV_FEATURE_SYNIC) != 0));
    if (!(a & HV_FEATURE_HYPERCALL) || !(a & HV_FEATURE_SYNIC)) {
        printk("[HV] FAIL: hypercall/synic not available\n");
        return;
    }

    /* 1. GUEST_OS_ID must be nonzero before the hypercall page can be enabled.
     *    The encoding is informational to the host; 'A' in the vendor field. */
    hv_wrmsr(HV_MSR_GUEST_OS_ID, 0x0041000000000000ull);

    /* 2. Hypercall page: allocate a page, map it executable, hand the host its
     *    GPA + enable bit. The host populates it with the hypercall trampoline. */
    uint64_t hc_pa;
    void *hc_va = kva_alloc_pages_low(1);
    if (!hc_va) { printk("[HV] FAIL: hypercall page alloc\n"); return; }
    hc_pa = kva_page_phys(hc_va);
    /* Remap executable (clear NX): present + writable, no VMM_FLAG_NX. */
    vmm_unmap_page((uintptr_t)hc_va);
    vmm_map_page((uintptr_t)hc_va, hc_pa, VMM_FLAG_PRESENT | VMM_FLAG_WRITABLE);
    s_hc_page = hc_va;
    /* HYPERCALL MSR: bit0 = enable, bits 63:12 = page GPA (page-aligned). */
    hv_wrmsr(HV_MSR_HYPERCALL, (hc_pa & ~0xFFFull) | 1ull);
    printk("[HV] hypercall page enabled @ pa=0x%lx\n", (unsigned long)hc_pa);

    /* 3. HvPostMessage input page (must be a single page, 8-byte aligned). */
    s_post_va = hv_alloc_page(&s_post_pa);
    if (!s_post_va) { printk("[HV] FAIL: post page alloc\n"); return; }

    /* 4. SynIC: message page (SIMP) + event-flags page (SIEFP) + enable. */
    uint64_t simp_pa = 0, siefp_pa = 0;  /* -O2 false positive: set by hv_alloc_page on success */
    s_simp  = hv_alloc_page(&simp_pa);
    s_siefp = hv_alloc_page(&siefp_pa);
    if (!s_simp || !s_siefp) { printk("[HV] FAIL: synic page alloc\n"); return; }
    hv_wrmsr(HV_MSR_SIMP,  (simp_pa  & ~0xFFFull) | 1ull);   /* bit0 = enable */
    hv_wrmsr(HV_MSR_SIEFP, (siefp_pa & ~0xFFFull) | 1ull);
    hv_wrmsr(HV_MSR_SCONTROL, 1ull);                          /* enable SynIC */

    /* 5. Route the VMBus SINT (2). Polling mode: messages land in the message
     *    page, no interrupt is generated (Aegis polls). Unmasked, vector 0x40. */
    hv_wrmsr(HV_MSR_SINT0 + HV_SINT_VMBUS, 0x40ull | HV_SINT_POLLING);

    printk("[HV] OK: hypercall + SynIC up (SIMP=0x%lx SIEFP=0x%lx, SINT%u polling)\n",
           (unsigned long)simp_pa, (unsigned long)siefp_pa, (unsigned)HV_SINT_VMBUS);
    s_ready = 1;
}

uint64_t
hv_post_message(uint32_t connection_id, const void *payload, uint32_t size)
{
    if (!s_ready) return ~0ull;
    if (size > 240) size = 240;
    hv_input_post_message_t *in = (hv_input_post_message_t *)s_post_va;
    hv_memset(in, 0, sizeof(*in));
    in->connection_id = connection_id;
    in->message_type  = HV_MSGTYPE_VMBUS;
    in->payload_size  = size;
    hv_memcpy(in->payload, payload, size);
    __asm__ volatile("mfence" ::: "memory");
    return hv_hypercall(HVCALL_POST_MESSAGE, s_post_pa, 0);
}

uint64_t
hv_signal_event(uint32_t connection_id)
{
    if (!s_ready) return ~0ull;
    /* Fast hypercall: input value in RDX = connection_id (flag 0 in high bits). */
    return hv_hypercall(HVCALL_SIGNAL_EVENT | HV_HYPERCALL_FAST_BIT,
                        (uint64_t)connection_id, 0);
}

int
hv_get_vmbus_message(hv_message_t *out)
{
    if (!s_ready) return 0;
    hv_message_t *slot = &((hv_message_t *)s_simp)[HV_SINT_VMBUS];
    if (slot->header.message_type == HV_MSGTYPE_NONE)
        return 0;
    hv_memcpy(out, slot, sizeof(*out));
    /* Consume: clear the slot, barrier, then EOM so the host can deliver next. */
    slot->header.message_type = HV_MSGTYPE_NONE;
    __asm__ volatile("mfence" ::: "memory");
    hv_wrmsr(HV_MSR_EOM, 0);
    return 1;
}
