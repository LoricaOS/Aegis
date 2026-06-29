/* hyperv.h — Microsoft Hyper-V paravirtualization foundation.
 *
 * Hyper-V's paravirtual devices are NOT on the PCI bus — they are offered over
 * VMBus, a software bus layered on Hyper-V hypercalls and the Synthetic
 * Interrupt Controller (SynIC). This file is the platform foundation that
 * VMBus (kernel/drivers/vmbus.c) builds on:
 *
 *   1. Detect Hyper-V         (CPUID leaf 0x40000000 → "Microsoft Hv")
 *   2. Enable hypercalls      (GUEST_OS_ID + HYPERCALL MSR → hypercall page)
 *   3. Enable the SynIC       (SCONTROL + SIMP message page + SIEFP event page)
 *   4. Route a SINT (polling)  so VMBus messages land in the message page
 *
 * References: Hyper-V Top Level Functional Specification (TLFS) v6.0;
 * Linux drivers/hv/hv.c, hyperv-tlfs.h.
 */
#ifndef HYPERV_H
#define HYPERV_H

#include <stdint.h>

/* ── CPUID leaves ─────────────────────────────────────────────────────────── */
#define HV_CPUID_VENDOR        0x40000000u   /* EBX/ECX/EDX = "Microsoft Hv" */
#define HV_CPUID_INTERFACE     0x40000001u   /* EAX = "Hv#1" (0x31237648)     */
#define HV_CPUID_FEATURES      0x40000003u   /* EAX feature bits              */

#define HV_FEATURE_HYPERCALL   (1u << 5)     /* EAX bit 5: hypercall MSRs     */
#define HV_FEATURE_SYNIC       (1u << 2)     /* EAX bit 2: SynIC MSRs         */

/* ── Synthetic MSRs ───────────────────────────────────────────────────────── */
#define HV_MSR_GUEST_OS_ID     0x40000000u
#define HV_MSR_HYPERCALL       0x40000001u
#define HV_MSR_VP_INDEX        0x40000002u
#define HV_MSR_SCONTROL        0x40000080u
#define HV_MSR_SIEFP           0x40000082u
#define HV_MSR_SIMP            0x40000083u
#define HV_MSR_EOM             0x40000084u
#define HV_MSR_SINT0           0x40000090u   /* SINT0..SINT15 = 0x90..0x9F    */
#define HV_MSR_TIME_REF_COUNT  0x40000020u   /* partition reference counter, 100ns units */

/* ── Hypercall call codes ─────────────────────────────────────────────────── */
#define HVCALL_POST_MESSAGE    0x005cu       /* slow: input page              */
#define HVCALL_SIGNAL_EVENT    0x005du       /* fast: input in RDX            */
#define HV_HYPERCALL_FAST_BIT  (1ull << 16)

/* ── SynIC message page ───────────────────────────────────────────────────── */
#define HV_MESSAGE_SIZE        256u          /* 16 slots per 4 KiB page       */
#define HV_SINT_VMBUS          2u            /* SINT index VMBus uses         */
#define HV_MSGTYPE_NONE        0u
#define HV_MSGTYPE_VMBUS       1u            /* posted message_type for VMBus */

/* SINTx MSR field bits. */
#define HV_SINT_MASKED         (1u << 16)
#define HV_SINT_AUTO_EOI       (1u << 17)
#define HV_SINT_POLLING        (1u << 18)

typedef struct __attribute__((packed)) {
    uint32_t message_type;       /* 0 = HVMSG_NONE (slot empty) */
    uint8_t  payload_size;
    uint8_t  message_flags;
    uint8_t  reserved[2];
    uint64_t sender;
} hv_message_header_t;
_Static_assert(sizeof(hv_message_header_t) == 16, "hv_message_header");

typedef struct __attribute__((packed)) {
    hv_message_header_t header;
    uint64_t            payload[30];          /* 240 bytes */
} hv_message_t;
_Static_assert(sizeof(hv_message_t) == 256, "hv_message");

/* HvPostMessage input (slow hypercall input page). */
typedef struct __attribute__((packed)) {
    uint32_t connection_id;
    uint32_t reserved;
    uint32_t message_type;
    uint32_t payload_size;
    uint8_t  payload[240];
} hv_input_post_message_t;
_Static_assert(sizeof(hv_input_post_message_t) == 256, "hv_input_post_message");

/* ── API ──────────────────────────────────────────────────────────────────── */

/* True if running under Hyper-V (cached CPUID probe). Safe before init. */
int  hyperv_present(void);

/* Detect + enable hypercalls + SynIC + route SINT2 (polling). Silent + no-op
 * when not on Hyper-V, so QEMU/bare-metal boots are unaffected. Logs each
 * step over serial for blind bring-up. Called once from kernel_main. */
void hyperv_init(void);

/* Post a VMBus message to the host (HvPostMessage). connection_id is the VMBus
 * message connection id; payload/size is the channel message. Returns the
 * hypercall status (0 = HV_STATUS_SUCCESS). */
uint64_t hv_post_message(uint32_t connection_id, const void *payload, uint32_t size);

/* Signal a channel event to the host (HvSignalEvent, fast). 0 on success. */
uint64_t hv_signal_event(uint32_t connection_id);

/* Partition reference counter in 100ns units (monotonic, rate-constant, always
 * available on Hyper-V). Returns 0 when not on Hyper-V. Used to calibrate the
 * LAPIC timer on Gen 2 VMs, which have no 8254 PIT to calibrate against. */
uint64_t hyperv_ref_time(void);

/* Poll SINT2's slot in the message page. If a VMBus message is pending, copy it
 * into *out (256 bytes), clear the slot, write EOM, and return 1. Else 0. */
int  hv_get_vmbus_message(hv_message_t *out);

#endif /* HYPERV_H */
