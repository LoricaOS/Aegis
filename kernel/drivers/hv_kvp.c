/* hv_kvp.c — Hyper-V Key-Value Pair / Data Exchange Integration Component.
 *
 * Lets the host read guest metadata over VMBus (no network needed) — this is
 * what makes Hyper-V Manager / Get-VMIntegrationService show the guest OS and
 * marks "Data Exchange" as OK.  The host drives: after the IC NEGOTIATE it sends
 * KVP_OP_ENUMERATE for the "auto" pool, walking indices 0,1,2,...; the guest
 * returns one OS-info key/value (UTF-16) per index and HV_E_FAIL once past the
 * end.  Unsupported ops/pools also return HV_E_FAIL.
 *
 * KVP messages are ~2.6 KB (key[512]+value[2048]), far larger than the other
 * ICs, so this uses hv_ic_poll_buf() with a dedicated buffer.  Framing/negotiate
 * /echo lives in hv_ic.c.  Transcribed from Linux include/uapi/linux/hyperv.h +
 * drivers/hv/hv_kvp.c.
 */
#include "hv_ic.h"
#include "printk.h"
#include <stdint.h>
#include <stddef.h>

#define KVP_OP_ENUMERATE        3u
#define KVP_POOL_AUTO           2u
#define KVP_POOL_AUTO_EXTERNAL  3u
#define REG_SZ                  1u
#define HV_E_FAIL               0x80004005u
#define HV_KVP_KEY_SIZE         512u
#define HV_KVP_VALUE_SIZE       2048u

#ifndef AEGIS_VERSION
#define AEGIS_VERSION "1.x"
#endif

typedef struct __attribute__((packed)) {
    uint32_t value_type;
    uint32_t key_size;
    uint32_t value_size;
    uint8_t  key[HV_KVP_KEY_SIZE];
    uint8_t  value[HV_KVP_VALUE_SIZE];
} kvp_value_t;
_Static_assert(sizeof(kvp_value_t) == 2572, "kvp_value");

/* hv_kvp_msg for the ENUMERATE operation: kvp_hdr{op,pool,pad} + index + data. */
typedef struct __attribute__((packed)) {
    uint8_t  operation;
    uint8_t  pool;
    uint16_t pad;
    uint32_t index;
    kvp_value_t data;
} kvp_enum_t;
_Static_assert(sizeof(kvp_enum_t) == 2580, "kvp_enum");

/* Guest intrinsic OS info served from the "auto" pool — shown in Hyper-V Manager. */
static const struct { const char *k, *v; } s_os_info[] = {
    { "OSName",                "Aegis" },
    { "OSMajorVersion",        "1" },
    { "OSMinorVersion",        "3" },
    { "OSBuildNumber",         AEGIS_VERSION },
    { "OSVersion",             AEGIS_VERSION },
    { "OSVendor",              "Aegis" },
    { "ProcessorArchitecture", "x86_64" },
};
#define OS_INFO_COUNT (sizeof(s_os_info) / sizeof(s_os_info[0]))

/* KVP IC interface type {a9a0f4e7-5a45-4d96-b827-8a841e8c03e6}
 * (wire byte order, captured verbatim from a real offer). */
static const vmbus_guid_t GUID_KVP = {{
    0xe7,0xf4,0xa0,0xa9,0x45,0x5a,0x96,0x4d,0xb8,0x27,0x8a,0x84,0x1e,0x8c,0x03,0xe6 }};

static vmbus_channel_t *s_ch;
static int s_ready;
static uint8_t s_kvp_buf[4096];   /* timer-thread only; holds a full KVP message */

/* Encode an ASCII string as UTF-16LE (+ terminator); returns byte length. */
static uint32_t
kvp_utf16(uint8_t *dst, uint32_t cap, const char *s)
{
    uint32_t n = 0;
    while (*s && n + 2u <= cap) { dst[n++] = (uint8_t)*s++; dst[n++] = 0; }
    if (n + 2u <= cap) { dst[n++] = 0; dst[n++] = 0; }
    return n;
}

static int
kvp_body(uint16_t msgtype, uint8_t *body, uint32_t bodylen)
{
    if (msgtype != ICMSGTYPE_KVPEXCHANGE || bodylen < sizeof(kvp_enum_t))
        return (int)HV_E_FAIL;
    kvp_enum_t *m = (kvp_enum_t *)body;
    if (m->operation == KVP_OP_ENUMERATE &&
        (m->pool == KVP_POOL_AUTO || m->pool == KVP_POOL_AUTO_EXTERNAL) &&
        m->index < OS_INFO_COUNT) {
        m->data.value_type = REG_SZ;
        m->data.key_size   = kvp_utf16(m->data.key,   HV_KVP_KEY_SIZE,   s_os_info[m->index].k);
        m->data.value_size = kvp_utf16(m->data.value, HV_KVP_VALUE_SIZE, s_os_info[m->index].v);
        return 0;   /* HV_S_OK */
    }
    return (int)HV_E_FAIL;   /* unsupported op/pool, or end of enumeration */
}

void
hv_kvp_poll(void)
{
    if (s_ready)
        hv_ic_poll_buf(s_ch, kvp_body, s_kvp_buf, sizeof(s_kvp_buf));
}

void
hv_kvp_init(void)
{
    if (!vmbus_connected())
        return;
    s_ch = vmbus_find_channel(&GUID_KVP);
    if (!s_ch) { printk("[HV-KVP] no kvp channel offered\n"); return; }
    if (vmbus_open(s_ch, 4u) != 0) {
        printk("[HV-KVP] channel open failed\n"); return; }
    s_ready = 1;
    printk("[HV-KVP] OK: data exchange (KVP) IC ready\n");
}
