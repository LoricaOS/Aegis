/* hv_timesync.c — Hyper-V Time Synchronization Integration Component (VMBus).
 *
 * On Gen 2 there is no reliable CMOS RTC path and chronos (NTP) races DHCP at
 * boot, so the wall clock is wrong (breaking TLS).  The host pushes its time to
 * the guest over this IC channel instead.  TIMESYNC carries the host time as a
 * Windows FILETIME (100ns since 1601-01-01); we convert to Unix epoch and call
 * arch_clock_settime().  The IC framing/negotiate/echo lives in hv_ic.c.
 */
#include "hv_ic.h"
#include "arch.h"
#include "printk.h"
#include <stdint.h>
#include <stddef.h>

typedef struct __attribute__((packed)) {
    uint64_t parenttime;
    uint64_t childtime;
    uint64_t roundtriptime;
    uint8_t  flags;
} ictimesync_data_t;
_Static_assert(sizeof(ictimesync_data_t) == 25, "ictimesync_data");

#define ICTIMESYNCFLAG_SYNC    1u
#define ICTIMESYNCFLAG_SAMPLE  2u

/* Seconds between 1601-01-01 (Windows FILETIME epoch) and 1970-01-01 (Unix). */
#define FILETIME_TO_UNIX_BIAS  11644473600ULL

/* TimeSync IC interface type {9527e630-d0ae-497b-adce-e80ab0175caf}. */
static const vmbus_guid_t GUID_TIMESYNC = {{
    0x30,0xe6,0x27,0x95,0xae,0xd0,0x7b,0x49,0xad,0xce,0xe8,0x0a,0xb0,0x17,0x5c,0xaf }};

static vmbus_channel_t *s_ch;
static int s_ready;
static int s_synced;

static int
timesync_body(uint16_t msgtype, uint8_t *body, uint32_t bodylen)
{
    if (msgtype != ICMSGTYPE_TIMESYNC || bodylen < sizeof(ictimesync_data_t))
        return 0;
    ictimesync_data_t *ts = (ictimesync_data_t *)body;
    if ((ts->flags & ICTIMESYNCFLAG_SYNC) ||
        (!s_synced && (ts->flags & ICTIMESYNCFLAG_SAMPLE))) {
        uint64_t unix_sec = ts->parenttime / 10000000ULL - FILETIME_TO_UNIX_BIAS;
        arch_clock_settime(unix_sec);
        s_synced = 1;
        printk("[HV-TIMESYNC] clock set: unix=%lu (flags=0x%x)\n",
               (unsigned long)unix_sec, (unsigned)ts->flags);
    }
    return 0;
}

void
hv_timesync_poll(void)
{
    if (s_ready)
        hv_ic_poll(s_ch, timesync_body);
}

void
hv_timesync_init(void)
{
    if (!vmbus_connected())
        return;
    s_ch = vmbus_find_channel(&GUID_TIMESYNC);
    if (!s_ch) { printk("[HV-TIMESYNC] no timesync channel offered\n"); return; }
    if (vmbus_open(s_ch, 4u) != 0) {
        printk("[HV-TIMESYNC] channel open failed\n"); return; }
    s_ready = 1;   /* the host drives the conversation; we just service it */
    printk("[HV-TIMESYNC] OK: time sync IC ready\n");
}
