/* hv_shutdown.c — Hyper-V Shutdown Integration Component (VMBus).
 *
 * Lets the host gracefully stop/restart the guest (Hyper-V Manager "Shut Down",
 * `Stop-VM`, `Restart-VM`) instead of a hard power-off.  The host sends a
 * SHUTDOWN message whose flags select the action (0/1 = power off, 2/3 = reboot,
 * 4 = hibernate; low bit = force).  We accept it (status 0) and signal vigil
 * (PID 1) to run the same clean teardown+sync path used by the GUI: SIGINT =
 * reboot, SIGTERM = power off.  IC framing/echo lives in hv_ic.c.
 */
#include "hv_ic.h"
#include "signal.h"
#include "printk.h"
#include <stdint.h>
#include <stddef.h>

typedef struct __attribute__((packed)) {
    uint32_t reason_code;
    uint32_t timeout_seconds;
    uint32_t flags;
    uint8_t  display_message[2048];
} shutdown_msg_data_t;

#define SHUTDOWN_FLAG_RESTART  0x2u
#define HV_SIGINT   2     /* → vigil: clean reboot  */
#define HV_SIGTERM  15    /* → vigil: clean power off */

/* Shutdown IC interface type {0e0b6031-5213-4934-818b-38d90ced39db}
 * (wire byte order, captured from a real offer). */
static const vmbus_guid_t GUID_SHUTDOWN = {{
    0x31,0x60,0x0b,0x0e,0x13,0x52,0x34,0x49,0x81,0x8b,0x38,0xd9,0x0c,0xed,0x39,0xdb }};

static vmbus_channel_t *s_ch;
static int s_ready;
static int s_requested;

static int
shutdown_body(uint16_t msgtype, uint8_t *body, uint32_t bodylen)
{
    if (msgtype != ICMSGTYPE_SHUTDOWN || bodylen < 12u || s_requested)
        return 0;
    shutdown_msg_data_t *sd = (shutdown_msg_data_t *)body;
    int reboot = (sd->flags & SHUTDOWN_FLAG_RESTART) ? 1 : 0;
    s_requested = 1;
    printk("[HV-SHUTDOWN] host requested %s (flags=0x%x)\n",
           reboot ? "reboot" : "poweroff", (unsigned)sd->flags);
    /* vigil does the orderly service teardown + fs sync, then sys_reboot(). */
    signal_send_pid(1, reboot ? HV_SIGINT : HV_SIGTERM);
    return 0;   /* HV_S_OK — request accepted */
}

void
hv_shutdown_poll(void)
{
    if (s_ready)
        hv_ic_poll(s_ch, shutdown_body);
}

void
hv_shutdown_init(void)
{
    if (!vmbus_connected())
        return;
    s_ch = vmbus_find_channel(&GUID_SHUTDOWN);
    if (!s_ch) { printk("[HV-SHUTDOWN] no shutdown channel offered\n"); return; }
    if (vmbus_open(s_ch, 4u) != 0) {
        printk("[HV-SHUTDOWN] channel open failed\n"); return; }
    s_ready = 1;
    printk("[HV-SHUTDOWN] OK: shutdown IC ready\n");
}
