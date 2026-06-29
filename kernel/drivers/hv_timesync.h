/* hv_timesync.h — Hyper-V Time Synchronization Integration Component (VMBus).
 * Host pushes its wall-clock time to the guest; we set arch_clock_settime().
 * No-op when not on Hyper-V. */
#ifndef HV_TIMESYNC_H
#define HV_TIMESYNC_H

void hv_timesync_init(void);   /* find + open the timesync IC channel */
void hv_timesync_poll(void);   /* service NEGOTIATE + TIMESYNC messages (polled) */

#endif /* HV_TIMESYNC_H */
