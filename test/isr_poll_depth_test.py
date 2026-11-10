#!/usr/bin/env python3
"""Run the production poll scopes through forced SMP overlap and nesting."""
from pathlib import Path
import re
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]


def function(path, name):
    source = (root / path).read_text()
    match = re.search(r'\n(?:static\s+)?void\s+' + name + r'\s*\(', source)
    assert match, name
    start = source.index('{', match.start())
    depth, end = 1, start + 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[match.start():end]


paths = {
    'poll_sources_run': 'kernel/core/poll.c',
    'netdev_poll_all': 'kernel/net/netdev.c',
    'virtio_net_irq': 'kernel/drivers/virtio_net.c',
    'xhci_eth_rx_complete': 'kernel/drivers/xhci.c',
}
bodies = '\n'.join(function(path, name) for name, path in paths.items())
source = r'''
#include <assert.h>
#include <pthread.h>
#include <sched.h>
#include <stdint.h>
#include <stddef.h>
typedef int irqflags_t;
typedef pthread_mutex_t spinlock_t;
static spinlock_t netdev_lock = PTHREAD_MUTEX_INITIALIZER;
static irqflags_t spin_lock_irqsave(spinlock_t *l) { assert(!pthread_mutex_lock(l)); return 0; }
static void spin_unlock_irqrestore(spinlock_t *l, irqflags_t f) { (void)f; assert(!pthread_mutex_unlock(l)); }
volatile int g_in_isr_poll;
static _Thread_local int cpu;
static unsigned entered, first_left, deliveries;
static int expected_depth;
typedef struct netdev { void *priv; void (*poll)(struct netdev *); } netdev_t;
static netdev_t s_dev;
static netdev_t *s_devices[] = { &s_dev };
static struct { void (*fn)(void); } s_sources[1];
static int s_count = 1;
static struct {
    uint8_t rx_buf[24];
    unsigned rx_count, rx_bytes, last_rx_len, rx_frames;
    netdev_t nd;
} s_eth;
static uint32_t le32(const uint8_t *b) {
    return (uint32_t)b[0] | ((uint32_t)b[1] << 8) |
           ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
}
static void netdev_rx_deliver(netdev_t *dev, const void *data, uint16_t len) {
    (void)dev; (void)data; assert(len == 14);
    assert(__atomic_load_n(&g_in_isr_poll, __ATOMIC_SEQ_CST) == expected_depth);
    deliveries++;
}
void virtio_net_irq(void);
void netdev_poll_all(void);
static void xhci_eth_rx_complete(uint32_t len);
static void virtio_net_service(netdev_t *dev) { (void)dev; xhci_eth_rx_complete(24); }
static void device_poll(netdev_t *dev) { (void)dev; virtio_net_irq(); }
'''
source += bodies
source += r'''
static void tick_source(void) {
    __atomic_fetch_add(&entered, 1, __ATOMIC_SEQ_CST);
    while (__atomic_load_n(&entered, __ATOMIC_SEQ_CST) != 2) sched_yield();
    if (cpu == 0) return;
    while (!__atomic_load_n(&first_left, __ATOMIC_SEQ_CST)) sched_yield();
    /* CPU 0 has left, but this CPU's poll scope still forbids blocking. */
    assert(__atomic_load_n(&g_in_isr_poll, __ATOMIC_SEQ_CST) == 1);
    expected_depth = 4;
    netdev_poll_all();
    assert(__atomic_load_n(&g_in_isr_poll, __ATOMIC_SEQ_CST) == 1);
}
static void *tick(void *arg) {
    cpu = (int)(uintptr_t)arg;
    poll_sources_run();
    if (cpu == 0) __atomic_store_n(&first_left, 1, __ATOMIC_SEQ_CST);
    return NULL;
}
int main(void) {
    s_dev.priv = &s_dev; s_dev.poll = device_poll;
    s_sources[0].fn = tick_source;
    /* One valid xHCI receive record: 16 frame bytes then header and trailer. */
    s_eth.rx_buf[18] = 16; s_eth.rx_buf[20] = 1; s_eth.rx_buf[22] = 16;
    for (int i = 0; i < 100; i++) {
        entered = first_left = 0;
        pthread_t a, b;
        assert(!pthread_create(&a, NULL, tick, (void *)0));
        while (__atomic_load_n(&entered, __ATOMIC_SEQ_CST) != 1) sched_yield();
        assert(!pthread_create(&b, NULL, tick, (void *)1));
        assert(!pthread_join(a, NULL)); assert(!pthread_join(b, NULL));
        assert(__atomic_load_n(&g_in_isr_poll, __ATOMIC_SEQ_CST) == 0);
    }
    expected_depth = 3;
    netdev_poll_all();
    assert(__atomic_load_n(&g_in_isr_poll, __ATOMIC_SEQ_CST) == 0);
    s_dev.priv = NULL; virtio_net_irq(); xhci_eth_rx_complete(3);
    assert(__atomic_load_n(&g_in_isr_poll, __ATOMIC_SEQ_CST) == 0);
    assert(deliveries == 101); /* syscall/task blocking is allowed again */
    return 0;
}
'''
with tempfile.TemporaryDirectory(prefix='aegis-poll-depth-') as tmp:
    path = Path(tmp) / 'check.c'
    binary = Path(tmp) / 'check'
    path.write_text(source)
    subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror', '-pthread', str(path), '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True, timeout=10)

# Every remaining runtime use must be atomic; definitions/externs stay compatible.
for path in paths.values():
    text = (root / path).read_text()
    assert not re.search(r'\bg_in_isr_poll\s*=\s*(?:1|prev)', text), path
for path in ('kernel/net/eth.c', 'kernel/net/ipv6.c'):
    text = (root / path).read_text()
    assert '__atomic_load_n(&g_in_isr_poll, __ATOMIC_SEQ_CST)' in text
    assert not re.search(r'if\s*\(\s*!?g_in_isr_poll\b', text), path
print('ISR poll SMP overlap, nested driver scopes and task-context reset: PASS')
