/* hda.c — Intel High Definition Audio (HDA) controller + codec driver
 *
 * Brings up an HDA controller, walks the first audio codec's widget graph to
 * find an output DAC and an output-capable pin, configures the path (format,
 * stream, amp unmute, pin output enable, EAPD), and plays a looping test tone
 * via a stream + Buffer Descriptor List (BDL) DMA.
 *
 * Codec commands use the Immediate Command Interface (ICOI/ICII/ICIS) — simpler
 * than the CORB/RIRB rings and sufficient for QEMU + many controllers. (Some
 * real controllers prefer CORB/RIRB; that is the portability follow-up.)
 *
 * Portability notes for real hardware: the controller + stream/BDL path is
 * HDA-spec-standard. The codec path here unmutes amps + sets pin control + EAPD
 * (the usual silence culprits), but real codecs have complex topologies and
 * per-board EAPD/GPIO quirks that only bare metal exercises — see the marked
 * spots below.
 *
 * References: Intel High Definition Audio Specification 1.0a.
 */
#include "hda.h"
#include "pcie.h"
#include "arch.h"
#include "kva.h"
#include "vmm.h"
#include "pmm.h"
#include "printk.h"
#include "spinlock.h"
#include "waitq.h"
#include "wait_event.h"
#include <stdint.h>
#include <stddef.h>

/* ── Controller registers (BAR0 + offset) ─────────────────────────────────── */
#define HDA_GCAP     0x00u   /* u16: OSS[15:12] ISS[11:8] */
#define HDA_GCTL     0x08u   /* u32: CRST bit0 */
#define HDA_STATESTS 0x0Eu   /* u16: codec presence (SDIN bits) */
#define HDA_INTCTL   0x20u
#define HDA_ICOI     0x60u   /* immediate command output */
#define HDA_ICII     0x64u   /* immediate response input */
#define HDA_ICIS     0x68u   /* u16: ICB bit0, IRV bit1 */
/* Stream descriptor n at 0x80 + n*0x20. */
#define SD_CTL       0x00u   /* u32 (low 24 bits): SRST bit0, RUN bit1, stream[23:20] */
#define SD_STS       0x03u   /* u8: BCIS bit2 (set when an IOC=1 entry completes) */
#define SD_STS_BCIS  0x04u
#define SD_CBL       0x08u   /* cyclic buffer length */
#define SD_LVI       0x0Cu   /* last valid index (u16) */
#define SD_FMT       0x12u   /* u16 format */
#define SD_BDPL      0x18u
#define SD_BDPU      0x1Cu

#define GCTL_CRST    (1u << 0)
#define ICIS_ICB     (1u << 0)
#define ICIS_IRV     (1u << 1)
#define SDCTL_SRST   (1u << 0)
#define SDCTL_RUN    (1u << 1)

/* ── Codec verbs ──────────────────────────────────────────────────────────── */
/* Verb IDs pre-shifted into the 20-bit verb+payload field: 12-bit verbs sit at
 * [19:8] (verb<<8, 8-bit payload), 4-bit verbs at [19:16] (verb<<16, 16-bit
 * payload). OR the payload in. */
#define VERB_GET_PARAM        (0xF00u << 8)   /* 12-bit; 8-bit param */
#define VERB_SET_CONV_FMT     (0x2u   << 16)  /* 4-bit;  16-bit format */
#define VERB_SET_CONV_STREAM  (0x706u << 8)
#define VERB_SET_PIN_CTL      (0x707u << 8)
#define VERB_SET_AMP          (0x3u   << 16)  /* 4-bit;  16-bit payload */
#define VERB_SET_EAPD         (0x70Cu << 8)
#define VERB_SET_POWER        (0x705u << 8)
#define VERB_GET_CFG_DEFAULT  (0xF1Cu << 8)  /* pin default configuration */
#define VERB_GET_CONN_ENTRY   (0xF02u << 8)  /* connection-list entry at index */
#define VERB_SET_CONN_SELECT  (0x701u << 8)  /* select connection-list input */
/* GET_PARAM parameter ids. */
#define PARAM_SUBNODE_COUNT   0x04u
#define PARAM_FN_GROUP_TYPE   0x05u
#define PARAM_AUDIO_WIDGET_CAP 0x09u
#define PARAM_PIN_CAP         0x0Cu
#define PARAM_CONN_LIST_LEN   0x0Eu
#define PARAM_OUT_AMP_CAP     0x12u
/* Widget types (AUDIO_WIDGET_CAP >> 20 & 0xF). */
#define WIDGET_DAC            0x0u
#define WIDGET_MIXER          0x2u
#define WIDGET_SELECTOR       0x3u
#define WIDGET_PIN            0x4u
/* AUDIO_WIDGET_CAP bits. */
#define WCAP_OUT_AMP          (1u << 2)
#define WCAP_CONN_LIST        (1u << 8)
/* Config-default device type (cfg >> 20 & 0xF) and connectivity (cfg >> 30). */
#define CFG_DEV_LINE_OUT      0x0u
#define CFG_DEV_SPEAKER       0x1u
#define CFG_DEV_HP_OUT        0x2u
#define CFG_CONN_NONE         0x1u   /* connectivity field: no physical jack */

#define SD_LPIB      0x04u   /* u32: link position in buffer (bytes played) */

#define HDA_POLL_BUDGET   2000000u
#define MAX_AUDIO_PAGES   64u           /* 256 KB ring (~1.36 s) — streaming, not
                                         * one-shot, so length is unbounded; small
                                         * keeps Stop's drain-tail short. */
#define STREAM_TAG        1u

typedef struct __attribute__((packed)) {
    uint64_t addr;
    uint32_t len;
    uint32_t ioc;     /* bit0 = interrupt-on-completion */
} hda_bdl_entry_t;

static volatile uint8_t *s_mmio;
static uint8_t  s_codec;
static uint8_t  s_afg;                 /* audio function group node */
static uint32_t s_sd_base;             /* first output stream descriptor offset */

/* ── Playback engine state ────────────────────────────────────────────────── */
static int       s_ready;              /* codec path + DMA buffers ready */
static uint8_t   s_dac, s_pin;
static uint32_t  s_nsteps;             /* output amp max gain step */
static hda_bdl_entry_t *s_bdl;         /* BDL (kernel VA), phys-contiguous */
static uint64_t  s_bdl_pa;
static volatile uint8_t *s_buf;        /* PCM ring (contiguous VA, DMA-safe) */
static uint32_t  s_buf_bytes;          /* ring capacity */

/* Streaming ring (protected by s_lock). The DMA runs the BDL over the whole
 * ring continuously; LPIB is the read pointer. A /dev/audio write fills ahead
 * of it and blocks on s_space_wq when the unplayed data fills the ring, so a
 * track of any length streams through this small buffer. hda_poll() advances
 * the play position from LPIB, wakes blocked writers, and stops at end. */
static spinlock_t s_lock;
static waitq_t   s_space_wq;
static uint64_t  s_wpos;               /* total bytes written by the producer */
static uint64_t  s_ppos;               /* total bytes played (LPIB + wraps) */
static uint64_t  s_final;              /* total to play; set at close (0 = open) */
static uint32_t  s_last_lpib;          /* previous LPIB (wrap detection) */
static uint64_t  s_wrap_base;          /* s_ppos = s_wrap_base + LPIB */
static int       s_streaming;          /* DMA running */
static int       s_closed = 1;         /* 1 = between write sessions */
static int       s_dead;               /* sink not draining (no working hw) */

static inline uint8_t  m8 (uint32_t o){ return *(volatile uint8_t  *)(s_mmio+o); }
static inline uint16_t m16(uint32_t o){ return *(volatile uint16_t *)(s_mmio+o); }
static inline uint32_t m32(uint32_t o){ return *(volatile uint32_t *)(s_mmio+o); }
static inline void w8 (uint32_t o,uint8_t v){ *(volatile uint8_t  *)(s_mmio+o)=v; }
static inline void w16(uint32_t o,uint16_t v){ *(volatile uint16_t *)(s_mmio+o)=v; }
static inline void w32(uint32_t o,uint32_t v){ *(volatile uint32_t *)(s_mmio+o)=v; }

static volatile uint8_t *
map_mmio(uint64_t pa, uint32_t n)
{
    uintptr_t va = (uintptr_t)kva_alloc_pages(n);
    if (!va) return NULL;
    for (uint32_t i=0;i<n;i++){ uintptr_t p=va+(uint64_t)i*4096;
        vmm_unmap_page(p);
        vmm_map_page(p, pa+(uint64_t)i*4096, VMM_FLAG_WRITABLE|VMM_FLAG_WC|VMM_FLAG_UCMINUS); }
    return (volatile uint8_t *)va;
}

/* Map n contiguous physical pages at `pa` as write-back (cached) memory — for
 * the PCM DMA buffer (x86 DMA is cache-coherent, so WB is fine and fast). */
static volatile uint8_t *
map_dma(uint64_t pa, uint32_t n)
{
    uintptr_t va = (uintptr_t)kva_alloc_pages(n);
    if (!va) return NULL;
    for (uint32_t i = 0; i < n; i++) {
        uintptr_t p = va + (uint64_t)i * 4096;
        vmm_unmap_page(p);
        vmm_map_page(p, pa + (uint64_t)i * 4096, VMM_FLAG_WRITABLE);
    }
    return (volatile uint8_t *)va;
}

/* Send one codec verb via the immediate command interface; return the 32-bit
 * response (0xFFFFFFFF on timeout). cmd = (codec<<28)|(node<<20)|verb_payload. */
static uint32_t
codec_cmd(uint8_t node, uint32_t verb_payload)
{
    uint32_t cmd = ((uint32_t)s_codec << 28) | ((uint32_t)node << 20) | verb_payload;
    uint32_t b = 0;
    while ((m16(HDA_ICIS) & ICIS_ICB) && ++b < HDA_POLL_BUDGET)
        arch_pause();
    w32(HDA_ICOI, cmd);
    w16(HDA_ICIS, ICIS_ICB);          /* set busy → send */
    b = 0;
    while (!(m16(HDA_ICIS) & ICIS_IRV) && ++b < HDA_POLL_BUDGET)
        arch_pause();
    if (b >= HDA_POLL_BUDGET)
        return 0xFFFFFFFFu;
    uint32_t resp = m32(HDA_ICII);
    w16(HDA_ICIS, ICIS_IRV);          /* clear result-valid */
    return resp;
}

static uint32_t get_param(uint8_t node, uint8_t p)
{ return codec_cmd(node, VERB_GET_PARAM | p); }

/* Unmute a node's OUTPUT amp at (near) max gain. */
static void
unmute_out(uint8_t node)
{
    uint32_t amp = get_param(node, PARAM_OUT_AMP_CAP);
    uint32_t steps = (amp >> 8) & 0x7Fu;
    if (steps == 0) steps = 0x2Au;
    /* set output(0x8000) | left(0x2000) | right(0x1000) | gain. */
    codec_cmd(node, VERB_SET_AMP | 0xB000u | (steps & 0x7Fu));
}

/* Unmute a node's INPUT amp for connection index `idx`. */
static void
unmute_in(uint8_t node, uint8_t idx)
{
    /* set input(0x4000) | left(0x2000) | right(0x1000) | index | gain. */
    codec_cmd(node, VERB_SET_AMP | 0x7000u | ((uint32_t)idx << 8) | 0x2Au);
}

/* Read `node`'s connection list (short-form NIDs) into out[]; returns count. */
static int
conn_list(uint8_t node, uint8_t *out, int max)
{
    uint32_t cap = get_param(node, PARAM_AUDIO_WIDGET_CAP);
    if (!(cap & WCAP_CONN_LIST))
        return 0;
    uint32_t cl = get_param(node, PARAM_CONN_LIST_LEN);
    int len = (int)(cl & 0x7Fu), n = 0;
    for (int i = 0; i < len && n < max; i++) {
        uint32_t r = codec_cmd(node, VERB_GET_CONN_ENTRY | (uint8_t)i);
        out[n++] = (uint8_t)(r & 0xFFu);   /* NIDs fit in a byte on these codecs */
    }
    return n;
}

/* Walk from `node` (a pin/mixer/selector) to an output DAC, selecting the
 * branch and unmuting the amps along the path. Returns the DAC NID or -1. */
static int
find_dac(uint8_t node, int depth)
{
    uint32_t cap  = get_param(node, PARAM_AUDIO_WIDGET_CAP);
    uint32_t type = (cap >> 20) & 0xFu;
    if (type == WIDGET_DAC) {
        codec_cmd(node, VERB_SET_POWER | 0x00u);
        unmute_out(node);
        return node;
    }
    if (depth >= 4)
        return -1;
    uint8_t cl[16];
    int n = conn_list(node, cl, 16);
    for (int i = 0; i < n; i++) {
        int d = find_dac(cl[i], depth + 1);
        if (d >= 0) {
            if (n > 1)
                codec_cmd(node, VERB_SET_CONN_SELECT | (uint8_t)i);
            if (cap & WCAP_OUT_AMP)
                unmute_out(node);
            unmute_in(node, (uint8_t)i);
            codec_cmd(node, VERB_SET_POWER | 0x00u);
            return d;
        }
    }
    return -1;
}

/* Bring up an HDA controller: enable PCI memory + bus-master, map BAR0 into
 * s_mmio, reset it, set s_sd_base. Returns the codec-presence bitmap (STATESTS)
 * or 0 on failure / no codec. */
static uint16_t
controller_up(const pcie_device_t *d)
{
    uint32_t cmd = pcie_read32(d->bus, d->dev, d->fn, 0x04);
    pcie_write32(d->bus, d->dev, d->fn, 0x04, cmd | (1u << 1) | (1u << 2));

    s_mmio = map_mmio(d->bar[0] & ~0xFFFULL, 4);
    if (!s_mmio)
        return 0;

    w32(HDA_GCTL, m32(HDA_GCTL) & ~GCTL_CRST);
    uint32_t b = 0;
    while ((m32(HDA_GCTL) & GCTL_CRST) && ++b < HDA_POLL_BUDGET) arch_pause();
    w32(HDA_GCTL, m32(HDA_GCTL) | GCTL_CRST);
    b = 0;
    while (!(m32(HDA_GCTL) & GCTL_CRST) && ++b < HDA_POLL_BUDGET) arch_pause();
    for (b = 0; b < 200000u; b++) arch_pause();   /* codec presence ~521 µs */

    uint16_t gcap = m16(HDA_GCAP);
    s_sd_base = 0x80u + ((gcap >> 8) & 0xFu) * 0x20u;
    return m16(HDA_STATESTS);
}

/* Scan the current codec (s_codec) for an output pin matching `want`:
 *   2 = analog speaker, 1 = any analog output (speaker/line-out/HP),
 *   0 = any output (last resort, e.g. HDMI-only). On success sets s_afg and
 * returns the DAC NID via *dac_out and the pin NID via *pin_out, or -1.
 *
 * This is what makes real machines work: AMD Renoir (the ThinkPad X13) has a
 * separate HDMI/DP audio codec (all-digital pins) AND the analog ALC257. Want
 * levels skip the digital codec and find the codec with the actual speaker. */
static int
codec_find_out(int want, int *pin_out, int *dac_out)
{
    uint32_t sub = get_param(0, PARAM_SUBNODE_COUNT);
    /* Node start+count come from the codec's SUBNODE_COUNT response. Use int
     * loop bounds: a malicious/broken codec with start+count > 255 would wrap a
     * uint8_t counter at 256 so the condition never fails → infinite verb loop
     * (boot hang). */
    unsigned fgs = (sub >> 16) & 0xFFu, fgc = sub & 0xFFu;
    for (unsigned fg = fgs; fg < fgs + fgc; fg++) {
        if ((get_param((int)fg, PARAM_FN_GROUP_TYPE) & 0xFFu) != 1u)
            continue;
        uint32_t wsub = get_param((int)fg, PARAM_SUBNODE_COUNT);
        unsigned ws = (wsub >> 16) & 0xFFu, wc = wsub & 0xFFu;
        int pin = -1, any_dac = -1;
        for (unsigned w = ws; w < ws + wc; w++) {
            uint32_t cap  = get_param(w, PARAM_AUDIO_WIDGET_CAP);
            uint32_t type = (cap >> 20) & 0xFu;
            if (type == WIDGET_DAC) { if (any_dac < 0) any_dac = w; continue; }
            if (type != WIDGET_PIN) continue;
            if (!(get_param(w, PARAM_PIN_CAP) & (1u << 4)))   /* output-capable? */
                continue;
            int digital = (cap & (1u << 9)) != 0;             /* HDMI/DP pin */
            uint32_t cfg = codec_cmd(w, VERB_GET_CFG_DEFAULT);
            uint32_t dev = (cfg >> 20) & 0xFu, conn = (cfg >> 30) & 0x3u;
            int match = 0;
            if (want == 2)
                match = (dev == CFG_DEV_SPEAKER && conn != CFG_CONN_NONE && !digital);
            else if (want == 1)
                match = (!digital && (dev == CFG_DEV_SPEAKER ||
                         dev == CFG_DEV_LINE_OUT || dev == CFG_DEV_HP_OUT));
            else
                match = 1;
            if (match && pin < 0)
                pin = w;
        }
        if (pin >= 0) {
            int dac = find_dac((uint8_t)pin, 0);
            if (dac < 0) dac = any_dac;
            if (dac >= 0) {
                s_afg = fg;
                *pin_out = pin;
                *dac_out = dac;
                return 1;
            }
        }
    }
    return 0;
}

void
hda_init(void)
{
    int ndev = pcie_device_count();
    const pcie_device_t *devs = pcie_get_devices();

    /* Find a controller + codec with a real analog output. Prefer a speaker
     * pin (want=2); fall back to any analog output (want=1); last resort any
     * output (want=0, e.g. an HDMI-only machine). */
    int pin = -1, dac = -1, found = 0;
    int is_speaker = 0;
    for (int want = 2; want >= 0 && !found; want--) {
        for (int i = 0; i < ndev && !found; i++) {
            const pcie_device_t *d = &devs[i];
            if (d->class_code != 0x04 || d->subclass != 0x03)
                continue;
            uint16_t st = controller_up(d);
            if (st == 0)
                continue;
            for (int slot = 0; slot < 15 && !found; slot++) {
                if (!(st & (1u << slot)))
                    continue;
                s_codec = (uint8_t)slot;
                if (codec_find_out(want, &pin, &dac)) {
                    found = 1;
                    is_speaker = (want == 2);
                }
            }
        }
    }
    if (!found)
        return;

    printk("[HDA] route: codec %u pin n%u (%s) <- DAC n%u\n",
           (unsigned)s_codec, (unsigned)pin,
           is_speaker ? "speaker" : "output", (unsigned)dac);

    /* ── Configure the DAC → pin path ─────────────────────────────────────── */
    codec_cmd((uint8_t)dac, VERB_SET_POWER | 0x00u);
    codec_cmd((uint8_t)pin, VERB_SET_POWER | 0x00u);
    /* DAC: 48 kHz, 16-bit, stereo; assign stream tag + channel 0. */
    codec_cmd((uint8_t)dac, VERB_SET_CONV_FMT | 0x0011u);
    codec_cmd((uint8_t)dac, VERB_SET_CONV_STREAM | (STREAM_TAG << 4) | 0u);
    unmute_out((uint8_t)dac);

    uint32_t amp_cap = get_param((uint8_t)dac, PARAM_OUT_AMP_CAP);
    uint32_t nsteps = (amp_cap >> 8) & 0x7Fu;
    if (nsteps == 0) nsteps = 0x2Au;
    /* Pin: output-enable, unmute its amp, EAPD on (external speaker-amp power —
     * a classic bare-metal-only silence cause; QEMU ignores it). */
    codec_cmd((uint8_t)pin, VERB_SET_PIN_CTL | 0x40u);     /* OUT enable */
    unmute_out((uint8_t)pin);
    codec_cmd((uint8_t)pin, VERB_SET_EAPD | 0x02u);        /* EAPD enable */

    s_dac = (uint8_t)dac;
    s_pin = (uint8_t)pin;
    s_nsteps = nsteps;

    /* ── Allocate the playback DMA buffers (filled later by /dev/audio) ──────
     * The PCM buffer is DMA-safe (<4GB) scattered pages with contiguous VA, so
     * each BDL entry maps one page. The BDL itself must be physically
     * contiguous (the controller reads it linearly) — 2 pages hold 512 entries
     * (2 MB of audio). */
    uint64_t bdl_pa = pmm_alloc_contig_low(2);
    if (!bdl_pa)
        return;
    s_bdl = (hda_bdl_entry_t *)map_dma(bdl_pa, 2);
    if (!s_bdl)
        return;
    s_bdl_pa = bdl_pa;

    uint32_t want = MAX_AUDIO_PAGES;
    void *buf = NULL;
    while (want >= 64u) {
        buf = kva_alloc_pages_low(want);
        if (buf) break;
        want /= 2u;
    }
    if (!buf)
        return;
    s_buf       = (volatile uint8_t *)buf;
    s_buf_bytes = want * 4096u;

    waitq_init(&s_space_wq);
    s_ready = 1;
    printk("[HDA] OK: codec %u DAC node %u pin node %u, /dev/audio %u KB ready\n",
           s_codec, (unsigned)dac, (unsigned)pin, s_buf_bytes / 1024u);
}

/* ── Playback engine ──────────────────────────────────────────────────────── */

int
hda_present(void)
{
    return s_ready;
}

static void
hda_stop(void)
{
    if (!s_ready) return;
    w32(s_sd_base + SD_CTL, m32(s_sd_base + SD_CTL) & ~SDCTL_RUN);
    s_streaming = 0;
}

/* Advance the play position from the hardware LPIB (link position in buffer),
 * carrying wraps so s_ppos is monotonic. Caller holds s_lock. */
static void
hda_update_ppos(void)
{
    if (!s_streaming) return;
    uint32_t lpib = m32(s_sd_base + SD_LPIB);
    if (lpib < s_last_lpib)
        s_wrap_base += s_buf_bytes;        /* LPIB wrapped past the ring end */
    s_last_lpib = lpib;
    uint64_t p = s_wrap_base + lpib;
    if (p > s_ppos) s_ppos = p;
}

/* Free space the producer may write without overwriting unplayed audio.
 * Caller holds s_lock. */
static uint64_t
hda_free_locked(void)
{
    hda_update_ppos();
    uint64_t inflight = s_wpos - s_ppos;
    return inflight < s_buf_bytes ? s_buf_bytes - inflight : 0;
}

/* wait_event condition (does its own locking). */
static int
hda_has_space(void)
{
    irqflags_t f = spin_lock_irqsave(&s_lock);
    uint64_t free = hda_free_locked();
    spin_unlock_irqrestore(&s_lock, f);
    return free > 0;
}

/* Program the BDL over the WHOLE ring and run the stream continuously. LPIB is
 * the read pointer; the producer fills ahead of it. Caller holds s_lock. */
static void
hda_start_stream(void)
{
    uint32_t pages = s_buf_bytes / 4096u;
    for (uint32_t i = 0; i < pages; i++) {
        s_bdl[i].addr = kva_page_phys((void *)(s_buf + i * 4096u));
        s_bdl[i].len  = 4096u;
        s_bdl[i].ioc  = 0u;
    }
    uint32_t sd = s_sd_base, b;
    w32(sd + SD_CTL, m32(sd + SD_CTL) | SDCTL_SRST);
    for (b = 0; !(m32(sd + SD_CTL) & SDCTL_SRST) && ++b < HDA_POLL_BUDGET; ) arch_pause();
    w32(sd + SD_CTL, m32(sd + SD_CTL) & ~SDCTL_SRST);
    for (b = 0; (m32(sd + SD_CTL) & SDCTL_SRST) && ++b < HDA_POLL_BUDGET; ) arch_pause();

    w32(sd + SD_BDPL, (uint32_t)s_bdl_pa);
    w32(sd + SD_BDPU, (uint32_t)(s_bdl_pa >> 32));
    w32(sd + SD_CBL, s_buf_bytes);         /* cyclic over the whole ring */
    w16(sd + SD_LVI, (uint16_t)(pages - 1u));
    w16(sd + SD_FMT, 0x0011);              /* 48k 16-bit stereo */
    uint32_t ctl = m32(sd + SD_CTL);
    ctl = (ctl & ~(0xFu << 20)) | (STREAM_TAG << 20);
    w32(sd + SD_CTL, ctl);
    w8(sd + SD_STS, SD_STS_BCIS);
    arch_wmb();

    s_last_lpib = 0;
    s_wrap_base = 0;
    s_ppos = 0;
    s_streaming = 1;
    w32(sd + SD_CTL, m32(sd + SD_CTL) | SDCTL_RUN);
}

/* Append PCM (48 kHz/16-bit/stereo) to the streaming ring. Blocks when the ring
 * is full until the DMA drains space (a track of any length streams through).
 * The first write of a session resets the ring; close() lets it drain. Returns
 * len on success; a partial/negative on EINTR. A sink that never drains (no
 * working hw) is detected once (s_dead) and thereafter consumes-and-drops so a
 * writer can never hang. Called from sys_write with a kernel staging buffer. */
int
hda_audio_write(const void *buf, uint32_t len)
{
    if (!s_ready)
        return (int)len;

    irqflags_t f = spin_lock_irqsave(&s_lock);
    if (s_closed) {                        /* first write of a new session */
        hda_stop();
        s_wpos = 0; s_ppos = 0; s_wrap_base = 0; s_last_lpib = 0;
        s_final = 0; s_closed = 0; s_dead = 0;
    }
    int dead = s_dead;
    spin_unlock_irqrestore(&s_lock, f);
    if (dead)
        return (int)len;                   /* dead sink: drop fast, never block */

    const uint8_t *src = (const uint8_t *)buf;
    uint32_t done = 0;
    while (done < len) {
        f = spin_lock_irqsave(&s_lock);
        uint64_t free = hda_free_locked();
        if (free == 0) {
            if (!s_streaming) hda_start_stream();   /* nothing draining yet */
            spin_unlock_irqrestore(&s_lock, f);
            int rc;
            uint64_t deadline = arch_get_ticks() + 300;   /* 3 s anti-hang */
            wait_event_timeout(&s_space_wq, hda_has_space(), deadline, rc);
            if (rc == BLOCK_EINTR)                      /* EINTR (process killed) */
                return done ? (int)done : -4;
            if (rc == -110) {                  /* sink not draining → give up */
                f = spin_lock_irqsave(&s_lock);
                s_dead = 1;
                spin_unlock_irqrestore(&s_lock, f);
                return (int)len;
            }
            continue;
        }
        uint32_t woff = (uint32_t)(s_wpos % s_buf_bytes);
        uint32_t cont = s_buf_bytes - woff;       /* contiguous to ring end */
        uint32_t n = len - done;
        if ((uint64_t)n > free) n = (uint32_t)free;
        if (n > cont) n = cont;
        __builtin_memcpy((void *)(s_buf + woff), src + done, n);
        s_wpos += n;
        done += n;
        /* Start draining once half the ring is buffered (latency margin). */
        if (!s_streaming && s_wpos >= s_buf_bytes / 2u)
            hda_start_stream();
        spin_unlock_irqrestore(&s_lock, f);
    }
    return (int)len;
}

/* End of a write session: the producer is done. Mark the final byte count and
 * let the DMA drain the buffered tail; hda_poll() stops it at the end. Does NOT
 * block (the player process can exit while the tail plays out). */
void
hda_audio_close(void)
{
    if (!s_ready) return;
    irqflags_t f = spin_lock_irqsave(&s_lock);
    if (!s_closed) {
        s_final = s_wpos;
        if (!s_streaming && s_wpos >= 4)
            hda_start_stream();            /* short clip never hit the prebuffer */
        /* Silence the immediate tail so the ≤1-tick overshoot past s_final
         * plays as silence, not stale ring data. */
        if (s_buf_bytes) {
            uint32_t foff = (uint32_t)(s_final % s_buf_bytes);
            uint32_t z = s_buf_bytes - foff;
            if (z > 8192u) z = 8192u;
            __builtin_memset((void *)(s_buf + foff), 0, z);
        }
        s_closed = 1;
    }
    spin_unlock_irqrestore(&s_lock, f);
}

/* Stop playback immediately and discard the buffered tail (Tunes' Stop button).
 * Unlike close (which drains), this halts the DMA now and resets the session. */
void
hda_audio_stop(void)
{
    if (!s_ready) return;
    irqflags_t f = spin_lock_irqsave(&s_lock);
    hda_stop();
    s_closed = 1;
    s_final = 0;
    s_wpos = s_ppos = 0;
    spin_unlock_irqrestore(&s_lock, f);
    waitq_wake_all(&s_space_wq);     /* free any writer blocked on the ring */
}

/* Milliseconds of audio actually played on the current stream (LPIB-derived,
 * so it tracks what the user is *hearing* — the A/V master clock, not what's
 * merely buffered). Resets to 0 at each new write session. 0 when idle or no
 * HDA. Format is fixed 48 kHz / 16-bit / stereo = 4 bytes/frame → 192 bytes/ms
 * (matches SD_FMT 0x0011 programmed in hda_start_stream). */
uint64_t
hda_play_position_ms(void)
{
    if (!s_ready) return 0;
    irqflags_t f = spin_lock_irqsave(&s_lock);
    hda_update_ppos();
    uint64_t bytes = s_ppos;
    spin_unlock_irqrestore(&s_lock, f);
    return bytes / 192u;
}

/* Timer tick: advance the play position, wake a blocked writer (space freed),
 * and stop the DMA once it has played everything the producer wrote. */
void
hda_poll(void)
{
    if (!s_ready || !s_streaming) return;
    irqflags_t f = spin_lock_irqsave(&s_lock);
    hda_update_ppos();
    if (s_final != 0 && s_ppos >= s_final)
        hda_stop();
    spin_unlock_irqrestore(&s_lock, f);
    waitq_wake_all(&s_space_wq);
}

/* Tiny buffer formatters (no libc) for hda_dump. */
static char *d_str(char *p, const char *s) { while (*s) *p++ = *s++; return p; }
static char *d_dec(char *p, uint32_t v)
{
    char t[10]; int i = 0;
    if (!v) { *p++ = '0'; return p; }
    while (v) { t[i++] = (char)('0' + v % 10); v /= 10; }
    while (i) *p++ = t[--i];
    return p;
}
static char *d_hex(char *p, uint32_t v)
{
    static const char hx[] = "0123456789abcdef";
    char t[8]; int i = 0;
    if (!v) { *p++ = '0'; return p; }
    while (v) { t[i++] = hx[v & 0xF]; v >>= 4; }
    while (i) *p++ = t[--i];
    return p;
}

/* Format the codec widget graph into buf (for /proc/hda). Re-issues codec
 * verbs each call. Returns the length written. */
int
hda_dump(char *buf, int bufsz)
{
    char *p = buf, *end = buf + bufsz - 96;   /* leave margin per line */
    if (!s_mmio || !s_ready) {
        p = d_str(p, "no HDA codec\n");
        *p = '\0';
        return (int)(p - buf);
    }
    p = d_str(p, "codec "); p = d_dec(p, s_codec);
    p = d_str(p, " afg ");  p = d_dec(p, s_afg); *p++ = '\n';

    uint32_t wsub = get_param(s_afg, PARAM_SUBNODE_COUNT);
    uint8_t ws = (uint8_t)(wsub >> 16), wc = (uint8_t)wsub;
    for (uint8_t w = ws; w < ws + wc && p < end; w++) {
        uint32_t cap = get_param(w, PARAM_AUDIO_WIDGET_CAP);
        uint32_t type = (cap >> 20) & 0xFu;
        p = d_str(p, "n"); p = d_dec(p, w); p = d_str(p, " ");
        if (type == WIDGET_PIN) {
            uint32_t cfg = codec_cmd(w, VERB_GET_CFG_DEFAULT);
            p = d_str(p, "PIN cfg=0x"); p = d_hex(p, cfg);
            p = d_str(p, " dev=");  p = d_dec(p, (cfg >> 20) & 0xF);
            p = d_str(p, " conn="); p = d_dec(p, (cfg >> 30) & 0x3);
        } else {
            const char *tn = type == WIDGET_DAC      ? "DAC" :
                             type == WIDGET_MIXER    ? "MIX" :
                             type == WIDGET_SELECTOR ? "SEL" : "w";
            p = d_str(p, tn); p = d_str(p, " type="); p = d_dec(p, type);
        }
        p = d_str(p, " wcap=0x"); p = d_hex(p, cap); *p++ = '\n';

        uint8_t cl[16];
        int nc = conn_list(w, cl, 16);
        for (int i = 0; i < nc && p < end; i++) {
            p = d_str(p, "  <- n"); p = d_dec(p, cl[i]); *p++ = '\n';
        }
    }
    *p = '\0';
    return (int)(p - buf);
}

/* Set the output volume (0..100%) by scaling the DAC + pin output amp gain. */
void
hda_set_volume(int pct)
{
    if (!s_ready) return;
    if (pct < 0) pct = 0;
    if (pct > 100) pct = 100;
    uint32_t gain = (s_nsteps * (uint32_t)pct) / 100u;
    /* 0xB000 = set output amp, left+right; low 7 bits = gain (bit7=mute). */
    codec_cmd(s_dac, VERB_SET_AMP | 0xB000u | (gain & 0x7Fu));
    codec_cmd(s_pin, VERB_SET_AMP | 0xB000u | (gain & 0x7Fu));
}
