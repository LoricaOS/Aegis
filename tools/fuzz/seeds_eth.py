#!/usr/bin/env python3
"""Ethernet-frame seeds for fuzz_ethrx. Host is 192.168.1.50/24, MAC 52:54:00:12:34:56."""
import os, struct, sys

root = os.path.join(sys.argv[1] if len(sys.argv) > 1 else ".", "corpus_ethrx")
os.makedirs(root, exist_ok=True)

MY_MAC = bytes.fromhex("525400123456")
PEER = bytes.fromhex("aabbccddeeff")
MY_IP = bytes([192, 168, 1, 50])
PEER_IP = bytes([192, 168, 1, 77])
BCAST = b"\xff" * 6


def w(name, data):
    open(os.path.join(root, name), "wb").write(data)


def eth(dst, src, ethertype, payload):
    return dst + src + struct.pack(">H", ethertype) + payload


def cksum(b):
    if len(b) % 2:
        b += b"\0"
    s = sum(struct.unpack(">%dH" % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def ip4(src, dst, proto, payload, flags_frag=0):
    total = 20 + len(payload)
    h = struct.pack(">BBHHHBBH", 0x45, 0, total, 0x1234, flags_frag, 64, proto, 0) + src + dst
    h = h[:10] + struct.pack(">H", cksum(h)) + h[12:]
    return h + payload


def arp(oper, sha, spa, tha, tpa):
    return struct.pack(">HHBBH", 1, 0x0800, 6, 4, oper) + sha + spa + tha + tpa


# ARP request for us (triggers the reply path + cache insert)
w("arp_req", eth(BCAST, PEER, 0x0806, arp(1, PEER, PEER_IP, b"\0" * 6, MY_IP)))
# ARP reply (unsolicited -> should be dropped)
w("arp_reply", eth(MY_MAC, PEER, 0x0806, arp(2, PEER, PEER_IP, MY_MAC, MY_IP)))

# ICMP echo request (checksum valid) -> reply path
icmp = struct.pack(">BBHHH", 8, 0, 0, 0x0001, 0x0001) + b"payload-" * 4
icmp = icmp[:2] + struct.pack(">H", cksum(icmp)) + icmp[4:]
w("icmp_echo", eth(MY_MAC, PEER, 0x0800, ip4(PEER_IP, MY_IP, 1, icmp)))

# big ICMP echo, near the 1480 ceiling
big = struct.pack(">BBHHH", 8, 0, 0, 2, 2) + b"A" * 1400
big = big[:2] + struct.pack(">H", cksum(big)) + big[4:]
w("icmp_big", eth(MY_MAC, PEER, 0x0800, ip4(PEER_IP, MY_IP, 1, big)))

# TCP SYN to port 80
tcp = struct.pack(">HHIIBBHHH", 44444, 80, 0x11223344, 0, 0x50, 0x02, 8192, 0, 0)
w("tcp_syn", eth(MY_MAC, PEER, 0x0800, ip4(PEER_IP, MY_IP, 6, tcp)))

# UDP datagram
udp = struct.pack(">HHHH", 5353, 68, 8 + 4, 0) + b"data"
w("udp", eth(MY_MAC, PEER, 0x0800, ip4(PEER_IP, MY_IP, 17, udp)))

# fragment (must be dropped) and a broadcast-destined echo (smurf reflector)
w("ip_frag", eth(MY_MAC, PEER, 0x0800, ip4(PEER_IP, MY_IP, 1, icmp, flags_frag=0x2000)))
w("icmp_bcast", eth(BCAST, PEER, 0x0800,
                    ip4(PEER_IP, bytes([192, 168, 1, 255]), 1, icmp)))

print("wrote", len(os.listdir(root)), "eth seeds to", os.path.abspath(root))

# ---- checksummed L4 seeds (the first pass shipped zero checksums, which both
# tcp_rx and udp_rx reject, so the state machine was never reached) ----------
def l4_cksum(src, dst, proto, payload):
    pseudo = src + dst + bytes([0, proto]) + struct.pack(">H", len(payload))
    return cksum(pseudo + payload)


def tcp_seg(sport, dport, seq, ack, flags, win=8192, payload=b"", opts=b""):
    off = (20 + len(opts)) // 4
    h = struct.pack(">HHIIBBHHH", sport, dport, seq, ack,
                    off << 4, flags, win, 0, 0) + opts + payload
    c = l4_cksum(PEER_IP, MY_IP, 6, h)
    return h[:16] + struct.pack(">H", c) + h[18:]


def udp_dg(sport, dport, payload):
    h = struct.pack(">HHHH", sport, dport, 8 + len(payload), 0) + payload
    c = l4_cksum(PEER_IP, MY_IP, 17, h)
    return h[:6] + struct.pack(">H", c) + h[8:]


SYN, SYNACK, ACK, FIN, RST, PSH = 0x02, 0x12, 0x10, 0x01, 0x04, 0x08
# MSS 1460 + window scale 3
OPTS = bytes([2, 4, 0x05, 0xB4, 3, 3, 3, 0])

w("tcp_syn_ck", eth(MY_MAC, PEER, 0x0800,
                    ip4(PEER_IP, MY_IP, 6, tcp_seg(44444, 80, 0x1000, 0, SYN, opts=OPTS))))
w("tcp_ack_ck", eth(MY_MAC, PEER, 0x0800,
                    ip4(PEER_IP, MY_IP, 6, tcp_seg(44444, 80, 0x1001, 1, ACK))))
w("tcp_data_ck", eth(MY_MAC, PEER, 0x0800,
                     ip4(PEER_IP, MY_IP, 6,
                         tcp_seg(44444, 80, 0x1001, 1, ACK | PSH, payload=b"GET / HTTP/1.0\r\n\r\n"))))
w("tcp_fin_ck", eth(MY_MAC, PEER, 0x0800,
                    ip4(PEER_IP, MY_IP, 6, tcp_seg(44444, 80, 0x1013, 1, FIN | ACK))))
w("tcp_rst_ck", eth(MY_MAC, PEER, 0x0800,
                    ip4(PEER_IP, MY_IP, 6, tcp_seg(44444, 80, 0x1013, 1, RST))))
w("udp_ck", eth(MY_MAC, PEER, 0x0800,
                ip4(PEER_IP, MY_IP, 17, udp_dg(67, 68, b"\x01\x02\x03\x04"))))
print("added checksummed L4 seeds")
