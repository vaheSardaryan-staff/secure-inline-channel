#!/usr/bin/env python3
"""
mitm_attack.py - active attacker sitting on the bridge between the two devices.

Run DURING a transfer, inside the mitm namespace:
    sudo ip netns exec mitm python3 mitm_attack.py            # capture m-d1, inject m-d2

It grabs one encrypted TCP data frame heading to Device2 and injects three
forgeries, each with a corrected TCP checksum like a real attacker would send:
  1. a flipped ciphertext byte
  2. a changed TCP sequence number
  3. a flipped byte in the GCM tag
Expected result: Device2 reports "dropped: auth failed : 3" and the transfer
still completes intact, because AES-GCM rejects every modified packet.
"""
import socket, struct, sys

CAP_IF = sys.argv[1] if len(sys.argv) > 1 else "m-d1"
INJ_IF = sys.argv[2] if len(sys.argv) > 2 else "m-d2"

def checksum(data):
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF

def fix_tcp(frame):
    f = bytearray(frame)
    ip = 14
    ihl = (f[ip] & 0x0F) * 4
    tot = struct.unpack("!H", f[ip+2:ip+4])[0]
    t = ip + ihl
    f[t+16:t+18] = b"\0\0"
    pseudo = bytes(f[ip+12:ip+20]) + struct.pack("!BBH", 0, 6, tot - ihl)
    f[t+16:t+18] = struct.pack("!H", checksum(pseudo + bytes(f[t:ip+tot])))
    return bytes(f)

cap = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
cap.bind((CAP_IF, 0))
print("waiting for an encrypted TCP data frame to Device2 ...")
pkt = None
while pkt is None:
    frame, _ = cap.recvfrom(65535)
    if len(frame) < 60 or frame[12:14] != b"\x08\x00" or frame[23] != 6:
        continue
    ip_ihl = (frame[14] & 0x0F) * 4
    tcp = 14 + ip_ihl
    tcp_hl = (frame[tcp+12] >> 4) * 4
    payload = tcp + tcp_hl
    if len(frame) - payload > 16:        # has encrypted data + tag
        pkt = frame

print("captured %d-byte encrypted frame, injecting 3 forgeries" % len(pkt))
inj = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
inj.bind((INJ_IF, 0))
ip_ihl = (pkt[14] & 0x0F) * 4
tcp = 14 + ip_ihl
tcp_hl = (pkt[tcp+12] >> 4) * 4
payload = tcp + tcp_hl

f = bytearray(pkt); f[payload+8] ^= 0x01;  inj.send(fix_tcp(f))   # ciphertext
f = bytearray(pkt); f[tcp+4] ^= 0x10;       inj.send(fix_tcp(f))   # seq number
f = bytearray(pkt); f[-1] ^= 0x80;          inj.send(fix_tcp(f))   # GCM tag
print("done - check Device2 stats for 'dropped: auth failed'")
