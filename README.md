# Secure inline channel with Diffie-Hellman + AES-256-GCM

A transparent "bump in the wire": two devices sit between two hosts, agree a key
with ephemeral Diffie-Hellman, and encrypt the TCP payload of every packet that
passes between them. The headers stay in place, nothing is encapsulated, and the
only thing added on the wire is the 16-byte GCM tag.

```
pc1 ----- d1 ----- mitm(bridge) ----- d2 ----- pc2
10.10.10.1  encrypt   can't read        decrypt   10.20.20.2
./sender  payload   or alter it       payload   ./receiver
          (no IP)                     (no IP)
```

## What it does

1. **Handshake (once per run).** On startup d1 and d2 run an ephemeral
   finite-field Diffie-Hellman exchange (ffdhe2048, RFC 7919) over small L2
   control frames. The exchange is authenticated with a 32-byte pre-shared key
   (`psk.hex`): each side proves it knows the PSK and saw the same two public
   keys. No TCP data is forwarded until both sides confirm the same session key.
   - **Forward secrecy:** the data key is ephemeral, so a recorded session can't
     be decrypted later even if `psk.hex` leaks.
   - **Authenticated:** an attacker who runs its own DH with each device is
     caught, because its substituted public keys change the confirmation value
     and it cannot forge that value without the PSK.

2. **Protected forwarding.** For every IPv4/TCP packet with a payload:
   - `plain -> cipher`: encrypt the payload with AES-256-GCM, append the 16-byte
     tag, fix the IP total length and recompute the IP and TCP checksums.
   - `cipher -> plain`: verify the tag, decrypt, drop the tag, restore the
     original length and checksums.
   - ARP, ICMP and payload-free TCP (SYN/ACK) pass through untouched.

```
on the link between the devices:
| Eth | IP | TCP | encrypted payload (same length) | TAG(16) |
```

No UDP wrapper, no custom header: between the devices each packet is still an
ordinary TCP/IP packet, just with an encrypted payload and a tag.

## Unique nonce for every packet, with zero bytes on the wire

AES-GCM needs a nonce that never repeats under one key. Instead of sending a
12-byte nonce in every packet, both devices **recompute** it from fields they
already see:

```
nonce = HMAC-SHA256(nonce_master, "N" | flow | seq | len)[0..12]
aad   =                           "A" | flow | seq          (authenticated)
```

- `flow` is the connection's 4-tuple in a canonical order plus a direction bit,
  identical on both devices.
- `seq` is the TCP sequence number; `len` is the payload length (the receiver
  gets it from `ciphertext length = received length - 16`).

Two different plaintexts can never share the same `(flow, seq, len)`, so the
nonce is unique for every packet. A genuine TCP retransmission of the same bytes
reproduces the same nonce and therefore the same ciphertext, which is safe. The
AAD binds each payload to its connection and stream position, so a valid
encrypted payload can't be replayed into another flow or offset.

## Files

| File | Role |
|---|---|
| `crypto.c` / `crypto.h` | DH handshake, HKDF key schedule, GCM seal/open, PRF nonce |
| `device.c` | the inline device: handshake + raw-socket forwarding (same binary on d1 and d2) |
| `sender.c` / `receiver.c` / `common.h` | plain TCP file transfer on PC1 / PC2 |
| `setup.sh` / `teardown.sh` | build / remove the 5-namespace lab |
| `run_test.sh` | automatic end-to-end test with SHA-256 check |
| `mitm_attack.py` | active attacker demo (tamper is rejected) |
| `selftest.c` | unit checks for the crypto module (`make test`) |

Requirements (Ubuntu/Debian): `sudo apt install build-essential libssl-dev iproute2 ethtool tcpdump`

## Quick start

```bash
chmod +x *.sh                  # once, after unzipping
make
sudo ./run_test.sh             # 20 MB, prints PASS/FAIL + device stats
sudo SIZE_MB=100 ./run_test.sh
sudo WRONGKEY=1 ./run_test.sh  # different PSKs -> handshake refused -> no data
make test                      # crypto unit tests (no root needed)
```

## Manual run (the 5-terminal way)

```bash
make
sudo ./setup.sh
openssl rand -hex 32 > psk.hex   # shared secret, same file for both devices
head -c 20M /dev/urandom > file

# T1  Device1
sudo ip netns exec d1 ./device d1-pc d1-net psk.hex
# T2  Device2
sudo ip netns exec d2 ./device d2-pc d2-net psk.hex
#     (both print "secure session established" after the DH handshake)
# T3  MITM - watch: the payload is unreadable, headers are intact
sudo ip netns exec mitm tcpdump -ni m-d1 -X 'tcp port 5000'
# T4  PC2
sudo ip netns exec pc2 ./receiver 5000 out
# T5  PC1
sudo ip netns exec pc1 ./sender 10.20.20.2 5000 file

sha256sum file out               # identical
```
Add `-v` to a device to log every packet. Ctrl+C prints its statistics.

## MITM demo

During a transfer, from the bridge namespace:
```bash
sudo ip netns exec mitm python3 mitm_attack.py
```
It injects a flipped-ciphertext packet, a changed-sequence packet and a
flipped-tag packet. Device2's stats show `dropped: auth failed : 3` and the file
still arrives intact.

## Why each setting exists

- **promisc on** - frames are addressed to the PC's MAC, not the device's;
  without it the interface would ignore them.
- **ethtool offloads off** - otherwise veth hands the raw socket 64 KB
  "super-packets" and packets with unfinished checksums.
- **MSS clamp (<= 1424)** - a full 1500-byte packet plus the 16-byte tag would
  exceed the MTU. Sender and receiver set `TCP_MAXSEG`, and the device also
  lowers the MSS in SYN packets as a safety net.
- **checksums verified before modifying** - a corrupted clear-text packet is
  dropped, never silently "repaired"; encrypted payloads are protected by the
  GCM tag.
- **ignore our own outgoing frames** - one socket per interface, and
  `PACKET_IGNORE_OUTGOING` / `sll_pkttype`, so the device never re-encrypts what
  it just sent.
- **handshake on a private EtherType (0x88B5)** - device-to-device control
  traffic only; it is never forwarded to the PCs, and the data path carries no
  extra header.

## Tested in this build

- 20 MB and 100 MB transfers: SHA-256 identical, 0 drops (~1 s for 100 MB).
- MITM capture: 0 plaintext matches vs ~199,000 on the PC-side link.
- Active tamper (ciphertext / sequence / tag): all 3 forgeries rejected, file
  still identical.
- Wrong PSK on one device: handshake refused, no data forwarded.
- Client that never sets MSS: device clamp engaged, file identical.
- `make test`: DH agreement, round trip, four tamper cases, and 4000-packet
  nonce-uniqueness check all pass.

## Known limits (prototype)

- Only IPv4 TCP payload is protected; ARP/ICMP/IPv6 pass in clear.
- The nonce uses the 32-bit TCP sequence number; a single connection moving more
  than ~4 GiB would wrap it. Out of scope for this prototype; a production
  version would add an explicit epoch counter.
- One pre-shared key authenticates the handshake. Replacing the PSK with
  certificates would remove the shared-secret requirement.
