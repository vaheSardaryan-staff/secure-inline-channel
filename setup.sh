#!/usr/bin/env bash
# Builds the lab as a transparent bump-in-the-wire:
#
#   pc1 --- d1 --- mitm(bridge) --- d2 --- pc2
#  10.10.10.1 (no IP)  (no IP)    (no IP)  10.20.20.2
#
# The PCs are on different subnets but on one L2 segment, so each has an on-link
# route and a fixed ARP entry for the other. Device1 and Device2 have no IP and
# sit inline; the MITM is a plain L2 bridge that forwards every frame (so it can
# also be used to try tampering). No IPv4 TCP passes until ./device completes
# its Diffie-Hellman handshake in both d1 and d2.
set -euo pipefail

[[ $EUID -eq 0 ]] || { echo "setup.sh: run as root (sudo ./setup.sh)" >&2; exit 1; }
for tool in ip ethtool; do
    command -v "$tool" >/dev/null || { echo "setup.sh: '$tool' not installed" >&2; exit 1; }
done

cd "$(dirname "$0")"
./teardown.sh >/dev/null 2>&1 || true

MTU=1500
for ns in pc1 d1 mitm d2 pc2; do
    ip netns add "$ns"
    ip -n "$ns" link set lo up
    [[ -e /proc/sys/net/ipv6 ]] && ip netns exec "$ns" sysctl -qw net.ipv6.conf.all.disable_ipv6=1 || true
done

mk_link() {   # ns_a if_a  ns_b if_b
    ip link add "$2" type veth peer name "$4"
    ip link set "$2" netns "$1"
    ip link set "$4" netns "$3"
}
mk_link pc1 pc1-eth  d1   d1-pc
mk_link d1  d1-net   mitm m-d1
mk_link mitm m-d2    d2   d2-net
mk_link d2  d2-pc    pc2  pc2-eth

cfg() {   # ns if
    ip -n "$1" link set "$2" mtu "$MTU"
    ip netns exec "$1" ethtool -K "$2" rx off tx off sg off tso off gso off gro off \
        >/dev/null 2>&1 || ip netns exec "$1" ethtool -K "$2" tx off gso off gro off tso off >/dev/null 2>&1 || true
    ip -n "$1" link set "$2" up
}
cfg pc1 pc1-eth
cfg d1 d1-pc ; cfg d1 d1-net
cfg mitm m-d1 ; cfg mitm m-d2
cfg d2 d2-net ; cfg d2 d2-pc
cfg pc2 pc2-eth

# Devices listen promiscuously (./device also sets this through its socket).
ip -n d1 link set d1-pc promisc on ; ip -n d1 link set d1-net promisc on
ip -n d2 link set d2-pc promisc on ; ip -n d2 link set d2-net promisc on

# MITM = transparent L2 bridge over its two ports.
ip -n mitm link add br0 type bridge
ip -n mitm link set br0 mtu "$MTU"
ip -n mitm link set m-d1 master br0
ip -n mitm link set m-d2 master br0
ip -n mitm link set br0 up

# PCs: two subnets, no router, so the peer is reached through an on-link route.
ip -n pc1 addr add 10.10.10.1/24 dev pc1-eth
ip -n pc2 addr add 10.20.20.2/24 dev pc2-eth
ip -n pc1 route add 10.20.20.2/32 dev pc1-eth
ip -n pc2 route add 10.10.10.1/32 dev pc2-eth
# Fixed ARP so the demo never waits on resolution (optional but tidy).
M1=$(ip -n pc1 link show pc1-eth | awk '/link\/ether/{print $2}')
M2=$(ip -n pc2 link show pc2-eth | awk '/link\/ether/{print $2}')
ip -n pc1 neigh replace 10.20.20.2 lladdr "$M2" dev pc1-eth
ip -n pc2 neigh replace 10.10.10.1 lladdr "$M1" dev pc2-eth

echo "Lab ready: pc1(10.10.10.1) - d1 - mitm(bridge) - d2 - pc2(10.20.20.2)"
echo "TCP flows only after ./device finishes the DH handshake in d1 and d2."
