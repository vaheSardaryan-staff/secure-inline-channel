#!/usr/bin/env bash
# Full automatic test: build, create lab, run the two devices (which perform the
# DH handshake), then transfer a file and compare SHA-256 end to end.
#
#   sudo ./run_test.sh                 # 20 MB
#   sudo SIZE_MB=100 ./run_test.sh
#   sudo WRONGKEY=1 ./run_test.sh      # devices get different PSKs -> no session
#   sudo KEEP=1 ./run_test.sh          # leave the lab up afterwards
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "run_test.sh: run as root (sudo)" >&2; exit 1; }
cd "$(dirname "$0")"

SIZE_MB=${SIZE_MB:-20}
WRONGKEY=${WRONGKEY:-0}
KEEP=${KEEP:-0}
PORT=5000

make -s
./setup.sh

[[ -f psk.hex ]] || { (umask 077; openssl rand -hex 32 > psk.hex); echo "Generated psk.hex"; }
PSK2=psk.hex
if [[ "$WRONGKEY" == 1 ]]; then
    PSK2=$(mktemp); openssl rand -hex 32 > "$PSK2"
    echo "Device2 is using a DIFFERENT PSK - handshake must fail"
fi

WORK=$(mktemp -d)
PIDS=()
cleanup() {
    for p in "${PIDS[@]}"; do kill -INT "$p" 2>/dev/null || true; done
    for p in "${PIDS[@]}"; do wait "$p" 2>/dev/null || true; done
    for l in d1 d2; do [[ -f "$WORK/$l.log" ]] && { echo "--- $l ---"; tail -n 17 "$WORK/$l.log"; }; done
    [[ "$KEEP" == 1 ]] || ./teardown.sh
    [[ "$WRONGKEY" == 1 ]] && rm -f "$PSK2"
    rm -rf "$WORK"
}
trap cleanup EXIT

head -c "${SIZE_MB}M" /dev/urandom > "$WORK/file"

ip netns exec d1 ./device d1-pc d1-net psk.hex > "$WORK/d1.log" 2>&1 & PIDS+=($!)
ip netns exec d2 ./device d2-pc d2-net "$PSK2" > "$WORK/d2.log" 2>&1 & PIDS+=($!)

# Wait for the handshake (both devices announce the established session).
echo -n "waiting for secure session"
ready=0
for _ in $(seq 40); do
    if grep -q "session established" "$WORK/d1.log" 2>/dev/null \
       && grep -q "session established" "$WORK/d2.log" 2>/dev/null; then ready=1; break; fi
    if grep -q "MISMATCH" "$WORK/d1.log" "$WORK/d2.log" 2>/dev/null; then break; fi
    echo -n "."; sleep 0.25
done
echo

if [[ "$WRONGKEY" == 1 ]]; then
    if [[ $ready == 1 ]]; then echo "FAIL: session came up despite wrong PSK" >&2; exit 1; fi
    echo "Handshake correctly refused. Confirming the data path stays blocked..."
    ip netns exec pc2 timeout 6 ./receiver "$PORT" "$WORK/out" >/dev/null 2>&1 & R=$!
    sleep 0.3
    if timeout 5 ip netns exec pc1 ./sender 10.20.20.2 "$PORT" "$WORK/file" >/dev/null 2>&1; then
        echo "FAIL: transfer succeeded with no session" >&2; kill $R 2>/dev/null; exit 1
    fi
    kill $R 2>/dev/null || true
    echo "PASS: no PSK agreement -> no session -> no data forwarded"
    exit 0
fi

[[ $ready == 1 ]] || { echo "FAIL: handshake did not complete" >&2; exit 1; }
echo "secure session up"

ip netns exec pc2 ./receiver "$PORT" "$WORK/out" & RECV=$!
for _ in $(seq 50); do
    ip netns exec pc2 ss -ltnH "sport = :$PORT" | grep -q . && break; sleep 0.1
done

start=$(date +%s.%N)
ip netns exec pc1 ./sender 10.20.20.2 "$PORT" "$WORK/file"
wait "$RECV"
end=$(date +%s.%N)

h1=$(sha256sum "$WORK/file" | cut -d' ' -f1)
h2=$(sha256sum "$WORK/out"  | cut -d' ' -f1)
echo "sha256 file: $h1"
echo "sha256 out : $h2"
printf 'time: %.2f s\n' "$(echo "$end - $start" | bc)"
[[ "$h1" == "$h2" ]] && echo "PASS: files are identical" || { echo "FAIL: files differ" >&2; exit 1; }
