#!/usr/bin/env bash
[[ $EUID -eq 0 ]] || { echo "teardown.sh: run as root" >&2; exit 1; }
for ns in pc1 d1 mitm d2 pc2; do
    ip netns pids "$ns" 2>/dev/null | xargs -r kill 2>/dev/null || true
    ip netns del "$ns" 2>/dev/null || true
done
exit 0
