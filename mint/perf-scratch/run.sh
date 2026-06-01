#!/bin/bash
# run.sh <config.yaml> <repeat> <pkt1.bin> [pkt2.bin ...]
# Applies config in the perf netns, finds prog id, runs PROG_TEST_RUN per pkt.
set -euo pipefail
ROOT=/home/user/mint-l2-mac-filter
NS=xdpmf_perf
IF=xdpmf_perf0
NSEXEC="sudo nsenter --net=/var/run/netns/$NS"
LOADER=$ROOT/build/src/cli/xdpmacfilter
SCRATCH=$ROOT/mint/perf-scratch

CFG="$1"; REPEAT="$2"; shift 2
sudo rm -rf /sys/fs/bpf/xdpmacfilter/$IF 2>/dev/null || true
$NSEXEC $LOADER apply --iface $IF -f "$CFG" >/tmp/perf_apply.log 2>&1 || { echo "APPLY FAIL"; cat /tmp/perf_apply.log; exit 1; }
ID=$(grep -oP 'prog id \K[0-9]+' /tmp/perf_apply.log)
echo "# config=$(basename "$CFG") prog_id=$ID repeat=$REPEAT"
for p in "$@"; do
  OUT=$(sudo bpftool prog run id $ID data_in "$SCRATCH/$p" repeat "$REPEAT" 2>&1 | tail -1)
  echo "  $p : $OUT"
done
