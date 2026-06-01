#!/bin/bash
# pktgen.sh <dst_ip> <src_ip> <count> [dst_mac] [udp_dport]
# Configures the kpktgend_0 thread (CPU0) to blast UDP/IPv4 frames out xdpmf_tx.
# Frames arrive on xdpmf_rx where the filter XDP prog runs (steered to CPU1 via rps).
set -euo pipefail
TX=xdpmf_tx
DST_IP="$1"; SRC_IP="$2"; COUNT="$3"
DST_MAC="${4:-ff:ff:ff:ff:ff:ff}"
DPORT="${5:-80}"

PG=/proc/net/pktgen
pgset() { echo "$1" > "$2"; }

# reset any prior config
echo "reset" > $PG/pgctrl

# bind device to thread 0 (kpktgend_0, pinned CPU0)
pgset "rem_device_all" $PG/kpktgend_0
pgset "add_device $TX" $PG/kpktgend_0

DEV=$PG/$TX
pgset "count $COUNT" $DEV
pgset "clone_skb 1000" $DEV          # reuse skb -> max pps (no per-pkt alloc)
pgset "pkt_size 60" $DEV             # 60B L2 frame (matches Tier-0 vectors)
pgset "delay 0" $DEV
pgset "dst_mac $DST_MAC" $DEV
pgset "dst $DST_IP" $DEV
pgset "src_min $SRC_IP" $DEV
pgset "src_max $SRC_IP" $DEV
pgset "udp_dst_min $DPORT" $DEV
pgset "udp_dst_max $DPORT" $DEV
pgset "flag UDPSRC_RND" $DEV
echo "configured pktgen on $TX: dst=$DST_IP src=$SRC_IP dmac=$DST_MAC count=$COUNT dport=$DPORT"
