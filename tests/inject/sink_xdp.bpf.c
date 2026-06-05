/*
 * sink_xdp.bpf.c — counting RX-sink XDP program for the redirect delivery
 * oracle (design §5.75.6 SELECT-B, T_REDIRECT_DELIVERY).
 *
 * Attached (generic/SKB mode) on the redirect-target peer iface (IFACE_D).
 * A frame the production datapath diverts via XDP_REDIRECT out the devmap[0]
 * target (IFACE_C) physically egresses on IFACE_C and arrives RX on its peer
 * IFACE_D, where THIS program runs and bumps `sink_count[0]` once per frame.
 * The test reads that pinned counter: a non-zero value is the irreducible
 * proof the divert PHYSICALLY LANDED on the target leg — not merely that the
 * classifier decided to redirect (which STAT_REDIRECT alone would show).
 *
 * The function name `sink_count_prog` is deliberately distinct from the
 * production entry point `xdpfilter_prog` — this object is NEVER opened by
 * C++ code (no skeleton header); the test loads + pins it with
 * `bpftool prog loadall … type xdp pinmaps …` and reads the pinned
 * `sink_count` map via tests/lib/read_stats.py (column 0 == summed key-0
 * count). PERCPU_ARRAY mirrors the production `stats` map so the existing
 * per-CPU summing reader applies verbatim.
 *
 * Built via `add_bpf_object(sink_xdp …)` in tests/CMakeLists.txt; same
 * sanitizer-isolation invariant as xdp_pass.bpf.c (XDPMF_SANITIZERS does
 * NOT propagate into the BPF compile).
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} sink_count SEC(".maps");

SEC("xdp")
int sink_count_prog(struct xdp_md *ctx)
{
    (void)ctx;
    __u32 key = 0;
    __u64 *cnt = bpf_map_lookup_elem(&sink_count, &key);
    if (cnt)
        __sync_fetch_and_add(cnt, 1);
    /* Sink consumes the frame after counting; the original disposition on
     * the source iface is the production datapath's concern, not ours. */
    return XDP_PASS;
}
