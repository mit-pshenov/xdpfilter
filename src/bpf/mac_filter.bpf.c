/*
 * mac_filter.bpf.c — XDP program: pass frames whose source MAC is in the
 * `allowlist` map, drop everything else. Decisions exposed via `stats`.
 *
 * Reads h_source only; ignores h_dest, h_proto, VLAN, payload (design §5.10).
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "common/mac_filter.h"

/*
 * Allow-list. Hash keyed on the 6-byte source MAC; value is a 1-byte
 * presence marker (content ignored). Pinned by name via LIBBPF_PIN_BY_NAME
 * — userspace sets pin_root_path on bpf_object_open_opts so libbpf
 * resolves the final path to /sys/fs/bpf/xdpmacfilter/<iface>/allowlist.
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct xdpmf_mac);
    __type(value, __u8);
    __uint(max_entries, XDPMF_ALLOWLIST_MAX);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} allowlist SEC(".maps");

/*
 * Stats counters. Per-CPU array (Decision §5.3 superseded by §5.23, MVP-2 Perf).
 * bpf_map_lookup_elem on a PERCPU_ARRAY returns a pointer to the CURRENT CPU's
 * slot — `*v += 1` is per-CPU local, no cross-CPU race, no atomic needed.
 * Userspace (read_stats.py) sums across CPUs per key.
 * Index space is `enum mac_filter_stat`; size is STAT_MAX.
 */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, STAT_MAX);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} stats SEC(".maps");

/* PERCPU bump: pointer returned is to this CPU's slot only. No atomic. */
static __always_inline void bump_stat(__u32 idx)
{
    __u64 *v = bpf_map_lookup_elem(&stats, &idx);
    if (v) {
        *v += 1;
    }
}

SEC("xdp")
int mac_filter_prog(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* Bounds-check before any Ethernet-header read; truncated frames
     * (data range < 14 bytes) are counted separately per Decision §5.5. */
    if (data + sizeof(struct ethhdr) > data_end) {
        bump_stat(STAT_DROP_MALFORMED);
        return XDP_DROP;
    }

    struct ethhdr *eth = data;
    struct xdpmf_mac key;
    __builtin_memcpy(key.octets, eth->h_source, sizeof(key.octets));

    if (bpf_map_lookup_elem(&allowlist, &key)) {
        bump_stat(STAT_PASS);
        return XDP_PASS;
    }

    bump_stat(STAT_DROP_DENY);
    return XDP_DROP;
}

char __license[] SEC("license") = "GPL";
