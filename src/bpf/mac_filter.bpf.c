/*
 * mac_filter.bpf.c — XDP program: pass frames whose source MAC is in the
 * active inner-map slot, otherwise consult defaults[active_idx]. Decisions
 * exposed via `stats`.
 *
 * Reads h_source only; ignores h_dest, h_proto, VLAN, payload (design §5.10).
 *
 * §5.26 (MVP-3.1): atomic apply via ARRAY_OF_MAPS[2] + active_idx ARRAY[1] +
 * defaults ARRAY[2] (Q2 A1 + Q2-extension). Userspace swaps rulesets by
 * (a) writing the new inner map (inactive slot) and the new defaults
 * (inactive slot), then (b) updating active_idx — a single u32 store that
 * the kernel guarantees atomic on aligned word writes. The verifier
 * recognizes the inner-deref pattern (`bpf_map_lookup_elem` on a
 * MAP_OF_MAPS value, then `bpf_map_lookup_elem` on the returned inner).
 *
 * Inner-map TYPE shape is shared via the named `xdpmf_allowlist_inner`
 * struct so &allowlist_a / &allowlist_b satisfy the outer `__array(values,
 * struct xdpmf_allowlist_inner)` pointer-type contract without warning.
 * The legacy `allowlist` symbol is RETAINED as a typed alias (same shape)
 * so any out-of-tree harness that linked against MVP-2's allowlist symbol
 * still resolves — runtime ruleset data lives ONLY in allowlist_a/_b.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "common/mac_filter.h"

/* Named inner-map type. Used by both concrete inner instances and the
 * outer MAP_OF_MAPS template (so &instance pointer types match exactly). */
struct xdpmf_allowlist_inner {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct xdpmf_mac);
    __type(value, __u8);
    __uint(max_entries, XDPMF_ALLOWLIST_MAX);
};

/* Concrete inner instances; pinned at apply time under PIN_DIR. */
struct xdpmf_allowlist_inner allowlist_a SEC(".maps");
struct xdpmf_allowlist_inner allowlist_b SEC(".maps");

/* Legacy `allowlist` symbol — retained for MVP-2 compat-time wiring; NOT
 * pinned (the two real slots take its place). Userspace clears its
 * pin_path explicitly in load_skeleton(). */
struct xdpmf_allowlist_inner allowlist SEC(".maps");

/*
 * Outer MAP_OF_MAPS: ARRAY[XDPMF_RULESET_COUNT] whose value at slot N is an
 * FD to allowlist_a (N=0) or allowlist_b (N=1). libbpf wires the FDs from
 * the `values` initializer at load time.
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
    __uint(max_entries, XDPMF_RULESET_COUNT);
    __uint(key_size, sizeof(__u32));
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __array(values, struct xdpmf_allowlist_inner);
} rulesets SEC(".maps") = {
    .values = { &allowlist_a, &allowlist_b },
};

/*
 * active_idx: single-slot ARRAY whose only entry is the index in {0,1}
 * naming the currently-live inner slot. Userspace atomic swap is a single
 * BPF_ANY update on key=0.
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} active_idx SEC(".maps");

/*
 * defaults: two-slot ARRAY indexed by the SAME active_idx — the default
 * action swaps atomically with the ruleset (Q2-extension). 0 = drop,
 * 1 = pass.
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, XDPMF_RULESET_COUNT);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} defaults SEC(".maps");

/*
 * Stats counters. Per-CPU array (Decision §5.3 superseded by §5.23, MVP-2 Perf).
 * bpf_map_lookup_elem on a PERCPU_ARRAY returns a pointer to the CURRENT CPU's
 * slot — `*v += 1` is per-CPU local, no cross-CPU race, no atomic needed.
 * Userspace (read_stats.py) sums across CPUs per key.
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

    /* §5.26 Q2 A1: read active_idx (single u32 read, atomic), then chain
     * map-of-maps lookup to obtain the live inner hash, then look up the
     * source MAC. Both NULL checks are verifier-required on map_of_maps
     * lookups and percpu map lookups; they should be unreachable in
     * practice because userspace populates both slots before the first attach. */
    __u32 zero = 0;
    __u32 *active_p = bpf_map_lookup_elem(&active_idx, &zero);
    if (!active_p) {
        bump_stat(STAT_DROP_DENY);
        return XDP_DROP;
    }
    __u32 active = *active_p;

    void *inner = bpf_map_lookup_elem(&rulesets, &active);
    if (!inner) {
        bump_stat(STAT_DROP_DENY);
        return XDP_DROP;
    }

    __u8 *present = bpf_map_lookup_elem(inner, &key);
    if (present) {
        bump_stat(STAT_PASS);
        return XDP_PASS;
    }

    /* Inner miss — consult defaults[active]. Q2-extension: same active_idx
     * value indexes both the ruleset AND the default; one u32 flip swaps both. */
    __u32 *default_p = bpf_map_lookup_elem(&defaults, &active);
    if (!default_p) {
        bump_stat(STAT_DROP_DENY);
        return XDP_DROP;
    }
    if (*default_p == 1u) {
        bump_stat(STAT_PASS);
        return XDP_PASS;
    }
    bump_stat(STAT_DROP_DENY);
    return XDP_DROP;
}

char __license[] SEC("license") = "GPL";
