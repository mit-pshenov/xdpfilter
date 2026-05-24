/*
 * mac_filter.bpf.c — XDP program with L2 MAC + L3 src-CIDR OR-compose match.
 *
 * §5.27 (MVP-3.2): two-axis match per Q2 OR1 (MAC HASH first, short-circuit;
 * then on IPv4 frames lookup src_ip in the CIDR LPM_TRIE). On miss-both,
 * consult defaults[active_idx]. Non-IPv4 ethertypes (ARP, IPv6, VLAN-tagged,
 * ...) bypass the CIDR branch entirely — preserves the MVP-3.1 MAC-only
 * semantic for non-IP traffic. Decisions exposed via `stats` (4-slot
 * PERCPU_ARRAY now: STAT_PASS, STAT_DROP_DENY, STAT_DROP_MALFORMED,
 * STAT_PASS_CIDR).
 *
 * §5.26 (MVP-3.1): atomic apply via ARRAY_OF_MAPS[2] + active_idx ARRAY[1] +
 * defaults ARRAY[2] (Q2 A1 + Q2-extension). §5.27 extends to a PARALLEL
 * cidr_rulesets_outer ARRAY_OF_MAPS[2] of LPM_TRIE inners — both outers
 * read the SAME active_idx snapshot at the head of the datapath, so a
 * single userspace u32 store at active_idx[0] is the atomic commit for
 * BOTH axes (Q1 AS1 — Composite-6 swap promise byte-equivalent to MVP-3.1).
 *
 * Inner-map TYPE shape is shared via the named `xdpmf_allowlist_inner` /
 * `xdpmf_cidr_inner` structs so &inner_a / &inner_b satisfy the outer
 * `__array(values, struct ...)` pointer-type contract without warning.
 * The legacy `allowlist` symbol is RETAINED as a typed alias (same shape)
 * so any out-of-tree harness that linked against MVP-2's allowlist symbol
 * still resolves — runtime ruleset data lives ONLY in allowlist_a/_b /
 * cidr_allowlist_a/_b.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>     /* §5.27: bpf_htons for ETH_P_IP compare */
#include "common/mac_filter.h"

/* §5.27: ETH_P_IP (0x0800) is a CPP macro from linux/if_ether.h — that
 * header is not available in the BPF-target build (we get types from
 * vmlinux.h, but vmlinux.h is BTF-derived so contains only types, no
 * macros). Define inline; matches the IANA EtherType value byte-equivalently. */
#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif

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
 * §5.27 Q1 AS1: parallel CIDR LPM_TRIE inner template + two pinned inner
 * instances (slots A/B) + parallel ARRAY_OF_MAPS outer. Both outers
 * (rulesets + cidr_rulesets) index off the same `active_idx`; a single
 * userspace u32 store on active_idx[0] commits the swap for BOTH axes.
 *
 * LPM_TRIE requires BPF_F_NO_PREALLOC. Key shape `xdpmf_cidr_v4` starts
 * with `__u32 prefixlen` per kernel BPF LPM_TRIE convention.
 */
struct xdpmf_cidr_inner {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct xdpmf_cidr_v4);
    __type(value, __u8);
    __uint(max_entries, XDPMF_ALLOWLIST_MAX);
    __uint(map_flags, BPF_F_NO_PREALLOC);
};

struct xdpmf_cidr_inner cidr_allowlist_a SEC(".maps");
struct xdpmf_cidr_inner cidr_allowlist_b SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
    __uint(max_entries, XDPMF_RULESET_COUNT);
    __uint(key_size, sizeof(__u32));
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __array(values, struct xdpmf_cidr_inner);
} cidr_rulesets SEC(".maps") = {
    .values = { &cidr_allowlist_a, &cidr_allowlist_b },
};

/*
 * active_idx: single-slot ARRAY whose only entry is the index in {0,1}
 * naming the currently-live inner slot. Userspace atomic swap is a single
 * BPF_ANY update on key=0. §5.27: shared across MAC AND CIDR outers.
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

/*
 * §5.29 (MVP-3.4) HG-3.4-1: rules + action_table SKELETON. DECLARED here +
 * POPULATED from config in userspace at apply time; the xdp datapath
 * (mac_filter_prog below) does NOT consult either map per-packet (PI-28
 * function-body byte-equivalence). MVP-3.4b will wire datapath consumption
 * once PI-13-3.1 adjudication on the inner-allowlist-value extension lands.
 *
 * `rules` is a SHARED ARRAY (NOT parallel-swapped via ARRAY_OF_MAPS, D-3.4-4):
 * because the datapath ignores it this cycle, atomic-swap is unnecessary;
 * clear-and-rewrite on every apply suffices. MVP-3.4b will revisit if the
 * map becomes datapath-consulted.
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct rule_entry);
    __uint(max_entries, XDPMF_ALLOWLIST_MAX);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} rules SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct action_entry);
    __uint(max_entries, ACTION_MAX);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} action_table SEC(".maps");

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

    /* §5.27 Q2 OR1: MAC miss → CIDR axis (only on IPv4 ethertype). Non-IPv4
     * frames (ARP, IPv6, VLAN-tagged, ...) skip the CIDR branch entirely
     * and fall through to defaults — preserves MVP-3.1 semantic for
     * non-IP traffic per brief §1. Read the same `active` snapshot so a
     * concurrent userspace flip cannot split the MAC/CIDR axes mid-packet. */
    if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        /* Verifier-required IPv4 header bounds check before saddr deref. */
        if ((void *)(eth + 1) + sizeof(struct iphdr) > data_end) {
            bump_stat(STAT_DROP_MALFORMED);
            return XDP_DROP;
        }
        struct iphdr *ip = (struct iphdr *)(eth + 1);

        void *cidr_inner = bpf_map_lookup_elem(&cidr_rulesets, &active);
        if (!cidr_inner) {
            bump_stat(STAT_DROP_DENY);
            return XDP_DROP;
        }
        struct xdpmf_cidr_v4 cidr_key = {
            .prefixlen = 32u,        /* lookup is /32 host-route; LPM_TRIE picks longest matching prefix */
            .addr      = ip->saddr,  /* network byte order on wire, matches LPM_TRIE key shape */
        };
        __u8 *cidr_hit = bpf_map_lookup_elem(cidr_inner, &cidr_key);
        if (cidr_hit) {
            bump_stat(STAT_PASS_CIDR);
            return XDP_PASS;
        }
    }

    /* Inner miss (both axes) — consult defaults[active]. Q2-extension: same
     * active_idx value indexes ruleset+CIDR+default; one u32 flip swaps all. */
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
