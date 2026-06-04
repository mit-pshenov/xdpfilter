#pragma once
/*
 * maps.h — the SEC(".maps") map objects + their inner-struct templates.
 *
 * Moved verbatim from xdpfilter.bpf.c (MVP-4.29 / B34b, §5.69). Included BEFORE
 * classifier.h (its __always_inline helpers reference map symbols at definition
 * point). §5.70 (MVP-4.30) B35: the `wildcard` + `defaults` ARRAYs collapse into
 * ONE `ruleset_state` ARRAY-of-struct (one fewer map) — an INTENTIONAL map-schema
 * VALUE-pack, so the datapath is NO LONGER byte-identical; correctness is held by
 * verdict-identity (T_*_ORACLE_AGREEMENT) and the B37 insn gate is re-baselined
 * to the measured post-pack count (D-mvp-4.30-REBASELINE).
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "common/xdpfilter.h"

/* Named inner-map type. Used by both concrete inner instances and the
 * outer MAP_OF_MAPS template (so &instance pointer types match exactly). */
struct xdpmf_allowlist_inner {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct xdpmf_mac);
    /* §5.47 MAC axis value: per-MAC rule-bitmask (`__u64`; bit k set iff rule k
     * constrains this exact src-MAC). EXACT match, NO prefix-closure (unlike the
     * LPM cidr axes). Topology + pin names (allowlist_a/_b, rulesets) UNCHANGED
     * (guard #16). */
    __type(value, __u64);
    __uint(max_entries, XDPMF_ALLOWLIST_MAX);
};

/* Concrete inner instances; pinned at apply time under PIN_DIR. */
struct xdpmf_allowlist_inner allowlist_a SEC(".maps");
struct xdpmf_allowlist_inner allowlist_b SEC(".maps");

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
 * §5.27 Q1 AS1: parallel CIDR LPM_TRIE axis. Both outers (rulesets +
 * cidr_rulesets) index off the same `active_idx`; a single userspace u32 store
 * on active_idx[0] commits the swap for BOTH axes.
 * LPM_TRIE requires BPF_F_NO_PREALLOC; key `xdpmf_cidr_v4` starts with
 * `__u32 prefixlen` per the kernel LPM_TRIE convention.
 */
struct xdpmf_cidr_inner {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct xdpmf_cidr_v4);
    /* §5.43 src-CIDR axis value: prefix-closed per-rule bitmask (`__u64`; bit k
     * set iff rule k constrains a prefix COVERING this entry). The datapath ORs
     * this mask into the src-axis survivors. Pin names UNCHANGED (guard #16). */
    __type(value, __u64);
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
 * §5.43 dst-CIDR axis: LPM_TRIE bitmask keyed by the /32-padded destination
 * address, mirroring the src-CIDR topology. The single active_idx u32 store
 * commits dst + src + wildcard + defaults + rules + rule_counters together
 * (§5.27 Q1 AS1 extended).
 */
struct xdpmf_dst_inner {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct xdpmf_cidr_v4);
    __type(value, __u64);
    __uint(max_entries, XDPMF_ALLOWLIST_MAX);
    __uint(map_flags, BPF_F_NO_PREALLOC);
};

struct xdpmf_dst_inner dst_bitmask_a SEC(".maps");
struct xdpmf_dst_inner dst_bitmask_b SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
    __uint(max_entries, XDPMF_RULESET_COUNT);
    __uint(key_size, sizeof(__u32));
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __array(values, struct xdpmf_dst_inner);
} dst_rulesets SEC(".maps") = {
    .values = { &dst_bitmask_a, &dst_bitmask_b },
};

/*
 * §5.70 (MVP-4.30) B35: ruleset_state — one struct per ruleset half, holding
 * the 9 per-axis wildcard __u64 halves (wc[BV_AXIS_*]) PLUS the folded default
 * action (default_action: 0=drop, 1=pass). Replaces the prior `wildcard`
 * ARRAY[RULESET_COUNT*AXES] of __u64 AND the `defaults` ARRAY[RULESET_COUNT] of
 * __u32. Read ONCE per packet — hoisted above the family dispatch as a single
 * inlined ARRAY lookup (key = active ∈ {0,1}), then rs->wc[axis] /
 * rs->default_action are direct bounded field loads (D-mvp-4.30-Q1-A2 /
 * D-mvp-4.30-Q2-FOLD). A rule that does NOT constrain an axis has its bit set in
 * rs->wc[axis] (and is ABSENT from that axis's map); the datapath ORs the
 * wildcard half into that axis's survivors. One indexed ARRAY (not per-axis
 * symbols) because a runtime active_idx can select only between slots of ONE
 * indexed ARRAY, not between top-level map symbols.
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct xdpmf_ruleset_state);
    __uint(max_entries, XDPMF_RULESET_COUNT);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} ruleset_state SEC(".maps");

/*
 * §5.53 IPv6 dst/src-CIDR axes: LPM_TRIE bitmasks keyed by `struct xdpmf_cidr_v6`
 * (prefixlen-first, addr6[16] in network byte order; close_prefixes6). Selected
 * via the SAME shared active_idx; one u32 store commits dst6/src6 with the rest.
 */
struct xdpmf_dst6_inner {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct xdpmf_cidr_v6);
    __type(value, __u64);
    __uint(max_entries, XDPMF_ALLOWLIST_MAX);
    __uint(map_flags, BPF_F_NO_PREALLOC);
};

struct xdpmf_dst6_inner dst6_bitmask_a SEC(".maps");
struct xdpmf_dst6_inner dst6_bitmask_b SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
    __uint(max_entries, XDPMF_RULESET_COUNT);
    __uint(key_size, sizeof(__u32));
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __array(values, struct xdpmf_dst6_inner);
} dst6_rulesets SEC(".maps") = {
    .values = { &dst6_bitmask_a, &dst6_bitmask_b },
};

struct xdpmf_dst6_inner src6_bitmask_a SEC(".maps");
struct xdpmf_dst6_inner src6_bitmask_b SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
    __uint(max_entries, XDPMF_RULESET_COUNT);
    __uint(key_size, sizeof(__u32));
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __array(values, struct xdpmf_dst6_inner);
} src6_rulesets SEC(".maps") = {
    .values = { &src6_bitmask_a, &src6_bitmask_b },
};

/*
 * §5.44 proto axis: HASH bitmask keyed by __u32 IP-protocol → __u64 rule-bitmask.
 * Exact-match, NO prefix-closure. A rule constraining `protocol=p` ORs its bit
 * into proto_bitmask[active][p]; selected via the SHARED active_idx.
 */
struct xdpmf_proto_inner {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, XDPMF_PROTO_HASH_MAX);
};

struct xdpmf_proto_inner proto_bitmask_a SEC(".maps");
struct xdpmf_proto_inner proto_bitmask_b SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
    __uint(max_entries, XDPMF_RULESET_COUNT);
    __uint(key_size, sizeof(__u32));
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __array(values, struct xdpmf_proto_inner);
} proto_rulesets SEC(".maps") = {
    .values = { &proto_bitmask_a, &proto_bitmask_b },
};

/*
 * §5.44 dst_port axis: ARRAY of `struct xdpmf_port_range{lo,hi,bit}` slots. The
 * datapath does a bounded `#pragma unroll` scan (port_scan) over
 * XDPMF_ALLOWLIST_MAX slots, OR-ing `bit` of every USED slot (lo<=hi) whose
 * inclusive [lo,hi] contains the dport. NO prefix-closure (explicit ranges).
 * Shared active_idx commits the swap with the rest.
 */
struct xdpmf_port_inner {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct xdpmf_port_range);
    __uint(max_entries, XDPMF_ALLOWLIST_MAX);
};

struct xdpmf_port_inner port_ranges_a SEC(".maps");
struct xdpmf_port_inner port_ranges_b SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
    __uint(max_entries, XDPMF_RULESET_COUNT);
    __uint(key_size, sizeof(__u32));
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __array(values, struct xdpmf_port_inner);
} port_rulesets SEC(".maps") = {
    .values = { &port_ranges_a, &port_ranges_b },
};

/*
 * §5.45 vlan axis: HASH bitmask keyed by __u32 outer VID [0,4095] → __u64
 * rule-bitmask. Exact-match, NO prefix-closure. Selected via the SHARED
 * active_idx. ORed into the vlan-axis survivors ONLY when has_vlan (the frame
 * carried an outer tag).
 */
struct xdpmf_vlan_inner {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, XDPMF_VLAN_HASH_MAX);
};

struct xdpmf_vlan_inner vlan_bitmask_a SEC(".maps");
struct xdpmf_vlan_inner vlan_bitmask_b SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
    __uint(max_entries, XDPMF_RULESET_COUNT);
    __uint(key_size, sizeof(__u32));
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __array(values, struct xdpmf_vlan_inner);
} vlan_rulesets SEC(".maps") = {
    .values = { &vlan_bitmask_a, &vlan_bitmask_b },
};

/*
 * §5.54 ethertype axis: HASH bitmask keyed by the post-VLAN inner ethertype
 * (host order) → __u64 rule-bitmask. Exact-match, NO prefix-closure. The lookup
 * is HOISTED once above the family dispatch (EtherType is the family selector)
 * and the `& (eth_mask|wc_eth)` term composes into all THREE arms (v4, v6, non-IP).
 */
struct xdpmf_ethertype_inner {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, XDPMF_ETHERTYPE_HASH_MAX);
};

struct xdpmf_ethertype_inner ethertype_bitmask_a SEC(".maps");
struct xdpmf_ethertype_inner ethertype_bitmask_b SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
    __uint(max_entries, XDPMF_RULESET_COUNT);
    __uint(key_size, sizeof(__u32));
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __array(values, struct xdpmf_ethertype_inner);
} ethertype_rulesets SEC(".maps") = {
    .values = { &ethertype_bitmask_a, &ethertype_bitmask_b },
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

/* §5.70 (MVP-4.30) B35: the `defaults` ARRAY is RETIRED — the default action is
 * folded into struct xdpmf_ruleset_state.default_action (see `ruleset_state`
 * above), still swapped atomically with the ruleset via the shared active_idx. */

/*
 * §5.61 (MVP-4.21) B30 D-mvp-4.21-Q1: slot_rule_id — USERSPACE-ONLY map.
 * Persists, per ruleset half, the operator `id` occupying each internal
 * `slot` (= id-sorted rank): slot_rule_id[active*XDPMF_ALLOWLIST_MAX + slot].
 * The loader writes it (copy-forward old-slot recovery + exporter stable-id
 * labelling); xdpfilter_prog NEVER references it, so the per-packet
 * instruction stream is byte-identical (HG-mvp-4.21-1) — only the .o maps
 * section gains this one entry.
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, XDPMF_RULESET_COUNT * XDPMF_ALLOWLIST_MAX);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} slot_rule_id SEC(".maps");

/*
 * Stats counters (§5.23 PERCPU_ARRAY). bpf_map_lookup_elem returns a pointer to
 * the CURRENT CPU's slot — `*v += 1` is per-CPU local, no cross-CPU race, no
 * atomic needed. Userspace sums across CPUs per key.
 */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, STAT_MAX);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} stats SEC(".maps");

/*
 * §5.34 rules axis: ARRAY_OF_MAPS keyed by slot; the active_idx u32 store
 * commits it with the other per-ruleset axes. Per match the datapath dispatches
 * rules_outer[active] → rules_inner[slot] → action_table[rule.action_id].
 *
 * `action_table` STAYS SHARED (D-3.4b-c2-6): values are static {PASS=0, DROP=1},
 * never mutate at runtime ⇒ atomic-swap meaningless.
 */

/* Inner-map template for rules_outer. NO `LIBBPF_PIN_BY_NAME` in the struct —
 * libbpf rejects pinning on ARRAY_OF_MAPS inner types (`inner def can't be
 * pinned`); rules_a/_b are pinned MANUALLY via `bpf_map__pin()` in loader.cpp's
 * `kManagedMaps[]` loop (symmetric with allowlist_a/_b, cidr_allowlist_a/_b). */
struct rules_inner {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct rule_entry);
    __uint(max_entries, XDPMF_ALLOWLIST_MAX);
};

struct rules_inner rules_a SEC(".maps");   /* pinned via kManagedMaps[] at ${PIN_DIR}/<iface>/rules_a */
struct rules_inner rules_b SEC(".maps");   /* pinned via kManagedMaps[] at ${PIN_DIR}/<iface>/rules_b */

/* Outer ARRAY_OF_MAPS parallel to existing rulesets / cidr_rulesets outers. */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
    __uint(max_entries, XDPMF_RULESET_COUNT);
    __uint(key_size, sizeof(__u32));
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __array(values, struct rules_inner);
} rules_outer SEC(".maps") = {
    .values = { &rules_a, &rules_b },
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct action_entry);
    __uint(max_entries, ACTION_MAX);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} action_table SEC(".maps");

/* §5.35 rule_counters axis: ARRAY_OF_MAPS with PERCPU_ARRAY inners, committed
 * with the other axes by the active_idx u32 store. PI-3.4b-2 counter-
 * monotonicity-across-apply is PRESERVED by a per-CPU copy-forward from the
 * old-active inner to the INACTIVE inner BEFORE the active_idx flip (D-3.4d-3 in
 * loader.cpp apply_request; guard #15). rule_counters_a/_b pinned manually via
 * kManagedMaps[] (LIBBPF_PIN_BY_NAME forbidden on AOM-inner templates). */
struct rule_counters_inner {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, XDPMF_RULE_COUNTERS_MAX);
};

struct rule_counters_inner rule_counters_a SEC(".maps");   /* pinned via kManagedMaps[] at ${PIN_DIR}/<iface>/rule_counters_a */
struct rule_counters_inner rule_counters_b SEC(".maps");   /* pinned via kManagedMaps[] at ${PIN_DIR}/<iface>/rule_counters_b */

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
    __uint(max_entries, XDPMF_RULESET_COUNT);
    __uint(key_size, sizeof(__u32));
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __array(values, struct rule_counters_inner);
} rule_counters_outer SEC(".maps") = {
    .values = { &rule_counters_a, &rule_counters_b },
};
