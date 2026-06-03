/*
 * mac_filter.bpf.c — XDP classifier: 9-axis bit-vector AND match.
 *
 * Per frame, AND-compose up to 9 axes (dst/src CIDR v4+v6, proto, dst_port,
 * vlan, mac, ethertype) into `acc`; the matched rule = __builtin_ffsll(acc)-1
 * (lowest internal slot wins). Three family arms (IPv4 / IPv6 / non-IP); the
 * IPv6 arm walks extension headers to the true L4 (§5.55). Each axis term is
 * (per-axis lpm/hash lookup) | wildcard[active*BITVEC_NUM_AXES + axis].
 * Verdicts surface via the `stats` PERCPU_ARRAY (STAT_PASS / DROP_DENY /
 * DROP_MALFORMED / PASS_CIDR).
 *
 * Atomic apply (§5.26): every axis is an ARRAY_OF_MAPS[2] indexed by a shared
 * active_idx[0]; one userspace u32 store flips all axes at once (the inner-map
 * TYPE is shared via named structs so &inner_a/&inner_b match the outer
 * __array pointer-type contract). Internal slot is decoupled from the operator
 * rule id (§5.61).
 *
 * Lineage (full history in design.md / CHANGELOG, not restated here): MAC-only
 * (§5.26) → +src-CIDR OR (§5.27) → OR→AND 2-axis pivot (§5.43) → +proto/port
 * (§5.44) → vlan (§5.45) → mac axis (§5.47) → cidr6 (§5.53) → ethertype (§5.54)
 * → IPv6 ext-walk (§5.55) → slot/id decouple (§5.61).
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>     /* §5.27: bpf_htons for ETH_P_IP compare */
#include "common/mac_filter.h"

/* §5.30 HK-5 (MVP-3.4.5): leaf-null-check / bounds-check branch hint. All
 * six call sites below mark verifier-MANDATED checks that are expected NOT
 * to fire under normal operation (userspace populates both ruleset slots
 * before first attach; valid Ethernet/IPv4 frames have well-formed bounds).
 * The hint affects JIT code layout (fall-through preferred for the common
 * non-error path); functional verdict is byte-equivalent (PI-28). */
#ifndef unlikely
#define unlikely(x) __builtin_expect(!!(x), 0)
#endif

/* Protocol / EtherType constants defined inline: vmlinux.h is BTF-derived
 * (types only, no CPP macros) and linux/if_ether.h + linux/in.h are unavailable
 * in the BPF-target build. All values are byte-equivalent to their IANA /
 * IEEE 802.1Q assignments. Trace: §5.27 (ETH_P_IP), §5.51/S1 (ETH_P_IPV6),
 * §5.41/MVP-4.1 (VLAN TPIDs), §5.44 (IPPROTO_TCP/UDP), §5.55/S6 (ext-hdr protos). */
#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif
#ifndef ETH_P_IPV6
#define ETH_P_IPV6 0x86DD
#endif
#ifndef ETH_P_8021Q
#define ETH_P_8021Q 0x8100
#endif
#ifndef ETH_P_8021AD
#define ETH_P_8021AD 0x88A8
#endif
/* §5.41: 802.1Q (C-TAG) + one stacked QinQ (S-TAG) ⇒ walk depth 2; the single
 * source of truth for the #pragma unroll count (HG-mvp-4.1-1). */
#define XDPMF_VLAN_MAX_DEPTH 2
#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif
#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif
/* §5.55: IPv6 ext-hdr protos for the bounded walk. HOPOPTS/ROUTING/DSTOPTS use
 * ipv6_opt_hdr (len (hdrlen+1)*8); FRAGMENT = frag_hdr (fixed 8B); NONE terminal. */
#ifndef IPPROTO_HOPOPTS
#define IPPROTO_HOPOPTS 0
#endif
#ifndef IPPROTO_ROUTING
#define IPPROTO_ROUTING 43
#endif
#ifndef IPPROTO_FRAGMENT
#define IPPROTO_FRAGMENT 44
#endif
#ifndef IPPROTO_NONE
#define IPPROTO_NONE 59
#endif
#ifndef IPPROTO_DSTOPTS
#define IPPROTO_DSTOPTS 60
#endif

/* §5.55 (MVP-4.15 / S6) D-mvp-4.15-MAXHOPS: ext-header walk hop cap. Single
 * source of truth for the #pragma unroll count. Spike-validated at 8 (rc=0,
 * 26548/1M insns, stack 280/512, max_states 12 on the 6.1 host); 8 covers all
 * realistic chains with huge verifier headroom. A chain exceeding the cap
 * fail-safes to a non-L4 residual proto ⇒ has_port=0 (D-mvp-4.15-Q2-CAP). */
#define MAX_EXT_HOPS 8

/* Named inner-map type. Used by both concrete inner instances and the
 * outer MAP_OF_MAPS template (so &instance pointer types match exactly). */
struct xdpmf_allowlist_inner {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct xdpmf_mac);
    /* §5.47 (MVP-4.7) D-mvp-4.7-Q1: MAC un-frozen as the 6th exact-match axis;
     * inner-value reshaped `struct allow_entry` (8B) → `__u64` (8B) — a per-MAC
     * rule-bitmask (bit k set iff rule k constrains this exact src-MAC). EXACT
     * match, NO prefix-closure (unlike the LPM cidr axes). Byte-size-neutral
     * reshape; topology + pin names (allowlist_a/_b, rulesets) UNCHANGED
     * (guard #16) — the byte-for-byte mirror of §5.43's cidr_allowlist reshape. */
    __type(value, __u64);
    __uint(max_entries, XDPMF_ALLOWLIST_MAX);
};

/* Concrete inner instances; pinned at apply time under PIN_DIR. */
struct xdpmf_allowlist_inner allowlist_a SEC(".maps");
struct xdpmf_allowlist_inner allowlist_b SEC(".maps");

/* §5.58 (MVP-4.18): the vestigial MVP-2 `allowlist` ABI alias map was retired
 * here — no in/out-of-tree consumer; superseded by allowlist_a/_b (HG-mvp-4.18-1). */

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
    /* §5.43 (MVP-4.3) D-mvp-4.3-Q1: src-CIDR axis VALUE reshaped from
     * `struct allow_entry` (8B) → `__u64` (8B) — a prefix-closed per-rule
     * bitmask (bit k set iff rule k constrains a prefix COVERING this entry).
     * Topology + pin names (cidr_allowlist_a/_b, cidr_rulesets) UNCHANGED
     * (guard #16). The datapath ORs this mask into the src axis survivors. */
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
 * §5.43 (MVP-4.3) D-mvp-4.3-Q1: NEW dst-CIDR axis — an ARRAY_OF_MAPS[2] LPM
 * trio mirroring the src-CIDR (§5.27) topology exactly. Inner LPM_TRIE
 * templates dst_bitmask_a/_b hold `__u64` prefix-closed bitmasks keyed by
 * the /32-padded destination address; the outer dst_rulesets selects the
 * active inner via the SAME shared active_idx. A single userspace u32 store
 * at active_idx[0] commits the swap for dst + src + wildcard + defaults +
 * rules + rule_counters together (D-mvp-4.3-Q2 / §5.27 Q1 AS1 extended).
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
 * §5.43 (MVP-4.3) D-mvp-4.3-Q2: single combined `wildcard` ARRAY of __u64,
 * max_entries = XDPMF_RULESET_COUNT * BITVEC_NUM_AXES (= 4), indexed
 * wildcard[active * BITVEC_NUM_AXES + axis] (axis 0 = dst, 1 = src). A rule
 * that does NOT constrain an axis has its bit set here (and is ABSENT from
 * the axis LPM map); the datapath ORs the wildcard half into that axis's
 * survivors. This is the realizable analog of the `defaults` precedent — a
 * runtime active_idx cannot select between two top-level map symbols, only
 * between slots of ONE indexed ARRAY (see design Anti-misdiagnosis note).
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, XDPMF_RULESET_COUNT * BITVEC_NUM_AXES);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} wildcard SEC(".maps");

/*
 * §5.53 (MVP-4.13) D-mvp-4.13-Q1: NEW IPv6 dst/src-CIDR axes — two fresh
 * ARRAY_OF_MAPS[2] LPM trios (dst6 + src6) FORKED from the §5.43 v4 dst trio.
 * Inner LPM_TRIE templates keyed by `struct xdpmf_cidr_v6` (prefixlen-first,
 * addr6[16] in network byte order) hold `__u64` prefix-closed bitmasks
 * (close_prefixes6). The outers select the active inner via the SAME shared
 * active_idx; a single u32 store commits dst6/src6 with the other axes' swap.
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
 * §5.44 (MVP-4.4) D-mvp-4.4-Q1: NEW proto axis — an ARRAY_OF_MAPS[2] of HASH
 * inners (proto_bitmask_a/_b + proto_rulesets) mirroring the §5.27 allowlist/
 * rulesets HASH-AOM topology (only key/value types differ: __u32 IP-protocol
 * → __u64 rule-bitmask). Exact-match keyed lookup, NO prefix-closure. A rule
 * constraining `protocol=p` ORs its bit into proto_bitmask[active][p]; the
 * outer selects the active inner via the SHARED active_idx. The datapath ORs
 * the looked-up mask into the proto-axis survivors before the cross-axis AND.
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
 * §5.44 (MVP-4.4) D-mvp-4.4-Q2: NEW dst_port axis — an ARRAY_OF_MAPS[2] of
 * ARRAY inners (port_ranges_a/_b + port_rulesets) holding `struct
 * xdpmf_port_range{lo,hi,bit}` slots (production analog of the §5.42 spike's
 * `bv_port_range`). The datapath does a bounded `#pragma unroll` scan
 * (port_scan) over XDPMF_ALLOWLIST_MAX slots, OR-ing `bit` of every USED slot
 * (lo<=hi) whose inclusive [lo,hi] contains the dport. NO prefix-closure
 * (explicit ranges, not LPM prefixes). Single shared active_idx commits the
 * swap with the dst/src/proto/defaults/rules/rule_counters swap.
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
 * §5.45 (MVP-4.5) D-mvp-4.5-Q1: NEW vlan axis — an ARRAY_OF_MAPS[2] of HASH
 * inners (vlan_bitmask_a/_b + vlan_rulesets) byte-mirroring the §5.44 proto
 * axis (only key semantics differ: __u32 outer VID [0,4095] → __u64
 * rule-bitmask). Exact-match keyed lookup, NO prefix-closure. A rule
 * constraining `vlan=v` ORs its bit into vlan_bitmask[active][v]; the outer
 * selects the active inner via the SHARED active_idx. The datapath ORs the
 * looked-up mask into the vlan-axis survivors before the cross-axis AND, but
 * ONLY when has_vlan (the frame carried an outer tag).
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
 * §5.54 (MVP-4.14) D-mvp-4.14-Q1: NEW ethertype axis — an ARRAY_OF_MAPS[2] of
 * HASH inners (ethertype_bitmask_a/_b + ethertype_rulesets) CLONING the §5.44
 * proto axis (only the keyed source differs: the post-VLAN inner ethertype,
 * host order). Exact-match keyed lookup, NO prefix-closure. A rule constraining
 * `ethertype=e` ORs its bit into ethertype_bitmask[active][e]; the outer selects
 * the active inner via the SHARED active_idx. The lookup is HOISTED once above
 * the family dispatch (EtherType is the family selector) and the axis term
 * `& (eth_mask|wc_eth)` is composed into all THREE arms (v4, v6, non-IP else).
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
 * §5.61 (MVP-4.21) B30 D-mvp-4.21-Q1: slot_rule_id — USERSPACE-ONLY map.
 * Persists, per ruleset half, the operator `id` occupying each internal
 * `slot` (= id-sorted rank): slot_rule_id[active*XDPMF_ALLOWLIST_MAX + slot].
 * The loader writes it (copy-forward old-slot recovery + exporter stable-id
 * labelling); mac_filter_prog NEVER references it, so the per-packet
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
 * §5.34 (MVP-3.4b cycle 2) HG-3.4b-c2-1: `rules` map promoted to parallel
 * ARRAY_OF_MAPS — BYTE-FOR-BYTE MIRROR of §5.27 CIDR axis shape (template +
 * 2 pinned inner ARRAYs + outer). Single `active_idx` u32 store atomically
 * commits MAC HASH inner + CIDR LPM_TRIE inner + defaults + rules inner —
 * all four axes share the same active_idx (§5.27 Q1 AS1 mechanism extended
 * to 4 axes per D-3.4b-c2-8). The prior §5.29 SHARED `rules` ARRAY is
 * RETIRED; PI-29-3.4b carve-out (datapath NOT consulting rules+action_table)
 * is CLOSED — `mac_filter_prog` now reads `rules_outer[active] →
 * rules_inner[entry->rule_id] → action_table[rule.action_id]` per match per
 * HG-3.4b-c2-4 dispatch contract.
 *
 * `action_table` STAYS SHARED per HG-3.4b-c2-3 (D-3.4b-c2-6): values are
 * static `{PASS=0, DROP=1}`, never mutate at runtime; atomic-swap meaningless.
 */

/* Named inner-map template — referenced by rules_outer.__array(values, ...)
 * AND used as the C type for the two concrete inner instances rules_a /
 * rules_b. Same idiom as the existing `xdpmf_cidr_inner` / `xdpmf_allowlist_
 * inner` templates above: NO `LIBBPF_PIN_BY_NAME` in the struct — libbpf
 * rejects pinning on inner-map types of ARRAY_OF_MAPS (`inner def can't be
 * pinned`). The two instances rules_a / rules_b are pinned MANUALLY via
 * `bpf_map__pin()` in loader.cpp's `kManagedMaps[]` per-iface pin loop,
 * symmetric with allowlist_a / allowlist_b / cidr_allowlist_a / _b. */
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

/* §5.35 (MVP-3.4d) HG-3.4d-4 + D-3.4d-1: rule_counters axis promoted to
 * parallel ARRAY_OF_MAPS — DIRECT MIRROR of §5.34 rules-axis shape but with
 * PERCPU_ARRAY inners (vs ARRAY inners for rules). Template + 2 pinned
 * inner PERCPU_ARRAY instances + outer ARRAY_OF_MAPS. Single active_idx u32
 * store atomically commits MAC HASH inner + CIDR LPM_TRIE inner + defaults
 * + rules inner + rule_counters inner — all FIVE axes share the same
 * active_idx (§5.27 Q1 AS1 mechanism extended to 5 axes per D-3.4d-7).
 *
 * STRUCTURAL-ONLY this slice (HG-3.4d-5): PI-3.4b-2 counter-monotonicity-
 * across-apply PRESERVED via apply-step per-CPU copy-forward from old-active
 * inner to inactive inner BEFORE active_idx flip (D-3.4d-3 in loader.cpp's
 * apply_request). NO semantic change to operator-observed counter values.
 *
 * The two instances rule_counters_a / rule_counters_b are pinned MANUALLY
 * via bpf_map__pin() in loader.cpp's kManagedMaps[] per-iface pin loop
 * (parallel to allowlist_a/_b, cidr_allowlist_a/_b, rules_a/_b per §5.34
 * inner-as-AOM-target convention — LIBBPF_PIN_BY_NAME forbidden on
 * AOM-inner template struct definitions). */
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

/* PERCPU bump: pointer returned is to this CPU's slot only. No atomic. */
static __always_inline void bump_stat(__u32 idx)
{
    __u64 *v = bpf_map_lookup_elem(&stats, &idx);
    if (v) {
        *v += 1;
    }
}

/* §5.31 (MVP-3.4b) PI-3.4b-4: per-rule counter bump. Called from the
 * bit-vector match dispatch in each family arm (Q1=B3 unified per-match
 * semantic — call-sites share the SAME helper). NB: the `rule_id` parameter
 * is actually the internal SLOT (`first_set_u64(acc) - 1`, an id-sorted rank
 * in [0, count)), NOT the operator `id` — per §5.61 (MVP-4.21) B30 the two
 * are decoupled and the raw counter map is slot-keyed. Verifier-required
 * bounds check on that slot is folded inline; an out-of-range value is
 * silently dropped (defense-in-depth — loader-side the rule COUNT is capped
 * at XDPMF_ALLOWLIST_MAX (config.cpp rule-count cap), so every assigned slot
 * is < XDPMF_RULE_COUNTERS_MAX; the old `id < XDPMF_ALLOWLIST_MAX` id-value
 * cap was removed in B30).
 *
 * §5.35 (MVP-3.4d) D-3.4d-2: signature extends with `active` parameter so
 * the caller can pass the SAME active_idx snapshot used for MAC / CIDR /
 * rules lookups (5-axis snapshot discipline per §5.27 Q1 AS1 extended).
 * Avoids a re-read of active_idx inside the helper, which would be a race-
 * window split across map families. */
static __always_inline void bump_rule(__u32 rule_id, __u32 active)
{
    if (rule_id >= XDPMF_RULE_COUNTERS_MAX) {
        return;
    }
    if (active >= XDPMF_RULESET_COUNT) {
        return;
    }
    void *inner = bpf_map_lookup_elem(&rule_counters_outer, &active);
    if (!inner) {
        return;
    }
    __u64 *v = bpf_map_lookup_elem(inner, &rule_id);
    if (v) {
        *v += 1;
    }
}

/* §5.43 (MVP-4.3) D-mvp-4.3-FFS: 1-based index of the lowest set bit of `x`
 * (0 if x == 0). Production-owned, single-consumer (guard #9 — transcribed,
 * NOT #include'd from the tests/bitvec spike). The caller computes
 * `rid = first_set_u64(acc) - 1` only when acc != 0, so the lowest-id
 * survivor wins (HG-mvp-4.3-4 first-match-by-id, free via ffsll).
 *
 * Default lowering = __builtin_ffsll (spike §5.42 verdict ADOPT confirmed it
 * verifies on the 5.15 floor). XDPMF_FFS_FALLBACK swaps in a bounded
 * #pragma unroll bit-scan (no back-edge) for verifier floors that reject the
 * builtin — activated only if the Phase 2.5 production load fails. */
static __always_inline __u32 first_set_u64(__u64 x)
{
#ifdef XDPMF_FFS_FALLBACK
    #pragma unroll
    for (__u32 i = 0; i < 64; i++) {
        if (x & (1ULL << i)) {
            return i + 1;
        }
    }
    return 0;
#else
    return (__u32)__builtin_ffsll((long long)x);
#endif
}

/* §5.44 (MVP-4.4) D-mvp-4.4-Q2 production-owned bounded port range-scan
 * (transcribed from the §5.42 spike's `bitvec_port_scan`, guard #9 — NOT
 * #include'd from tests/bitvec). OR `bit` of every USED slot whose inclusive
 * [lo,hi] contains `dport`; `lo > hi` marks an unused slot. The
 * `#pragma unroll` over XDPMF_ALLOWLIST_MAX has no back-edge, so the 5.15
 * verifier sees straight-line code (mirrors l3_after_vlan / first_set_u64).
 * `port_inner` is the active inner ARRAY fd from port_rulesets[active].
 *
 * B18 (§5.49) early-`break` on the `lo > hi` sentinel: used slots are
 * dense-at-front (populate_port_inner_slot writes ranges[0..N-1] after
 * bulk-clearing all 64 to the lo=1,hi=0 sentinel) AND every real range has
 * lo<=hi (config.cpp parse_dst_port rejects lo>hi at exit 9; single-port ⇒
 * lo==hi). So the first `lo > hi` slot is the dense-pack boundary and every
 * slot beyond it is also a sentinel — `break` skips ONLY sentinels and is
 * bit-identical to the old full-walk `continue`. This coupling is NON-LOCAL:
 * see the matching note at populate_port_inner_slot (loader.cpp) — guard #26.
 * The `!r` null-check above STAYS a `continue`: it is verifier-mandated and a
 * transient null on slot i says nothing about slots >i (PI-mvp-4.9). */
static __always_inline __u64 port_scan(void *port_inner, __u32 dport)
{
    __u64 mask = 0;
#pragma unroll
    for (__u32 i = 0; i < XDPMF_ALLOWLIST_MAX; i++) {
        __u32 k = i;
        struct xdpmf_port_range *r = bpf_map_lookup_elem(port_inner, &k);
        if (!r) {
            continue;
        }
        if (r->lo > r->hi) {
            break;  /* B18 (§5.49): sentinel = dense-pack boundary; all slots
                     * beyond are sentinels too, so break is safe + saves
                     * ~(64-N) lookups/packet. See header comment. */
        }
        if (dport >= r->lo && dport <= r->hi) {
            mask |= r->bit;
        }
    }
    return mask;
}

/* §5.41 (MVP-4.1) Q1.A2 single-consumer helper: walk up to
 * XDPMF_VLAN_MAX_DEPTH stacked VLAN tags (802.1Q C-TAG or 802.1AD S-TAG) and
 * return the inner EtherType + the first byte past the L2/VLAN headers (the
 * candidate L3 start). The bounded #pragma unroll has no back-edge, so the
 * verifier sees a straight-line path with explicit per-tag bounds checks
 * (kernel floor 5.15 — no bpf_loop). On a frame with no VLAN tag the loop body
 * never runs: *l3hdr = eth + sizeof(ethhdr) and we return eth->h_proto —
 * byte-equivalent to the pre-§5.41 `(struct iphdr *)(eth + 1)` path. On a
 * truncated tag (no room for a full vlan_hdr) the walk STOPS with `proto`
 * still a VLAN TPID (non-IPv4), so the caller's ETH_P_IP test fails and the
 * frame falls through to defaults — NEVER reclassified MALFORMED
 * (HG-mvp-4.1-2; D-mvp-4.1-MALFORMED). The caller MUST still bounds-check
 * sizeof(struct iphdr) at *l3hdr before dereferencing (this helper validates
 * only the VLAN tags it consumed, not the L3 header). */
static __always_inline __u16 l3_after_vlan(void *eth, void *data_end, void **l3hdr,
                                           __u16 *out_vlan_id)
{
    void *cursor = eth + sizeof(struct ethhdr);
    __u16 proto  = ((struct ethhdr *)eth)->h_proto;

    /* §5.45 D-mvp-4.5-Q2: capture the OUTER (first) tag's VID during the
     * existing walk. Sentinel until a tag is consumed; an untagged or
     * truncated-outer-tag frame leaves it at XDPMF_VLAN_NONE so the datapath
     * derives has_vlan=0. VID 0 is a valid distinct key, hence a sentinel
     * outside [0,4095] rather than 0. */
    *out_vlan_id = XDPMF_VLAN_NONE;

#pragma unroll
    for (int i = 0; i < XDPMF_VLAN_MAX_DEPTH; i++) {
        if (proto != bpf_htons(ETH_P_8021Q) && proto != bpf_htons(ETH_P_8021AD)) {
            break;
        }
        if (cursor + sizeof(struct vlan_hdr) > data_end) {
            break;
        }
        struct vlan_hdr *vlan = cursor;
        /* Outer tag only (i==0): low 12 bits of the TCI are the VID; the high
         * 4 bits (PCP[3]+DEI[1]) are masked off (NOT matched — §7 OOS). Inner
         * tags (i>=1) do NOT overwrite the captured outer VID. */
        if (i == 0) {
            *out_vlan_id = bpf_ntohs(vlan->h_vlan_TCI) & 0x0FFF;
        }
        proto  = vlan->h_vlan_encapsulated_proto;
        cursor += sizeof(struct vlan_hdr);
    }

    *l3hdr = cursor;
    return proto;
}

SEC("xdp")
int mac_filter_prog(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* Bounds-check before any Ethernet-header read; truncated frames
     * (data range < 14 bytes) are counted separately per Decision §5.5. */
    if (unlikely(data + sizeof(struct ethhdr) > data_end)) {
        bump_stat(STAT_DROP_MALFORMED);
        return XDP_DROP;
    }

    struct ethhdr *eth = data;

    /* §5.26 Q2 A1: read active_idx (single u32 read, atomic) at the head of
     * the datapath. The SAME `active` snapshot indexes every per-ruleset
     * outer (dst_rulesets, cidr_rulesets, wildcard, rules_outer,
     * rule_counters_outer, defaults), so a concurrent userspace active_idx
     * flip cannot split the axes mid-packet (§5.27 Q1 AS1, extended in §5.43).
     * The NULL check is verifier-required; unreachable in practice because
     * userspace populates both slots before the first attach. */
    __u32 zero = 0;
    __u32 *active_p = bpf_map_lookup_elem(&active_idx, &zero);
    if (unlikely(!active_p)) {
        bump_stat(STAT_DROP_DENY);
        return XDP_DROP;
    }
    __u32 active = *active_p;

    /* §5.43 (MVP-4.3) OR→AND bit-vector classification. The MAC HASH maps
     * are FROZEN (declared + pinned, NOT consulted — HG-mvp-4.3-2); MAC
     * matching returns as a bit-vector axis in mvp-4.5. Classification is the
     * AND-intersection of two LPM axes (dst_cidr AND src_cidr), both read
     * from the post-VLAN IPv4 header — so only IPv4 frames are classified;
     * every other ethertype (ARP, IPv6, non-IPv4-after-VLAN, truncated-tag)
     * falls through to defaults[active] (preserves the pre-§5.43 non-IP
     * semantic per brief §1). */

    /* §5.41 (MVP-4.1): walk up to 2 VLAN tags so a tagged Gi frame reaches the
     * L3 axes. inner_proto / l3hdr come from the post-VLAN cursor; on an
     * untagged frame this is byte-equivalent to the prior `eth + 1` path. */
    void *l3hdr;
    __u16 vlan_id = XDPMF_VLAN_NONE;
    __u16 inner_proto = l3_after_vlan(eth, data_end, &l3hdr, &vlan_id);
    /* §5.45 (MVP-4.5) D-mvp-4.5-Q2: an untagged/truncated-tag frame leaves
     * vlan_id at the sentinel → has_vlan=0 → vlan axis contributes 0 (only
     * vlan-wildcard rules survive). Parallels the §5.44 has_port semantic. */
    int has_vlan = (vlan_id != XDPMF_VLAN_NONE);

    /* §5.54 (MVP-4.14) D-mvp-4.14-Q1: HOIST the ethertype axis lookup ONCE above
     * the family dispatch. EtherType IS the family selector — family-independent
     * — so a single lookup is natural and composes the `& (eth_mask|wc_eth)`
     * term into all THREE arms (v4, v6, and the NEW non-IP else arm). The key is
     * the HOST-order post-VLAN inner ethertype (D-mvp-4.14-ETHKEY); exact-HASH,
     * NO closure (guard #23 N/A). For a config with no ethertype rule every rule
     * wildcards this axis ⇒ (eth_mask|wc_eth) is an all-ones no-op ⇒ the IP-arm
     * verdicts stay bit-identical (PI-mvp-4.14-IPVERDICT). */
    void *eth_inner = bpf_map_lookup_elem(&ethertype_rulesets, &active);
    if (unlikely(!eth_inner)) {
        bump_stat(STAT_DROP_DENY);
        return XDP_DROP;
    }
    __u32 eth_key  = (__u32)bpf_ntohs(inner_proto);
    __u64 eth_mask = 0;
    __u64 *em = bpf_map_lookup_elem(eth_inner, &eth_key);
    if (em) {
        eth_mask = *em;
    }
    __u64 wc_eth = 0;
    __u32 wc_eth_key = active * BITVEC_NUM_AXES + BV_AXIS_ETHERTYPE;
    __u64 *wc_eth_p = bpf_map_lookup_elem(&wildcard, &wc_eth_key);
    if (wc_eth_p) {
        wc_eth = *wc_eth_p;
    }

    if (inner_proto == bpf_htons(ETH_P_IP)) {
        /* Verifier-required IPv4 header bounds check before daddr/saddr deref
         * — applied at the post-VLAN L3 offset (the only MALFORMED path). */
        if (unlikely(l3hdr + sizeof(struct iphdr) > data_end)) {
            bump_stat(STAT_DROP_MALFORMED);
            return XDP_DROP;
        }
        struct iphdr *ip = (struct iphdr *)l3hdr;

        /* §5.44 (MVP-4.4) D-mvp-4.4-Q3 proto axis: ip->protocol is offset-stable
         * for every IPv4 frame (no L4 parse needed). */
        __u8 proto = ip->protocol;

        /* §5.44 D-mvp-4.4-IHL L4 offset: the L4 header sits ip->ihl*4 bytes
         * past the IPv4 header start (variable for IPv4-options frames). Reject
         * ihl<5 (illegal IPv4 — header shorter than the fixed 20B) as MALFORMED
         * so ihl*4 ∈ [20,60] is bounded for the verifier. dport is read only
         * for TCP/UDP after an explicit L4-header bounds-check (has_port);
         * non-TCP/UDP frames keep has_port=0 → port_mask=0 (only port-wildcard
         * rules survive the port axis), exactly the §5.42 spike's has_port
         * logic. (FALLBACK: if the 5.15 verifier rejects the variable ihl*4
         * offset, swap to the fixed-20B `(void*)(ip+1)` per D-mvp-4.4-IHL —
         * Phase 2.5-gated, NO design change.) */
        if (unlikely(ip->ihl < 5)) {
            bump_stat(STAT_DROP_MALFORMED);
            return XDP_DROP;
        }
        void *l4 = (void *)ip + ip->ihl * 4;
        __u32 dport    = 0;
        int   has_port = 0;
        if (proto == IPPROTO_TCP) {
            struct tcphdr *t = l4;
            if (unlikely((void *)(t + 1) > data_end)) {
                bump_stat(STAT_DROP_MALFORMED);
                return XDP_DROP;
            }
            dport    = bpf_ntohs(t->dest);
            has_port = 1;
        } else if (proto == IPPROTO_UDP) {
            struct udphdr *u = l4;
            if (unlikely((void *)(u + 1) > data_end)) {
                bump_stat(STAT_DROP_MALFORMED);
                return XDP_DROP;
            }
            dport    = bpf_ntohs(u->dest);
            has_port = 1;
        }

        /* Per-axis active inners (dst + src + proto + port) via the shared
         * `active` snapshot (§5.27 Q1 AS1 extended to 4 axes). */
        void *dst_inner = bpf_map_lookup_elem(&dst_rulesets, &active);
        if (unlikely(!dst_inner)) {
            bump_stat(STAT_DROP_DENY);
            return XDP_DROP;
        }
        void *src_inner = bpf_map_lookup_elem(&cidr_rulesets, &active);
        if (unlikely(!src_inner)) {
            bump_stat(STAT_DROP_DENY);
            return XDP_DROP;
        }
        void *proto_inner = bpf_map_lookup_elem(&proto_rulesets, &active);
        if (unlikely(!proto_inner)) {
            bump_stat(STAT_DROP_DENY);
            return XDP_DROP;
        }
        void *port_inner = bpf_map_lookup_elem(&port_rulesets, &active);
        if (unlikely(!port_inner)) {
            bump_stat(STAT_DROP_DENY);
            return XDP_DROP;
        }
        void *vlan_inner = bpf_map_lookup_elem(&vlan_rulesets, &active);
        if (unlikely(!vlan_inner)) {
            bump_stat(STAT_DROP_DENY);
            return XDP_DROP;
        }
        /* §5.47 (MVP-4.7) D-mvp-4.7-Q2: MAC axis un-frozen — the same shared
         * `active` snapshot selects the active allowlist inner (HASH-AOM). */
        void *mac_inner = bpf_map_lookup_elem(&rulesets, &active);
        if (unlikely(!mac_inner)) {
            bump_stat(STAT_DROP_DENY);
            return XDP_DROP;
        }

        /* §5.43 D-mvp-4.3-Q2 wildcard halves: wildcard[active*BITVEC_NUM_AXES
         * + axis]. A rule unconstrained on an axis lives here (and is ABSENT
         * from that axis's LPM map — mutual exclusion). NULL → 0 (no wildcard
         * survivors on that axis). */
        __u64 wc_dst   = 0;
        __u64 wc_src   = 0;
        __u64 wc_proto = 0;
        __u64 wc_port  = 0;
        __u64 wc_vlan  = 0;
        __u64 wc_mac   = 0;
        __u32 wc_dst_key   = active * BITVEC_NUM_AXES + BV_AXIS_DST;
        __u32 wc_src_key   = active * BITVEC_NUM_AXES + BV_AXIS_SRC;
        __u32 wc_proto_key = active * BITVEC_NUM_AXES + BV_AXIS_PROTO;
        __u32 wc_port_key  = active * BITVEC_NUM_AXES + BV_AXIS_PORT;
        __u32 wc_vlan_key  = active * BITVEC_NUM_AXES + BV_AXIS_VLAN;
        __u32 wc_mac_key   = active * BITVEC_NUM_AXES + BV_AXIS_MAC;
        __u64 *wc_dst_p = bpf_map_lookup_elem(&wildcard, &wc_dst_key);
        if (wc_dst_p) {
            wc_dst = *wc_dst_p;
        }
        __u64 *wc_src_p = bpf_map_lookup_elem(&wildcard, &wc_src_key);
        if (wc_src_p) {
            wc_src = *wc_src_p;
        }
        __u64 *wc_proto_p = bpf_map_lookup_elem(&wildcard, &wc_proto_key);
        if (wc_proto_p) {
            wc_proto = *wc_proto_p;
        }
        __u64 *wc_port_p = bpf_map_lookup_elem(&wildcard, &wc_port_key);
        if (wc_port_p) {
            wc_port = *wc_port_p;
        }
        __u64 *wc_vlan_p = bpf_map_lookup_elem(&wildcard, &wc_vlan_key);
        if (wc_vlan_p) {
            wc_vlan = *wc_vlan_p;
        }
        __u64 *wc_mac_p = bpf_map_lookup_elem(&wildcard, &wc_mac_key);
        if (wc_mac_p) {
            wc_mac = *wc_mac_p;
        }
        /* §5.53 (MVP-4.13) C1: the v6 address axes' wildcard halves. A v4
         * frame has NO v6 address ⇒ the dst6/src6 LPM survivors are 0 ⇒ those
         * two AND-terms reduce to `& wc_dst6 & wc_src6`. A v4-only rule lives
         * in wc_dst6/wc_src6 (family-blind lowering) so these terms are
         * all-ones no-ops for v4-only configs (PI-mvp-4.13-IPV4-VERDICT); a
         * v6-only rule is ABSENT from wc_dst6/wc_src6 ⇒ excluded from v4
         * traffic (PI-mvp-4.13-CROSS-FAMILY). */
        __u64 wc_dst6 = 0;
        __u64 wc_src6 = 0;
        __u32 wc_dst6_key = active * BITVEC_NUM_AXES + BV_AXIS_DST6;
        __u32 wc_src6_key = active * BITVEC_NUM_AXES + BV_AXIS_SRC6;
        __u64 *wc_dst6_p = bpf_map_lookup_elem(&wildcard, &wc_dst6_key);
        if (wc_dst6_p) {
            wc_dst6 = *wc_dst6_p;
        }
        __u64 *wc_src6_p = bpf_map_lookup_elem(&wildcard, &wc_src6_key);
        if (wc_src6_p) {
            wc_src6 = *wc_src6_p;
        }

        /* /32 host-route LPM keys (network byte order, matches LPM_TRIE key
         * shape). LPM_TRIE returns the longest matching prefix's value — the
         * prefix-closed __u64 bitmask (FI-1 cover-closure computed loader-side
         * in close_prefixes). NULL → 0 (no LPM survivors on that axis). */
        struct xdpmf_cidr_v4 dst_key = {
            .prefixlen = 32u,
            .addr      = ip->daddr,
        };
        struct xdpmf_cidr_v4 src_key = {
            .prefixlen = 32u,
            .addr      = ip->saddr,
        };
        __u64 dmask = 0;
        __u64 smask = 0;
        __u64 *dm = bpf_map_lookup_elem(dst_inner, &dst_key);
        if (dm) {
            dmask = *dm;
        }
        __u64 *sm = bpf_map_lookup_elem(src_inner, &src_key);
        if (sm) {
            smask = *sm;
        }

        /* §5.44 proto axis: exact-HASH lookup keyed by ip->protocol (NO
         * closure). NULL → 0 (no proto survivors). port axis: bounded
         * range-scan over the active port inner ARRAY, only when the frame
         * carries an L4 port (TCP/UDP); non-port frames contribute 0 so only
         * port-wildcard rules survive the port axis. */
        __u32 proto_key = proto;
        __u64 proto_mask = 0;
        __u64 *pm = bpf_map_lookup_elem(proto_inner, &proto_key);
        if (pm) {
            proto_mask = *pm;
        }
        __u64 port_mask = has_port ? port_scan(port_inner, dport) : 0;

        /* §5.45 vlan axis: exact-HASH lookup keyed by the captured outer VID
         * (NO closure), ONLY when the frame carried a tag (has_vlan). An
         * untagged frame contributes 0 so only vlan-wildcard rules survive the
         * vlan axis (HG-mvp-4.5-4; parallels the proto/port has_port logic). */
        __u32 vlan_key = (__u32)vlan_id;
        __u64 vlan_mask = 0;
        if (has_vlan) {
            __u64 *vm = bpf_map_lookup_elem(vlan_inner, &vlan_key);
            if (vm) {
                vlan_mask = *vm;
            }
        }

        /* §5.47 (MVP-4.7) D-mvp-4.7-Q2 MAC axis: exact-HASH lookup keyed by the
         * SOURCE MAC (eth->h_source — the v1 semantic, §5.26; NO closure). The
         * src MAC sits at the base-eth fixed offset (read before the VLAN walk,
         * already bounds-checked above), so it is VLAN-agnostic. Every frame
         * carries a src MAC → no "absent" sentinel (unlike vlan); a rule that
         * omits `mac` survives via wc_mac. */
        struct xdpmf_mac mac_key = {0};
        __builtin_memcpy(mac_key.octets, eth->h_source, 6);
        __u64 mac_mask = 0;
        __u64 *mm = bpf_map_lookup_elem(mac_inner, &mac_key);
        if (mm) {
            mac_mask = *mm;
        }

        /* The OR→AND pivot (PI-mvp-4.3-AND / …4 / …5 / PI-mvp-4.7-MAC): per
         * axis, OR the axis survivors with the axis wildcard half, then
         * INTERSECT across all six axes. A rule survives iff EVERY axis it
         * constrains matches; unconstrained axes contribute the always-true
         * wildcard half. */
        __u64 acc = (dmask      | wc_dst)   &
                    (smask      | wc_src)   &
                    (proto_mask | wc_proto) &
                    (port_mask  | wc_port)  &
                    (vlan_mask  | wc_vlan)  &
                    (mac_mask   | wc_mac)   &
                    wc_dst6                 &
                    wc_src6                 &
                    (eth_mask   | wc_eth);  /* §5.54 hoisted ethertype axis */
        if (acc != 0) {
            /* HG-mvp-4.3-4 first-match-by-id: the lowest set bit IS the lowest
             * matching rule id (bit position == id), so ffsll picks it for
             * free with NO sort. bump_rule first (per-match counter, HG-5),
             * then the reused rules_outer → rules_inner → action_table
             * dispatch (DROP → STAT_DROP_DENY + XDP_DROP; PASS or any
             * NULL-fallthrough → STAT_PASS_CIDR + XDP_PASS, D-mvp-4.3-STAT). */
            __u32 rid = first_set_u64(acc) - 1;
            bump_rule(rid, active);
            void *rules_inner_map = bpf_map_lookup_elem(&rules_outer, &active);
            if (rules_inner_map) {
                struct rule_entry *r = bpf_map_lookup_elem(rules_inner_map, &rid);
                if (r && r->present) {
                    __u32 aid = r->action_id;
                    struct action_entry *a = bpf_map_lookup_elem(&action_table, &aid);
                    if (a && a->action_type == ACTION_DROP) {
                        bump_stat(STAT_DROP_DENY);
                        return XDP_DROP;
                    }
                }
            }
            bump_stat(STAT_PASS_CIDR);
            return XDP_PASS;
        }
        /* acc == 0 → no rule matched; fall through to defaults[active]. */
    } else if (inner_proto == bpf_htons(ETH_P_IPV6)) {
        /* §5.53 (MVP-4.13 / S4) D-mvp-4.13-Q2: the IPv6 classification arm.
         * Symmetric 8-term AND mirroring the v4 arm; the v4 address axes
         * contribute wildcard-only halves (no v4 address in a v6 frame), and
         * dst6/src6 carry the IPv6 LPM survivors. §5.55 (MVP-4.15 / S6)
         * D-mvp-4.15-Q1-WALK: proto/port now read the TRUE upper-layer L4 via a
         * bounded ext-header chain walk (PI-mvp-4.15-EXT-WALK; the S4
         * base-header-only boundary PI-mvp-4.13-BASE-HEADER is RETIRED). */

        /* Verifier-required IPv6 base-header bounds check before nexthdr/addr
         * deref — the ONLY MALFORMED path for a 0x86DD frame
         * (D-mvp-4.13-NO-MALFORMED-NONV6). */
        if (unlikely(l3hdr + sizeof(struct ipv6hdr) > data_end)) {
            bump_stat(STAT_DROP_MALFORMED);
            return XDP_DROP;
        }
        struct ipv6hdr *ip6 = (struct ipv6hdr *)l3hdr;

        /* §5.55 (MVP-4.15 / S6) bounded ext-header walk (D-mvp-4.15-Q1-WALK,
         * A1 fixed-MAX_EXT_HOPS #pragma unroll — the verifier-safe no-back-edge
         * pattern proven by port_scan / the VLAN tag-walk). Start at the base
         * nexthdr / 40B offset (== today's base-only values), then advance the
         * cursor over {HOPOPTS,ROUTING,DSTOPTS} by (hdrlen+1)*8 and over
         * FRAGMENT by a fixed 8B, bounds-checking each hop. The loop breaks at a
         * recognized L4 / unrecognized nexthdr / NONE (terminal), leaving proto
         * = true upper-layer protocol and cursor = the L4 (or terminal) header.
         * A non-ext frame breaks at hop 0 ⇒ proto/cursor == the old base-offset
         * values (PI-mvp-4.15-NONEXT-V6 no-op). A chain exceeding MAX_EXT_HOPS
         * leaves proto an ext-header number (≠ TCP/UDP) ⇒ has_port=0 fail-safe
         * (D-mvp-4.15-Q2-CAP — no explicit post-loop check needed). */
        __u8 proto    = ip6->nexthdr;
        void *cursor  = (void *)(ip6 + 1);
#pragma unroll
        for (__u32 i = 0; i < MAX_EXT_HOPS; i++) {
            if (proto == IPPROTO_HOPOPTS || proto == IPPROTO_ROUTING ||
                proto == IPPROTO_DSTOPTS) {
                /* Mid-walk bounds miss ⇒ genuinely malformed chain
                 * (D-mvp-4.15-Q2-MALFORMED). */
                if (unlikely(cursor + sizeof(struct ipv6_opt_hdr) > data_end)) {
                    bump_stat(STAT_DROP_MALFORMED);
                    return XDP_DROP;
                }
                struct ipv6_opt_hdr *opt = cursor;
                proto  = opt->nexthdr;
                cursor += ((__u32)opt->hdrlen + 1) * 8;
            } else if (proto == IPPROTO_FRAGMENT) {
                if (unlikely(cursor + sizeof(struct frag_hdr) > data_end)) {
                    bump_stat(STAT_DROP_MALFORMED);
                    return XDP_DROP;
                }
                /* frag_off NOT consulted — first-fragment L4 only; deep
                 * reassembly OUT OF SCOPE (D-mvp-4.15-FRAG). */
                struct frag_hdr *frag = cursor;
                proto  = frag->nexthdr;
                cursor += 8;
            } else {
                /* Terminal: a recognized L4 (TCP/UDP), NONE, ICMPv6, or any
                 * unrecognized nexthdr (D-mvp-4.15-Q2-UNRECOGNIZED). */
                break;
            }
        }

        /* L4 (or terminal header) sits at the walked offset. dport read only
         * for TCP/UDP after an explicit L4-header bounds-check (has_port); other
         * frames — incl. a residual ext-header proto if the chain exceeded
         * MAX_EXT_HOPS, NONE, ICMPv6, unrecognized — keep has_port=0 ⇒
         * port_mask=0 (only port-wildcard rules survive), mirroring the v4
         * arm's has_port logic. */
        void *l4 = cursor;
        __u32 dport    = 0;
        int   has_port = 0;
        if (proto == IPPROTO_TCP) {
            struct tcphdr *t = l4;
            if (unlikely((void *)(t + 1) > data_end)) {
                bump_stat(STAT_DROP_MALFORMED);
                return XDP_DROP;
            }
            dport    = bpf_ntohs(t->dest);
            has_port = 1;
        } else if (proto == IPPROTO_UDP) {
            struct udphdr *u = l4;
            if (unlikely((void *)(u + 1) > data_end)) {
                bump_stat(STAT_DROP_MALFORMED);
                return XDP_DROP;
            }
            dport    = bpf_ntohs(u->dest);
            has_port = 1;
        }

        /* Per-axis active inners via the shared `active` snapshot. */
        void *dst6_inner = bpf_map_lookup_elem(&dst6_rulesets, &active);
        if (unlikely(!dst6_inner)) {
            bump_stat(STAT_DROP_DENY);
            return XDP_DROP;
        }
        void *src6_inner = bpf_map_lookup_elem(&src6_rulesets, &active);
        if (unlikely(!src6_inner)) {
            bump_stat(STAT_DROP_DENY);
            return XDP_DROP;
        }
        void *proto_inner = bpf_map_lookup_elem(&proto_rulesets, &active);
        if (unlikely(!proto_inner)) {
            bump_stat(STAT_DROP_DENY);
            return XDP_DROP;
        }
        void *port_inner = bpf_map_lookup_elem(&port_rulesets, &active);
        if (unlikely(!port_inner)) {
            bump_stat(STAT_DROP_DENY);
            return XDP_DROP;
        }
        void *vlan_inner = bpf_map_lookup_elem(&vlan_rulesets, &active);
        if (unlikely(!vlan_inner)) {
            bump_stat(STAT_DROP_DENY);
            return XDP_DROP;
        }
        void *mac_inner = bpf_map_lookup_elem(&rulesets, &active);
        if (unlikely(!mac_inner)) {
            bump_stat(STAT_DROP_DENY);
            return XDP_DROP;
        }

        /* All 8 wildcard halves. The v4 address axes (dst/src) contribute
         * wildcard-only here: a v6 frame has NO v4 address ⇒ dst/src LPM
         * survivors are 0 ⇒ `& (0|wc_dst) & (0|wc_src)` = `& wc_dst & wc_src`.
         * A v4-only rule is ABSENT from wc_dst/wc_src ⇒ excluded from v6
         * traffic (PI-mvp-4.13-CROSS-FAMILY). */
        __u64 wc_dst   = 0;
        __u64 wc_src   = 0;
        __u64 wc_proto = 0;
        __u64 wc_port  = 0;
        __u64 wc_vlan  = 0;
        __u64 wc_mac   = 0;
        __u64 wc_dst6  = 0;
        __u64 wc_src6  = 0;
        __u32 wc_dst_key   = active * BITVEC_NUM_AXES + BV_AXIS_DST;
        __u32 wc_src_key   = active * BITVEC_NUM_AXES + BV_AXIS_SRC;
        __u32 wc_proto_key = active * BITVEC_NUM_AXES + BV_AXIS_PROTO;
        __u32 wc_port_key  = active * BITVEC_NUM_AXES + BV_AXIS_PORT;
        __u32 wc_vlan_key  = active * BITVEC_NUM_AXES + BV_AXIS_VLAN;
        __u32 wc_mac_key   = active * BITVEC_NUM_AXES + BV_AXIS_MAC;
        __u32 wc_dst6_key  = active * BITVEC_NUM_AXES + BV_AXIS_DST6;
        __u32 wc_src6_key  = active * BITVEC_NUM_AXES + BV_AXIS_SRC6;
        __u64 *wc_dst_p = bpf_map_lookup_elem(&wildcard, &wc_dst_key);
        if (wc_dst_p) {
            wc_dst = *wc_dst_p;
        }
        __u64 *wc_src_p = bpf_map_lookup_elem(&wildcard, &wc_src_key);
        if (wc_src_p) {
            wc_src = *wc_src_p;
        }
        __u64 *wc_proto_p = bpf_map_lookup_elem(&wildcard, &wc_proto_key);
        if (wc_proto_p) {
            wc_proto = *wc_proto_p;
        }
        __u64 *wc_port_p = bpf_map_lookup_elem(&wildcard, &wc_port_key);
        if (wc_port_p) {
            wc_port = *wc_port_p;
        }
        __u64 *wc_vlan_p = bpf_map_lookup_elem(&wildcard, &wc_vlan_key);
        if (wc_vlan_p) {
            wc_vlan = *wc_vlan_p;
        }
        __u64 *wc_mac_p = bpf_map_lookup_elem(&wildcard, &wc_mac_key);
        if (wc_mac_p) {
            wc_mac = *wc_mac_p;
        }
        __u64 *wc_dst6_p = bpf_map_lookup_elem(&wildcard, &wc_dst6_key);
        if (wc_dst6_p) {
            wc_dst6 = *wc_dst6_p;
        }
        __u64 *wc_src6_p = bpf_map_lookup_elem(&wildcard, &wc_src6_key);
        if (wc_src6_p) {
            wc_src6 = *wc_src6_p;
        }

        /* /128 host-route v6 LPM keys: addr6 is network byte order
         * (addr6[0]=MSB), memcpy'd straight from ip6->daddr/saddr (no swap —
         * PI-mvp-4.13-V6KEY). LPM_TRIE returns the longest matching prefix's
         * prefix-closed __u64 bitmask (close_prefixes6). NULL → 0. */
        struct xdpmf_cidr_v6 dst6_key = { .prefixlen = 128u };
        struct xdpmf_cidr_v6 src6_key = { .prefixlen = 128u };
        __builtin_memcpy(dst6_key.addr6, &ip6->daddr, 16);
        __builtin_memcpy(src6_key.addr6, &ip6->saddr, 16);
        __u64 dmask6 = 0;
        __u64 smask6 = 0;
        __u64 *dm6 = bpf_map_lookup_elem(dst6_inner, &dst6_key);
        if (dm6) {
            dmask6 = *dm6;
        }
        __u64 *sm6 = bpf_map_lookup_elem(src6_inner, &src6_key);
        if (sm6) {
            smask6 = *sm6;
        }

        /* proto exact-HASH (NO closure); port bounded range-scan only for
         * TCP/UDP; vlan exact-HASH only when the frame carried a tag. */
        __u32 proto_key = proto;
        __u64 proto_mask = 0;
        __u64 *pm = bpf_map_lookup_elem(proto_inner, &proto_key);
        if (pm) {
            proto_mask = *pm;
        }
        __u64 port_mask = has_port ? port_scan(port_inner, dport) : 0;
        __u32 vlan_key = (__u32)vlan_id;
        __u64 vlan_mask = 0;
        if (has_vlan) {
            __u64 *vm = bpf_map_lookup_elem(vlan_inner, &vlan_key);
            if (vm) {
                vlan_mask = *vm;
            }
        }

        /* src-MAC exact-HASH (eth->h_source, VLAN-agnostic base offset). */
        struct xdpmf_mac mac_key = {0};
        __builtin_memcpy(mac_key.octets, eth->h_source, 6);
        __u64 mac_mask = 0;
        __u64 *mm = bpf_map_lookup_elem(mac_inner, &mac_key);
        if (mm) {
            mac_mask = *mm;
        }

        /* Symmetric 9-term AND (Q2 + §5.54): v4 address axes are wildcard-only
         * here; the hoisted ethertype axis composes uniformly (eth_mask carries
         * the bit for an `ethertype: ipv6` rule on a 0x86DD frame). */
        __u64 acc = wc_dst                  &
                    wc_src                  &
                    (proto_mask | wc_proto) &
                    (port_mask  | wc_port)  &
                    (vlan_mask  | wc_vlan)  &
                    (mac_mask   | wc_mac)   &
                    (dmask6     | wc_dst6)  &
                    (smask6     | wc_src6)  &
                    (eth_mask   | wc_eth);  /* §5.54 hoisted ethertype axis */
        if (acc != 0) {
            /* first-match-by-id + the reused rules_outer → rules_inner →
             * action_table dispatch (identical to the v4 arm). */
            __u32 rid = first_set_u64(acc) - 1;
            bump_rule(rid, active);
            void *rules_inner_map = bpf_map_lookup_elem(&rules_outer, &active);
            if (rules_inner_map) {
                struct rule_entry *r = bpf_map_lookup_elem(rules_inner_map, &rid);
                if (r && r->present) {
                    __u32 aid = r->action_id;
                    struct action_entry *a = bpf_map_lookup_elem(&action_table, &aid);
                    if (a && a->action_type == ACTION_DROP) {
                        bump_stat(STAT_DROP_DENY);
                        return XDP_DROP;
                    }
                }
            }
            bump_stat(STAT_PASS_CIDR);
            return XDP_PASS;
        }
        /* acc == 0 → no rule matched; fall through to defaults[active]. */
    } else {
        /* §5.54 (MVP-4.14) D-mvp-4.14-Q1 / D-mvp-4.14-NONIP-ARM: the NEW non-IP
         * classification arm. A non-IP frame (ARP 0x0806, LLDP 0x88B5, …) has NO
         * L3/L4, so the IP-family axes (dst/src/proto/port/dst6/src6) contribute
         * WILDCARD-ONLY halves; the family-agnostic axes (mac via eth->h_source,
         * vlan via the captured outer VID, ethertype via the hoisted eth_mask)
         * carry real survivors. This is the FULL SYMMETRIC 9-term AND — an
         * "ethertype-only" path would silently never-match `ethertype: X` + `mac:`
         * / `vlan:` rules (zeroed by & wc_mac / & wc_vlan). NO MALFORMED path
         * (D-mvp-4.14-NONIP-NO-MALFORMED): a non-IP frame carries no L3/L4 to
         * bounds-check; runts are caught upstream by the base-eth check at the
         * datapath head. Family-agnostic mac/vlan now fire on non-IP frames —
         * SUPERSEDING the old mac-IPv4-gated boundary (D-mvp-4.14-MAC-NONIP-SUPERSEDE). */
        void *vlan_inner = bpf_map_lookup_elem(&vlan_rulesets, &active);
        if (unlikely(!vlan_inner)) {
            bump_stat(STAT_DROP_DENY);
            return XDP_DROP;
        }
        void *mac_inner = bpf_map_lookup_elem(&rulesets, &active);
        if (unlikely(!mac_inner)) {
            bump_stat(STAT_DROP_DENY);
            return XDP_DROP;
        }

        /* All wildcard halves. The IP-family axes (dst/src/proto/port/dst6/src6)
         * have NO real survivors on a non-IP frame ⇒ each reduces to its
         * wildcard half. A rule constraining an IP-family axis is ABSENT from
         * that axis's wildcard ⇒ excluded from non-IP traffic. */
        __u64 wc_dst   = 0;
        __u64 wc_src   = 0;
        __u64 wc_proto = 0;
        __u64 wc_port  = 0;
        __u64 wc_vlan  = 0;
        __u64 wc_mac   = 0;
        __u64 wc_dst6  = 0;
        __u64 wc_src6  = 0;
        __u32 wc_dst_key   = active * BITVEC_NUM_AXES + BV_AXIS_DST;
        __u32 wc_src_key   = active * BITVEC_NUM_AXES + BV_AXIS_SRC;
        __u32 wc_proto_key = active * BITVEC_NUM_AXES + BV_AXIS_PROTO;
        __u32 wc_port_key  = active * BITVEC_NUM_AXES + BV_AXIS_PORT;
        __u32 wc_vlan_key  = active * BITVEC_NUM_AXES + BV_AXIS_VLAN;
        __u32 wc_mac_key   = active * BITVEC_NUM_AXES + BV_AXIS_MAC;
        __u32 wc_dst6_key  = active * BITVEC_NUM_AXES + BV_AXIS_DST6;
        __u32 wc_src6_key  = active * BITVEC_NUM_AXES + BV_AXIS_SRC6;
        __u64 *wc_dst_p = bpf_map_lookup_elem(&wildcard, &wc_dst_key);
        if (wc_dst_p) {
            wc_dst = *wc_dst_p;
        }
        __u64 *wc_src_p = bpf_map_lookup_elem(&wildcard, &wc_src_key);
        if (wc_src_p) {
            wc_src = *wc_src_p;
        }
        __u64 *wc_proto_p = bpf_map_lookup_elem(&wildcard, &wc_proto_key);
        if (wc_proto_p) {
            wc_proto = *wc_proto_p;
        }
        __u64 *wc_port_p = bpf_map_lookup_elem(&wildcard, &wc_port_key);
        if (wc_port_p) {
            wc_port = *wc_port_p;
        }
        __u64 *wc_vlan_p = bpf_map_lookup_elem(&wildcard, &wc_vlan_key);
        if (wc_vlan_p) {
            wc_vlan = *wc_vlan_p;
        }
        __u64 *wc_mac_p = bpf_map_lookup_elem(&wildcard, &wc_mac_key);
        if (wc_mac_p) {
            wc_mac = *wc_mac_p;
        }
        __u64 *wc_dst6_p = bpf_map_lookup_elem(&wildcard, &wc_dst6_key);
        if (wc_dst6_p) {
            wc_dst6 = *wc_dst6_p;
        }
        __u64 *wc_src6_p = bpf_map_lookup_elem(&wildcard, &wc_src6_key);
        if (wc_src6_p) {
            wc_src6 = *wc_src6_p;
        }

        /* vlan exact-HASH only when the frame carried an outer tag (parallels
         * the IP arms); src-MAC exact-HASH (eth->h_source, VLAN-agnostic base
         * offset, already bounds-checked at the datapath head). */
        __u32 vlan_key = (__u32)vlan_id;
        __u64 vlan_mask = 0;
        if (has_vlan) {
            __u64 *vm = bpf_map_lookup_elem(vlan_inner, &vlan_key);
            if (vm) {
                vlan_mask = *vm;
            }
        }
        struct xdpmf_mac mac_key = {0};
        __builtin_memcpy(mac_key.octets, eth->h_source, 6);
        __u64 mac_mask = 0;
        __u64 *mm = bpf_map_lookup_elem(mac_inner, &mac_key);
        if (mm) {
            mac_mask = *mm;
        }

        /* Full symmetric 9-term AND: IP-family axes wildcard-only; mac/vlan/
         * ethertype carry real survivors. */
        __u64 acc = wc_dst                  &
                    wc_src                  &
                    wc_proto                &
                    wc_port                 &
                    (vlan_mask  | wc_vlan)  &
                    (mac_mask   | wc_mac)   &
                    wc_dst6                 &
                    wc_src6                 &
                    (eth_mask   | wc_eth);
        if (acc != 0) {
            /* first-match-by-id + the reused rules_outer → rules_inner →
             * action_table dispatch (identical to the IP arms). */
            __u32 rid = first_set_u64(acc) - 1;
            bump_rule(rid, active);
            void *rules_inner_map = bpf_map_lookup_elem(&rules_outer, &active);
            if (rules_inner_map) {
                struct rule_entry *r = bpf_map_lookup_elem(rules_inner_map, &rid);
                if (r && r->present) {
                    __u32 aid = r->action_id;
                    struct action_entry *a = bpf_map_lookup_elem(&action_table, &aid);
                    if (a && a->action_type == ACTION_DROP) {
                        bump_stat(STAT_DROP_DENY);
                        return XDP_DROP;
                    }
                }
            }
            bump_stat(STAT_PASS_CIDR);
            return XDP_PASS;
        }
        /* acc == 0 → no rule matched; fall through to defaults[active]. */
    }

    /* No match (non-IP with acc==0, or IPv4/IPv6 with acc==0) — consult
     * defaults[active]. The same active_idx value indexes every outer; one u32
     * flip swaps all. */
    __u32 *default_p = bpf_map_lookup_elem(&defaults, &active);
    if (unlikely(!default_p)) {
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
