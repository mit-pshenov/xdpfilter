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

/* §5.30 HK-5 (MVP-3.4.5): leaf-null-check / bounds-check branch hint. All
 * six call sites below mark verifier-MANDATED checks that are expected NOT
 * to fire under normal operation (userspace populates both ruleset slots
 * before first attach; valid Ethernet/IPv4 frames have well-formed bounds).
 * The hint affects JIT code layout (fall-through preferred for the common
 * non-error path); functional verdict is byte-equivalent (PI-28). */
#ifndef unlikely
#define unlikely(x) __builtin_expect(!!(x), 0)
#endif

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
    /* §5.31 (MVP-3.4b) PI-13-3.4b adjudicated PASS-as-additive: inner-value
     * extends from `__u8 present` (value_size 1) to `struct allow_entry`
     * (value_size 8). Byte at offset 0 stays byte-equivalent to PI-27's
     * `present` byte; offset-4 `rule_id` is the NEW per-rule counter index. */
    __type(value, struct allow_entry);
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
    /* §5.31 (MVP-3.4b) PI-13-3.4b CIDR symmetry per T.5 OQ #3: inner-value
     * extends to `struct allow_entry` matching MAC HASH branch — without
     * symmetry MAC and CIDR rule_ids would live in different shape-spaces. */
    __type(value, struct allow_entry);
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

/* §5.31 (MVP-3.4b) PI-3.4b-4: per-rule counter bump. Called from BOTH the
 * MAC HASH-hit branch AND the CIDR LPM_TRIE-hit branch in mac_filter_prog
 * (Q1=B3 unified per-match semantic — two source-line call-sites sharing
 * the SAME helper). Verifier-required bounds check on `rule_id` is folded
 * inline; an out-of-range value is silently dropped (defense-in-depth —
 * loader-side validation at config.cpp:204 already ensures
 * `rule.id < XDPMF_ALLOWLIST_MAX`).
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
    struct xdpmf_mac key;
    __builtin_memcpy(key.octets, eth->h_source, sizeof(key.octets));

    /* §5.26 Q2 A1: read active_idx (single u32 read, atomic), then chain
     * map-of-maps lookup to obtain the live inner hash, then look up the
     * source MAC. Both NULL checks are verifier-required on map_of_maps
     * lookups and percpu map lookups; they should be unreachable in
     * practice because userspace populates both slots before the first attach. */
    __u32 zero = 0;
    __u32 *active_p = bpf_map_lookup_elem(&active_idx, &zero);
    if (unlikely(!active_p)) {
        bump_stat(STAT_DROP_DENY);
        return XDP_DROP;
    }
    __u32 active = *active_p;

    void *inner = bpf_map_lookup_elem(&rulesets, &active);
    if (unlikely(!inner)) {
        bump_stat(STAT_DROP_DENY);
        return XDP_DROP;
    }

    /* §5.31 (MVP-3.4b) PI-28-3.4b: inner-VALUE is `struct allow_entry`
     * (PI-13-3.4b adjudication). Offset-0 byte-equivalent null-check
     * pattern is preserved; offset-4 `rule_id` is read for bump_rule + the
     * §5.34 rules→action_table dispatch chain below.
     *
     * §5.34 (MVP-3.4b cycle 2) HG-3.4b-c2-4 dispatch chain — datapath now
     * consults `rules_outer[active] → rules_inner[rule_id] → action_table[
     * action_id]` per match. bump_rule() runs BEFORE the chain per
     * HG-3.4b-c2-5 (per-rule counter bumps on every match regardless of
     * verdict). On `action_type == ACTION_DROP` we bump STAT_DROP_DENY
     * (Q1.B re-uses the existing bucket — no new STAT enum slot) and
     * return XDP_DROP. On ACTION_PASS or NULL-fallthrough at any chain
     * step (defense-in-depth — practically unreachable because loader
     * populates rules_inner + action_table before the active_idx flip)
     * we fall through to the existing STAT_PASS branch. */
    struct allow_entry *entry = bpf_map_lookup_elem(inner, &key);
    if (entry) {
        bump_rule(entry->rule_id, active);
        __u32 rid = entry->rule_id;
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
        if (unlikely((void *)(eth + 1) + sizeof(struct iphdr) > data_end)) {
            bump_stat(STAT_DROP_MALFORMED);
            return XDP_DROP;
        }
        struct iphdr *ip = (struct iphdr *)(eth + 1);

        void *cidr_inner = bpf_map_lookup_elem(&cidr_rulesets, &active);
        if (unlikely(!cidr_inner)) {
            bump_stat(STAT_DROP_DENY);
            return XDP_DROP;
        }
        struct xdpmf_cidr_v4 cidr_key = {
            .prefixlen = 32u,        /* lookup is /32 host-route; LPM_TRIE picks longest matching prefix */
            .addr      = ip->saddr,  /* network byte order on wire, matches LPM_TRIE key shape */
        };
        /* §5.31 (MVP-3.4b) PI-28-3.4b CIDR symmetry + §5.34 HG-3.4b-c2-4
         * dispatch chain: same shape as MAC HASH-hit branch above —
         * bump_rule first (HG-3.4b-c2-5), then rules_outer → rules_inner →
         * action_table chain. STAT_DROP_DENY on DROP (Q1.B); STAT_PASS_CIDR
         * preserved on PASS / NULL-fallthrough. Active snapshot discipline:
         * the SAME `active` u32 read at the head of the datapath indexes
         * BOTH `cidr_rulesets` AND `rules_outer` here — concurrent
         * userspace flip is benign per §5.27 Q1 AS1 race-window analysis
         * extended to the 4th axis. */
        struct allow_entry *cidr_hit = bpf_map_lookup_elem(cidr_inner, &cidr_key);
        if (cidr_hit) {
            bump_rule(cidr_hit->rule_id, active);
            __u32 c_rid = cidr_hit->rule_id;
            void *c_rules_inner_map = bpf_map_lookup_elem(&rules_outer, &active);
            if (c_rules_inner_map) {
                struct rule_entry *cr = bpf_map_lookup_elem(c_rules_inner_map, &c_rid);
                if (cr && cr->present) {
                    __u32 c_aid = cr->action_id;
                    struct action_entry *ca = bpf_map_lookup_elem(&action_table, &c_aid);
                    if (ca && ca->action_type == ACTION_DROP) {
                        bump_stat(STAT_DROP_DENY);
                        return XDP_DROP;
                    }
                }
            }
            bump_stat(STAT_PASS_CIDR);
            return XDP_PASS;
        }
    }

    /* Inner miss (both axes) — consult defaults[active]. Q2-extension: same
     * active_idx value indexes ruleset+CIDR+default; one u32 flip swaps all. */
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
