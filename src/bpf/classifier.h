#pragma once
/*
 * classifier.h — per-packet classify toolkit: 6 __always_inline helpers
 * (bump_stat / bump_rule / first_set_u64 / port_scan / l3_after_vlan /
 * mac_axis) + 3 statement macros (DISPATCH_MATCH / LOOKUP_INNER_OR_DROP /
 * READ_DPORT).
 *
 * Moved verbatim from xdpfilter.bpf.c (MVP-4.29 / B34b, §5.69); absorbs the
 * 1-function vlan helper (l3_after_vlan). The helpers reference map symbols
 * (maps.h) and the constant shims (defs.h) at definition point, so both
 * MUST precede this header. §5.70 (MVP-4.30) B35: the per-axis wildcard loads
 * collapse into the hoisted `ruleset_state` read (fold #2 RESOLVED below) — an
 * INTENTIONAL codegen change, so the xdp section is NO LONGER byte-identical;
 * correctness is held by verdict-identity (T_*_ORACLE_AGREEMENT) and the B37
 * insn gate is re-baselined to the measured post-pack count.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "defs.h"
#include "maps.h"

/* PERCPU bump: pointer returned is to this CPU's slot only. No atomic. */
static __always_inline void bump_stat(__u32 idx)
{
    __u64 *v = bpf_map_lookup_elem(&stats, &idx);
    if (v) {
        *v += 1;
    }
}

/* §5.31 per-rule counter bump, shared by every family arm's match dispatch. NB:
 * the `rule_id` parameter is the internal SLOT (`first_set_u64(acc) - 1`, an
 * id-sorted rank in [0, count)), NOT the operator `id` — the two are decoupled
 * and the raw counter map is slot-keyed (§5.61). The verifier-required slot
 * bounds check is folded inline; an out-of-range value is silently dropped
 * (defense-in-depth — config.cpp caps the rule COUNT at XDPMF_ALLOWLIST_MAX).
 * §5.35 D-3.4d-2: `active` is passed in (not re-read) so the bump uses the SAME
 * active_idx snapshot as the lookups — a re-read would be a race-window split
 * across map families. */
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

/* §5.68 (MVP-4.28) fold #1: the shared post-match dispatch tail, factored out of
 * the three family arms (byte-identical code-movement; the v4/v6/non-IP callers
 * keep their own `acc != 0` guard so acc==0 still falls through to
 * defaults[active]).
 *
 * HG-mvp-4.3-4 first-match-by-id: the lowest set bit IS the lowest matching rule
 * id (bit position == id), so ffsll picks it for free with NO sort. bump_rule
 * first (per-match counter, HG-5), then the reused rules_outer → rules_inner →
 * action_table dispatch (DROP → STAT_DROP_DENY + XDP_DROP; PASS or any
 * NULL-fallthrough → STAT_PASS_CIDR + XDP_PASS, D-mvp-4.3-STAT). */
#define DISPATCH_MATCH(acc_, active_) \
    do { \
        __u32 rid = first_set_u64(acc_) - 1; \
        bump_rule(rid, active_); \
        void *rules_inner_map = bpf_map_lookup_elem(&rules_outer, &active_); \
        if (rules_inner_map) { \
            struct rule_entry *r = bpf_map_lookup_elem(rules_inner_map, &rid); \
            if (r && r->present) { \
                __u32 aid = r->action_id; \
                struct action_entry *a = bpf_map_lookup_elem(&action_table, &aid); \
                if (a && a->action_type == ACTION_DROP) { \
                    bump_stat(STAT_DROP_DENY); \
                    return XDP_DROP; \
                } \
            } \
        } \
        bump_stat(STAT_PASS_CIDR); \
        return XDP_PASS; \
    } while (0)

/* §5.68 (MVP-4.28) fold #3: the verifier-mandated inner-lookup-or-deny idiom,
 * shared by all 15 outer-map lookups (eth_inner + the per-arm dst/src/proto/
 * port/vlan/mac inners). A statement MACRO (NOT a helper): a BPF
 * __always_inline helper cannot early-`return XDP_DROP` from the CALLER, and
 * textual substitution is byte-identical BY CONSTRUCTION (D-mvp-4.28-Q1-MACRO).
 * NO `do { } while(0)` wrapper — `var` is deliberately declared into the
 * caller's scope (the caller dereferences it). `active` is captured from the
 * enclosing scope by name (every call site has `__u32 active` live). The
 * trailing `;` at each call site is a harmless null statement.
 *
 * §5.26 Q2 A1 / §5.27: the NULL check is verifier-required; unreachable in
 * practice because userspace populates both ruleset slots before the first
 * attach (the §5.30 HK-5 `unlikely` hint biases JIT layout to the common
 * non-error fall-through). */
#define LOOKUP_INNER_OR_DROP(var, outer) \
    void *var = bpf_map_lookup_elem(&(outer), &active); \
    if (unlikely(!var)) { \
        bump_stat(STAT_DROP_DENY); \
        return XDP_DROP; \
    }

/* §5.68 (MVP-4.28) fold #2 (load_wildcards) — RESOLVED by §5.70 (MVP-4.30) B35.
 * The fold was DROPPED at §5.68 (guard #36) because byte-identity forbade it: the
 * three family arms used DIFFERENT source orderings of the per-axis wildcard
 * loads, and each ordering compiled to a different insn count (the 3658 gate
 * could never be held by one shared body). B35 collapses ALL per-axis wildcard
 * lookups into ONE hoisted `ruleset_state` read; every arm now reads the halves
 * UNIFORMLY via `rs->wc[axis]` (no divergent per-arm load ordering remains —
 * D-mvp-4.30-UNIFORM-ARMS / PI-mvp-4.30-UNIFORM-ARMS). The divergence the dropped
 * fold documented is GONE (resolved, not relocated); correctness is now held by
 * verdict-identity, not the byte-identity that blocked the original fold. */

/* §5.68 (MVP-4.28) fold #12: the src-MAC axis lookup, shared by all three arms.
 *
 * §5.47 (MVP-4.7) D-mvp-4.7-Q2 MAC axis: exact-HASH lookup keyed by the SOURCE
 * MAC (eth->h_source — the v1 semantic, §5.26; NO closure). The src MAC sits at
 * the base-eth fixed offset (read before the VLAN walk, already bounds-checked
 * at the datapath head), so it is VLAN-agnostic. Every frame carries a src MAC →
 * no "absent" sentinel (unlike vlan); a rule that omits `mac` survives via
 * wc_mac. NULL → 0 (no MAC survivors). */
static __always_inline __u64 mac_axis(void *mac_inner, const __u8 *src_mac)
{
    struct xdpmf_mac mac_key = {0};
    __builtin_memcpy(mac_key.octets, src_mac, 6);
    __u64 mac_mask = 0;
    __u64 *mm = bpf_map_lookup_elem(mac_inner, &mac_key);
    if (mm) {
        mac_mask = *mm;
    }
    return mac_mask;
}

/* §5.68 (MVP-4.28) fold #13: the TCP/UDP dport read, shared by the v4 + v6 arms
 * (non-IP has no L4). The per-arm `l4` OFFSET is computed in each arm (v4
 * ip->ihl*4, v6 ext-walk cursor) and passed in — only the READ is shared.
 *
 * Realized as a statement MACRO (the D-mvp-4.28-13 macro FALLBACK): the
 * out-param helper form round-trips dport/has_port through pointers and the
 * malformed flag through a caller branch — neither folds back under -O2
 * (gate measured +50 insns), so it does NOT hold 3658. The macro expands the
 * exact original TCP/UDP block (incl. the two MALFORMED `return XDP_DROP`) in
 * caller scope → byte-identical BY CONSTRUCTION (like fold #3). `data_end` is
 * captured from the enclosing scope (both arms have it live); the per-block
 * `t`/`u` declarations are scoped inside their own braces.
 *
 * §5.44 (MVP-4.4): dport is read only for TCP/UDP after an explicit L4-header
 * bounds-check (has_port); non-TCP/UDP frames keep has_port=0 → port_mask=0
 * (only port-wildcard rules survive the port axis), per the §5.42 spike. */
#define READ_DPORT(proto_, l4_, dport_, has_port_) \
    if (proto_ == IPPROTO_TCP) { \
        struct tcphdr *t = l4_; \
        if (unlikely((void *)(t + 1) > data_end)) { \
            bump_stat(STAT_DROP_MALFORMED); \
            return XDP_DROP; \
        } \
        dport_    = bpf_ntohs(t->dest); \
        has_port_ = 1; \
    } else if (proto_ == IPPROTO_UDP) { \
        struct udphdr *u = l4_; \
        if (unlikely((void *)(u + 1) > data_end)) { \
            bump_stat(STAT_DROP_MALFORMED); \
            return XDP_DROP; \
        } \
        dport_    = bpf_ntohs(u->dest); \
        has_port_ = 1; \
    }
