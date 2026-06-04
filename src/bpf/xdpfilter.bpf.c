/*
 * xdpfilter.bpf.c — XDP classifier: 9-axis bit-vector AND match.
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
#include "common/xdpfilter.h"
#include "defs.h"          /* NEW (B34b §5.69): constant shims + unlikely + walk caps */
#include "maps.h"          /* NEW (B34b §5.69): 39 map objects (BEFORE classifier) */
#include "classifier.h"    /* NEW (B34b §5.69): helpers + macros (use map symbols + defs.h) */

SEC("xdp")
int xdpfilter_prog(struct xdp_md *ctx)
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

    /* §5.43 OR→AND bit-vector classification: AND-intersect the per-axis
     * survivors (each axis = its lookup OR its wildcard half). Dispatched into
     * three family arms below (IPv4 / IPv6 / non-IP); a frame with no matching
     * rule (acc==0) falls through to defaults[active]. All 9 axes — incl. MAC,
     * a live axis since §5.47 — compose uniformly. */

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

    /* §5.54 ethertype axis lookup, HOISTED once above the family dispatch
     * (EtherType is the family selector) so `& (eth_mask|wc_eth)` composes into
     * all THREE arms. Key = HOST-order post-VLAN inner ethertype; exact-HASH, NO
     * closure. With no ethertype rule, (eth_mask|wc_eth) is an all-ones no-op ⇒
     * IP-arm verdicts stay bit-identical (PI-mvp-4.14-IPVERDICT). */
    LOOKUP_INNER_OR_DROP(eth_inner, ethertype_rulesets);  /* §5.68 fold #3 */
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
        /* §5.68 fold #13: shared TCP/UDP dport read (per-arm l4 offset above). */
        __u32 dport    = 0;
        int   has_port = 0;
        READ_DPORT(proto, l4, dport, has_port);

        /* Per-axis active inners (dst + src + proto + port + vlan) via the
         * shared `active` snapshot (§5.27 Q1 AS1 extended to 4 axes); §5.47
         * D-mvp-4.7-Q2: MAC axis un-frozen, same snapshot selects the active
         * allowlist inner (HASH-AOM). §5.68 fold #3 LOOKUP_INNER_OR_DROP. */
        LOOKUP_INNER_OR_DROP(dst_inner, dst_rulesets);
        LOOKUP_INNER_OR_DROP(src_inner, cidr_rulesets);
        LOOKUP_INNER_OR_DROP(proto_inner, proto_rulesets);
        LOOKUP_INNER_OR_DROP(port_inner, port_rulesets);
        LOOKUP_INNER_OR_DROP(vlan_inner, vlan_rulesets);
        LOOKUP_INNER_OR_DROP(mac_inner, rulesets);

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

        /* §5.68 fold #12: src-MAC axis via mac_axis (see helper for §5.47). */
        __u64 mac_mask = mac_axis(mac_inner, eth->h_source);

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
            DISPATCH_MATCH(acc, active);  /* §5.68 fold #1 */
        }
        /* acc == 0 → no rule matched; fall through to defaults[active]. */
    } else if (inner_proto == bpf_htons(ETH_P_IPV6)) {
        /* §5.53 IPv6 classification arm: symmetric 9-term AND mirroring the v4
         * arm; the v4 address axes contribute wildcard-only halves (no v4 address
         * in a v6 frame), dst6/src6 carry the IPv6 LPM survivors. §5.55: proto/port
         * read the TRUE upper-layer L4 via the bounded ext-header walk below
         * (PI-mvp-4.15-EXT-WALK). */

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
        /* §5.68 fold #13: shared TCP/UDP dport read (per-arm l4 = walked cursor). */
        __u32 dport    = 0;
        int   has_port = 0;
        READ_DPORT(proto, l4, dport, has_port);

        /* Per-axis active inners via the shared `active` snapshot. §5.68 fold
         * #3 LOOKUP_INNER_OR_DROP. */
        LOOKUP_INNER_OR_DROP(dst6_inner, dst6_rulesets);
        LOOKUP_INNER_OR_DROP(src6_inner, src6_rulesets);
        LOOKUP_INNER_OR_DROP(proto_inner, proto_rulesets);
        LOOKUP_INNER_OR_DROP(port_inner, port_rulesets);
        LOOKUP_INNER_OR_DROP(vlan_inner, vlan_rulesets);
        LOOKUP_INNER_OR_DROP(mac_inner, rulesets);

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

        /* §5.68 fold #12: src-MAC axis via mac_axis (eth->h_source,
         * VLAN-agnostic base offset). */
        __u64 mac_mask = mac_axis(mac_inner, eth->h_source);

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
            DISPATCH_MATCH(acc, active);  /* §5.68 fold #1 */
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
        /* §5.68 fold #3 LOOKUP_INNER_OR_DROP (non-IP arm: only vlan + mac
         * inners — no L3/L4 axes). */
        LOOKUP_INNER_OR_DROP(vlan_inner, vlan_rulesets);
        LOOKUP_INNER_OR_DROP(mac_inner, rulesets);

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
        /* §5.68 fold #12: src-MAC axis via mac_axis. */
        __u64 mac_mask = mac_axis(mac_inner, eth->h_source);

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
            DISPATCH_MATCH(acc, active);  /* §5.68 fold #1 */
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
