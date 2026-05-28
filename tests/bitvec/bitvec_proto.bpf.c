/*
 * bitvec_proto.bpf.c — MVP-4.2 bit-vector AND-classification SPIKE datapath.
 *
 * §5.42 (rule-model S2). ISOLATED PROTOTYPE — NOT production. Proves the
 * per-axis-u64-bitmask -> `acc &= (matched | wildcard)` across axes ->
 * first-set-bit lowering classifies a mixed-primitive rule-set on the 5.15
 * verifier floor. The whole rule-match-set is a single u64 (N<=64). The
 * per-packet observable is the matched rule-id via bv_result[] (NOMATCH
 * bucket included); the spike's verdict signal is WHICH id matched, not the
 * PASS/DROP (D-mvp-4.2-OBSERVABLE).
 *
 * Datapath shape (D-mvp-4.2 Interfaces #1):
 *   parse Eth -> bounded VLAN skip (depth<=2, re-implemented locally per
 *   guard #9 — does NOT share the production l3_after_vlan) -> require inner
 *   IPv4 -> extract dst/src/proto + (TCP/UDP) dport ->
 *   acc = (lpm(dst)|wc[0]) & (lpm(src)|wc[1]) & (hash(proto)|wc[2])
 *                                             & (scan(port)|wc[3])
 *   -> rid = first_set(acc)-1 ; bump bv_result[rid|NOMATCH] ; XDP_DROP iff
 *   bv_action[rid]==DROP else XDP_PASS.
 *
 * D-mvp-4.2-FFS-FEAS / D-mvp-4.2-FFS-FALLBACK: the default first-set lowering
 * is __builtin_ffsll. If the Phase-2.5 verifier/libcall smoke fails, compile
 * with -DBITVEC_FFS_FALLBACK to swap in a bounded #pragma unroll bit-scan
 * (no back-edge; mirrors the proven §5.41 l3_after_vlan unroll). The fallback
 * changes NO map layout / scope / observable — only the bit-scan lowering.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "bitvec_proto.h"

/* vmlinux.h is BTF-derived (types only, no CPP macros); linux/if_ether.h and
 * linux/in.h are unavailable in the BPF-target build. Define the few EtherType
 * / IP-proto / VLAN constants we need (byte-equivalent to the kernel values).
 * Mirrors the production datapath's inline-define convention. */
#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif
#ifndef ETH_P_8021Q
#define ETH_P_8021Q 0x8100
#endif
#ifndef ETH_P_8021AD
#define ETH_P_8021AD 0x88A8
#endif
#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif
#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif

/* §5.42 HG-mvp-4.2-4: depth-2 VLAN walk (802.1Q + one stacked QinQ tag),
 * matching the production XDPMF_VLAN_MAX_DEPTH (re-stated locally — guard #9,
 * the prototype does NOT include the production header for this). */
#define BITVEC_VLAN_MAX_DEPTH 2

char _license[] SEC("license") = "GPL";

/* ── Prototype maps (D-mvp-4.2-WILDCARD: single non-swapped slot, NO
 * active_idx, NO [2] doubling). NONE are in production kManagedMaps[].
 * Only bv_result is pinned by the harness (BITVEC_RESULT_PIN). ─────────── */

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct bv_cidr_v4);
    __type(value, __u64);
    __uint(max_entries, BITVEC_RULE_MAX);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} bv_dst_lpm SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct bv_cidr_v4);
    __type(value, __u64);
    __uint(max_entries, BITVEC_RULE_MAX);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} bv_src_lpm SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 8);
} bv_proto_hash SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct bv_port_range);
    __uint(max_entries, BITVEC_RULE_MAX);
} bv_port_ranges SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, BITVEC_NUM_AXES);
} bv_wildcard SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u8);
    __uint(max_entries, BITVEC_RULE_MAX);
} bv_action SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, BITVEC_NOMATCH + 1);
} bv_result SEC(".maps");

/* ── Helpers ─────────────────────────────────────────────────────────── */

/* §5.42 D-mvp-4.2-FFS-FEAS default / D-mvp-4.2-FFS-FALLBACK alternate. Caller
 * guarantees acc != 0, so the default path's __builtin_ffsll(acc) is in
 * [1,64] and the -1 yields a valid bit index. The fallback is a fixed
 * 64-iteration scan (no back-edge, 5.15-safe). */
static __always_inline int bitvec_first_set(__u64 acc)
{
#ifdef BITVEC_FFS_FALLBACK
#pragma unroll
    for (int i = 0; i < BITVEC_RULE_MAX; i++) {
        if (acc & (1ULL << i)) {
            return i;
        }
    }
    return BITVEC_NOMATCH;
#else
    return __builtin_ffsll((long long)acc) - 1;
#endif
}

/* §5.42 wildcard baseline for one axis (0 on map miss). */
static __always_inline __u64 bitvec_wildcard(__u32 axis)
{
    __u64 *v = bpf_map_lookup_elem(&bv_wildcard, &axis);
    return v ? *v : 0;
}

/* §5.42 D-mvp-4.2-RANGE bounded port scan: OR `bit` of every USED slot whose
 * inclusive [lo,hi] contains dport. `lo > hi` slots are unused (skipped).
 * Bounded #pragma unroll, no back-edge (mirrors §5.41 precedent). */
static __always_inline __u64 bitvec_port_scan(__u32 dport)
{
    __u64 mask = 0;
#pragma unroll
    for (__u32 i = 0; i < BITVEC_RULE_MAX; i++) {
        __u32 k = i;
        struct bv_port_range *r = bpf_map_lookup_elem(&bv_port_ranges, &k);
        if (!r) {
            continue;
        }
        if (r->lo > r->hi) {
            continue; /* unused slot */
        }
        if (dport >= r->lo && dport <= r->hi) {
            mask |= r->bit;
        }
    }
    return mask;
}

/* §5.42 prefix-closure lookup (FI-1): the harness pre-closes each stored mask
 * (OR of all covering rules), so a single longest-prefix LPM hit already
 * carries every less-specific rule's bit. A miss contributes 0. */
static __always_inline __u64 bitvec_lpm_dst(__u32 addr_net)
{
    struct bv_cidr_v4 key = {};
    key.prefixlen = 32;
    key.addr = addr_net;
    __u64 *v = bpf_map_lookup_elem(&bv_dst_lpm, &key);
    return v ? *v : 0;
}

static __always_inline __u64 bitvec_lpm_src(__u32 addr_net)
{
    struct bv_cidr_v4 key = {};
    key.prefixlen = 32;
    key.addr = addr_net;
    __u64 *v = bpf_map_lookup_elem(&bv_src_lpm, &key);
    return v ? *v : 0;
}

static __always_inline void bitvec_bump(__u32 rid)
{
    __u64 *v = bpf_map_lookup_elem(&bv_result, &rid);
    if (v) {
        *v += 1;
    }
}

/* §5.42 local VLAN walk (guard #9: re-implemented, NOT shared with production
 * l3_after_vlan). Returns the inner EtherType + first byte past L2/VLAN. */
static __always_inline __u16 bitvec_l3_after_vlan(void *eth, void *data_end,
                                                  void **l3hdr)
{
    void *cursor = eth + sizeof(struct ethhdr);
    __u16 proto  = ((struct ethhdr *)eth)->h_proto;

#pragma unroll
    for (int i = 0; i < BITVEC_VLAN_MAX_DEPTH; i++) {
        if (proto != bpf_htons(ETH_P_8021Q) &&
            proto != bpf_htons(ETH_P_8021AD)) {
            break;
        }
        if (cursor + sizeof(struct vlan_hdr) > data_end) {
            break;
        }
        struct vlan_hdr *vlan = cursor;
        proto  = vlan->h_vlan_encapsulated_proto;
        cursor += sizeof(struct vlan_hdr);
    }

    *l3hdr = cursor;
    return proto;
}

SEC("xdp")
int bitvec_proto_prog(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    if (data + sizeof(struct ethhdr) > data_end) {
        return XDP_PASS; /* spike does not classify malformed frames */
    }

    void *l3 = 0;
    __u16 inner = bitvec_l3_after_vlan(data, data_end, &l3);
    if (inner != bpf_htons(ETH_P_IP)) {
        return XDP_PASS; /* non-IPv4 not classified */
    }

    struct iphdr *ip = l3;
    if ((void *)(ip + 1) > data_end) {
        return XDP_PASS;
    }

    /* Network byte order on the wire == the LPM key byte order. */
    __u32 dst   = ip->daddr;
    __u32 src   = ip->saddr;
    __u8  proto = ip->protocol;

    /* The prototype injector emits no IPv4 options (ihl=5), so the L4 header
     * sits immediately after the fixed 20-byte IPv4 header. */
    void *l4 = (void *)(ip + 1);

    __u32 dport    = 0;
    int   has_port = 0;
    if (proto == IPPROTO_TCP) {
        struct tcphdr *t = l4;
        if ((void *)(t + 1) > data_end) {
            return XDP_PASS;
        }
        dport    = bpf_ntohs(t->dest);
        has_port = 1;
    } else if (proto == IPPROTO_UDP) {
        struct udphdr *u = l4;
        if ((void *)(u + 1) > data_end) {
            return XDP_PASS;
        }
        dport    = bpf_ntohs(u->dest);
        has_port = 1;
    }
    /* ICMP / other: no L4 port -> only port-wildcard rules survive the port
     * axis (port_mask stays 0). */

    __u32 proto_key  = proto;
    __u64 *proto_ptr = bpf_map_lookup_elem(&bv_proto_hash, &proto_key);
    __u64 proto_mask = proto_ptr ? *proto_ptr : 0;

    __u64 port_mask = has_port ? bitvec_port_scan(dport) : 0;

    __u64 acc = (bitvec_lpm_dst(dst)   | bitvec_wildcard(BITVEC_AXIS_DST)) &
                (bitvec_lpm_src(src)   | bitvec_wildcard(BITVEC_AXIS_SRC)) &
                (proto_mask            | bitvec_wildcard(BITVEC_AXIS_PROTO)) &
                (port_mask             | bitvec_wildcard(BITVEC_AXIS_PORT));

    if (acc == 0) {
        bitvec_bump(BITVEC_NOMATCH);
        return XDP_PASS;
    }

    int rid = bitvec_first_set(acc);
    if (rid < 0 || rid >= BITVEC_RULE_MAX) {
        bitvec_bump(BITVEC_NOMATCH);
        return XDP_PASS;
    }

    bitvec_bump((__u32)rid);

    __u32 akey = (__u32)rid;
    __u8 *action = bpf_map_lookup_elem(&bv_action, &akey);
    if (action && *action == 1) {
        return XDP_DROP;
    }
    return XDP_PASS;
}
