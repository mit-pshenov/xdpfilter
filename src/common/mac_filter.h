/*
 * mac_filter.h — types/constants shared between BPF C and C++23 userspace.
 *
 * Includable from both sides because it uses only `unsigned char`
 * (guaranteed 1 byte everywhere) and the C preprocessor. In BPF C this
 * header MAY be included after `vmlinux.h` (no symbol collisions).
 */
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Allow-list key. Source MAC of a received Ethernet frame is copied into
 * `octets` (network order: octets[0] is the first byte on the wire) and
 * looked up in the `allowlist` hash map.
 *
 * Named `xdpmf_mac` (not `mac_addr`) because vmlinux.h on Linux ≥ 5.x
 * already declares an unrelated kernel-internal `struct mac_addr` that
 * collides at BPF compile time. This is a forced rename from design §3.1
 * — see mint/impl-notes.md.
 */
struct xdpmf_mac {
    unsigned char octets[6];
} __attribute__((packed));

/*
 * §5.27 (MVP-3.2): L3 src-CIDR axis — see design §5.27 Q1 + Q2.
 *
 * LPM_TRIE key for IPv4 CIDR matching. Kernel BPF LPM_TRIE requires the
 * key to begin with `__u32 prefixlen`; the trailing field holds the
 * address in NETWORK BYTE ORDER (big-endian; matches `iphdr.saddr` on
 * the wire — no swap needed in datapath). Total size = 8 bytes.
 *
 * `unsigned int` is used (not `__u32`) because this header is included
 * from BOTH userspace C++ (where `__u32` isn't a libc type) AND BPF C
 * (where `unsigned int` is binary-compatible with kernel `__u32`).
 */
struct xdpmf_cidr_v4 {
    unsigned int prefixlen;  /* bits in network mask, range [0, 32] */
    unsigned int addr;       /* IPv4 address, big-endian (network order) */
} __attribute__((packed));

/*
 * §5.53 (MVP-4.13): L3 IPv6 dst/src-CIDR axes — see design §5.53 HG-1 + Q1.
 *
 * LPM_TRIE key for IPv6 CIDR matching. As with xdpmf_cidr_v4 the key begins
 * with `unsigned int prefixlen`; `addr6` holds the 16 address bytes in
 * NETWORK byte order (addr6[0] is the MSB / first byte on the wire — matches
 * `ipv6hdr.daddr/saddr`, no swap needed). The kernel LPM_TRIE walks the key
 * MSB-first byte-by-byte, so the byte array (NOT host-order limbs) is the
 * contract. Total size = 20 bytes.
 *
 * `unsigned int`/`unsigned char` (not `__u32`/`__u8`) for the same shared-
 * header reason as xdpmf_cidr_v4.
 */
struct xdpmf_cidr_v6 {
    unsigned int  prefixlen;   /* bits in network mask, range [0, 128] */
    unsigned char addr6[16];   /* IPv6 address, NETWORK byte order (addr6[0]=MSB) */
} __attribute__((packed));

/*
 * Index into the `stats` BPF_MAP_TYPE_PERCPU_ARRAY. Each invocation of
 * the XDP program bumps exactly one slot. STAT_MAX is the array
 * max_entries (sentinel; bumped 3 → 4 in §5.27 alongside STAT_PASS_CIDR).
 *
 * §5.27 PI-10-3.2 carve-out: enum slots 0/1/2 are byte-identical to
 * pre-§5.27; STAT_PASS_CIDR = 3 is additive; STAT_MAX is a derived
 * sentinel (allowed to grow with the enum).
 */
enum mac_filter_stat {
    STAT_PASS           = 0,
    STAT_DROP_DENY      = 1,
    STAT_DROP_MALFORMED = 2,
    STAT_PASS_CIDR      = 3,  /* §5.27 NEW: frame passed via CIDR-axis match */
    STAT_MAX            = 4,  /* §5.27 BUMP: 3 → 4 (sentinel = stats max_entries) */
};

/* Bpffs layout (see design §3.5). The per-interface subdir under this
 * root doubles as the ownership marker for idempotent reload (§5.4). */
#define XDPMF_BPFFS_ROOT "/sys/fs/bpf/xdpmacfilter"

/* Allow-list capacity — see design Decision §5.1. */
#define XDPMF_ALLOWLIST_MAX 64

/* Map names — MUST match `SEC(".maps")` declarations in mac_filter.bpf.c
 * because libbpf auto-pins by map name under pin_root_path. */
#define XDPMF_MAP_ALLOWLIST_NAME "allowlist"
#define XDPMF_MAP_STATS_NAME     "stats"

/* §5.26 (MVP-3.1): atomic apply via ARRAY_OF_MAPS[2] — see design §5.26 Q2.
 * Outer map of maps holds two inner allowlist instances; a one-slot
 * active_idx ARRAY selects the live one; a two-slot defaults ARRAY parallels
 * the outer indexing so default_action atomically swaps with the ruleset. */
#define XDPMF_RULESET_COUNT            2                  /* outer max_entries */
#define XDPMF_MAP_ACTIVE_IDX_NAME      "active_idx"      /* ARRAY[1] of __u32 */
#define XDPMF_MAP_RULESETS_OUTER_NAME  "rulesets"        /* ARRAY_OF_MAPS[XDPMF_RULESET_COUNT] */
#define XDPMF_MAP_INNER_A_NAME         "allowlist_a"     /* inner slot 0 */
#define XDPMF_MAP_INNER_B_NAME         "allowlist_b"     /* inner slot 1 */
#define XDPMF_MAP_DEFAULTS_NAME        "defaults"        /* ARRAY[XDPMF_RULESET_COUNT] of __u32 */

/* §5.26 P0a: bpf_link pin basename under the per-iface bpffs dir. */
#define XDPMF_LINK_PIN_BASENAME        "link"

/* §5.27 (MVP-3.2) Q1 AS1: parallel ARRAY_OF_MAPS outer pointing at two
 * LPM_TRIE inners (cidr_allowlist_a / cidr_allowlist_b). Same shared
 * active_idx ARRAY[1] commits both outers' swap with a single u32 write —
 * see design §5.27 Q1 race-window analysis. */
#define XDPMF_MAP_CIDR_RULESETS_OUTER_NAME  "cidr_rulesets"     /* ARRAY_OF_MAPS[XDPMF_RULESET_COUNT] of LPM_TRIE fds */
#define XDPMF_MAP_CIDR_INNER_A_NAME         "cidr_allowlist_a"  /* inner slot 0, LPM_TRIE */
#define XDPMF_MAP_CIDR_INNER_B_NAME         "cidr_allowlist_b"  /* inner slot 1, LPM_TRIE */

/* §5.43 (MVP-4.3) OR→AND bit-vector pivot — see design §5.43 Q1/Q2.
 *
 * Two LPM axes (dst_cidr NEW + src_cidr reshaped) composed by per-axis __u64
 * bitmask intersection; first-match by __builtin_ffsll(acc)-1. The src axis
 * REUSES the existing cidr_allowlist_a/_b/cidr_rulesets pins (value reshaped
 * from `struct allow_entry` → `__u64`; pin names UNCHANGED per guard #16).
 * The dst axis is a NEW ARRAY_OF_MAPS trio mirroring the §5.27 CIDR topology.
 *
 * BITVEC_NUM_AXES = number of LPM axes this slice (dst, src). The `wildcard`
 * map is ONE BPF_MAP_TYPE_ARRAY of __u64 with max_entries
 * XDPMF_RULESET_COUNT * BITVEC_NUM_AXES (= 4), indexed wildcard[active *
 * BITVEC_NUM_AXES + axis] — the realizable analog of the `defaults` precedent
 * (D-mvp-4.3-Q2; a runtime active_idx cannot select between two top-level map
 * symbols, only between slots of ONE indexed ARRAY). A rule that does NOT
 * constrain an axis has its bit set in that axis's wildcard half and is ABSENT
 * from the axis LPM map (mutual exclusion). */
#define XDPMF_MAP_DST_RULESETS_OUTER_NAME  "dst_rulesets"   /* ARRAY_OF_MAPS[XDPMF_RULESET_COUNT] of LPM_TRIE fds */
#define XDPMF_MAP_DST_INNER_A_NAME         "dst_bitmask_a"  /* inner slot 0, LPM_TRIE of __u64 */
#define XDPMF_MAP_DST_INNER_B_NAME         "dst_bitmask_b"  /* inner slot 1, LPM_TRIE of __u64 */
#define XDPMF_MAP_WILDCARD_NAME            "wildcard"       /* ARRAY[XDPMF_RULESET_COUNT*BITVEC_NUM_AXES] of __u64 */

/* §5.44 (MVP-4.4) D-mvp-4.4-Q1/Q2/Q4: ADDITIVE +2 bit-vector axes — proto
 * (exact-match HASH) + dst_port (bounded range-scan) — extending the §5.43
 * two-LPM-axis (dst/src) AND classifier. BITVEC_NUM_AXES 2→4 (the ONE foreseen
 * value flip) auto-grows the `wildcard` ARRAY's max_entries 4→8 via the
 * XDPMF_RULESET_COUNT * BITVEC_NUM_AXES formula (no literal edit in the .bpf.c
 * decl). New axis indices BV_AXIS_PROTO=2 / BV_AXIS_PORT=3.
 *
 *   proto: ARRAY_OF_MAPS[2] of HASH inners (proto_bitmask_a/_b + proto_rulesets),
 *          key __u32 IP-protocol number, value __u64 rule-bitmask, NO closure.
 *   port:  ARRAY_OF_MAPS[2] of ARRAY inners (port_ranges_a/_b + port_rulesets),
 *          key __u32 slot index, value struct xdpmf_port_range, NO closure. */
#define XDPMF_MAP_PROTO_RULESETS_OUTER_NAME "proto_rulesets"  /* ARRAY_OF_MAPS[XDPMF_RULESET_COUNT] of HASH fds */
#define XDPMF_MAP_PROTO_INNER_A_NAME        "proto_bitmask_a" /* inner slot 0, HASH of __u64 */
#define XDPMF_MAP_PROTO_INNER_B_NAME        "proto_bitmask_b" /* inner slot 1, HASH of __u64 */
#define XDPMF_MAP_PORT_RULESETS_OUTER_NAME  "port_rulesets"   /* ARRAY_OF_MAPS[XDPMF_RULESET_COUNT] of ARRAY fds */
#define XDPMF_MAP_PORT_INNER_A_NAME         "port_ranges_a"   /* inner slot 0, ARRAY of xdpmf_port_range */
#define XDPMF_MAP_PORT_INNER_B_NAME         "port_ranges_b"   /* inner slot 1, ARRAY of xdpmf_port_range */

/* Proto HASH inner capacity — sparse keyed lookup over IP-protocol numbers
 * [0,255] (D-mvp-4.4-Q1). */
#define XDPMF_PROTO_HASH_MAX 256

/* §5.45 (MVP-4.5) D-mvp-4.5-Q1: ADDITIVE +1 bit-vector axis — vlan (outer
 * 802.1Q tag VID, exact-match HASH) — byte-mirroring the §5.44 proto axis.
 * BITVEC_NUM_AXES 4→5 (the ONE foreseen value flip) auto-grows the `wildcard`
 * ARRAY's max_entries 8→10 via the XDPMF_RULESET_COUNT * BITVEC_NUM_AXES
 * formula (no literal edit in the .bpf.c decl). New axis index BV_AXIS_VLAN=4.
 *
 *   vlan: ARRAY_OF_MAPS[2] of HASH inners (vlan_bitmask_a/_b + vlan_rulesets),
 *         key __u32 outer VID [0,4095], value __u64 rule-bitmask, NO closure. */
#define XDPMF_MAP_VLAN_RULESETS_OUTER_NAME "vlan_rulesets"  /* ARRAY_OF_MAPS[XDPMF_RULESET_COUNT] of HASH fds */
#define XDPMF_MAP_VLAN_INNER_A_NAME        "vlan_bitmask_a" /* inner slot 0, HASH of __u64 */
#define XDPMF_MAP_VLAN_INNER_B_NAME        "vlan_bitmask_b" /* inner slot 1, HASH of __u64 */

/* Vlan HASH inner capacity — full 12-bit VID key space [0,4095]
 * (D-mvp-4.5-Q1); occupancy bounded far lower by rule count. */
#define XDPMF_VLAN_HASH_MAX 4096

/* Capture sentinel: out of the valid VID range [0,4095] — l3_after_vlan writes
 * it to *out_vlan_id on an untagged/truncated frame; the datapath derives
 * has_vlan = (vlan_id != XDPMF_VLAN_NONE). VID 0 (priority-tagged) is a VALID
 * distinct key, so 0 cannot mean "no tag" (D-mvp-4.5-Q2). */
#define XDPMF_VLAN_NONE 0xFFFF

/* §5.53 (MVP-4.13) D-mvp-4.13-Q1/Q2: ADDITIVE +2 bit-vector axes — dst6 + src6
 * (IPv6 CIDR LPM_TRIE, mirroring the §5.43 dst/src v4 LPM trios). BITVEC_NUM_AXES
 * 6→8 auto-grows the `wildcard` ARRAY's max_entries 12→16 via the
 * XDPMF_RULESET_COUNT * BITVEC_NUM_AXES formula (no literal edit in the .bpf.c
 * decl). New axis indices BV_AXIS_DST6=6 / BV_AXIS_SRC6=7. Fresh ARRAY_OF_MAPS
 * trios (dst6_ and src6_ prefixes) of LPM_TRIE inners keyed by struct
 * xdpmf_cidr_v6, value __u64 rule-bitmask, WITH closure (close_prefixes6). Both
 * datapath arms AND all 8 axis terms; the other address family contributes
 * 0|wildcard (Q2). */
#define XDPMF_MAP_DST6_RULESETS_OUTER_NAME "dst6_rulesets"  /* ARRAY_OF_MAPS[XDPMF_RULESET_COUNT] of LPM_TRIE fds */
#define XDPMF_MAP_DST6_INNER_A_NAME        "dst6_bitmask_a" /* inner slot 0, LPM_TRIE of __u64 */
#define XDPMF_MAP_DST6_INNER_B_NAME        "dst6_bitmask_b" /* inner slot 1, LPM_TRIE of __u64 */
#define XDPMF_MAP_SRC6_RULESETS_OUTER_NAME "src6_rulesets"  /* ARRAY_OF_MAPS[XDPMF_RULESET_COUNT] of LPM_TRIE fds */
#define XDPMF_MAP_SRC6_INNER_A_NAME        "src6_bitmask_a" /* inner slot 0, LPM_TRIE of __u64 */
#define XDPMF_MAP_SRC6_INNER_B_NAME        "src6_bitmask_b" /* inner slot 1, LPM_TRIE of __u64 */

/* §5.54 (MVP-4.14) D-mvp-4.14-Q1: ADDITIVE +1 bit-vector axis — ethertype (the
 * post-VLAN inner L2 EtherType, exact-match HASH) — a CLONE of the §5.44 proto
 * axis (only the keyed source differs: the inner ethertype, host order).
 * BITVEC_NUM_AXES 8→9 auto-grows the `wildcard` ARRAY's max_entries 16→18 via
 * the XDPMF_RULESET_COUNT * BITVEC_NUM_AXES formula (no literal edit in the
 * .bpf.c decl). New axis index BV_AXIS_ETHERTYPE=8. The ethertype lookup is
 * HOISTED once above the family dispatch (EtherType is the family selector,
 * family-independent) and the axis term is composed into ALL THREE arms (v4,
 * v6, and the NEW non-IP `else` arm) — see design §5.54 Q1. NO closure. */
#define XDPMF_MAP_ETHERTYPE_RULESETS_OUTER_NAME "ethertype_rulesets"  /* ARRAY_OF_MAPS[XDPMF_RULESET_COUNT] of HASH fds */
#define XDPMF_MAP_ETHERTYPE_INNER_A_NAME        "ethertype_bitmask_a" /* inner slot 0, HASH of __u64 */
#define XDPMF_MAP_ETHERTYPE_INNER_B_NAME        "ethertype_bitmask_b" /* inner slot 1, HASH of __u64 */

/* EtherType HASH inner capacity — distinct ethertypes are bounded by the rule
 * count (≤ XDPMF_ALLOWLIST_MAX), NOT the 16-bit key space (D-mvp-4.14-HASH-MAX).
 * Pre-sizing to 65536 would be wasteful; entries ≤ 64 ⇒ no separate bound-check. */
#define XDPMF_ETHERTYPE_HASH_MAX XDPMF_ALLOWLIST_MAX

#define BITVEC_NUM_AXES 9
#define BV_AXIS_DST     0
#define BV_AXIS_SRC     1
#define BV_AXIS_PROTO   2
#define BV_AXIS_PORT    3
#define BV_AXIS_VLAN    4
/* §5.47 (MVP-4.7): axis 5 = src-MAC (eth->h_source) exact-match HASH; the v1
 * MAC allowlist un-frozen as the 6th AND-composed bit-vector axis. */
#define BV_AXIS_MAC     5
/* §5.53 (MVP-4.13): axes 6/7 = IPv6 dst/src CIDR LPM. */
#define BV_AXIS_DST6    6
#define BV_AXIS_SRC6    7
/* §5.54 (MVP-4.14): axis 8 = post-VLAN inner EtherType exact-match HASH. */
#define BV_AXIS_ETHERTYPE 8

/* §5.44 (MVP-4.4) D-mvp-4.4-Q2: production-owned port-range slot — analog of
 * the §5.42 spike's `bv_port_range`. One slot per port-constrained rule; a
 * single port is encoded lo==hi. `lo > hi` marks an UNUSED slot (the datapath
 * port_scan skips it). Types follow the xdpmf_cidr_v4/allow_entry convention:
 * `unsigned int` (not `__u32`) + `unsigned long long` (not `__u64`) because
 * this header is included from BOTH userspace C++ (where `__u32`/`__u64` are
 * not libc types) AND BPF C (where these widths are binary-compatible with
 * kernel `__u32`/`__u64` on every supported arch). The design §5.44 prose
 * wrote `__u32`/`__u64` shorthand; the stated rationale ("per existing
 * convention; BPF+C++ compatible") governs (see impl-notes). */
struct xdpmf_port_range {
    unsigned int       lo;   /* inclusive low  (host order; valid range [0,65535]) */
    unsigned int       hi;   /* inclusive high (host order; valid range [0,65535]) */
    unsigned long long bit;  /* rule bit = 1ULL << rule_id; binary-compat with __u64 */
};

/* §5.29 (MVP-3.4): rules + action_table skeleton — see design §5.29 HG-3.4-1 + Q3.
 *
 * STRUCTURAL-ONLY this slice. Populated on apply; NOT consulted in datapath
 * (mac_filter_prog). MVP-3.4b will wire datapath consumption (gated on the
 * PI-13-3.1 adjudication of the inner-allowlist-value extension).
 *
 * `unsigned char` (not `__u8`) for the same reason as xdpmf_cidr_v4: this
 * header is included from BOTH BPF C (after vmlinux.h) AND userspace C++
 * — `__u8` isn't a libc type, but `unsigned char` is binary-compatible
 * with kernel `__u8` on every supported architecture.
 */
struct rule_entry {
    unsigned char present;     /* 0 = empty slot; 1 = occupied */
    unsigned char action_id;   /* index into action_table; valid range [0, ACTION_MAX-1] */
    unsigned char _pad[2];     /* explicit padding; total sizeof == 4 (u32-aligned) */
};

struct action_entry {
    unsigned char action_type; /* enum xdpmf_action_type */
    unsigned char _pad[3];     /* explicit padding; total sizeof == 4 */
};

enum xdpmf_action_type {
    ACTION_PASS = 0,
    ACTION_DROP = 1,
    ACTION_MAX  = 2,           /* sentinel; future MVP-3.8+ may extend (MIRROR/RL/TAG) */
};

/* §5.34 (MVP-3.4b cycle 2) HG-3.4b-c2-1: `rules` axis promoted to parallel
 * ARRAY_OF_MAPS — DIRECT MIRROR of §5.27 CIDR-axis shape. Inner template +
 * 2 pinned inners + outer; shared `active_idx` commits MAC + CIDR + defaults
 * + rules atomically with a single u32 store. The SHARED `rules` ARRAY pin
 * (and its `XDPMF_MAP_RULES_NAME` constant) is RETIRED — userspace no longer
 * sees a single `${PIN_DIR}/<iface>/rules` dentry. */
#define XDPMF_MAP_RULES_OUTER_NAME    "rules_outer"     /* ARRAY_OF_MAPS[XDPMF_RULESET_COUNT] of ARRAY fds */
#define XDPMF_MAP_RULES_INNER_A_NAME  "rules_a"         /* inner slot 0, ARRAY of struct rule_entry */
#define XDPMF_MAP_RULES_INNER_B_NAME  "rules_b"         /* inner slot 1, ARRAY of struct rule_entry */
#define XDPMF_MAP_ACTION_TABLE_NAME   "action_table"    /* ARRAY[ACTION_MAX] of struct action_entry */

/* §5.31 (MVP-3.4b): inner-allowlist-value extension carrying per-rule id.
 *
 * PI-13-3.4b adjudication = PASS as additive (HG-3.4b-1 + D-3.4b-1). Byte
 * layout is byte-by-byte explicit so the offset-0 `present` byte stays
 * byte-equivalent to PI-27's prior `__u8 present` reading (bpftool dump
 * `format c | head -c 1` still returns 0x01 for occupied slots — old
 * single-byte readers observe the SAME byte at the same offset). The
 * `_pad[3]` is explicit (not implicit ABI padding) so loader-side
 * memset-to-zero on the struct guarantees no uninitialised bytes go to
 * the verifier — pessimistic verifiers reject uninitialised stack reads.
 *
 * Used as INNER value for BOTH `xdpmf_allowlist_inner` (MAC HASH) AND
 * `xdpmf_cidr_inner` (CIDR LPM_TRIE) per T.5 OQ #3 — symmetric. Datapath
 * reads `rule_id` at offset 4 on every successful inner-map lookup and
 * passes it to `bump_rule()` (mac_filter.bpf.c §5.31). */
struct allow_entry {
    unsigned char present;     /* offset 0, size 1: 0x01 = occupied; 0x00 = empty */
    unsigned char _pad[3];     /* offsets 1-3, size 3: explicit u32 alignment padding */
    unsigned int  rule_id;     /* offsets 4-7, size 4: rule_id in [0, XDPMF_ALLOWLIST_MAX-1] */
};                             /* total: 8 bytes */

/* §5.31 (MVP-3.4b) + §5.35 (MVP-3.4d): per-rule packet counter map(s).
 *
 * §5.35 HG-3.4d-4 + D-3.4d-1: rule_counters axis promoted to parallel
 * ARRAY_OF_MAPS — DIRECT MIRROR of §5.34 rules-axis shape (only inner-map
 * type differs: PERCPU_ARRAY vs ARRAY). Single active_idx commits both
 * axes (and the other three) atomically. Inner PERCPU_ARRAYs each carry
 * XDPMF_RULE_COUNTERS_MAX (= 64) __u64 slots; bumped by `bump_rule(rule_id,
 * active)` at the MAC HASH-hit and CIDR LPM_TRIE-hit branches in
 * mac_filter_prog. Read by xdpmf-exporter (rule_counters_reader.cpp) via
 * the active inner pin for the
 * `xdpfilter_rule_match_total{iface, rule_id, action}` Prometheus series. */
#define XDPMF_MAP_RULE_COUNTERS_OUTER_NAME    "rule_counters_outer"  /* ARRAY_OF_MAPS[XDPMF_RULESET_COUNT] of PERCPU_ARRAY fds */
#define XDPMF_MAP_RULE_COUNTERS_INNER_A_NAME  "rule_counters_a"      /* inner slot 0, PERCPU_ARRAY of __u64 */
#define XDPMF_MAP_RULE_COUNTERS_INNER_B_NAME  "rule_counters_b"      /* inner slot 1, PERCPU_ARRAY of __u64 */
/* §5.31 (MVP-3.4b): alias for XDPMF_ALLOWLIST_MAX = 64. Documents that the
 * rule_counters[] index space and the operator's YAML `id:` namespace are
 * IDENTICAL (Q5 R1 + D-3.4b-9 + PI-3.4b-7). */
#define XDPMF_RULE_COUNTERS_MAX      XDPMF_ALLOWLIST_MAX

/* §5.31 EDIT-1 (Phase B Q3 P4 correction): sidecar lives on tmpfs under
 * /run because bpffs (kernel/bpf/inode.c) rejects regular-file creation via
 * EPERM at the inode_create hook. The initial design's Q3 P1 (under bpffs)
 * was retracted at impl Phase B with concrete platform-constraint evidence;
 * `/run` is the systemd-blessed tmpfs convention for ephemeral state. */
#define XDPMF_SIDECAR_ROOT  "/run/xdpmacfilter"

#ifdef __cplusplus
}
#endif
