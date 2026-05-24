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

#ifdef __cplusplus
}
#endif
