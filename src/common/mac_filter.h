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
