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
 * Index into the `stats` BPF_MAP_TYPE_ARRAY. Each invocation of the XDP
 * program bumps exactly one slot. STAT_MAX is the array max_entries.
 */
enum mac_filter_stat {
    STAT_PASS = 0,
    STAT_DROP_DENY = 1,
    STAT_DROP_MALFORMED = 2,
    STAT_MAX = 3,
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

#ifdef __cplusplus
}
#endif
