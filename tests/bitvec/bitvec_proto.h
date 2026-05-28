/*
 * bitvec_proto.h — MVP-4.2 bit-vector AND-classification SPIKE shared types.
 *
 * §5.42 (rule-model S2). PROTOTYPE-ONLY: this header is consumed by the
 * isolated prototype BPF datapath (tests/bitvec/bitvec_proto.bpf.c) and the
 * test-only populate/dump harness (tests/bitvec/bitvec_harness.cpp). It is
 * DELIBERATELY separate from production src/common/mac_filter.h — the spike's
 * value depends on the production types/datapath staying byte-untouched
 * (D-mvp-4.2-ISOLATION). Do NOT include this from any production TU.
 *
 * Width-stable integer aliases let the SAME struct layouts compile under both
 * the BPF target (vmlinux.h has already typedef'd __u32/__u64 when this header
 * is reached from the .bpf.c) and the C++23 harness (<cstdint>). The on-wire
 * map-value layouts (bv_port_range; the bv_cidr_v4 LPM key) are therefore
 * byte-identical across the producer (harness) and consumer (datapath).
 */
#ifndef XDPMF_TESTS_BITVEC_PROTO_H
#define XDPMF_TESTS_BITVEC_PROTO_H

#if defined(__cplusplus)
#include <cstdint>
typedef std::uint8_t  bv_u8;
typedef std::uint32_t bv_u32;
typedef std::uint64_t bv_u64;
#else
/* BPF target: the .bpf.c includes vmlinux.h before this header. */
typedef __u8  bv_u8;
typedef __u32 bv_u32;
typedef __u64 bv_u64;
#endif

/*
 * §5.42 HG-mvp-4.2-4: N<=64, so the whole rule-match-set is a single u64 and
 * `id` is the bit position in [0, BITVEC_RULE_MAX-1]. Mirrors the production
 * XDPMF_ALLOWLIST_MAX=64 capacity WITHOUT depending on mac_filter.h.
 */
#define BITVEC_RULE_MAX 64

/* §5.42 axes (BITVEC_NUM_AXES = 4): 0=dst-IP (LPM), 1=src-IP (LPM),
 * 2=proto (exact HASH), 3=dst-port (range scan). */
#define BITVEC_NUM_AXES 4
#define BITVEC_AXIS_DST   0
#define BITVEC_AXIS_SRC   1
#define BITVEC_AXIS_PROTO 2
#define BITVEC_AXIS_PORT  3

/* §5.42 D-mvp-4.2-OBSERVABLE: bv_result slot for "no rule matched". Sits one
 * past the last rule id so a clean per-id histogram + a NOMATCH bucket fit in
 * a single PERCPU_ARRAY of BITVEC_RULE_MAX+1 entries. */
#define BITVEC_NOMATCH BITVEC_RULE_MAX

/* §5.42 D-mvp-4.2-ISOLATION: separate bpffs root — the prototype's pins MUST
 * NOT collide with the production XDPMF_BPFFS_ROOT and its maps are NOT in
 * kManagedMaps[] (guard #10). Only bv_result is pinned (the observable). */
#define BITVEC_BPFFS_ROOT "/sys/fs/bpf/xdpmf-bitvec-proto"
#define BITVEC_RESULT_PIN BITVEC_BPFFS_ROOT "/bv_result"

/*
 * LPM_TRIE key — prefixlen FIRST (kernel ABI), addr in network byte order.
 * Same shape as production struct xdpmf_cidr_v4, re-declared here for
 * isolation (D-mvp-4.2-ISOLATION; the design permits an own decl).
 */
struct bv_cidr_v4 {
    bv_u32 prefixlen; /* mask bits, [0,32] */
    bv_u32 addr;      /* IPv4, big-endian (network order) */
};

/*
 * §5.42 D-mvp-4.2-RANGE (Q2 A2): one dst-port range slot scanned by the
 * bounded datapath unroll. `lo > hi` marks an UNUSED slot (skipped). A used
 * slot ORs `bit` into the port-axis survivor mask when lo <= dport <= hi.
 * Port values are HOST byte order on both sides (harness stores host order;
 * datapath compares the bpf_ntohs'd dport).
 */
struct bv_port_range {
    bv_u32 lo;
    bv_u32 hi;
    bv_u64 bit;
};

#endif /* XDPMF_TESTS_BITVEC_PROTO_H */
