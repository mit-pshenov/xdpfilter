/*
 * mac_filter_bad.bpf.c — verifier-reject fixture for T_VERIFIER_REJECT
 * (design §6.20, MVP-2 Robust / §5.24 Q4 Option (c)).
 *
 * Deliberately contains an unbounded-shape loop (bounded only by a
 * runtime value derived from packet data — `ctx->data_end - ctx->data` —
 * with NO `#pragma unroll`). clang -target bpf accepts this at compile
 * time; the kernel BPF verifier rejects it at bpf()-syscall
 * BPF_PROG_LOAD time, which is exactly the path T_VERIFIER_REJECT
 * exercises in the loader.
 *
 * Skeleton-compatibility constraints (load-bearing for §5.24 Q4):
 *   The loader's XDPMF_BPF_OBJECT_PATH override re-opens THIS .bpf.o
 *   into the skeleton generated from src/bpf/mac_filter.bpf.c. libbpf's
 *   skeleton-populate step looks up maps and programs BY NAME; if the
 *   override .bpf.o is missing any expected name, populate fails with
 *   -ENOENT BEFORE BPF_PROG_LOAD is ever called — surfacing as
 *   "failed to find skeleton map 'allowlist'" stderr instead of the
 *   verifier-shaped diagnostic §6.20 A3 asserts. To reach the verifier:
 *
 *   - Program SEC("xdp") name `mac_filter_prog` MUST match the real
 *     prog (matches the skeleton's prog field).
 *   - Map names `allowlist` and `stats` MUST be present (skeleton
 *     populate looks them up by name).
 *   - Map shapes (types/key-size/value-size/max_entries) match the real
 *     declarations in src/bpf/mac_filter.bpf.c so the skeleton's typed
 *     accessors don't trip subtype mismatches; verifier-reject is
 *     orthogonal to map shape — the program rejection fires on its
 *     own bytecode regardless of map types.
 *
 * The function name `mac_filter_prog` is irrelevant for the
 * verifier-reject path (the verifier fires before any name-based
 * identity gate could run on this never-loaded program), but
 * skeleton-populate's prog-lookup also matches by name — so the
 * matching name is doubly necessary.
 *
 * If a future kernel verifier silently accepts this pattern, the test's
 * SKIP probe catches it and exits 77 (ctest SKIP); manual swap to an
 * OOB-deref backup pattern is the §5.24 Q4 documented fallback.
 *
 * Built via `add_bpf_object(mac_filter_bad …)` in tests/CMakeLists.txt;
 * the .bpf.o is loaded by our C++ loader at runtime when the test sets
 * XDPMF_BPF_OBJECT_PATH=${BUILD_DIR}/mac_filter_bad.bpf.o.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "common/mac_filter.h"

char LICENSE[] SEC("license") = "GPL";

/*
 * Allowlist map — name + shape mirrors src/bpf/mac_filter.bpf.c so the
 * skeleton's populate step succeeds. NOT pinned (LIBBPF_PIN_BY_NAME is
 * omitted) — this object is never reached past the verifier; pinning
 * intent is irrelevant.
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct xdpmf_mac);
    __type(value, __u8);
    __uint(max_entries, XDPMF_ALLOWLIST_MAX);
} allowlist SEC(".maps");

/*
 * Stats map — PERCPU_ARRAY to match the real prog (per §5.23). Same
 * skeleton-populate rationale as `allowlist`.
 */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, STAT_MAX);
} stats SEC(".maps");

SEC("xdp")
int mac_filter_prog(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    int n = (int)((char *)data_end - (char *)data);

    /* `volatile` defeats clang's loop-elimination / closed-form folding,
     * forcing the emitted BPF to contain a runtime-bounded loop that
     * the verifier must walk — and reject — at BPF_PROG_LOAD time.
     * Deliberate: NO `#pragma unroll` directive. */
    volatile int acc = 0;
    for (int i = 0; i < n; i++) {
        acc = acc + 1;
    }

    return (acc != 0) ? XDP_PASS : XDP_DROP;
}
