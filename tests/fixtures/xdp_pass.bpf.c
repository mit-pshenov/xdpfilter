/*
 * xdp_pass.bpf.c — foreign-XDP fixture for T_ATTACH_ALIEN_REFUSAL (design §6.9).
 *
 * Minimal XDP program returning XDP_PASS unconditionally. The function
 * name `xdp_pass_prog` MUST differ from `xdpfilter_prog` (the entry
 * point in src/bpf/xdpfilter.bpf.c): the §5.19 identity check compares
 * `bpf_prog_info.name` against `"xdpfilter_prog"`; the mismatch here is
 * the load-bearing differentiator that causes our loader to classify
 * this program as alien (state c, exit 4).
 *
 * Built via `add_bpf_object(xdp_pass …)` in tests/CMakeLists.txt
 * (impl's wiring); the .bpf.o output is loaded into the kernel by the
 * test script via `ip link set veth_a xdpgeneric obj …` and is NEVER
 * opened by C++ code, so no skeleton header is generated.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

SEC("xdp")
int xdp_pass_prog(struct xdp_md *ctx)
{
    (void)ctx;
    return XDP_PASS;
}
