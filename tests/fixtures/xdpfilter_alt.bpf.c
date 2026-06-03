/*
 * xdpfilter_alt.bpf.c — tag-mismatch fixture for T_ATTACH_TAG_MISMATCH
 * (design §6.14, MVP-2 Sec).
 *
 * Same `SEC()` function name as the real prog (`xdpfilter_prog`), so the
 * §5.19 name-check PASSES — that is intentional. The §5.22 tag-check is
 * the gate this fixture targets: bytecode body is minimal (return
 * XDP_PASS) so the SHA1 over the bytecode (`bpf_prog_info.tag`) differs
 * from src/bpf/xdpfilter.bpf.c's built object.
 *
 * Load-bearing constraints (per design §6.14):
 *   - Function name MUST be `xdpfilter_prog` (identical to real prog).
 *     Renaming makes this a duplicate of §6.9 (name-mismatch test) and
 *     defeats the tag-axis triangulation.
 *   - Body MUST NOT be a verbatim copy of the real prog's logic — any
 *     trivially-different body works; `return XDP_PASS;` is the minimum.
 *   - `SEC("xdp")` and `SEC("license") = "GPL"` are mandatory (kernel
 *     requires both for an attachable XDP program).
 *
 * Built via `add_bpf_object(xdpfilter_alt …)` in tests/CMakeLists.txt;
 * the .bpf.o output is loaded into the kernel by the test script via
 * `ip link set <iface> xdpgeneric obj …` and is NEVER opened by C++
 * code, so no skeleton header is generated.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

SEC("xdp")
int xdpfilter_prog(struct xdp_md *ctx)
{
    (void)ctx;
    return XDP_PASS;
}
