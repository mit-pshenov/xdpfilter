/*
 * materialize.hpp — PRIVATE header (not exported, not installed).
 *
 * §5.76 (MVP-4.36) B43 D-mvp-4.36-Q2-A1: the config→map-cell render contract,
 * shared by loader.cpp (LIVE apply) + the offline dryrun_harness. Declares the
 * three apply-site entry points (`materialize`, `populate_action_table`,
 * `populate_redirect_devmap`) the apply sequence drives, plus the
 * `resolve_ifindex` LINK SEAM (D-mvp-4.36-RESOLVE-SEAM): a multi-caller helper
 * whose REAL def stays in loader.cpp (live if_nametoindex) while the harness
 * links a fake — so it is promoted to an external symbol declared here, NOT
 * moved and NOT threaded through a signature.
 *
 * NOT in loader.hpp (PI-7 zero-diff streak). The render helpers stay file-local
 * in materialize.cpp's anon-namespace; only these four symbols are declared.
 * Fwd-decls `struct xdpfilter_bpf;` (pointer param only) → NO <bpf/libbpf.h>
 * here; the full skel type is needed only in materialize.cpp's compile path.
 */
#pragma once

#include <cstdint>
#include <string>

#include "compiled_ruleset.hpp"  // CompiledRuleset
#include "config.hpp"            // Config
#include "loader.hpp"            // LoaderError

struct xdpfilter_bpf;  // libbpf-skel type; full definition only in materialize.cpp

namespace xdpmf {

/* §5.48/§5.73: populate ALL RESET-on-apply map cells for `slot` from the named
 * CompiledRuleset — 9 axis inners (via inactive_axis_fd + per-axis populate),
 * ruleset_state, rules, slot_rule_id. Byte-identical write-set to the pre-B43
 * loader.cpp body (PI-mvp-4.36-LIVE-IDENTITY). */
void materialize(xdpfilter_bpf* skel, std::uint32_t slot, const CompiledRuleset& cr);

/* §5.29/§5.75: pre-populate action_table with reserved {PASS,DROP,REDIRECT}. */
void populate_action_table(int action_table_fd);

/* §5.75: fill the single global redirect tap (devmap[0] = resolved steering
 * target ifindex), or clear it when no steering. Resolves via resolve_ifindex. */
void populate_redirect_devmap(int devmap_fd, const Config& cfg);

/* §5.4 + D-mvp-4.36-RESOLVE-SEAM: resolve interface name → ifindex, or throw
 * `on_fail`. External link seam: REAL def in loader.cpp (live if_nametoindex);
 * the dryrun_harness links a fake returning a sentinel + recording the name. */
[[nodiscard]] int resolve_ifindex(const std::string& iface, LoaderError on_fail);

}  // namespace xdpmf
