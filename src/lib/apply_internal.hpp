/*
 * apply_internal.hpp — PRIVATE header (not exported, not installed).
 *
 * Per design §5.26 Phase B EDIT-1 ("Internal layering helper"): exposes
 * the single atomic-apply implementation that drives both
 *   loader::attach()                       (legacy AttachConfig path)
 *   apply::apply_config_inmemory()         (CLI-side Config path)
 * so the active_idx-flip + ruleset/defaults population logic lives in
 * exactly ONE place. Held out of loader.hpp to honour PI-7 (loader.hpp
 * diff = exactly one enumerator line — `ConfigError = 9`).
 *
 * NOT installed; NOT in loader.hpp; namespace `xdpmf::internal` keeps it
 * lexically distinct from the public `xdpmf::` API surface.
 */
#pragma once

#include <cstdint>
#include <optional>
#include <string>

#include "config.hpp"   // xdpmf::Config (already-validated by caller)
#include "loader.hpp"   // xdpmf::XdpMode

namespace xdpmf::internal {

/* Per design §5.26 EDIT-1 contract. Caller is responsible for:
 *   - validating the Config against schema_version 2 (config.cpp::validate),
 *   - reconciling Config.iface with the CLI --iface (mismatch → ConfigError 9).
 * apply_request() then runs the full kernel-touch flow:
 *   kernel-version probe → trust_model env parse + stderr-log →
 *   ifindex resolve → BpffsRootFd → skel load → §5.4 state machine →
 *   ensure per-iface dir → pin maps (fresh) or open pinned (reattach) →
 *   populate inactive inner slot + defaults → atomic active_idx flip →
 *   create+pin XDP link (fresh) or bpf_link__update_program (reattach).
 *
 * Throws std::system_error{LoaderError::*, ...} on any failure.
 * Returns the kernel-assigned prog id of the now-live program. */
struct ApplyRequest {
    std::string iface;   // CLI --iface (authoritative; reconciled with Config.iface upstream)
    XdpMode     mode;    // CLI --mode (forwarded to bpf_link_create on first attach only)
    Config      config;  // fully-validated; default_action + rules drive the kernel-side state
};

[[nodiscard]] std::uint32_t apply_request(const ApplyRequest& req);

/* §5.36 (MVP-3.4e) HG-3.4e-1 + EDIT-1: reset-counters internal-helper
 * entry. Mirrors apply_request's call-shape but with a TIGHTER existence
 * contract — reset-counters operates on host-global BPF pin folders
 * (§5.25 P1 pin-path host-globalness invariant), NOT on netdev ifindex.
 * Caller (src/cli/reset_counters.cpp) is responsible for argv-parse +
 * audit-log emission BEFORE calling. Helper body:
 *   validate_iface_name (shape-check; throws LoaderError::PathRefused on
 *     bad shape) →
 *   BpffsRootFd ctor (root symlink/non-dir → PathRefused) →
 *   iface_entry_is_real_dir
 *     true  → proceed → bpf_obj_get inner_a + inner_b → per-CPU zero
 *             buffer → bpf_map_update_elem zero-write → return true
 *     false → emit reset_counters.refused.no_pin + return false
 *             (operator-observable: CLI exit 1, preserving §5.35
 *             T_CLI_RESET_COUNTERS_NO_IFACE expectation)
 *     symlink/non-dir → throws LoaderError::PathRefused (exit 8)
 *
 * NOTE on `resolve_ifindex` (§5.36 EDIT-1): NOT called. Reset-counters
 * is a BPF-MAP operation on host-global pins; netdev ifindex is
 * unnecessary AND counterproductive in netns-isolated test setups
 * (existing §5.35 ctests run reset-counters from host context against
 * pins created from inside a netns). Pin folder presence is the
 * authoritative attached?-signal.
 *
 * Throws std::system_error{LoaderError::*, ...} on PathRefused class
 * (caller's main.cpp catch arm maps PathRefused → exit 8) and on hard
 * BPF errors (bpf_obj_get failures on real pins, libbpf failures →
 * mapped exit 2). Returns true on success, false on iface-not-attached
 * (CLI maps false → exit 1). */
struct ResetCountersRequest {
    std::string                  iface;
    std::optional<std::uint32_t> rule_id;
};

[[nodiscard]] bool reset_counters_request(const ResetCountersRequest& req);

}  // namespace xdpmf::internal
