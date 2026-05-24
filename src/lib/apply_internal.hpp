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
#include <string>

#include "config.hpp"   // xdpmf::Config (already-validated by caller)
#include "loader.hpp"   // xdpmf::XdpMode

namespace xdpmf::internal {

/* Per design §5.26 EDIT-1 contract. Caller is responsible for:
 *   - validating the Config against schema_version 1 (config.cpp::validate),
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

}  // namespace xdpmf::internal
