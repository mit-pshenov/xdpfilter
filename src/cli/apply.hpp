/*
 * apply.hpp — apply orchestrator (design §5.26 Q4 G1).
 *
 * `apply -f <path>` reads a YAML config, validates against schema_version 1,
 * reconciles with --iface (interface-mismatch → ConfigError exit 9), and
 * applies via the §5.26 Q2 A1 atomic-swap mechanism.
 *
 * `apply_config_inmemory` is the same orchestrator with a pre-parsed Config
 * — used by cli.cpp's --allow shorthand path (Q3 BC1).
 *
 * Both functions internally route through src/lib/apply_internal.hpp's
 * `internal::apply()` helper so the atomic-swap semantics live in exactly
 * one place (see §5.26 design dialog: "ONE helper (impl detail)").
 */
#pragma once

#include <cstdint>
#include <string>

#include "lib/config.hpp"
#include "lib/loader.hpp"  // XdpMode

namespace xdpmf {

struct ApplyConfig {
    std::string iface;
    std::string config_path;
    XdpMode     mode = XdpMode::Generic;
};

/* Read + parse + validate the YAML at cfg.config_path, reconcile its
 * `interface:` field (if present) with cfg.iface, and apply.
 * Throws std::system_error with LoaderError codes on failure. */
[[nodiscard]] std::uint32_t apply_config(const ApplyConfig& cfg);

/* Same atomic-swap semantics with a pre-built Config — used by the
 * attach --allow shorthand path. */
[[nodiscard]] std::uint32_t apply_config_inmemory(const std::string& iface,
                                                  const Config&      parsed,
                                                  XdpMode            mode);

}  // namespace xdpmf
