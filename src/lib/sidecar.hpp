/*
 * sidecar.hpp — `rule_index.json` sidecar writer API (§5.31 MVP-3.4b).
 *
 * Loader-side: invoked from `internal::apply_request` post active_idx-flip
 * (D-3.4b-16) so the written sidecar describes the LIVE config. The
 * exporter reads this file per scrape to label per-rule counters with
 * human-readable `action` strings (D-3.4b-3 + Q4 A3).
 *
 * Write is NEVER fatal (D-3.4b-17): a disk-full / permission / transient
 * filesystem error logs a single stderr WARN line and returns silently.
 * The kernel filter has already been committed (active_idx flipped) before
 * this call; failing the apply at this stage would leave the operator in
 * a confused state ("apply reported error but the kernel filter changed").
 *
 * Schema_version emitted = 1 (Q2 S1 defaults-only shape).
 * Path: `<sidecar_root>/<iface>/rule_index.json` (Q3 P4 = `/run/xdpfilter/...`
 * per §5.31 EDIT-1 Phase B platform-constraint correction — bpffs rejects
 * regular-file creation, so /run-tmpfs is the corrected target).
 * Atomic write idiom: write-to-tmp → fsync → rename-into-place; the
 * per-iface directory is mkdir-p'd if missing.
 * Roll-your-own JSON writer (D-3.4b-10) — no nlohmann/json dep.
 */
#pragma once

#include <string_view>

#include "config.hpp"   // xdpmf::Config

namespace xdpmf::sidecar {

/* Write `${sidecar_root}/<iface>/rule_index.json` describing `cfg`.
 *
 * Creates `${sidecar_root}` and `${sidecar_root}/<iface>` if missing (mkdir-p
 * with mode 0755); writes file with mode 0644 (operator + exporter readable;
 * loader runs as root, exporter as CAP_BPF-only).
 *
 * NEVER throws — sidecar-write failures degrade gracefully:
 *   - logs `xdpfilter: WARN: rule_index.json write failed: <errno>` on stderr
 *   - returns silently (apply continues, exits 0)
 *   - exporter degrades to `action="unknown"` labels for the affected iface
 *     until the next successful apply (PI-32-3.4b orphan tolerance)
 *
 * `cfg.rules` is emitted in source-order; `applied_at` uses CLOCK_REALTIME
 * ISO-8601 UTC `YYYY-MM-DDTHH:MM:SSZ` (D-3.4b-20 one-rule-per-line shape). */
void write_rule_index(std::string_view iface,
                      std::string_view sidecar_root,
                      const Config&    cfg) noexcept;

}  // namespace xdpmf::sidecar
