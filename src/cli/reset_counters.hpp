/*
 * reset_counters.hpp — `xdpfilter reset-counters` subcommand
 * (§5.35 HG-3.4d-1..6, MVP-3.4d).
 *
 * Operator-facing primitive: zero the rule_counters PERCPU map(s) on an
 * iface — either ALL 64 slots (no --rule-id) or a single slot (--rule-id N).
 * Audit-stderr line + iface-must-be-attached precondition. Reuses CLI
 * exit-code 1 for usage / precondition errors; BPF write errors propagate
 * as std::system_error via main.cpp's catch arm. loader.hpp ABI is
 * byte-equivalent across this slice (PI-7-3.4d-hpp 10th consecutive
 * ZERO-diff cycle).
 */
#pragma once

#include <cstdint>
#include <optional>
#include <string>

namespace xdpmf {

/* Parsed `reset-counters` subcommand inputs. Populated by cli::parse();
 * dispatched by main.cpp via the existing ParsedCommand variant-visit
 * pattern. */
struct ResetCountersConfig {
    std::string                   iface;     /* REQUIRED */
    std::optional<std::uint32_t>  rule_id;   /* absent = zero ALL 64 slots; present = zero only slot rule_id */
};

/* Run the reset-counters action: emit audit-log to stderr (mirroring bypass
 * shape per HG-3.4d-6), then open the rule_counters_outer pin(s) and apply
 * zero-writes per rule_id selection (HG-3.4d-1/HG-3.4d-2). Returns exit code
 * (0 on success; 1 on iface-not-attached precondition fail; loader exit codes
 * propagate via std::system_error from main.cpp's catch arm for BPF errors).
 *
 * §5.35 HG-3.4d-4 atomic-swap shape: zeros BOTH inner_a AND inner_b pins
 * (D-3.4d-RESET-BOTH — symmetric reset regardless of subsequent active_idx
 * flips). */
[[nodiscard]] int reset_counters_main(const ResetCountersConfig& cfg);

}  // namespace xdpmf
