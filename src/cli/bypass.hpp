/*
 * bypass.hpp — `xdpfilter bypass` subcommand (§5.29 HG-3.4-2, MVP-3.4).
 *
 * Operator-facing primitive: detach the XDP filter on an interface with an
 * audit-stderr line + non-tty `--unsafe` gate. NO new BPF map flag, NO
 * datapath touch — `bypass` is a CLI-side alias over the existing
 * `loader::detach()` path (PI-30). loader.hpp ABI is byte-equivalent
 * across this slice (PI-7-3.4 4th consecutive ZERO-diff cycle).
 */
#pragma once

#include <string>

namespace xdpmf {

/* Parsed `bypass` subcommand inputs. Populated by cli::parse(); dispatched
 * by main.cpp via the existing ParsedCommand variant-visit pattern. */
struct BypassConfig {
    std::string iface;
    std::string reason;     /* may be empty — audit-log substitutes "UNSPECIFIED" */
    bool        unsafe = false;
};

/* Run the bypass action: tty / --unsafe gating, audit-log to stderr, then
 * delegate to loader::detach(iface). Returns exit code (0 on success or
 * operator-cancelled prompt; 1 on missing --unsafe in non-tty; loader exit
 * codes propagate via std::system_error from main.cpp's catch arm). */
[[nodiscard]] int bypass_main(const BypassConfig& cfg);

}  // namespace xdpmf
