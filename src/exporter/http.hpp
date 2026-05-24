/*
 * http.hpp — embedded minimal HTTP/1.0 server for `xdpmf-exporter` (HG-3.4-3).
 *
 * Plain-socket TCP server, ~150-200 LOC. Routes:
 *   GET /metrics  → 200 OK, text/plain; version=0.0.4, prom_format::emit_metrics()
 *   GET /healthz  → 200 OK, text/plain, body "ok\n"
 *   anything else → 404 Not Found, text/plain, body "not found\n"
 *
 * Threading: single-threaded acceptor + per-conn synchronous handle. The
 * accept loop polls with a 1-second timeout so a SIGINT/SIGTERM stop-flag is
 * observed promptly. NO keep-alive (HTTP/1.0 closes per response).
 */
#pragma once

#include <cstdint>
#include <string>

namespace xdpmf::exporter {

struct HttpConfig {
    std::string   bind_addr;   // default "127.0.0.1"
    std::uint16_t port = 0;    // default 9417 (filled by caller)
    std::string   bpffs_root;  // default XDPMF_BPFFS_ROOT
};

/* Bind / listen / serve until SIGINT/SIGTERM. Returns 0 on clean shutdown,
 * non-zero on fatal bind/listen failure. NEVER throws (top-level daemon
 * function — exceptions caught + logged + non-zero return). */
[[nodiscard]] int run(const HttpConfig& cfg);

/* Signal handler installation. main.cpp installs SIGINT + SIGTERM handlers
 * that flip a global stop flag the accept loop polls. Exposed for testability
 * if needed; main.cpp is the canonical caller. */
void install_signal_handlers();

}  // namespace xdpmf::exporter
