/*
 * http.cpp — embedded minimal HTTP/1.0 server (HG-3.4-3).
 *
 * Single-threaded acceptor; per-conn synchronous handler with bounded read
 * budget (4 KiB request line + headers; 5-second read timeout per conn);
 * each response sets `Connection: close` and the socket is closed after.
 *
 * Why hand-rolled (not microhttpd / cpp-httplib): D-3.4-3 "zero non-standard
 * deps" project value. Same reason cli.cpp hand-rolls its argv parser.
 */
#include "http.hpp"

#include "prom_format.hpp"
#include "rule_counters_reader.hpp"   // §5.31 MVP-3.4b
#include "sidecar_reader.hpp"         // §5.31 MVP-3.4b
#include "stats_reader.hpp"

#include "common/logger.hpp"          // §5.32 (MVP-3.5) structured-logging surface
#include "common/mac_filter.h"        // §5.31 EDIT-1: XDPMF_SIDECAR_ROOT (/run/xdpmacfilter)

#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <format>
#include <map>
#include <string>
#include <string_view>
#include <vector>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

namespace xdpmf::exporter {

namespace {

/* sig_atomic_t is the only safely-signal-handlable type per the standard;
 * the accept loop polls this between poll() calls. */
volatile std::sig_atomic_t g_stop = 0;

/* §5.30 HK-17 (MVP-3.4.5): per-scrape all-EACCES detection sets this flag
 * from the /metrics handler; the accept loop polls it alongside g_stop and
 * returns kExitAllEacces (= 6) from run(). main.cpp emits the HK-17 stderr
 * line "immediately before exit(6)" using `g_exit_six_total` for the <N>
 * field. Single-threaded acceptor + per-conn synchronous handler — no
 * atomic needed; volatile + sig_atomic_t suffices for the visibility
 * contract (sig handler reads g_stop, handler thread reads/writes both). */
volatile std::sig_atomic_t g_exit_six       = 0;
std::size_t                g_exit_six_total = 0;

extern "C" void stop_handler(int /*signo*/) noexcept
{
    g_stop = 1;
}

/* Read up to `max_bytes` from `fd` until we see "\r\n\r\n" (end-of-headers)
 * OR a 5-second wall clock budget elapses. Returns the bytes read OR -1 on
 * error / -2 on timeout / -3 on overflow. Defensive against slowloris-style
 * partial-write attackers — the daemon is not high-security but neither
 * should it be trivially DoS-able by a misbehaving scraper.
 *
 * NOT a general HTTP parser — we only need the request line for routing,
 * so we read JUST until headers end. */
[[nodiscard]] int read_request(int fd, std::string& out, std::size_t max_bytes)
{
    using clock = std::chrono::steady_clock;
    const auto deadline = clock::now() + std::chrono::seconds{5};

    out.clear();
    out.reserve(1024);
    char buf[1024];
    while (out.size() < max_bytes) {
        const auto now = clock::now();
        if (now >= deadline) {
            return -2;
        }
        const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
            deadline - now).count();
        struct pollfd pfd{};
        pfd.fd = fd;
        pfd.events = POLLIN;
        const int pr = ::poll(&pfd, 1, static_cast<int>(remaining));
        if (pr < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (pr == 0) {
            return -2;
        }
        const ssize_t n = ::read(fd, buf, sizeof(buf));
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (n == 0) {
            break;  // peer closed
        }
        out.append(buf, buf + n);
        /* Found end-of-headers? */
        if (out.find("\r\n\r\n") != std::string::npos) {
            break;
        }
    }
    if (out.size() > max_bytes) {
        return -3;
    }
    return 0;
}

/* Write the full `data` blob to `fd`, looping on partial writes. Returns
 * true on full success. We don't actually care if the client closed mid-
 * response (Prometheus scrapers may abort on timeout); just don't crash. */
bool write_all(int fd, std::string_view data) noexcept
{
    const char* p   = data.data();
    std::size_t rem = data.size();
    while (rem > 0) {
        const ssize_t n = ::write(fd, p, rem);
        if (n < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        p   += n;
        rem -= static_cast<std::size_t>(n);
    }
    return true;
}

/* Parse the request line (first line of the request). Populates method and
 * path; returns false on malformed shape (caller emits 400). */
[[nodiscard]] bool parse_request_line(std::string_view req,
                                       std::string&     method,
                                       std::string&     path)
{
    const auto eol = req.find("\r\n");
    if (eol == std::string_view::npos) {
        return false;
    }
    std::string_view line = req.substr(0, eol);
    const auto sp1 = line.find(' ');
    if (sp1 == std::string_view::npos) return false;
    const auto sp2 = line.find(' ', sp1 + 1);
    if (sp2 == std::string_view::npos) return false;
    method.assign(line.substr(0, sp1));
    path.assign(line.substr(sp1 + 1, sp2 - sp1 - 1));
    /* version (line.substr(sp2+1)) ignored — we send HTTP/1.0 on responses
     * regardless of the requested version; HTTP/1.1 clients gracefully
     * downgrade per the spec's lower-version-tolerance rule. */
    return true;
}

[[nodiscard]] std::string build_response(int                status,
                                          std::string_view   status_text,
                                          std::string_view   content_type,
                                          std::string_view   body)
{
    return std::format(
        "HTTP/1.0 {} {}\r\n"
        "Content-Type: {}\r\n"
        "Content-Length: {}\r\n"
        "Connection: close\r\n"
        "\r\n"
        "{}",
        status, status_text, content_type, body.size(), body);
}

void handle_connection(int conn_fd, std::string_view bpffs_root)
{
    constexpr std::size_t kMaxRequestBytes = 4096;
    std::string raw;
    const int rrc = read_request(conn_fd, raw, kMaxRequestBytes);
    if (rrc != 0) {
        const std::string resp = build_response(400, "Bad Request",
                                                "text/plain", "bad request\n");
        (void)write_all(conn_fd, resp);
        return;
    }

    std::string method, path;
    if (!parse_request_line(raw, method, path)) {
        const std::string resp = build_response(400, "Bad Request",
                                                "text/plain", "bad request\n");
        (void)write_all(conn_fd, resp);
        return;
    }
    /* Strip query string (we don't accept query params on any route). */
    const auto qpos = path.find('?');
    if (qpos != std::string::npos) {
        path.resize(qpos);
    }

    if (method != "GET") {
        const std::string resp = build_response(405, "Method Not Allowed",
                                                "text/plain", "method not allowed\n");
        (void)write_all(conn_fd, resp);
        return;
    }
    if (path == "/metrics") {
        /* §5.30 HK-17: every scrape populates a DiscoveryAccounting struct.
         * After writing the response, we check the all-EACCES trigger
         * (`total_discovered > 0 && eacces_failures == total_discovered &&
         *  successes == 0`) — if it holds, set the exit-six flag (the
         * accept loop sees it and run() returns 6 to main, which emits
         * the HK-17 stderr line and exits 6 per D-3.4.5-2). Note: we
         * serve the response FIRST so the scraping client sees the
         * empty body, then bail. */
        DiscoveryAccounting acc;
        const auto samples = read_all_attached_with_acc(bpffs_root, acc);

        /* §5.31 (MVP-3.4b) PI-3.4b-6: read the per-rule counter map AND
         * each iface's rule_index.json sidecar; pass both into the
         * formatter for the new `xdpfilter_rule_match_total` series.
         * Sidecar-missing → empty vector → all-orphan path emits
         * `action="unknown"` labels per Q4 A3 + PI-32-3.4b.
         *
         * §5.31 EDIT-1 + D-3.4b-21: sidecar lives under XDPMF_SIDECAR_ROOT
         * = `/run/xdpmacfilter/` (tmpfs); rule_counters map lives under
         * bpffs as before. Two roots; iface key is the join. */
        const auto rule_samples = read_rule_counters(bpffs_root);
        std::map<std::string, std::vector<RuleMeta>> meta_by_iface;
        for (const RuleCountersSample& rs : rule_samples) {
            std::string p{XDPMF_SIDECAR_ROOT};
            p.push_back('/');
            p += rs.iface;
            p += "/rule_index.json";
            meta_by_iface.emplace(rs.iface, parse_rule_index(p));
        }

        const std::string body = emit_metrics(samples, rule_samples, meta_by_iface);
        const std::string resp = build_response(
            200, "OK", "text/plain; version=0.0.4", body);
        (void)write_all(conn_fd, resp);
        if (acc.total_discovered > 0
            && acc.eacces_failures == acc.total_discovered
            && acc.successes       == 0)
        {
            g_exit_six_total = acc.total_discovered;
            g_exit_six       = 1;
        }
        return;
    }
    if (path == "/healthz") {
        const std::string resp = build_response(200, "OK", "text/plain", "ok\n");
        (void)write_all(conn_fd, resp);
        return;
    }
    const std::string resp = build_response(404, "Not Found", "text/plain",
                                             "not found\n");
    (void)write_all(conn_fd, resp);
}

/* Resolve an IPv4 dotted-quad to in_addr. Returns false on parse failure
 * (caller exits 1). IPv6 explicitly OOS this slice (§7 OOS). */
[[nodiscard]] bool parse_bind_addr(std::string_view s, struct in_addr& out)
{
    /* inet_pton wants a NUL-terminated C-string. */
    std::string copy{s};
    return ::inet_pton(AF_INET, copy.c_str(), &out) == 1;
}

/* §5.39 (MVP-3.4h) HG-3.4h-2 + D-3.4h-2: numerical 127.0.0.0/8 check on a
 * post-`inet_pton` `struct in_addr`. Robust vs string-prefix edge cases. */
[[nodiscard]] bool is_loopback_ipv4(struct in_addr addr)
{
    return (addr.s_addr & ::htonl(0xff000000)) == ::htonl(0x7f000000);
}

}  // namespace

void install_signal_handlers()
{
    struct sigaction sa{};
    sa.sa_handler = stop_handler;
    ::sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;  // NOT SA_RESTART — we want poll() to return on signal
    (void)::sigaction(SIGINT,  &sa, nullptr);
    (void)::sigaction(SIGTERM, &sa, nullptr);
    /* SIGPIPE from a client that closed mid-response should NOT kill us;
     * write_all swallows EPIPE via its error return. */
    struct sigaction ign{};
    ign.sa_handler = SIG_IGN;
    ::sigemptyset(&ign.sa_mask);
    (void)::sigaction(SIGPIPE, &ign, nullptr);
}

int run(const HttpConfig& cfg)
{
    struct in_addr bind_inaddr{};
    if (!parse_bind_addr(cfg.bind_addr, bind_inaddr)) {
        /* §5.32 (MVP-3.5): byte-equivalent text-mode + bind_addr in JSON. */
        const std::string msg = std::format(
            "xdpmf-exporter: invalid --bind address: '{}'\n", cfg.bind_addr);
        const xdpmf::logger::Field fs[] = {
            xdpmf::logger::Field{"bind_addr", std::string_view{cfg.bind_addr}},
        };
        xdpmf::logger::emit(xdpmf::logger::Level::Error,
                            "exporter.bind.invalid_addr", msg, fs);
        return 1;
    }

    /* §5.39 (MVP-3.4h) HG-3.4h-3 + Q2: byte-equivalent text-mode WARN +
     * bind_addr field in JSON envelope. Process-scoped (no iface). Fires
     * AFTER parse_bind_addr success, BEFORE ::socket() — visible in stderr
     * ordering BEFORE any bind/listen failure AND BEFORE exporter.listening. */
    if (!is_loopback_ipv4(bind_inaddr)) {
        const std::string warn_msg = std::format(
            "xdpmf-exporter: WARN --bind {} is not loopback (127.0.0.0/8); "
            "/metrics will be exposed on a routable interface\n",
            cfg.bind_addr);
        const xdpmf::logger::Field warn_fields[] = {
            xdpmf::logger::Field{"bind_addr", std::string_view{cfg.bind_addr}},
        };
        xdpmf::logger::emit(xdpmf::logger::Level::Warn,
                            "exporter.warn.bind_non_loopback",
                            warn_msg, warn_fields);
    }

    const int listen_fd = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (listen_fd < 0) {
        const std::string errno_str = std::strerror(errno);
        const std::string msg = std::format(
            "xdpmf-exporter: socket(): {}\n", errno_str);
        const xdpmf::logger::Field fs[] = {
            xdpmf::logger::Field{"errno_str", std::string_view{errno_str}},
            xdpmf::logger::Field{"errno",     static_cast<std::int64_t>(errno)},
        };
        xdpmf::logger::emit(xdpmf::logger::Level::Error,
                            "exporter.bind.socket_failed", msg, fs);
        return 1;
    }

    /* SO_REUSEADDR so a quick restart doesn't TIME_WAIT-stick on the port. */
    int one = 1;
    (void)::setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr   = bind_inaddr;
    addr.sin_port   = ::htons(cfg.port);
    if (::bind(listen_fd, reinterpret_cast<struct sockaddr*>(&addr),
                sizeof(addr)) < 0) {
        const std::string errno_str = std::strerror(errno);
        const std::string msg = std::format(
            "xdpmf-exporter: bind({}:{}): {}\n",
            cfg.bind_addr, cfg.port, errno_str);
        const xdpmf::logger::Field fs[] = {
            xdpmf::logger::Field{"bind_addr", std::string_view{cfg.bind_addr}},
            xdpmf::logger::Field{"port",      static_cast<std::int64_t>(cfg.port)},
            xdpmf::logger::Field{"errno_str", std::string_view{errno_str}},
            xdpmf::logger::Field{"errno",     static_cast<std::int64_t>(errno)},
        };
        xdpmf::logger::emit(xdpmf::logger::Level::Error,
                            "exporter.bind.failed", msg, fs);
        (void)::close(listen_fd);
        return 1;
    }
    if (::listen(listen_fd, 16) < 0) {
        const std::string errno_str = std::strerror(errno);
        const std::string msg = std::format(
            "xdpmf-exporter: listen(): {}\n", errno_str);
        const xdpmf::logger::Field fs[] = {
            xdpmf::logger::Field{"errno_str", std::string_view{errno_str}},
            xdpmf::logger::Field{"errno",     static_cast<std::int64_t>(errno)},
        };
        xdpmf::logger::emit(xdpmf::logger::Level::Error,
                            "exporter.bind.listen_failed", msg, fs);
        (void)::close(listen_fd);
        return 1;
    }

    /* §5.32 (MVP-3.5): the load-bearing operator startup signal. Byte-
     * equivalent text-mode (PI-3.5-1); JSON exposes bind_addr + port. */
    const std::string listening_msg = std::format(
        "xdpmf-exporter: listening on {}:{}\n", cfg.bind_addr, cfg.port);
    const xdpmf::logger::Field listening_fields[] = {
        xdpmf::logger::Field{"bind_addr", std::string_view{cfg.bind_addr}},
        xdpmf::logger::Field{"port",      static_cast<std::int64_t>(cfg.port)},
    };
    xdpmf::logger::emit(xdpmf::logger::Level::Info,
                        "exporter.listening",
                        listening_msg, listening_fields);

    /* §5.30 HK-17: exit the accept loop ALSO when the /metrics handler
     * fires the all-EACCES trigger. run() returns kExitAllEacces below;
     * main.cpp catches the rc + emits the HK-17 stderr line + exit(6). */
    while (g_stop == 0 && g_exit_six == 0) {
        struct pollfd pfd{};
        pfd.fd = listen_fd;
        pfd.events = POLLIN;
        const int pr = ::poll(&pfd, 1, 1000 /* ms */);
        if (pr < 0) {
            if (errno == EINTR) continue;
            /* §5.32 (MVP-3.5): byte-equivalent text-mode + errno in JSON. */
            const std::string errno_str = std::strerror(errno);
            const std::string msg = std::format(
                "xdpmf-exporter: poll(): {}\n", errno_str);
            const xdpmf::logger::Field fs[] = {
                xdpmf::logger::Field{"errno_str", std::string_view{errno_str}},
                xdpmf::logger::Field{"errno",     static_cast<std::int64_t>(errno)},
            };
            xdpmf::logger::emit(xdpmf::logger::Level::Error,
                                "exporter.accept.poll_failed", msg, fs);
            break;
        }
        if (pr == 0) {
            continue;  // poll timeout — re-check g_stop and loop
        }

        struct sockaddr_in client{};
        socklen_t          client_len = sizeof(client);
        const int conn_fd = ::accept4(
            listen_fd,
            reinterpret_cast<struct sockaddr*>(&client),
            &client_len,
            SOCK_CLOEXEC);
        if (conn_fd < 0) {
            if (errno == EINTR) continue;
            /* §5.32 (MVP-3.5): byte-equivalent text-mode + errno in JSON. */
            const std::string errno_str = std::strerror(errno);
            const std::string msg = std::format(
                "xdpmf-exporter: accept(): {}\n", errno_str);
            const xdpmf::logger::Field fs[] = {
                xdpmf::logger::Field{"errno_str", std::string_view{errno_str}},
                xdpmf::logger::Field{"errno",     static_cast<std::int64_t>(errno)},
            };
            xdpmf::logger::emit(xdpmf::logger::Level::Warn,
                                "exporter.accept.failed", msg, fs);
            continue;
        }
        handle_connection(conn_fd, cfg.bpffs_root);
        (void)::close(conn_fd);
    }

    (void)::close(listen_fd);
    /* §5.32 (MVP-3.5): byte-equivalent text-mode (PI-3.5-1) for the
     * shutdown signal. No fields. */
    xdpmf::logger::emit(xdpmf::logger::Level::Info,
                        "exporter.shutdown",
                        "xdpmf-exporter: shutdown\n");
    /* §5.30 HK-17: communicate the all-EACCES exit code through run()'s
     * return. main.cpp reads the value and (if 6) emits the canonical
     * stderr line with last_exit_six_total() and exits 6 itself. */
    if (g_exit_six != 0) {
        return 6;
    }
    return 0;
}

std::size_t last_exit_six_total() noexcept
{
    /* §5.30 HK-17 helper: main.cpp uses this to format the HK-17 stderr
     * line's <N> field (number of discovered interfaces, all of which
     * failed EACCES/EPERM on the scrape that fired the trigger). Always
     * 0 when run() returned 0 (no all-EACCES); >= 1 when run() returned 6. */
    return g_exit_six_total;
}

}  // namespace xdpmf::exporter
