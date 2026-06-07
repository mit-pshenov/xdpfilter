/*
 * cidr.cpp — IPv4 CIDR string parser implementation (§5.27 MVP-3.2).
 *
 * Single entry point: parse_cidr_v4(). Uses POSIX inet_pton(AF_INET, ...)
 * for the address portion (already-network-byte-order, stricter than
 * inet_aton). v6 detection is a literal scan for ':' BEFORE invoking
 * inet_pton — required to surface the v6-specific stderr message
 * (HG-3.2-1) instead of a generic parse error.
 */
#include "cidr.hpp"
#include "loader.hpp"

#include <cstdint>
#include <cstring>
#include <format>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>

#include <arpa/inet.h>  // inet_pton, AF_INET

namespace xdpmf::cidr {

namespace {

[[noreturn]] void throw_cfg(std::string_view file,
                            std::uint32_t    line,
                            std::uint32_t    col,
                            std::string_view message)
{
    std::string what =
        std::format("xdpfilter: config error: {}: {}:{}:{}",
                    message, file, line, col);
    throw std::system_error(make_error_code(LoaderError::ConfigError), std::move(what));
}

/* §5.79 (B47-2): one parser for both families, parameterized by the prefix
 * ceiling (32 for IPv4, 128 for IPv6 — passed by the caller). Returns -1 on any
 * malformed input (empty, non-digit, overflow above `ceiling`). Negatives are
 * caught by the caller scanning for '-' BEFORE calling here — keeps the message
 * catalogue distinct between "empty prefix" and "out of range". */
[[nodiscard]] int parse_prefix(std::string_view s, int ceiling) noexcept
{
    if (s.empty()) return -1;
    int v = 0;
    for (char c : s) {
        if (c < '0' || c > '9') return -1;
        v = v * 10 + (c - '0');
        if (v > ceiling) return -1;  // family ceiling; bail early
    }
    return v;
}

}  // namespace

xdpmf_cidr_v4 parse_cidr_v4(std::string_view s,
                            std::string_view file,
                            std::uint32_t    line,
                            std::uint32_t    col)
{
    if (s.empty()) {
        throw_cfg(file, line, col, "malformed CIDR: empty string");
    }

    // HG-3.2-1: any ':' in the value → v6 family — reject with the
    // specific stderr. Scan BEFORE the slash-split so "::1/128",
    // "2001:db8::/32", and IPv4-mapped-IPv6 (`::ffff:10.0.0.0/104`) all
    // route through the IPv6 message rather than a generic parse error.
    if (s.find(':') != std::string_view::npos) {
        throw_cfg(file, line, col,
                  std::format("IPv6 CIDR not supported until MVP-3.2.5: '{}'", s));
    }

    const auto slash = s.find('/');
    if (slash == std::string_view::npos) {
        throw_cfg(file, line, col,
                  std::format("malformed CIDR: missing prefix length: '{}'", s));
    }

    const std::string_view addr_part   = s.substr(0, slash);
    const std::string_view prefix_part = s.substr(slash + 1);

    if (prefix_part.empty()) {
        throw_cfg(file, line, col,
                  std::format("malformed CIDR: empty prefix length: '{}'", s));
    }

    // Reject explicit signs ('-', '+') before parse_prefix sees only digits.
    // Negative prefix gets the out-of-range message (catalogue line 5).
    if (prefix_part.front() == '-' || prefix_part.front() == '+') {
        throw_cfg(file, line, col,
                  std::format("malformed CIDR: prefix length out of range [0,32]: '{}'", s));
    }

    const int prefix = parse_prefix(prefix_part, 32);
    if (prefix < 0) {
        throw_cfg(file, line, col,
                  std::format("malformed CIDR: prefix length out of range [0,32]: '{}'", s));
    }

    // inet_pton needs NUL-terminated input; substr is not guaranteed
    // terminated. Copy the addr portion into a small stack-safe buffer.
    // INET_ADDRSTRLEN = 16 (incl. NUL); guard against overrun explicitly.
    if (addr_part.size() >= INET_ADDRSTRLEN) {
        throw_cfg(file, line, col,
                  std::format("malformed CIDR: invalid IPv4 address: '{}'", s));
    }
    char addr_cstr[INET_ADDRSTRLEN] = {};
    std::memcpy(addr_cstr, addr_part.data(), addr_part.size());

    in_addr ina{};
    if (::inet_pton(AF_INET, addr_cstr, &ina) != 1) {
        throw_cfg(file, line, col,
                  std::format("malformed CIDR: invalid IPv4 address: '{}'", s));
    }
    const std::uint32_t addr_be = ina.s_addr;  // already network byte order

    // Host-bits-set check: addr_be (network-byte-order) ANDed with the
    // network-byte-order INVERSE-mask must be zero. mask is constructed
    // in host order then htonl'd to compare against addr_be.
    // Edge: prefix == 0 → mask = 0 → host_bits = addr_be (full address);
    // any non-zero address is "bits set below prefix" → reject. Matches
    // the catalogue ("10.0.0.5/8" → hint to 10.0.0.0/8).
    const std::uint32_t mask_host = (prefix == 0)
        ? 0u
        : (0xFFFFFFFFu << static_cast<unsigned>(32 - prefix));
    const std::uint32_t mask_be    = ::htonl(mask_host);
    const std::uint32_t host_bits  = addr_be & ~mask_be;
    if (host_bits != 0) {
        const std::uint32_t network_be = addr_be & mask_be;
        char canon_buf[INET_ADDRSTRLEN] = {};
        in_addr canon_ina{};
        canon_ina.s_addr = network_be;
        (void)::inet_ntop(AF_INET, &canon_ina, canon_buf, sizeof(canon_buf));
        // Pass canon as a C-string (decays via const char*) so std::format
        // uses NUL termination instead of the fixed array length —
        // otherwise embedded NULs corrupt the downstream what() output.
        const char* canon_c = canon_buf;
        throw_cfg(file, line, col,
                  std::format("malformed CIDR: host bits set below prefix: "
                              "'{}' (did you mean {}/{}?)",
                              s, canon_c, prefix));
    }

    xdpmf_cidr_v4 out{};
    out.prefixlen = static_cast<std::uint32_t>(prefix);
    out.addr      = addr_be;
    return out;
}

xdpmf_cidr_v6 parse_cidr_v6(std::string_view s,
                            std::string_view file,
                            std::uint32_t    line,
                            std::uint32_t    col)
{
    if (s.empty()) {
        throw_cfg(file, line, col, "malformed CIDR: empty string");
    }

    const auto slash = s.find('/');
    if (slash == std::string_view::npos) {
        throw_cfg(file, line, col,
                  std::format("malformed IPv6 CIDR: missing prefix length: '{}'", s));
    }

    const std::string_view addr_part   = s.substr(0, slash);
    const std::string_view prefix_part = s.substr(slash + 1);

    if (prefix_part.empty()) {
        throw_cfg(file, line, col,
                  std::format("malformed IPv6 CIDR: empty prefix length: '{}'", s));
    }

    // Reject explicit signs before parse_prefix sees only digits.
    if (prefix_part.front() == '-' || prefix_part.front() == '+') {
        throw_cfg(file, line, col,
                  std::format("malformed IPv6 CIDR: prefix length out of range [0,128]: '{}'", s));
    }

    const int prefix = parse_prefix(prefix_part, 128);
    if (prefix < 0) {
        throw_cfg(file, line, col,
                  std::format("malformed IPv6 CIDR: prefix length out of range [0,128]: '{}'", s));
    }

    // inet_pton needs NUL-terminated input; substr is not guaranteed
    // terminated. INET6_ADDRSTRLEN = 46 (incl. NUL); guard against overrun.
    if (addr_part.size() >= INET6_ADDRSTRLEN) {
        throw_cfg(file, line, col,
                  std::format("malformed IPv6 CIDR: invalid IPv6 address: '{}'", s));
    }
    char addr_cstr[INET6_ADDRSTRLEN] = {};
    std::memcpy(addr_cstr, addr_part.data(), addr_part.size());

    in6_addr in6{};
    if (::inet_pton(AF_INET6, addr_cstr, &in6) != 1) {
        throw_cfg(file, line, col,
                  std::format("malformed IPv6 CIDR: invalid IPv6 address: '{}'", s));
    }

    // Host-bits-set check in the 16-byte (network-order) domain. Build the
    // per-byte network mask for `prefix` bits; addr & ~mask must be all-zero.
    // Byte k is fully inside the prefix if (k+1)*8 <= prefix → 0xFF; fully
    // outside if k*8 >= prefix → 0x00; the boundary byte keeps its top
    // (prefix - k*8) bits. prefix==0 → all bytes 0x00 (every set bit is a host
    // bit → reject a non-zero address).
    unsigned char mask[16] = {};
    for (int k = 0; k < 16; ++k) {
        const int bit_lo = k * 8;
        if (prefix >= bit_lo + 8) {
            mask[k] = 0xFF;
        } else if (prefix <= bit_lo) {
            mask[k] = 0x00;
        } else {
            const int keep = prefix - bit_lo;  // 1..7 top bits
            mask[k] = static_cast<unsigned char>((0xFF << (8 - keep)) & 0xFF);
        }
    }
    bool host_bits = false;
    for (int k = 0; k < 16; ++k) {
        if (in6.s6_addr[k] & static_cast<unsigned char>(~mask[k])) {
            host_bits = true;
            break;
        }
    }
    if (host_bits) {
        in6_addr canon{};
        for (int k = 0; k < 16; ++k) {
            canon.s6_addr[k] = static_cast<unsigned char>(in6.s6_addr[k] & mask[k]);
        }
        char canon_buf[INET6_ADDRSTRLEN] = {};
        (void)::inet_ntop(AF_INET6, &canon, canon_buf, sizeof(canon_buf));
        const char* canon_c = canon_buf;
        throw_cfg(file, line, col,
                  std::format("malformed IPv6 CIDR: host bits set below prefix: "
                              "'{}' (did you mean {}/{}?)",
                              s, canon_c, prefix));
    }

    xdpmf_cidr_v6 out{};
    out.prefixlen = static_cast<std::uint32_t>(prefix);
    std::memcpy(out.addr6, in6.s6_addr, 16);  // already network byte order
    return out;
}

}  // namespace xdpmf::cidr
