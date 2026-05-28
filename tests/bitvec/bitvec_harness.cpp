/*
 * bitvec_harness.cpp — MVP-4.2 §5.42 test-only loader / populate / dump /
 * detach harness for the isolated bit-vector AND-classification prototype.
 *
 * D-mvp-4.2-ISOLATION: this is a SEPARATE program from the production loader
 * (it does NOT touch src/lib/loader.* or the production apply path). It loads
 * the bitvec_proto skeleton, derives the bit-vector structures from the
 * canonical rule-set (THE source of truth, canonical_ruleset.inc), writes the
 * prototype maps directly via bpf_map_update_elem (HG-mvp-4.2-2: NO config
 * parser), attaches the XDP prog in SKB mode, and pins bv_result under the
 * SEPARATE bpffs root (BITVEC_BPFFS_ROOT). There is NO atomic-swap / [2]
 * doubling here (Q1 spike simplification, D-mvp-4.2-WILDCARD).
 *
 * Subcommands (Interfaces #2):
 *   populate <iface>  load + derive + write maps + attach SKB-mode + pin
 *                     bv_result. rc 0 on success.
 *   dump              print "<id> <count>" for every bv_result slot (incl. the
 *                     NOMATCH bucket at id=BITVEC_NOMATCH), summed across CPUs.
 *   detach <iface>    detach XDP + unpin bv_result + rmdir the bpffs root.
 *
 * The #1 bit-vector trap (FI-1) lives in close_prefixes(): each stored LPM
 * mask MUST be the OR of every COVERING (less-or-equally-specific) rule's bit,
 * NOT just the rule's own bit. Getting the cover-direction backwards is the
 * classic bug the §5.42 overlap + first-match-tie vectors are designed to
 * catch.
 */
#include <arpa/inet.h>
#include <linux/if_link.h>
#include <net/if.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <utility>
#include <string>
#include <string_view>
#include <vector>

#include "bitvec_proto.h"
#include "bitvec_proto.skel.h"

#include "canonical_ruleset.inc"

namespace {

/* One constrained prefix on an LPM axis: host-order network address +
 * prefixlen + the owning rule's bit. */
struct PrefixEntry {
    std::uint32_t host_addr; /* network address, HOST byte order (for masking) */
    std::uint32_t prefixlen;
    std::uint64_t bit;
};

/* Parse "a.b.c.d/len" → (network-order addr, host-order addr, prefixlen).
 * Returns false on malformed input. */
[[nodiscard]] bool parse_cidr(std::string_view cidr,
                              std::uint32_t&   net_addr,
                              std::uint32_t&   host_addr,
                              std::uint32_t&   prefixlen)
{
    const auto slash = cidr.find('/');
    if (slash == std::string_view::npos) {
        return false;
    }
    const std::string addr_part{cidr.substr(0, slash)};
    const std::string len_part{cidr.substr(slash + 1)};

    in_addr a{};
    if (::inet_pton(AF_INET, addr_part.c_str(), &a) != 1) {
        return false;
    }
    net_addr  = a.s_addr;            /* network byte order */
    host_addr = ::ntohl(a.s_addr);   /* host byte order for prefix masking */

    char*               end = nullptr;
    const unsigned long len = std::strtoul(len_part.c_str(), &end, 10);
    if (end == len_part.c_str() || *end != '\0' || len > 32) {
        return false;
    }
    prefixlen = static_cast<std::uint32_t>(len);
    return true;
}

/* Host-order mask for a prefix length ([0,32]). len==0 → all-zero mask. */
[[nodiscard]] std::uint32_t host_mask(std::uint32_t prefixlen)
{
    if (prefixlen == 0) {
        return 0;
    }
    return 0xFFFFFFFFu << (32u - prefixlen);
}

/* FI-1 prefix-closure: for each prefix P_i in `entries`, OR in bit_j of every
 * P_j that COVERS P_i (P_j.prefixlen <= P_i.prefixlen AND P_j == P_i truncated
 * to P_j.prefixlen), INCLUDING P_i itself. The cover direction is the trap:
 * the less-specific (shorter) prefix's bit flows INTO the more-specific
 * (longer) prefix's stored mask, so a longest-prefix LPM hit carries every
 * covering rule. Returns the closed mask aligned 1:1 with `entries`. */
[[nodiscard]] std::vector<std::uint64_t>
close_prefixes(const std::vector<PrefixEntry>& entries)
{
    std::vector<std::uint64_t> closed(entries.size(), 0);
    for (std::size_t i = 0; i < entries.size(); ++i) {
        const PrefixEntry& pi = entries[i];
        for (const PrefixEntry& pj : entries) {
            if (pj.prefixlen > pi.prefixlen) {
                continue; /* pj more specific than pi → cannot cover it */
            }
            const std::uint32_t m = host_mask(pj.prefixlen);
            if ((pi.host_addr & m) == (pj.host_addr & m)) {
                closed[i] |= pj.bit; /* pj covers pi (incl. pi==pj) */
            }
        }
    }
    return closed;
}

/* Update one map slot; logs + returns false on failure. */
[[nodiscard]] bool map_update(int fd, const void* key, const void* val,
                              std::string_view what)
{
    const int rc = ::bpf_map_update_elem(fd, key, val, BPF_ANY);
    if (rc != 0) {
        std::fprintf(stderr, "bitvec_harness: bpf_map_update_elem(%.*s) failed: %s\n",
                     static_cast<int>(what.size()), what.data(),
                     std::strerror(-rc));
        return false;
    }
    return true;
}

/* Populate one LPM axis (dst or src) with the prefix-closed masks. */
[[nodiscard]] bool populate_lpm(int fd, const std::vector<PrefixEntry>& entries,
                                std::string_view axis)
{
    const std::vector<std::uint64_t> closed = close_prefixes(entries);
    for (std::size_t i = 0; i < entries.size(); ++i) {
        bv_cidr_v4 key{};
        key.prefixlen = entries[i].prefixlen;
        key.addr      = ::htonl(entries[i].host_addr); /* LPM key = network order */
        const std::uint64_t mask = closed[i];
        if (!map_update(fd, &key, &mask, axis)) {
            return false;
        }
    }
    return true;
}

[[nodiscard]] int do_populate(const char* iface)
{
    const unsigned ifindex = ::if_nametoindex(iface);
    if (ifindex == 0) {
        std::fprintf(stderr, "bitvec_harness: unknown iface '%s'\n", iface);
        return 1;
    }

    bitvec_proto_bpf* skel = bitvec_proto_bpf__open_and_load();
    if (skel == nullptr) {
        std::fprintf(stderr, "bitvec_harness: skeleton open_and_load failed\n");
        return 1;
    }

    int rc = 1;
    do {
        /* ── Derive the bit-vector structures from the canonical set ──── */
        std::vector<PrefixEntry> dst_prefixes;
        std::vector<PrefixEntry> src_prefixes;
        std::uint64_t            wildcard[BITVEC_NUM_AXES] = {0, 0, 0, 0};
        /* proto → OR of bits sharing that exact proto number. */
        std::vector<std::pair<std::uint32_t, std::uint64_t>> proto_masks;
        std::vector<bv_port_range>                           port_slots;
        std::uint8_t actions[BITVEC_RULE_MAX] = {};

        auto or_proto = [&](std::uint32_t proto, std::uint64_t bit) {
            for (auto& pm : proto_masks) {
                if (pm.first == proto) {
                    pm.second |= bit;
                    return;
                }
            }
            proto_masks.emplace_back(proto, bit);
        };

        bool parse_ok = true;
        for (std::size_t i = 0; i < BITVEC_CANONICAL_RULE_COUNT; ++i) {
            const bv_rule&      r   = kCanonicalRules[i];
            const std::uint64_t bit = 1ULL << r.id;

            if (r.dst_cidr != nullptr) {
                std::uint32_t net = 0, host = 0, len = 0;
                if (!parse_cidr(r.dst_cidr, net, host, len)) {
                    parse_ok = false;
                    break;
                }
                dst_prefixes.push_back(PrefixEntry{host, len, bit});
            } else {
                wildcard[BITVEC_AXIS_DST] |= bit;
            }

            if (r.src_cidr != nullptr) {
                std::uint32_t net = 0, host = 0, len = 0;
                if (!parse_cidr(r.src_cidr, net, host, len)) {
                    parse_ok = false;
                    break;
                }
                src_prefixes.push_back(PrefixEntry{host, len, bit});
            } else {
                wildcard[BITVEC_AXIS_SRC] |= bit;
            }

            if (r.proto >= 0) {
                or_proto(static_cast<std::uint32_t>(r.proto), bit);
            } else {
                wildcard[BITVEC_AXIS_PROTO] |= bit;
            }

            if (r.port_lo >= 0) {
                bv_port_range pr{};
                pr.lo  = static_cast<std::uint32_t>(r.port_lo);
                pr.hi  = static_cast<std::uint32_t>(r.port_hi);
                pr.bit = bit;
                port_slots.push_back(pr);
            } else {
                wildcard[BITVEC_AXIS_PORT] |= bit;
            }

            if (r.id < BITVEC_RULE_MAX) {
                actions[r.id] = static_cast<std::uint8_t>(r.action);
            }
        }
        if (!parse_ok) {
            std::fprintf(stderr, "bitvec_harness: malformed CIDR in canonical set\n");
            break;
        }

        /* ── Write the maps ───────────────────────────────────────────── */
        if (!populate_lpm(bpf_map__fd(skel->maps.bv_dst_lpm), dst_prefixes, "bv_dst_lpm")) {
            break;
        }
        if (!populate_lpm(bpf_map__fd(skel->maps.bv_src_lpm), src_prefixes, "bv_src_lpm")) {
            break;
        }

        bool map_ok = true;
        const int proto_fd = bpf_map__fd(skel->maps.bv_proto_hash);
        for (const auto& pm : proto_masks) {
            const std::uint32_t key  = pm.first;
            const std::uint64_t mask = pm.second;
            if (!map_update(proto_fd, &key, &mask, "bv_proto_hash")) {
                map_ok = false;
                break;
            }
        }
        if (!map_ok) {
            break;
        }

        /* Port-range ARRAY: mark ALL slots unused (lo=1 > hi=0) first, then
         * fill the constrained ones. A zero-initialised slot (lo=hi=0) would
         * spuriously match dport 0 on bit 0 — hence the explicit sentinel. */
        const int port_fd = bpf_map__fd(skel->maps.bv_port_ranges);
        for (std::uint32_t i = 0; i < BITVEC_RULE_MAX; ++i) {
            bv_port_range pr{};
            if (i < port_slots.size()) {
                pr = port_slots[i];
            } else {
                pr.lo  = 1;
                pr.hi  = 0; /* unused sentinel: lo > hi */
                pr.bit = 0;
            }
            if (!map_update(port_fd, &i, &pr, "bv_port_ranges")) {
                map_ok = false;
                break;
            }
        }
        if (!map_ok) {
            break;
        }

        const int wc_fd = bpf_map__fd(skel->maps.bv_wildcard);
        for (std::uint32_t a = 0; a < BITVEC_NUM_AXES; ++a) {
            if (!map_update(wc_fd, &a, &wildcard[a], "bv_wildcard")) {
                map_ok = false;
                break;
            }
        }
        if (!map_ok) {
            break;
        }

        const int act_fd = bpf_map__fd(skel->maps.bv_action);
        for (std::uint32_t id = 0; id < BITVEC_RULE_MAX; ++id) {
            if (!map_update(act_fd, &id, &actions[id], "bv_action")) {
                map_ok = false;
                break;
            }
        }
        if (!map_ok) {
            break;
        }

        /* ── Attach XDP (SKB / generic mode) ──────────────────────────── */
        const int prog_fd = bpf_program__fd(skel->progs.bitvec_proto_prog);
        const int arc = ::bpf_xdp_attach(static_cast<int>(ifindex), prog_fd,
                                         XDP_FLAGS_SKB_MODE, nullptr);
        if (arc != 0) {
            std::fprintf(stderr, "bitvec_harness: bpf_xdp_attach failed: %s\n",
                         std::strerror(-arc));
            break;
        }

        /* ── Pin bv_result under the SEPARATE bpffs root ──────────────── */
        std::error_code ec;
        std::filesystem::create_directories(BITVEC_BPFFS_ROOT, ec);
        if (ec) {
            std::fprintf(stderr, "bitvec_harness: mkdir %s failed: %s\n",
                         BITVEC_BPFFS_ROOT, ec.message().c_str());
            ::bpf_xdp_detach(static_cast<int>(ifindex), XDP_FLAGS_SKB_MODE, nullptr);
            break;
        }
        std::filesystem::remove(BITVEC_RESULT_PIN, ec); /* best-effort stale pin */
        const int prc = bpf_map__pin(skel->maps.bv_result, BITVEC_RESULT_PIN);
        if (prc != 0) {
            std::fprintf(stderr, "bitvec_harness: pin %s failed: %s\n",
                         BITVEC_RESULT_PIN, std::strerror(-prc));
            ::bpf_xdp_detach(static_cast<int>(ifindex), XDP_FLAGS_SKB_MODE, nullptr);
            break;
        }

        rc = 0; /* attached prog + populated maps persist via the netdev
                 * reference; bv_result additionally held by its pin. */
    } while (false);

    bitvec_proto_bpf__destroy(skel);
    return rc;
}

[[nodiscard]] std::size_t round_up_8(std::size_t n)
{
    return (n + 7u) & ~static_cast<std::size_t>(7u);
}

[[nodiscard]] int do_dump()
{
    const int fd = ::bpf_obj_get(BITVEC_RESULT_PIN);
    if (fd < 0) {
        std::fprintf(stderr, "bitvec_harness: bpf_obj_get(%s) failed: %s\n",
                     BITVEC_RESULT_PIN, std::strerror(errno));
        return 1;
    }

    const int num_cpus = ::libbpf_num_possible_cpus();
    if (num_cpus <= 0) {
        std::fprintf(stderr, "bitvec_harness: libbpf_num_possible_cpus failed\n");
        ::close(fd);
        return 1;
    }
    const std::size_t per_slot = round_up_8(sizeof(std::uint64_t));
    std::vector<std::uint8_t> buf(static_cast<std::size_t>(num_cpus) * per_slot, 0);

    int rc = 0;
    for (std::uint32_t key = 0; key <= BITVEC_NOMATCH; ++key) {
        std::uint64_t total = 0;
        if (::bpf_map_lookup_elem(fd, &key, buf.data()) == 0) {
            for (int cpu = 0; cpu < num_cpus; ++cpu) {
                std::uint64_t v = 0;
                std::memcpy(&v,
                            buf.data() + static_cast<std::size_t>(cpu) * per_slot,
                            sizeof(std::uint64_t));
                total += v;
            }
        } else {
            rc = 1;
        }
        std::printf("%u %llu\n", key,
                    static_cast<unsigned long long>(total));
    }
    ::close(fd);
    return rc;
}

[[nodiscard]] int do_detach(const char* iface)
{
    const unsigned ifindex = ::if_nametoindex(iface);
    int rc = 0;
    if (ifindex == 0) {
        std::fprintf(stderr, "bitvec_harness: unknown iface '%s'\n", iface);
        rc = 1;
    } else {
        const int drc = ::bpf_xdp_detach(static_cast<int>(ifindex),
                                         XDP_FLAGS_SKB_MODE, nullptr);
        if (drc != 0) {
            std::fprintf(stderr, "bitvec_harness: bpf_xdp_detach failed: %s\n",
                         std::strerror(-drc));
            rc = 1;
        }
    }
    std::error_code ec;
    std::filesystem::remove(BITVEC_RESULT_PIN, ec);
    std::filesystem::remove(BITVEC_BPFFS_ROOT, ec); /* rmdir if now empty */
    return rc;
}

void usage()
{
    std::fprintf(stderr,
                 "usage: bitvec_harness populate <iface>\n"
                 "       bitvec_harness dump\n"
                 "       bitvec_harness detach <iface>\n");
}

} // namespace

int main(int argc, char** argv)
{
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    if (argc < 2) {
        usage();
        return 2;
    }
    const std::string_view cmd{argv[1]};

    if (cmd == "populate") {
        if (argc != 3) {
            usage();
            return 2;
        }
        return do_populate(argv[2]);
    }
    if (cmd == "dump") {
        if (argc != 2) {
            usage();
            return 2;
        }
        return do_dump();
    }
    if (cmd == "detach") {
        if (argc != 3) {
            usage();
            return 2;
        }
        return do_detach(argv[2]);
    }

    usage();
    return 2;
}
