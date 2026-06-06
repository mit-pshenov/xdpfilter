/*
 * materialize.cpp — config→map-cell render subset (the host side of apply).
 *
 * §5.76 (MVP-4.36) B43: MOVED whole-cloth from loader.cpp (guard #9 — MOVE,
 * not re-implement). Holds the render helpers (`populate_*_inner_slot`,
 * `write_ruleset_state`, `write_slot_rule_id`, `inactive_axis_fd`) + the three
 * apply-site entry points (`materialize`, `populate_action_table`,
 * `populate_redirect_devmap`). The emitted bpf_map_* write-set is byte-identical
 * to the pre-B43 loader.cpp (PI-mvp-4.36-LIVE-IDENTITY): the LIVE apply path and
 * the offline dryrun_harness drive the SAME object code (single source of truth).
 *
 * This TU references ONLY {loader_error symbols, compiled_ruleset close_prefixes*,
 * the resolve_ifindex link seam, fakeable bpf_*} outside its own file-local
 * helpers — nothing loader.cpp-local (D-mvp-4.36-MOVE-BYTE-IDENTICAL). The
 * bpf headers + skel.h includes are COMPILE-path only (SPIKE-1: the dryrun_harness
 * links a recording fake of the bpf_map_* surface, not libbpf).
 */
#include "materialize.hpp"

#include "compiled_ruleset.hpp"  // §5.73 close_prefixes / close_prefixes6
#include "config.hpp"
#include "loader_error.hpp"      // §5.76 classify / throw_loader
#include "map_writer.hpp"        // §5.77 object seam: map_* wrappers + map_resolve_ifindex (D-mvp-4.37-Q1-OBJSEAM)

#include <array>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <format>
#include <span>
#include <type_traits>
#include <unordered_map>
#include <utility>
#include <vector>

#include <bpf/bpf.h>

extern "C" {
#include "xdpfilter.skel.h"  // struct xdpfilter_bpf (full type; compile-path only)
}

#include "common/xdpfilter.h"

namespace xdpmf {

namespace {

/* §5.50 (MVP-4.10 B28-1) unify populate_inner_slot (mac, §5.47 D-mvp-4.7-Q1) /
 * populate_proto_inner_slot (§5.44) / populate_vlan_inner_slot (§5.45) into ONE
 * monomorphized template (rule-of-three OVERRIDES guard #9 per §5.37 /
 * D-3.4f-1). The three were byte-shape-identical (the old populate_vlan comment
 * already asserted "IDENTICAL shape to populate_proto_inner_slot") — differing
 * ONLY by the inner-map HASH key type (xdpmf_mac / __u32) + a diagnostic label.
 * Each inner value is a per-key aggregated rule-bitmask (bit k set iff rule k
 * constrains this exact key). EXACT match, NO prefix-closure. Bulk-clear (get_
 * next_key -> delete_elem, ENOENT-terminated) THEN insert (update_elem BPF_ANY);
 * the map is small (<= XDPMF_ALLOWLIST_MAX entries) so the clear cost is
 * bounded. `Key{}` value-init covers xdpmf_mac{} (zeroed) and __u32{} (=0),
 * matching the originals' prev{}/cur{} vs prev=0/cur=0. `what` is the diagnostic
 * label ("mac"/"proto"/"vlan"); error strings are key-agnostic — the old
 * proto/vlan key-in-message embed is dropped (D-mvp-4.10-DIAG; error path only,
 * not test-pinned). RESET-on-apply: caller passes the INACTIVE inner fd and
 * writes BEFORE the active_idx flip. */
template<class Key>
void populate_hash_inner_slot(int inner_fd,
                              const std::vector<std::pair<Key, std::uint64_t>>& entries,
                              const char* what)
{
    // Bulk-clear: iterate keys via bpf_map_get_next_key and delete each.
    Key  prev{};
    Key  cur{};
    bool have_prev = false;
    while (true) {
        const int rc = map_next_key(inner_fd,
                                            have_prev ? &prev : nullptr,
                                            &cur);
        if (rc != 0) {
            if (-rc == ENOENT) break;
            throw_loader(classify(rc, LoaderError::LoadFailed),
                         std::format("bpf_map_get_next_key({}_inner): {}",
                                     what, std::strerror(-rc)));
        }
        const int drc = map_delete(inner_fd, &cur);
        if (drc != 0 && -drc != ENOENT) {
            throw_loader(classify(drc, LoaderError::LoadFailed),
                         std::format("bpf_map_delete_elem({}_inner): {}",
                                     what, std::strerror(-drc)));
        }
        prev      = cur;
        have_prev = true;
    }
    for (const std::pair<Key, std::uint64_t>& e : entries) {
        const Key           key  = e.first;
        const std::uint64_t mask = e.second;
        const int rc = map_update(inner_fd, &key, &mask, BPF_ANY);
        if (rc < 0) {
            throw_loader(classify(rc, LoaderError::LoadFailed),
                         std::format("bpf_map_update_elem({}_inner): {}",
                                     what, std::strerror(-rc)));
        }
    }
}

/* §5.43 (MVP-4.3) D-mvp-4.3-Q1/Q3 + §5.71 (MVP-4.31) B5: populate one LPM
 * bit-vector axis inner — value-reshaped to a __u64 prefix-closed bitmask.
 * ONE template (D-mvp-4.31-Q1, mirroring populate_hash_inner_slot<Key>)
 * covering BOTH the v4 axes (dst_bitmask/cidr_allowlist, key xdpmf_cidr_v4,
 * close_prefixes) and the v6 axes (dst6_bitmask/src6_bitmask, key
 * xdpmf_cidr_v6, close_prefixes6) — the two forks differed ONLY in key type +
 * prefix-vec element type + the close fn + the "bitvec_inner"/"bitvec6_inner"
 * diagnostic label. The close fn is passed as a SEPARATE arg: guard #23's
 * cover-direction trap lives in close_prefixes/close_prefixes6, which stay TWO
 * separate named definitions, NOT merged. Bulk-clear-then-insert preserved.
 * RESET-on-apply: the caller passes the INACTIVE inner fd and writes BEFORE
 * the active_idx flip (D-mvp-4.3-RESET-VS-PRESERVE — match maps reflect only
 * the current config; NO copy-forward). */
template<class Prefix, class CloseFn>
void populate_bitvec_inner_slot(int                        inner_fd,
                                const std::vector<Prefix>& prefixes,
                                CloseFn                    close_fn,
                                const char*                what)
{
    using Key = std::remove_cvref_t<decltype(std::declval<Prefix>().cidr)>;
    Key  prev{};
    Key  cur{};
    bool have_prev = false;
    while (true) {
        const int rc = map_next_key(inner_fd,
                                            have_prev ? &prev : nullptr,
                                            &cur);
        if (rc != 0) {
            if (-rc == ENOENT) break;
            throw_loader(classify(rc, LoaderError::LoadFailed),
                         std::format("bpf_map_get_next_key({}): {}",
                                     what, std::strerror(-rc)));
        }
        const int drc = map_delete(inner_fd, &cur);
        if (drc != 0 && -drc != ENOENT) {
            throw_loader(classify(drc, LoaderError::LoadFailed),
                         std::format("bpf_map_delete_elem({}): {}",
                                     what, std::strerror(-drc)));
        }
        prev      = cur;
        have_prev = true;
    }
    // FI-1 cover-closure: each entry's stored __u64 = OR of every covering
    // rule's bit (close_fn). Duplicate prefixes (two rules sharing an exact
    // prefix) get IDENTICAL closed masks and collapse to one map entry.
    const std::vector<std::uint64_t> closed = close_fn(prefixes);
    for (std::size_t i = 0; i < prefixes.size(); ++i) {
        const Key           key  = prefixes[i].cidr;  // addr already network order
        const std::uint64_t mask = closed[i];
        const int rc = map_update(inner_fd, &key, &mask, BPF_ANY);
        if (rc < 0) {
            throw_loader(classify(rc, LoaderError::LoadFailed),
                         std::format("bpf_map_update_elem({}): {}",
                                     what, std::strerror(-rc)));
        }
    }
}

/* §5.44 (MVP-4.4) D-mvp-4.4-Q2 + D-mvp-4.4-PORT-ARRAY-CLEAR: populate one
 * dst_port-axis ARRAY inner (port_ranges_<a|b>). BPF ARRAY maps have no
 * delete, so clear by overwriting ALL XDPMF_ALLOWLIST_MAX slots with the
 * UNUSED sentinel {lo=1, hi=0, bit=0} (lo>hi → datapath port_scan skips it),
 * then write the used range slots (mirrors populate_rules_inner_slot's
 * clear-all-slots-then-write precedent). RESET-on-apply: caller passes the
 * INACTIVE inner fd and writes BEFORE the active_idx flip.
 *
 * B18 (§5.49) PRODUCER end of a NON-LOCAL coupling: the datapath port_scan
 * early-`break`s on the first lo>hi sentinel. That break is correct ONLY
 * because this function packs used slots DENSE-AT-FRONT (ranges[0..N-1]
 * contiguous after the bulk-clear) AND config.cpp parse_dst_port guarantees
 * every real range has lo<=hi (so no real slot can masquerade as a sentinel).
 * Do NOT introduce gaps/holes in the used-slot range or the break would skip
 * legit slots. Consumer note: port_scan in xdpfilter.bpf.c — guard #26. */
void populate_port_inner_slot(int inner_fd, const std::vector<xdpmf_port_range>& ranges)
{
    /* Clear all slots to the unused sentinel (lo>hi). */
    xdpmf_port_range unused{};
    unused.lo  = 1;
    unused.hi  = 0;
    unused.bit = 0;
    for (std::uint32_t k = 0; k < static_cast<std::uint32_t>(XDPMF_ALLOWLIST_MAX); ++k) {
        const int rc = map_update(inner_fd, &k, &unused, BPF_ANY);
        if (rc < 0) {
            throw_loader(classify(rc, LoaderError::LoadFailed),
                         std::format("bpf_map_update_elem(port_inner[{}] clear): {}",
                                     k, std::strerror(-rc)));
        }
    }
    /* Then write the used range slots. range count ≤ rule count ≤
     * XDPMF_ALLOWLIST_MAX (bounded by apply_request's pre-check). */
    for (std::uint32_t i = 0; i < ranges.size(); ++i) {
        const xdpmf_port_range slot = ranges[i];
        const int rc = map_update(inner_fd, &i, &slot, BPF_ANY);
        if (rc < 0) {
            throw_loader(classify(rc, LoaderError::LoadFailed),
                         std::format("bpf_map_update_elem(port_inner[{}]): {}",
                                     i, std::strerror(-rc)));
        }
    }
}

/* §5.70 (MVP-4.30) B35 [supersedes §5.43 write_wildcard_slots + write_default_slot]:
 * write the INACTIVE half of the single combined `ruleset_state` ARRAY-of-struct
 * before the active_idx flip — the 9 per-axis wildcard halves (wc[BV_AXIS_*]) PLUS
 * the folded default_action, in ONE bpf_map_update_elem (ARRAY values are written
 * whole). The struct is ZERO-initialised (`val{}`) so `_pad` carries no
 * uninitialised bytes (D-mvp-4.30-LAYOUT). RESET-write (no copy-forward,
 * D-mvp-4.30-RESET): the whole struct is recomputed fresh each apply; the single
 * active_idx u32 store commits the ruleset_state swap together with the
 * dst/src/proto/port/vlan/mac/dst6/src6/rules/rule_counters swap. */
void write_ruleset_state(int ruleset_state_fd, std::uint32_t inactive,
                         std::uint64_t wc_dst, std::uint64_t wc_src,
                         std::uint64_t wc_proto, std::uint64_t wc_port,
                         std::uint64_t wc_vlan, std::uint64_t wc_mac,
                         std::uint64_t wc_dst6, std::uint64_t wc_src6,
                         std::uint64_t wc_eth, DefaultAction default_action)
{
    struct xdpmf_ruleset_state val{};
    val.wc[BV_AXIS_DST]       = wc_dst;
    val.wc[BV_AXIS_SRC]       = wc_src;
    val.wc[BV_AXIS_PROTO]     = wc_proto;
    val.wc[BV_AXIS_PORT]      = wc_port;
    val.wc[BV_AXIS_VLAN]      = wc_vlan;
    val.wc[BV_AXIS_MAC]       = wc_mac;
    val.wc[BV_AXIS_DST6]      = wc_dst6;
    val.wc[BV_AXIS_SRC6]      = wc_src6;
    val.wc[BV_AXIS_ETHERTYPE] = wc_eth;
    val.default_action = (default_action == DefaultAction::Pass) ? 1u : 0u;

    const int rc = map_update(ruleset_state_fd, &inactive, &val, BPF_ANY);
    if (rc < 0) {
        throw_loader(classify(rc, LoaderError::LoadFailed),
                     std::format("bpf_map_update_elem(ruleset_state[{}]): {}",
                                 inactive, std::strerror(-rc)));
    }
}

/* §5.34 populate the INACTIVE `rules` inner ARRAY slot from the validated
 * Config (per-axis inactive-slot pattern). The caller writes BEFORE the
 * active_idx flip so the single u32 store commits rules with the other axes.
 *
 * Encoding: a Config.rules entry with action=Pass becomes {present=1,
 * action_id=ACTION_PASS}; Drop becomes {present=1, action_id=ACTION_DROP}.
 * Empty slots written as {present=0, action_id=0} so a removed rule doesn't
 * leave stale state. BOTH pass and drop rules are written faithfully; the
 * action discrimination happens downstream at the rules→action_table chain. */
void populate_rules_inner_slot(int rules_inner_fd, std::span<const Rule> rules,
    const std::unordered_map<std::uint32_t, std::uint32_t>& id_to_slot)
{
    /* Clear all 64 slots first — operator may have removed rules across
     * applies; the prior occupant must not survive. */
    const struct rule_entry empty{};
    for (std::uint32_t k = 0; k < static_cast<std::uint32_t>(XDPMF_ALLOWLIST_MAX); ++k) {
        const int rc = map_update(rules_inner_fd, &k, &empty, BPF_ANY);
        if (rc < 0) {
            throw_loader(classify(rc, LoaderError::LoadFailed),
                         std::format("bpf_map_update_elem(rules_inner[{}] clear): {}",
                                     k, std::strerror(-rc)));
        }
    }
    /* Then write occupied slots. §5.61 (MVP-4.21) B30: keyed by the rule's
     * internal `slot` (id-sorted rank), NOT its operator id — the datapath
     * winner `rid = ffsll(acc)-1` is a slot index into rules_inner, so this
     * MUST use the SAME slot the lowering bit-shifts used (D-mvp-4.21-SLOT-
     * COHERENCE). slot ∈ [0,count) is in range (config caps the count). */
    for (const Rule& r : rules) {
        struct rule_entry entry{};
        entry.present   = 1;
        /* §5.75: 3-way — Pass→0, Redirect→2, else (Drop)→1. */
        entry.action_id =
            (r.action == RuleAction::Pass)     ? static_cast<unsigned char>(ACTION_PASS)     :
            (r.action == RuleAction::Redirect) ? static_cast<unsigned char>(ACTION_REDIRECT) :
                                                 static_cast<unsigned char>(ACTION_DROP);
        const std::uint32_t slot = id_to_slot.at(r.id);
        const int rc = map_update(rules_inner_fd, &slot, &entry, BPF_ANY);
        if (rc < 0) {
            throw_loader(classify(rc, LoaderError::LoadFailed),
                         std::format("bpf_map_update_elem(rules_inner[{}]): {}",
                                     slot, std::strerror(-rc)));
        }
    }
}

/* §5.61 (MVP-4.21) B30 D-mvp-4.21-Q1: write the INACTIVE half of the single
 * combined `slot_rule_id` ARRAY before the active_idx flip — slot_rule_id
 * [inactive*XDPMF_ALLOWLIST_MAX + slot] = the operator id occupying that slot,
 * or XDPMF_SLOT_ID_EMPTY for the unoccupied tail [count,64). RESET-on-apply
 * (mirrors write_wildcard_slots / populate_rules_inner_slot): the whole half
 * is rewritten so no stale id survives. The single active_idx u32 store commits
 * this swap together with all 9 axes + defaults + rules + rule_counters +
 * wildcard. NEVER read by xdpfilter_prog — userspace-only (HG-mvp-4.21-1). */
void write_slot_rule_id(int slot_rule_id_fd, std::uint32_t inactive,
    const std::array<std::uint32_t, XDPMF_RULE_COUNTERS_MAX>& slot_to_id)
{
    const std::uint32_t base = inactive * static_cast<std::uint32_t>(XDPMF_ALLOWLIST_MAX);
    for (std::uint32_t slot = 0;
         slot < static_cast<std::uint32_t>(XDPMF_ALLOWLIST_MAX); ++slot) {
        const std::uint32_t key = base + slot;
        const std::uint32_t val = slot_to_id[slot];  // id or XDPMF_SLOT_ID_EMPTY
        const int rc = map_update(slot_rule_id_fd, &key, &val, BPF_ANY);
        if (rc < 0) {
            throw_loader(classify(rc, LoaderError::LoadFailed),
                         std::format("bpf_map_update_elem(slot_rule_id[{}]): {}",
                                     key, std::strerror(-rc)));
        }
    }
}

/* §5.48 (MVP-4.8) D-mvp-4.8-Q1 + D-mvp-4.8-FD-HELPER-SCOPE: fd-selector for the
 * 7 PAIRED axis inners (allowlist / dst_bitmask / cidr_allowlist /
 * proto_bitmask / port_ranges / vlan_bitmask / rules). Picks slot==0?a:b,
 * fetches the inner-map fd, throws LoadFailed(what) on <0. This is the SINGLE
 * home for the `_a`/`_b`<->slot decision — the HK-9 lockstep hazard B20 closes
 * (a wrong pair/slot in any one of the former 14 hand-rolled sites silently
 * corrupted the atomic swap and was compiler-invisible). Named `inactive_axis_fd`
 * (not the brief's `inactive_inner_fd`) to avoid shadowing the same-named
 * parameter in copy_rule_counters_forward — D-mvp-4.8-NAME-SHADOW. */
int inactive_axis_fd(bpf_map* a, bpf_map* b, std::uint32_t slot, const char* what)
{
    bpf_map*  inner = (slot == 0) ? a : b;
    const int fd    = map_fd(inner);
    if (fd < 0) {
        throw_loader(LoaderError::LoadFailed, what);
    }
    return fd;
}

}  // namespace

/* §5.29 (MVP-3.4): pre-populate action_table with the reserved actions per §5.29
 * apply step 8.5. Idempotent (write-same-value). The action_id field stored in
 * `rules` is an index into THIS array. §5.75 appends REDIRECT[2]; [0]/[1]
 * (PASS/DROP) UNCHANGED, no [3]=MIRROR (reserved hole). */
void populate_action_table(int action_table_fd)
{
    struct action_entry pass_entry{};
    pass_entry.action_type = static_cast<unsigned char>(ACTION_PASS);
    struct action_entry drop_entry{};
    drop_entry.action_type = static_cast<unsigned char>(ACTION_DROP);
    const std::uint32_t k_pass = static_cast<std::uint32_t>(ACTION_PASS);
    const std::uint32_t k_drop = static_cast<std::uint32_t>(ACTION_DROP);
    int rc = map_update(action_table_fd, &k_pass, &pass_entry, BPF_ANY);
    if (rc < 0) {
        throw_loader(classify(rc, LoaderError::LoadFailed),
                     std::format("bpf_map_update_elem(action_table[PASS]): {}",
                                 std::strerror(-rc)));
    }
    rc = map_update(action_table_fd, &k_drop, &drop_entry, BPF_ANY);
    if (rc < 0) {
        throw_loader(classify(rc, LoaderError::LoadFailed),
                     std::format("bpf_map_update_elem(action_table[DROP]): {}",
                                 std::strerror(-rc)));
    }
    struct action_entry redirect_entry{};
    redirect_entry.action_type = static_cast<unsigned char>(ACTION_REDIRECT);
    const std::uint32_t k_redirect = static_cast<std::uint32_t>(ACTION_REDIRECT);
    rc = map_update(action_table_fd, &k_redirect, &redirect_entry, BPF_ANY);
    if (rc < 0) {
        throw_loader(classify(rc, LoaderError::LoadFailed),
                     std::format("bpf_map_update_elem(action_table[REDIRECT]): {}",
                                 std::strerror(-rc)));
    }
}

/* §5.75 (MVP-4.35) D-mvp-4.35-Q2-A1 / DEVMAP-SHARED: fill the single global
 * redirect tap (devmap[0] = resolved steering target ifindex). Called in BOTH
 * apply branches alongside populate_action_table, BEFORE the active_idx flip.
 * Fail-closed at apply (HG-3): an unresolvable target throws (config
 * cross-validation guarantees steering exists iff a redirect rule exists). With
 * no steering, key 0 is deleted so a stale ifindex from a prior apply cannot
 * persist (the devmap is unused then — no redirect rule references it). */
void populate_redirect_devmap(int devmap_fd, const Config& cfg)
{
    const std::uint32_t k0 = 0;
    if (cfg.steering.has_value()) {
        const std::uint32_t idx = static_cast<std::uint32_t>(
            map_resolve_ifindex(cfg.steering->redirect_to, LoaderError::AttachFailed));
        const int rc = map_update(devmap_fd, &k0, &idx, BPF_ANY);
        if (rc < 0) {
            throw_loader(classify(rc, LoaderError::AttachFailed),
                         std::format("bpf_map_update_elem(redirect_devmap[0]): {}",
                                     std::strerror(-rc)));
        }
    } else {
        const int rc = map_delete(devmap_fd, &k0);
        // ENOENT is benign — there was simply no prior entry to clear.
        if (rc < 0 && errno != ENOENT) {
            throw_loader(classify(-errno, LoaderError::AttachFailed),
                         std::format("bpf_map_delete_elem(redirect_devmap[0]): {}",
                                     std::strerror(errno)));
        }
    }
}

/* §5.48 (MVP-4.8) D-mvp-4.8-BOUNDARY/ORDER: populate ALL RESET-on-apply
 * destinations into `slot` (fresh=0, reattach=inactive), in the EXACT current
 * order — mac, dst, src, proto, port, vlan, wildcard, defaults, rules. BOTH
 * apply_request branches call this; it replaces the per-branch hand-rolled
 * (slot==0?_a:_b)->fd->throw->populate blocks (the HK-9 14x idiom). EXCLUDES
 * populate_action_table (shared static {PASS,DROP}, no slot dimension) and
 * copy_rule_counters_forward (PRESERVE, branch-divergent args — guard #15);
 * those stay EXPLICIT per branch. Behavior-preserving: same maps, same slots,
 * same populate_* callees, same order as before the refactor. wildcard +
 * defaults are SINGLE maps indexed BY slot (direct bpf_map__fd, not pair-select
 * — D-mvp-4.8-FD-HELPER-SCOPE). */
// §5.73 (MVP-4.33) B40: collapses the prior 16-arg populate_all_axes into a
// 3-arg materialize over the named CompiledRuleset — each former positional arg
// is now read off the matching `cr.` member (positional→member rename ONLY,
// behavior-preserving). Body wraps populate_all_axes' content EXCLUSIVELY (HG-1
// / guard #15): populate_action_table + copy_rule_counters_forward stay EXPLICIT
// at each apply_request call site.
void materialize(xdpfilter_bpf* skel, std::uint32_t slot, const CompiledRuleset& cr)
{
    // 1 mac — paired allowlist_a/_b -> __u64 aggregated rule-bitmask
    populate_hash_inner_slot(
        inactive_axis_fd(skel->maps.allowlist_a, skel->maps.allowlist_b, slot,
                         "inactive mac inner fd unavailable"),
        cr.mac_low.entries, "mac");
    // 2 dst — paired dst_bitmask_a/_b LPM bit-vector
    populate_bitvec_inner_slot(
        inactive_axis_fd(skel->maps.dst_bitmask_a, skel->maps.dst_bitmask_b, slot,
                         "inactive dst inner fd unavailable"),
        cr.dst_low.prefixes, close_prefixes, "bitvec_inner");
    // 3 src — paired cidr_allowlist_a/_b LPM bit-vector
    populate_bitvec_inner_slot(
        inactive_axis_fd(skel->maps.cidr_allowlist_a, skel->maps.cidr_allowlist_b, slot,
                         "inactive src inner fd unavailable"),
        cr.src_low.prefixes, close_prefixes, "bitvec_inner");
    // 4 proto — paired proto_bitmask_a/_b exact-HASH
    populate_hash_inner_slot(
        inactive_axis_fd(skel->maps.proto_bitmask_a, skel->maps.proto_bitmask_b, slot,
                         "inactive proto inner fd unavailable"),
        cr.proto_low.entries, "proto");
    // 5 port — paired port_ranges_a/_b range ARRAY
    populate_port_inner_slot(
        inactive_axis_fd(skel->maps.port_ranges_a, skel->maps.port_ranges_b, slot,
                         "inactive port inner fd unavailable"),
        cr.port_low.ranges);
    // 6 vlan — paired vlan_bitmask_a/_b exact-HASH
    populate_hash_inner_slot(
        inactive_axis_fd(skel->maps.vlan_bitmask_a, skel->maps.vlan_bitmask_b, slot,
                         "inactive vlan inner fd unavailable"),
        cr.vlan_low.entries, "vlan");
    // §5.53 dst6 — paired dst6_bitmask_a/_b LPM bit-vector (v6 key)
    populate_bitvec_inner_slot(
        inactive_axis_fd(skel->maps.dst6_bitmask_a, skel->maps.dst6_bitmask_b, slot,
                         "inactive dst6 inner fd unavailable"),
        cr.dst6_low.prefixes, close_prefixes6, "bitvec6_inner");
    // §5.53 src6 — paired src6_bitmask_a/_b LPM bit-vector (v6 key)
    populate_bitvec_inner_slot(
        inactive_axis_fd(skel->maps.src6_bitmask_a, skel->maps.src6_bitmask_b, slot,
                         "inactive src6 inner fd unavailable"),
        cr.src6_low.prefixes, close_prefixes6, "bitvec6_inner");
    // §5.54 ethertype — paired ethertype_bitmask_a/_b exact-HASH (host-order u32 key)
    populate_hash_inner_slot(
        inactive_axis_fd(skel->maps.ethertype_bitmask_a, skel->maps.ethertype_bitmask_b, slot,
                         "inactive ethertype inner fd unavailable"),
        cr.eth_low.entries, "ethertype");
    // 7 ruleset_state — §5.70 (MVP-4.30) B35: SINGLE map indexed by slot; the 9
    //   wildcard halves + folded default_action in ONE struct write (replaces the
    //   prior `wildcard` + `defaults` two-block populate). (D-mvp-4.8-FD-HELPER-SCOPE)
    {
        const int ruleset_state_fd = map_fd(skel->maps.ruleset_state);
        if (ruleset_state_fd < 0) {
            throw_loader(LoaderError::LoadFailed, "ruleset_state fd unavailable");
        }
        write_ruleset_state(ruleset_state_fd, slot,
                            cr.dst_low.wildcard, cr.src_low.wildcard,
                            cr.proto_low.wildcard, cr.port_low.wildcard,
                            cr.vlan_low.wildcard, cr.mac_low.wildcard,
                            cr.dst6_low.wildcard, cr.src6_low.wildcard,
                            cr.eth_low.wildcard, cr.default_action);
    }
    // 9 rules — paired rules_a/_b inner ARRAY (keyed by internal slot)
    populate_rules_inner_slot(
        inactive_axis_fd(skel->maps.rules_a, skel->maps.rules_b, slot,
                         "inactive rules inner fd unavailable"),
        cr.rules, cr.id_to_slot);
    // 10 slot_rule_id — SINGLE map indexed by slot (§5.61 B30 D-mvp-4.21-Q1);
    // RESET-on-apply, mirrors wildcard/defaults. Userspace-only.
    {
        const int sri_fd = map_fd(skel->maps.slot_rule_id);
        if (sri_fd < 0) {
            throw_loader(LoaderError::LoadFailed, "slot_rule_id fd unavailable");
        }
        write_slot_rule_id(sri_fd, slot, cr.slot_to_id);
    }
}

}  // namespace xdpmf
