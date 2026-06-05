/*
 * ruleset_delta.cpp — §5.74 (MVP-4.34 / B41): the pure no-throw `diff()` body,
 * the id-classification scan LIFTED VERBATIM from the old inline
 * copy_rule_counters_forward loop (loader.cpp:1505–1515, guard #9 — relocation,
 * NOT re-implementation). The ONLY change vs the deleted block: it records the
 * matched old_slot into source[k] instead of doing the bpf_map_lookup_elem (the
 * lookup stays in the consumer). PURE / libbpf-free / no-throw: this TU links
 * WITHOUT libbpf and WITHOUT loader.cpp — that clean link is the testability /
 * purity contract (§5.74 OPS-canary). O(n²) preserved (HG-3).
 */
#include "ruleset_delta.hpp"

#include <cstdint>

namespace xdpmf {

RulesetDelta diff(std::span<const std::uint32_t> old_slot_to_id,
                  std::span<const std::uint32_t> new_slot_to_id) noexcept
{
    RulesetDelta d{};
    for (std::uint32_t k = 0;
         k < static_cast<std::uint32_t>(XDPMF_RULE_COUNTERS_MAX);
         ++k) {
        d.source[k] = XDPMF_SLOT_ID_EMPTY;
        const std::uint32_t new_id = new_slot_to_id[k];
        if (new_id != XDPMF_SLOT_ID_EMPTY) {
            /* Find the OLD slot this surviving id occupied; name it the source. */
            for (std::uint32_t old_slot = 0;
                 old_slot < static_cast<std::uint32_t>(XDPMF_RULE_COUNTERS_MAX);
                 ++old_slot) {
                if (old_slot_to_id[old_slot] == new_id) {
                    d.source[k] = old_slot;
                    break;  // ids are unique → at most one old slot
                }
            }
            /* new id absent from old → source[k] stays NONE (zeros forwarded). */
        }
    }
    return d;
}

}  // namespace xdpmf
