/*
 * ruleset_delta.hpp — §5.74 (MVP-4.34 / B41): names the apply's only stateful
 * "two versions meet" seam — the per-operator-id counter-reconciliation that
 * `copy_rule_counters_forward` (loader.cpp) drives across an active_idx flip.
 * PURE HOST-SIDE: this header (and ruleset_delta.cpp) touch NO libbpf / skeleton
 * / .bpf.c / fd — `diff()` is a total pure, side-effect-free, noexcept transform.
 * `struct RulesetDelta` is a dumb value-aggregate (guard #36); `diff()` is a free
 * function whose body is the classification scan LIFTED VERBATIM from the old
 * inline loader.cpp loop (guard #9 — relocation, NOT re-implementation; O(n²)
 * preserved). Private header (src/lib/, like compiled_ruleset.hpp /
 * apply_internal.hpp) — names no loader.hpp public symbol (PI-7).
 */
#ifndef XDPMF_RULESET_DELTA_HPP
#define XDPMF_RULESET_DELTA_HPP

#include "common/xdpfilter.h"  // XDPMF_RULE_COUNTERS_MAX, XDPMF_SLOT_ID_EMPTY

#include <array>
#include <cstdint>
#include <span>

namespace xdpmf {

/* §5.74 D-mvp-4.34-Q1-A1 + guard #36: the precomputed copy-source map for one
 * apply's counter reconciliation. `source[k]` (k = a NEW bit-vector slot) is:
 *   - an OLD slot ∈ [0,64)            → the surviving id's old slot; its counter
 *                                       is copied forward (source[k]==k means
 *                                       survived-in-place, source[k]!=k is the
 *                                       B30 moved-keeps-counter case);
 *   - XDPMF_SLOT_ID_EMPTY (0xFFFFFFFF) → NONE: new slot is unoccupied OR carries
 *                                       a brand-new id → zeros forwarded.
 * A dropped id is not directly represented — its old slot is simply never named
 * by any source[k]. Carries data only; no methods, no logic. */
struct RulesetDelta {
    std::array<std::uint32_t, XDPMF_RULE_COUNTERS_MAX> source;
};

/* §5.74 D-mvp-4.34-GUARD9-VERBATIM: for each NEW slot k ∈ [0,64), find the OLD
 * slot whose id equals new_slot_to_id[k] (ids unique → at most one) and record
 * it into source[k]; unoccupied/new slots get the NONE sentinel. The O(n²)
 * outer-k × inner-old_slot scan is byte-for-byte the existing loader.cpp logic
 * (HG-3 — O(n) is OOS). Inputs are non-owning slot→id spans (each indexed by
 * slot ∈ [0,64), element = operator id or XDPMF_SLOT_ID_EMPTY); both spans MUST
 * have size ≥ XDPMF_RULE_COUNTERS_MAX (diff() reads exactly [0,64), no bounds
 * check). Borrow-only; retains no reference. PURE / libbpf-free / noexcept. */
[[nodiscard]] RulesetDelta diff(std::span<const std::uint32_t> old_slot_to_id,
                                std::span<const std::uint32_t> new_slot_to_id) noexcept;

}  // namespace xdpmf

#endif  // XDPMF_RULESET_DELTA_HPP
