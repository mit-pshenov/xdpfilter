/*
 * map_image.hpp — PRIVATE header (not exported, not installed).
 *
 * §5.77 (MVP-4.37 / B44) the production offline map-image render surface. Two
 * symbols, both libbpf-free:
 *   • render_dryrun_image — the offline orchestration (compile → sentinel skel →
 *     RecordingScope → the SAME 3-call apply sequence → format). ZERO kernel
 *     calls by construction (every primitive routes through RecordingMapWriter).
 *     The SINGLE production consumer driving the seam (CLI `apply --dry-run`).
 *   • format_dryrun_image — the formatter (relocated from the B43 harness; guard
 *     #36 capture-vs-format split): the SINGLE producer of the
 *     `# xdpfilter-image v1` text (§5.76.4(6)) for BOTH the CLI verb AND the
 *     harness oracle (SSoT; guard #9 / PI-mvp-4.37-SSOT).
 */
#pragma once

#include <string>
#include <vector>

#include "config.hpp"      // Config
#include "map_writer.hpp"  // RecordedWrite

namespace xdpmf {

/* §5.77.4(3): render the frozen offline map-image for `cfg`, OFFLINE. Drives the
 * production materialize/populate_* via the RecordingMapWriter — ZERO kernel
 * calls / ZERO map writes / ZERO attach (PI-mvp-4.37-ZERO-TOUCH). Slot fixed at 0
 * (D-mvp-4.36-SLOT0). */
[[nodiscard]] std::string render_dryrun_image(const Config& cfg);

/* §5.77.4(5): format a recorded write-set → the canonical `# xdpfilter-image v1`
 * text. Policy (§5.76.4(6)/(6a) VERBATIM): maps in catalog (apply-issue) order;
 * last-write-wins final image; within-map memcmp key sort; fixed-width lowercase
 * hex; symbolic `redirect_devmap[0]` (the operator target name + RESOLVED-AT-APPLY,
 * never a numeric ifindex). `devmap_target` is the resolved steering name. */
[[nodiscard]] std::string format_dryrun_image(const std::vector<RecordedWrite>& recs,
                                              const std::string& devmap_target);

}  // namespace xdpmf
