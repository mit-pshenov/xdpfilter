/*
 * yaml_subset.hpp — custom YAML 1.2 subset parser (design §5.26 HG1 / Q-HG1).
 *
 * Accepted constructs: block mappings, block sequences, single/double-quoted
 * scalars, bareword scalars, signed integer scalars, null/~, # comments,
 * optional leading "---". DoS guards: 1 MiB file, 4 KiB scalar, 8-level
 * nesting. Tabs in indentation, flow-form, anchors/aliases, tags, block
 * scalars, multi-doc, BOM, booleans — all REJECTED with a single-line
 * stderr-shaped ParseError carrying line/col provenance.
 *
 * The parser produces a minimal Node tree (just enough for the cycle-1
 * config schema — NOT a full YAML 1.2 AST).
 *
 * Errors are surfaced via std::system_error{LoaderError::ConfigError, ...};
 * the caller (config.cpp / apply.cpp) translates exit code via the same
 * loader_error_category() the rest of the loader uses.
 */
#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace xdpmf::yaml {

struct ParseError {
    std::string   feature;   // human-readable category — matches Q-HG1 table
    std::string   file;      // path supplied by caller (diagnostic only)
    std::uint32_t line = 0;  // 1-based source line
    std::uint32_t col  = 0;  // 1-based source column
    std::string   message;   // optional extra context
};

struct Node {
    enum class Kind { Null, Scalar, Mapping, Sequence };
    Kind                                       kind = Kind::Null;
    std::string                                scalar;     // valid iff Kind::Scalar
    std::vector<std::pair<std::string, Node>>  mapping;    // valid iff Kind::Mapping (insertion order; duplicates rejected)
    std::vector<Node>                          sequence;   // valid iff Kind::Sequence
    std::uint32_t                              line = 0;   // 1-based provenance
    std::uint32_t                              col  = 0;   // 1-based provenance
};

/* Throws std::system_error{LoaderError::ConfigError, ...} on any rejection
 * per Q-HG1. On success returns the root Node (always Kind::Mapping for
 * top-level YAML per the §5.26 schema; an empty file → empty Kind::Mapping). */
[[nodiscard]] Node parse(std::string_view source, std::string_view file_path_for_diagnostics);

}  // namespace xdpmf::yaml
