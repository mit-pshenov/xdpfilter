/*
 * yaml_subset.cpp — single-pass, line/col-tracking YAML 1.2 subset parser
 * (design §5.26 HG1 / Q-HG1). Rejects everything outside the accepted
 * subset (anchors, aliases, tags, flow-form, block scalars, booleans,
 * multi-doc, BOM, tabs in indentation, etc.) with a uniform stderr shape:
 *   xdpmacfilter: config error: <feature>: <file>:<line>:<col>[: <message>]
 *
 * DoS guards enforced at parse time:
 *   - file size > 1 MiB → reject (caller-checked but parse() rechecks defensively)
 *   - scalar length > 4 KiB → reject
 *   - nesting depth > 8 → reject
 *
 * Parser organization:
 *   - Cursor tracks (pos, line, col) over source.
 *   - parse_block(min_indent) reads either a mapping or a sequence whose
 *     items all start at the same indent (≥ min_indent). The first indented
 *     child sets the level's indent; subsequent siblings MUST match it.
 *   - Nested values are parsed by recursing on the same logic.
 *   - All "reject"-paths throw via throw_cfg().
 */
#include "yaml_subset.hpp"
#include "loader.hpp"  // LoaderError::ConfigError (drives error_code category)

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <format>
#include <system_error>
#include <utility>

namespace xdpmf::yaml {

namespace {

/* §5.26 Q-HG1 DoS guards. */
constexpr std::size_t kMaxFileBytes   = 1u * 1024u * 1024u;  // 1 MiB
constexpr std::size_t kMaxScalarBytes = 4096u;                // 4 KiB
constexpr std::uint32_t kMaxNestDepth = 8;

/* Cursor over the YAML source. line/col are 1-based; col counts characters
 * (we don't unicode-decode — the accepted subset is ASCII-only for keys
 * and tokens; quoted strings may contain raw UTF-8 bytes which we pass
 * through verbatim). */
struct Cursor {
    std::string_view src;
    std::string_view file;
    std::size_t      pos  = 0;
    std::uint32_t    line = 1;
    std::uint32_t    col  = 1;
};

[[noreturn]] void throw_cfg(const Cursor& c, std::string_view feature, std::string message = {})
{
    /* Stderr shape matches Q-HG1 contract: caller's std::system_error's
     * what() will be rendered by main()'s catch block as
     * "error: <what>" — we shape <what> so that splicing produces the
     * canonical "xdpmacfilter: config error: <feature>: <file>:<line>:<col>"
     * sentinel that ops scripts grep on. */
    std::string what =
        message.empty()
            ? std::format("xdpmacfilter: config error: {}: {}:{}:{}",
                          feature, c.file, c.line, c.col)
            : std::format("xdpmacfilter: config error: {}: {}:{}:{}: {}",
                          feature, c.file, c.line, c.col, message);
    throw std::system_error(make_error_code(LoaderError::ConfigError), std::move(what));
}

[[nodiscard]] bool at_eof(const Cursor& c) noexcept
{
    return c.pos >= c.src.size();
}

[[nodiscard]] char peek(const Cursor& c, std::size_t k = 0) noexcept
{
    return (c.pos + k < c.src.size()) ? c.src[c.pos + k] : '\0';
}

void advance(Cursor& c) noexcept
{
    if (c.pos >= c.src.size()) return;
    if (c.src[c.pos] == '\n') {
        ++c.line;
        c.col = 1;
    } else {
        ++c.col;
    }
    ++c.pos;
}

/* Advance past whitespace ON THE CURRENT LINE only. Stops at '\n' / EOF.
 * Tabs in any whitespace position trigger an error (Q-HG1 "Tabs in
 * indentation" is the strict subset of this — but we reject mid-line tabs
 * too as a defensive simplification; the schema has no legitimate tab use). */
void skip_inline_spaces(Cursor& c)
{
    while (!at_eof(c)) {
        const char ch = peek(c);
        if (ch == ' ') { advance(c); continue; }
        if (ch == '\t') {
            throw_cfg(c, "tab in indentation");
        }
        break;
    }
}

/* Strip the rest of the current line if a '#' comment is found, leaving the
 * cursor at the EOL ('\n') or EOF. Inline comments require the '#' to be
 * preceded by whitespace (consistent with YAML 1.2). The caller must have
 * skipped trailing whitespace before invoking this. */
void skip_line_comment(Cursor& c)
{
    if (peek(c) != '#') return;
    while (!at_eof(c) && peek(c) != '\n') advance(c);
}

/* Consume the EOL ('\n' or EOF). Caller must have positioned cursor at EOL. */
void consume_eol(Cursor& c)
{
    if (peek(c) == '\n') advance(c);
}

/* Count the leading-space count of the current line and leave the cursor
 * AT the first non-space byte (or at '\n'/EOF if the line is blank/comment).
 * Rejects tabs in indentation per Q-HG1. */
[[nodiscard]] std::uint32_t measure_indent(Cursor& c)
{
    std::uint32_t n = 0;
    while (!at_eof(c)) {
        const char ch = peek(c);
        if (ch == ' ') { advance(c); ++n; continue; }
        if (ch == '\t') {
            throw_cfg(c, "tab in indentation");
        }
        break;
    }
    return n;
}

/* Advance cursor past any sequence of fully-blank or comment-only lines.
 * Tabs in indentation are still rejected on each line probed. */
void skip_blank_lines(Cursor& c)
{
    while (!at_eof(c)) {
        const std::size_t save_pos  = c.pos;
        const std::uint32_t save_ln = c.line;
        const std::uint32_t save_co = c.col;
        // Reject tab-indented lines even if blank (Q-HG1 strictness).
        (void)measure_indent(c);
        if (at_eof(c) || peek(c) == '\n') {
            /* Truly blank line — consume the EOL and try the next line. */
            consume_eol(c);
            continue;
        }
        if (peek(c) == '#') {
            skip_line_comment(c);
            consume_eol(c);
            continue;
        }
        /* Non-blank, non-comment — rewind to start-of-line and let caller
         * re-measure the indent in their own frame. */
        c.pos = save_pos;
        c.line = save_ln;
        c.col  = save_co;
        return;
    }
}

/* Match a literal token at the cursor (CASE-SENSITIVE). Returns true and
 * advances iff matched. Does NOT consume trailing whitespace. */
[[nodiscard]] bool match_literal(Cursor& c, std::string_view tok) noexcept
{
    if (c.src.size() - c.pos < tok.size()) return false;
    if (c.src.substr(c.pos, tok.size()) != tok) return false;
    for (std::size_t i = 0; i < tok.size(); ++i) advance(c);
    return true;
}

/* Q-HG1: bareword scalar — non-empty [A-Za-z0-9._\-:] sequence. ':' is
 * allowed in VALUE position (to support MAC literals "AA:BB:CC:DD:EE:FF")
 * but NEVER in KEY position; this function returns the scalar; the caller
 * disambiguates key vs value by context. */
[[nodiscard]] bool is_bareword_byte(char ch) noexcept
{
    if (ch >= 'A' && ch <= 'Z') return true;
    if (ch >= 'a' && ch <= 'z') return true;
    if (ch >= '0' && ch <= '9') return true;
    return ch == '.' || ch == '_' || ch == '-' || ch == ':';
}

/* Read a bareword starting at the cursor. Stops at first non-bareword byte.
 * Enforces 4 KiB scalar cap (Q-HG1 DoS guard). Returns empty string if no
 * bareword bytes consumed. */
[[nodiscard]] std::string read_bareword(Cursor& c)
{
    const std::size_t start = c.pos;
    while (!at_eof(c) && is_bareword_byte(peek(c))) {
        if (c.pos - start >= kMaxScalarBytes) {
            throw_cfg(c, "scalar exceeds 4 KiB limit");
        }
        advance(c);
    }
    return std::string{c.src.substr(start, c.pos - start)};
}

/* Read a key bareword. Same as read_bareword() but REJECTS embedded ':'
 * (Q-HG1: ":" never allowed in a key). */
[[nodiscard]] std::string read_key_bareword(Cursor& c)
{
    const std::uint32_t k_line = c.line;
    const std::uint32_t k_col  = c.col;
    const std::size_t start = c.pos;
    while (!at_eof(c) && is_bareword_byte(peek(c))) {
        if (peek(c) == ':') break;  // key terminator
        if (c.pos - start >= kMaxScalarBytes) {
            throw_cfg(c, "scalar exceeds 4 KiB limit");
        }
        advance(c);
    }
    if (c.pos == start) {
        Cursor at{c.src, c.file, c.pos, k_line, k_col};
        throw_cfg(at, "expected key", "empty or invalid key");
    }
    return std::string{c.src.substr(start, c.pos - start)};
}

/* Read a single- or double-quoted scalar. Accepted escapes:
 *   double-quoted: \\ , \"        (others → reject)
 *   single-quoted: ''             (escape for embedded ')
 * Multi-line quoted strings are rejected (Q-HG1). */
[[nodiscard]] std::string read_quoted_scalar(Cursor& c)
{
    const char quote = peek(c);
    advance(c);  // consume opening quote
    std::string out;
    while (!at_eof(c)) {
        const char ch = peek(c);
        if (ch == '\n') {
            throw_cfg(c, "multi-line quoted string not supported");
        }
        if (quote == '"' && ch == '\\') {
            advance(c);
            if (at_eof(c)) {
                throw_cfg(c, "unterminated string");
            }
            const char esc = peek(c);
            if (esc == '\\' || esc == '"') {
                out.push_back(esc);
                advance(c);
                continue;
            }
            throw_cfg(c, "unsupported escape sequence");
        }
        if (quote == '\'' && ch == '\'') {
            // YAML single-quote: '' inside single-quoted = literal '
            if (peek(c, 1) == '\'') {
                out.push_back('\'');
                advance(c);
                advance(c);
                continue;
            }
            advance(c);  // closing quote
            return out;
        }
        if (ch == quote) {
            advance(c);  // closing quote
            return out;
        }
        if (out.size() >= kMaxScalarBytes) {
            throw_cfg(c, "scalar exceeds 4 KiB limit");
        }
        out.push_back(ch);
        advance(c);
    }
    throw_cfg(c, "unterminated string");
}

/* Read a scalar starting at the cursor. The scalar ends at EOL, the start
 * of an inline '#' comment (preceded by whitespace), or — for barewords —
 * at the first non-bareword byte.
 *
 * Per Q-HG1: bareword `true`/`false` is REJECTED (no boolean field in
 * cycle-1 schema). `null` / `~` / empty are normalized to the empty
 * scalar with `is_null = true` returned via out-parameter.
 *
 * Returns the scalar content. The cursor is left at the byte after the
 * scalar (i.e. at whitespace, '#', or EOL). */
[[nodiscard]] std::string read_value_scalar(Cursor& c, bool& is_null)
{
    is_null = false;

    // Reject flow-form / block-scalar markers up front (we don't support them).
    const char ch = peek(c);
    if (ch == '{') throw_cfg(c, "flow-style mapping not supported");
    if (ch == '[') throw_cfg(c, "flow-style sequence not supported");
    if (ch == '|' || ch == '>') throw_cfg(c, "block scalar not supported");
    if (ch == '&' || ch == '*') throw_cfg(c, "anchors/aliases not supported");
    if (ch == '!') throw_cfg(c, "explicit tags not supported");

    if (ch == '"' || ch == '\'') {
        return read_quoted_scalar(c);
    }

    // null / ~ explicitly null
    if (ch == '~') {
        advance(c);
        is_null = true;
        return {};
    }
    // EOL means null (empty value)
    if (ch == '\0' || ch == '\n' || ch == '#') {
        is_null = true;
        return {};
    }

    // Bareword: read greedy [A-Za-z0-9._\-:]+; reject true/false.
    std::string bw = read_bareword(c);
    if (bw.empty()) {
        throw_cfg(c, "unexpected character", std::format("byte 0x{:02x}", static_cast<unsigned>(ch)));
    }
    if (bw == "true" || bw == "false") {
        throw_cfg(c, "boolean scalars not supported");
    }
    if (bw == "null") {
        is_null = true;
        return {};
    }
    return bw;
}

void check_depth(const Cursor& c, std::uint32_t depth)
{
    if (depth > kMaxNestDepth) {
        throw_cfg(c, "nesting depth exceeds 8");
    }
}

/* Forward decls — block parser is mutually recursive between mapping/sequence. */
Node parse_value(Cursor& c, std::uint32_t parent_indent, std::uint32_t depth);
void parse_mapping(Cursor& c, Node& out, std::uint32_t my_indent, std::uint32_t depth);
void parse_sequence(Cursor& c, Node& out, std::uint32_t my_indent, std::uint32_t depth);

/* Parse a YAML value starting at the cursor's current position. The value
 * may be:
 *   - inline on this line after a 'key:' (next non-space char is non-EOL/#)
 *   - a nested block starting on the next line at a strictly greater indent
 * The caller has positioned the cursor JUST AFTER the 'key:' / '- ' prefix
 * (possibly with whitespace). `parent_indent` is the indent of the line
 * that introduced this value (= the key's line indent). */
Node parse_value(Cursor& c, std::uint32_t parent_indent, std::uint32_t depth)
{
    check_depth(c, depth);
    Node node;
    node.line = c.line;
    node.col  = c.col;

    skip_inline_spaces(c);

    // Inline scalar on the same line as the key? (Anything that's not EOL
    // or '#' is treated as inline scalar.)
    const char ch = peek(c);
    const bool inline_present = (ch != '\0' && ch != '\n' && ch != '#');
    if (inline_present) {
        bool is_null = false;
        std::string scalar = read_value_scalar(c, is_null);
        skip_inline_spaces(c);
        skip_line_comment(c);
        if (peek(c) != '\n' && peek(c) != '\0') {
            throw_cfg(c, "trailing junk after scalar");
        }
        consume_eol(c);
        if (is_null) {
            node.kind = Node::Kind::Null;
        } else {
            node.kind   = Node::Kind::Scalar;
            node.scalar = std::move(scalar);
        }
        return node;
    }

    // Inline empty → nested block (or null if no greater-indent line follows).
    skip_line_comment(c);
    consume_eol(c);
    skip_blank_lines(c);

    if (at_eof(c)) {
        node.kind = Node::Kind::Null;
        return node;
    }

    // Probe next non-blank line's indent. Must be STRICTLY greater than
    // parent_indent to count as a nested block; otherwise the value is null.
    const std::size_t   save_pos = c.pos;
    const std::uint32_t save_ln  = c.line;
    const std::uint32_t save_co  = c.col;
    const std::uint32_t indent   = measure_indent(c);
    if (at_eof(c) || peek(c) == '\n' || peek(c) == '#') {
        // Blank/comment line — shouldn't happen after skip_blank_lines, but
        // be defensive: rewind and treat as null.
        c.pos = save_pos; c.line = save_ln; c.col = save_co;
        node.kind = Node::Kind::Null;
        return node;
    }
    if (indent <= parent_indent) {
        // Sibling-or-shallower follows — value is null. Rewind to start of
        // this line so the caller's loop sees it.
        c.pos = save_pos; c.line = save_ln; c.col = save_co;
        node.kind = Node::Kind::Null;
        return node;
    }

    // We are now at the first non-space byte of a properly-indented child.
    // Decide mapping vs sequence by first byte, then REWIND the cursor to
    // start-of-line — both parse_mapping and parse_sequence's main loop
    // assume start-of-line and re-measure indent themselves.
    const bool is_seq = (peek(c) == '-')
                        && (peek(c, 1) == ' ' || peek(c, 1) == '\n' || peek(c, 1) == '\0');
    c.pos = save_pos; c.line = save_ln; c.col = save_co;
    if (is_seq) {
        node.kind = Node::Kind::Sequence;
        parse_sequence(c, node, indent, depth + 1);
    } else {
        node.kind = Node::Kind::Mapping;
        parse_mapping(c, node, indent, depth + 1);
    }
    return node;
}

void parse_mapping(Cursor& c, Node& out, std::uint32_t my_indent, std::uint32_t depth)
{
    check_depth(c, depth);
    out.kind = Node::Kind::Mapping;

    while (true) {
        skip_blank_lines(c);
        if (at_eof(c)) return;

        const std::size_t   save_pos = c.pos;
        const std::uint32_t save_ln  = c.line;
        const std::uint32_t save_co  = c.col;
        const std::uint32_t indent   = measure_indent(c);

        if (at_eof(c) || peek(c) == '\n' || peek(c) == '#') {
            consume_eol(c);
            continue;
        }
        if (indent < my_indent) {
            c.pos = save_pos; c.line = save_ln; c.col = save_co;
            return;  // sibling-shallower terminates this mapping
        }
        if (indent > my_indent) {
            throw_cfg(c, "inconsistent indentation");
        }

        // Sequence marker at a mapping's expected indent → end of mapping
        // (parent owns the sequence). Defensive — uncommon for our schema
        // but handles `rules:`'s nested sequence under top-level mapping.
        if (peek(c) == '-' && (peek(c, 1) == ' ' || peek(c, 1) == '\n')) {
            c.pos = save_pos; c.line = save_ln; c.col = save_co;
            return;
        }

        // key:
        const std::uint32_t key_line = c.line;
        const std::uint32_t key_col  = c.col;
        std::string key = read_key_bareword(c);
        if (peek(c) != ':') {
            throw_cfg(c, "expected ':' after key");
        }
        advance(c);  // consume ':'

        // Duplicate-key check (Q-HG1 strict).
        const bool dup = std::any_of(
            out.mapping.begin(), out.mapping.end(),
            [&](const std::pair<std::string, Node>& kv) { return kv.first == key; });
        if (dup) {
            Cursor at{c.src, c.file, c.pos, key_line, key_col};
            throw_cfg(at, "duplicate key", key);
        }

        Node child = parse_value(c, my_indent, depth + 1);
        child.line = key_line;
        child.col  = key_col;
        out.mapping.emplace_back(std::move(key), std::move(child));
    }
}

void parse_sequence(Cursor& c, Node& out, std::uint32_t my_indent, std::uint32_t depth)
{
    check_depth(c, depth);
    out.kind = Node::Kind::Sequence;

    while (true) {
        skip_blank_lines(c);
        if (at_eof(c)) return;

        const std::size_t   save_pos = c.pos;
        const std::uint32_t save_ln  = c.line;
        const std::uint32_t save_co  = c.col;
        const std::uint32_t indent   = measure_indent(c);

        if (at_eof(c) || peek(c) == '\n' || peek(c) == '#') {
            consume_eol(c);
            continue;
        }
        if (indent < my_indent) {
            c.pos = save_pos; c.line = save_ln; c.col = save_co;
            return;
        }
        if (indent > my_indent) {
            throw_cfg(c, "inconsistent indentation");
        }
        if (peek(c) != '-') {
            // Sibling key at mapping indent — end of sequence.
            c.pos = save_pos; c.line = save_ln; c.col = save_co;
            return;
        }
        // '- ' marker (or '-' EOL — null entry).
        advance(c);  // consume '-'
        if (peek(c) == ' ') {
            advance(c);
        } else if (peek(c) != '\n' && peek(c) != '\0') {
            throw_cfg(c, "expected space after '-'");
        }

        const std::uint32_t entry_line = save_ln;
        const std::uint32_t entry_col  = save_co + 1;  // '- '

        // The "block-mapping-after-dash" idiom: `- key: value` on one line
        // (where the FIRST item key starts right after '- '). We treat this
        // as: the sequence entry is a mapping whose first key starts at
        // (my_indent + 2). Re-measure by computing virtual indent.
        //
        // We push a fresh Node, parse the entry value at virtual_indent =
        // my_indent + 2 (column of first byte after "- ").
        Node entry;
        entry.line = entry_line;
        entry.col  = entry_col;

        if (peek(c) == '\n' || peek(c) == '\0') {
            // Empty entry → null (or nested block on the next line).
            entry = parse_value(c, my_indent, depth + 1);
        } else if (peek(c) == '-' && (peek(c, 1) == ' ' || peek(c, 1) == '\n')) {
            // Nested sequence directly after '- '.
            entry.kind = Node::Kind::Sequence;
            parse_sequence(c, entry, c.col, depth + 1);
        } else {
            // Either a scalar OR a mapping starting with key:.
            // Detect by scanning ahead on the SAME line for ':' (excluding
            // ':' in quoted strings — which we reject anyway as keys).
            // Simplest: try-parse as bareword key + ':'.
            const std::size_t   peek_save_pos = c.pos;
            const std::uint32_t peek_save_ln  = c.line;
            const std::uint32_t peek_save_co  = c.col;

            // Scan candidate key.
            const std::uint32_t virtual_indent = c.col - 1;  // 0-based equivalent
            bool looks_like_mapping = false;
            if (peek(c) == '"' || peek(c) == '\'') {
                // Quoted keys not in our subset; treat as scalar.
                looks_like_mapping = false;
            } else {
                std::size_t p = c.pos;
                while (p < c.src.size() && is_bareword_byte(c.src[p]) && c.src[p] != ':' && c.src[p] != '\n') {
                    ++p;
                }
                if (p < c.src.size() && c.src[p] == ':') {
                    looks_like_mapping = true;
                }
            }

            if (looks_like_mapping) {
                entry.kind = Node::Kind::Mapping;
                // First key:value lives on the dash-line; parse it inline
                // because parse_mapping's loop assumes start-of-line cursor.
                // Subsequent siblings (next lines) are parsed by parse_mapping
                // at virtual_indent.
                const std::uint32_t key_line = c.line;
                const std::uint32_t key_col  = c.col;
                std::string first_key = read_key_bareword(c);
                if (peek(c) != ':') {
                    throw_cfg(c, "expected ':' after key");
                }
                advance(c);  // consume ':'
                Node first_child = parse_value(c, virtual_indent, depth + 1);
                first_child.line = key_line;
                first_child.col  = key_col;
                entry.mapping.emplace_back(std::move(first_key), std::move(first_child));
                // Continue with subsequent same-indent siblings.
                parse_mapping(c, entry, virtual_indent, depth + 1);
            } else {
                bool is_null = false;
                std::string sv = read_value_scalar(c, is_null);
                skip_inline_spaces(c);
                skip_line_comment(c);
                if (peek(c) != '\n' && peek(c) != '\0') {
                    throw_cfg(c, "trailing junk after scalar");
                }
                consume_eol(c);
                if (is_null) entry.kind = Node::Kind::Null;
                else { entry.kind = Node::Kind::Scalar; entry.scalar = std::move(sv); }
            }
            (void)peek_save_pos; (void)peek_save_ln; (void)peek_save_co;
        }

        out.sequence.push_back(std::move(entry));
    }
}

}  // namespace

Node parse(std::string_view source, std::string_view file_path_for_diagnostics)
{
    Cursor c{source, file_path_for_diagnostics, 0, 1, 1};

    if (source.size() > kMaxFileBytes) {
        throw_cfg(c, "config file exceeds 1 MiB limit");
    }

    // BOM check (Q-HG1 reject).
    if (source.size() >= 3
        && static_cast<unsigned char>(source[0]) == 0xEF
        && static_cast<unsigned char>(source[1]) == 0xBB
        && static_cast<unsigned char>(source[2]) == 0xBF) {
        throw_cfg(c, "BOM not supported");
    }

    // Optional leading "---" document marker — accept once, reject second.
    skip_blank_lines(c);
    if (!at_eof(c)) {
        const std::size_t save_pos = c.pos;
        const std::uint32_t save_ln = c.line;
        const std::uint32_t save_co = c.col;
        const std::uint32_t lead_indent = measure_indent(c);
        if (lead_indent == 0 && match_literal(c, "---")) {
            // Must be followed by EOL / whitespace+EOL only on this line.
            skip_inline_spaces(c);
            skip_line_comment(c);
            if (peek(c) != '\n' && peek(c) != '\0') {
                throw_cfg(c, "content following '---' not supported");
            }
            consume_eol(c);
        } else {
            c.pos = save_pos; c.line = save_ln; c.col = save_co;
        }
    }
    skip_blank_lines(c);

    // Second '---' mid-stream → reject (multi-doc not supported).
    // We detect by scanning forward: any line whose first non-space chars
    // are '---' triggers the reject.
    // Done by checking inline at the parse_mapping loop top — simpler:
    // re-scan source for an additional '---' marker AFTER cursor pos.
    // (Cheap because the file is ≤ 1 MiB; one extra pass.)
    {
        std::size_t scan = c.pos;
        while (scan < source.size()) {
            std::size_t line_start = scan;
            // skip leading spaces only (tabs already rejected by main parser)
            while (line_start < source.size() && source[line_start] == ' ') ++line_start;
            if (line_start + 3 <= source.size() && source.compare(line_start, 3, "---") == 0) {
                const std::size_t after = line_start + 3;
                if (after >= source.size() || source[after] == '\n' || source[after] == ' '
                    || source[after] == '\t' || source[after] == '#') {
                    // Recompute line/col for diagnostic.
                    std::uint32_t ln = 1; std::uint32_t co = 1;
                    for (std::size_t i = 0; i < line_start; ++i) {
                        if (source[i] == '\n') { ++ln; co = 1; }
                        else                   { ++co; }
                    }
                    Cursor at{source, file_path_for_diagnostics, line_start, ln, co};
                    throw_cfg(at, "multi-document streams not supported");
                }
            }
            // Advance to next line.
            std::size_t nl = source.find('\n', scan);
            if (nl == std::string_view::npos) break;
            scan = nl + 1;
        }
    }

    Node root;
    root.line = 1;
    root.col  = 1;

    if (at_eof(c)) {
        root.kind = Node::Kind::Mapping;
        return root;
    }

    // Top-level MUST be a block mapping (Q-HG1). Flow form at top-level is
    // already rejected by read_value_scalar; sequence at top-level would
    // start with '- '.
    const std::size_t   save_pos = c.pos;
    const std::uint32_t save_ln  = c.line;
    const std::uint32_t save_co  = c.col;
    const std::uint32_t indent   = measure_indent(c);
    if (indent != 0) {
        throw_cfg(c, "inconsistent indentation", "top-level must start at column 1");
    }
    if (peek(c) == '-' && (peek(c, 1) == ' ' || peek(c, 1) == '\n')) {
        throw_cfg(c, "top-level sequence not supported");
    }
    if (peek(c) == '{') {
        throw_cfg(c, "flow-style mapping not supported");
    }
    // Restore so parse_mapping re-measures indent itself.
    c.pos = save_pos; c.line = save_ln; c.col = save_co;

    root.kind = Node::Kind::Mapping;
    parse_mapping(c, root, 0, 1);

    skip_blank_lines(c);
    if (!at_eof(c)) {
        throw_cfg(c, "unexpected content after end of mapping");
    }
    return root;
}

}  // namespace xdpmf::yaml
