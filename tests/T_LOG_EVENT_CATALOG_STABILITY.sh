#!/bin/bash
# T_LOG_EVENT_CATALOG_STABILITY — design §6.58 (MVP-3.5 / §5.32).
#
# kEventNames constexpr catalog SET-EQUALITY against committed reference
# tests/fixtures/log_events_v1.txt.
#
# Mechanism B (architect recommended, simpler — no test-only TU):
#   - grep all `"…"` string literals from `src/common/logger.hpp`'s
#     kEventNames block — the dot-delimited event names.
#   - sort + cmp against `log_events_v1.txt` (also sorted).
#   - count must equal the fixture's line count (the canonical event count).
#
# NEGATION CONTROL:
#   - inject an extra event-name into a COPY of the source via sed; re-run
#     extractor; assert MISMATCH. Proves the comparator isn't a no-op.
#
# Observable outcome:
#   (a) sorted-list of extracted names == sorted committed reference, byte
#       for byte.
#   (b) line count matches reference fixture's line count (= the catalog size).
#   (c) Negation: injecting an extra name causes a mismatch (validator
#       isn't a tautology).
#
# Sanity-floor smoke: (a)+(b) — without these the test would have nothing
# to check.
# Negation control: (c).
#
# SKIP conditions: none required (this is a static-analysis test; needs
# no root, no veth, no jq). If `src/common/logger.hpp` is missing this is
# a hard FAIL (= impl never created the file).
#
# Cleanup: rm tmp files.
#
# Maps to: PI-3.5-4 (event catalog stability), HG-3.5-4, D-3.5-1.
set -euo pipefail
source "${TEST_DIR}/lib/common.sh"

LOGGER_HEADER="${SOURCE_DIR}/src/common/logger.hpp"
REF_FIXTURE="${TEST_DIR}/fixtures/log_events_v1.txt"

if [[ ! -f "${LOGGER_HEADER}" ]]; then
    echo "FAIL: ${LOGGER_HEADER} missing — impl did not create the logger module" >&2
    exit 1
fi
if [[ ! -f "${REF_FIXTURE}" ]]; then
    echo "FAIL: ${REF_FIXTURE} missing — reference fixture not committed" >&2
    exit 1
fi

extracted=$(mktemp /tmp/xdpmf-catalog-extracted.XXXXXX)
extracted_sorted=$(mktemp /tmp/xdpmf-catalog-extracted-sorted.XXXXXX)
ref_sorted=$(mktemp /tmp/xdpmf-catalog-ref-sorted.XXXXXX)
header_copy=$(mktemp /tmp/xdpmf-catalog-header-copy.XXXXXX)
extracted_copy=$(mktemp /tmp/xdpmf-catalog-extracted-copy.XXXXXX)
trap 'rm -f "${extracted}" "${extracted_sorted}" "${ref_sorted}" "${header_copy}" "${extracted_copy}"' EXIT

# ── extractor (Mechanism B) ─────────────────────────────────────────────
# Pattern matches: lines containing `"<dotted.snake_name>",` where each
# segment is lowercase snake_case. Architects mandate this exact convention
# (Q3 E1). The grep is intentionally narrow — we only want literal string
# entries from the kEventNames table.
#
# Approach:
#   - Strip the file to the kEventNames block: between `kEventNames = {`
#     and the closing `}` on its own line (greedy until first `};`).
#   - Within that block, grep `"[a-z][a-z0-9_.]*",` and extract the
#     contents of the quotes.
extract_events() {
    local hdr="$1" out="$2"
    awk '
        /kEventNames[ \t]*=[ \t]*\{/ { capture = 1; next }
        capture && /^\s*\};/         { capture = 0 }
        capture                       { print }
    ' "${hdr}" \
        | grep -oE '"[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+"' \
        | sed -E 's/^"//; s/"$//' \
        > "${out}"
}

extract_events "${LOGGER_HEADER}" "${extracted}"
echo "=== extracted events from ${LOGGER_HEADER}:"
cat "${extracted}"
echo "=== reference fixture ${REF_FIXTURE}:"
cat "${REF_FIXTURE}"

# Sort both.
sort -u "${extracted}" > "${extracted_sorted}"
sort -u "${REF_FIXTURE}" > "${ref_sorted}"

fail=0

# ── (a) sorted-list byte-equivalence ───────────────────────────────────
echo
echo "=== (a) sorted lists match byte-for-byte"
if ! cmp -s "${extracted_sorted}" "${ref_sorted}"; then
    echo "FAIL[a]: catalog drift detected — extracted vs reference DIFFER" >&2
    echo "--- only in extracted (new/unexpected events) ---" >&2
    comm -23 "${extracted_sorted}" "${ref_sorted}" >&2 || true
    echo "--- only in reference (missing events) ---" >&2
    comm -13 "${extracted_sorted}" "${ref_sorted}" >&2 || true
    fail=1
fi

# ── (b) counts match ──────────────────────────────────────────────────
echo
echo "=== (b) catalog count matches reference count"
ext_count=$(wc -l < "${extracted_sorted}")
ref_count=$(wc -l < "${ref_sorted}")
echo "extracted count: ${ext_count}"
echo "reference count: ${ref_count}"
if [[ "${ext_count}" != "${ref_count}" ]]; then
    echo "FAIL[b]: count mismatch — extracted=${ext_count}, reference=${ref_count}" >&2
    fail=1
fi
# Also extracted count must be > 0 (smoke that extractor isn't empty).
if (( ext_count < 1 )); then
    echo "FAIL[b-smoke]: extractor returned zero events — extractor regex broken or header empty" >&2
    fail=1
fi

# ── (c) NEGATION CONTROL: extra-event injection produces mismatch ──────
echo
echo "=== (c) NEGATION CONTROL: inject extra event into a COPY → comparator must catch"
cp "${LOGGER_HEADER}" "${header_copy}"
# Inject an extra string literal after the line opening the block. Use
# a name that DEFINITELY won't be in the catalog.
awk '
    /kEventNames[ \t]*=[ \t]*\{/ {
        print
        print "    \"negation.injected.event\","
        next
    }
    { print }
' "${header_copy}" > "${header_copy}.new" && mv "${header_copy}.new" "${header_copy}"

extract_events "${header_copy}" "${extracted_copy}"
sort -u "${extracted_copy}" > "${extracted_copy}.sorted"

if cmp -s "${extracted_copy}.sorted" "${ref_sorted}"; then
    echo "FAIL[c]: negation: injection of 'negation.injected.event' did NOT cause mismatch" >&2
    echo "         comparator is a no-op" >&2
    fail=1
else
    echo "[c] OK: comparator catches injected extra event-name"
fi
rm -f "${extracted_copy}.sorted"

[[ "${fail}" == 0 ]] && echo "PASS: T_LOG_EVENT_CATALOG_STABILITY"
exit "${fail}"
