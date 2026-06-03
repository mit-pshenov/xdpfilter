#!/bin/bash
# T_FLEET_DOCS_SUBSTRING — design §6.36 (MVP-3.3 / §5.28) — load-bearing for PI-23.
#
# 6-substring grep over docs/FLEET_DEPLOYMENT.md per §5.28 Q3 D1
# substring catalogue + PI-23 verbatim stderr-format citation.
#
# Per §6.36 Observable outcome (all 6 substrings present):
#   1. `XDPMF_TRUST_MODEL`   (variable name appears verbatim)
#   2. `trust_model=strict`  (stderr literal for strict mode)
#   3. `trust_model=fleet`   (stderr literal for fleet mode)
#   4. `xdpfilter: trust_model=`   (the exact stderr prefix from §5.26)
#   5. `XDPMF_TRUST_MODEL=fleet` inside a code block (Drop-In Environment= snippet)
#   6. At least one PI-fence reference: §5.4 | §5.19 | §5.22 | §5.24
#
# Each substring missing → distinct FAIL message (NOT generic "docs broken")
# so operators reading failure log can fix the docs directly.
#
# NOTE: substring 5 requires the literal to appear INSIDE a fenced
# code block (between ``` ... ``` fences) per §5.28 Q3 D1 anti-prose-drift
# requirement. We extract code-block content via awk and grep within it.
#
# Sanity-floor smoke: docs file must exist before any grep (file-existence baseline).
# Negation: 6 independent substring checks each fail distinctly = 6 negations.
#
# NO veth, NO root, NO RESOURCE_LOCK.
set -euo pipefail
source "${TEST_DIR}/lib/common.sh"

FLEET_DOCS="${FLEET_DOCS:-${SOURCE_DIR}/docs/FLEET_DEPLOYMENT.md}"

# Sanity / smoke: docs file must exist.
if [[ ! -f "${FLEET_DOCS}" ]]; then
    echo "FAIL: fleet docs not found at ${FLEET_DOCS}" >&2
    exit 1
fi

echo "=== checking 6 PI-23 substrings in ${FLEET_DOCS}"
fail=0

# ── Substring 1: XDPMF_TRUST_MODEL variable name verbatim ────────────────
if grep -qE '\bXDPMF_TRUST_MODEL\b' "${FLEET_DOCS}"; then
    echo "  [1] OK: 'XDPMF_TRUST_MODEL' present"
else
    echo "FAIL[1]: substring 'XDPMF_TRUST_MODEL' (env-var name) missing from ${FLEET_DOCS}" >&2
    fail=1
fi

# ── Substring 2: trust_model=strict stderr literal ───────────────────────
if grep -qE 'trust_model=strict\b' "${FLEET_DOCS}"; then
    echo "  [2] OK: 'trust_model=strict' present"
else
    echo "FAIL[2]: substring 'trust_model=strict' (strict-mode stderr literal) missing from ${FLEET_DOCS}" >&2
    fail=1
fi

# ── Substring 3: trust_model=fleet stderr literal ────────────────────────
if grep -qE 'trust_model=fleet\b' "${FLEET_DOCS}"; then
    echo "  [3] OK: 'trust_model=fleet' present"
else
    echo "FAIL[3]: substring 'trust_model=fleet' (fleet-mode stderr literal) missing from ${FLEET_DOCS}" >&2
    fail=1
fi

# ── Substring 4: exact stderr prefix from §5.26 (audit-grep target) ──────
# PI-23 verbatim: the loader's stderr-emit catalogue uses this exact prefix.
if grep -qE 'xdpfilter: trust_model=' "${FLEET_DOCS}"; then
    echo "  [4] OK: 'xdpfilter: trust_model=' present"
else
    echo "FAIL[4]: substring 'xdpfilter: trust_model=' (exact stderr prefix per §5.26) missing from ${FLEET_DOCS}" >&2
    fail=1
fi

# ── Substring 5: XDPMF_TRUST_MODEL=fleet inside a fenced code block ──────
# Extract everything between ``` ... ``` fences and grep within that
# subset. awk toggle-state: when we see a line that is exactly ``` (or
# ```lang), flip in/out. Only emit lines while inside a fenced block.
code_block_content=$(awk '
    /^```/ { in_block = !in_block; next }
    in_block { print }
' "${FLEET_DOCS}")

if grep -qE 'XDPMF_TRUST_MODEL=fleet' <<<"${code_block_content}"; then
    echo "  [5] OK: 'XDPMF_TRUST_MODEL=fleet' present inside a fenced code block"
else
    # Diagnostic: was it in the doc at all but not in a code block?
    if grep -qE 'XDPMF_TRUST_MODEL=fleet' "${FLEET_DOCS}"; then
        echo "FAIL[5]: substring 'XDPMF_TRUST_MODEL=fleet' present but NOT inside a fenced ('\`\`\`') code block" >&2
        echo "        (PI-23 / §5.28 Q3 D1: Drop-In Environment= snippet MUST be code-block context)" >&2
    else
        echo "FAIL[5]: substring 'XDPMF_TRUST_MODEL=fleet' missing from ${FLEET_DOCS} entirely" >&2
    fi
    fail=1
fi

# ── Substring 6: at least one PI-fence reference (§5.4|§5.19|§5.22|§5.24) ─
# One match suffices ("at least one of the four") per §6.36 spec.
if grep -qE '§5\.(4|19|22|24)\b' "${FLEET_DOCS}"; then
    echo "  [6] OK: at least one PI-fence §-reference present (§5.4|§5.19|§5.22|§5.24)"
else
    echo "FAIL[6]: NO PI-fence reference present (need at least one of §5.4 / §5.19 / §5.22 / §5.24) in ${FLEET_DOCS}" >&2
    fail=1
fi

[[ "${fail}" == 0 ]] && echo "PASS: T_FLEET_DOCS_SUBSTRING"
exit "${fail}"
